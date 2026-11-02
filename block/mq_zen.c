// SPDX-License-Identifier: GPL-2.0
/*
 * Zen I/O Scheduler - Kyber Architecture Base
 * No Freeze Ultimate Edition
 */
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/elevator.h>
#include <linux/module.h>
#include <linux/sbitmap.h>

#include "blk.h"
#include "blk-mq.h"
#include "blk-mq-sched.h"
#include "blk-mq-tag.h"
#include "blk-stat.h"

enum { ZEN_READ, ZEN_SYNC_WRITE, ZEN_OTHER, ZEN_NUM_DOMAINS };
enum { ZEN_MIN_DEPTH = 256, ZEN_ASYNC_PERCENT = 75 };

static const unsigned int zen_depth[] = {
	[ZEN_READ] = 256, [ZEN_SYNC_WRITE] = 128, [ZEN_OTHER] = 64,
};

static const unsigned int zen_batch_size[] = {
	[ZEN_READ] = 16, [ZEN_SYNC_WRITE] = 4, [ZEN_OTHER] = 4,
};

struct zen_ctx_queue {
	spinlock_t lock;
	struct list_head rq_list[ZEN_NUM_DOMAINS];
} ____cacheline_aligned_in_smp;

struct zen_queue_data {
	struct request_queue *q;
	struct blk_stat_callback *cb;
	struct sbitmap_queue domain_tokens[ZEN_NUM_DOMAINS];
	unsigned int async_depth;
	u64 read_lat_nsec, write_lat_nsec;
};

struct zen_hctx_data {
	spinlock_t lock;
	struct list_head rqs[ZEN_NUM_DOMAINS];
	unsigned int cur_domain;
	unsigned int batching;
	struct zen_ctx_queue *kcqs;
	struct sbitmap kcq_map[ZEN_NUM_DOMAINS];
	wait_queue_entry_t domain_wait[ZEN_NUM_DOMAINS];
	struct sbq_wait_state *domain_ws[ZEN_NUM_DOMAINS];
	atomic_t wait_index[ZEN_NUM_DOMAINS];
};

static int zen_domain_wake(wait_queue_entry_t *wait, unsigned mode, int flags, void *key);

static unsigned int zen_sched_domain(unsigned int op)
{
	if ((op & REQ_OP_MASK) == REQ_OP_READ) return ZEN_READ;
	else if ((op & REQ_OP_MASK) == REQ_OP_WRITE && op_is_sync(op)) return ZEN_SYNC_WRITE;
	else return ZEN_OTHER;
}

enum { NONE = 0, GOOD = 1, GREAT = 2, BAD = -1, AWFUL = -2 };
#define IS_GOOD(status) ((status) > 0)
#define IS_BAD(status) ((status) < 0)

static int zen_lat_status(struct blk_stat_callback *cb, unsigned int sched_domain, u64 target)
{
	u64 latency;
	if (!cb->stat[sched_domain].nr_samples) return NONE;
	latency = cb->stat[sched_domain].mean;
	if (latency >= 2 * target) return AWFUL;
	else if (latency > target) return BAD;
	else if (latency <= target / 2) return GREAT;
	else return GOOD;
}

static void zen_adjust_rw_depth(struct zen_queue_data *kqd, unsigned int sched_domain, int this_status, int other_status)
{
	unsigned int orig_depth, depth;
	if (this_status == NONE || (IS_GOOD(this_status) && IS_GOOD(other_status)) || (IS_BAD(this_status) && IS_BAD(other_status))) return;

	orig_depth = depth = kqd->domain_tokens[sched_domain].sb.depth;
	if (other_status == NONE) depth++;
	else {
		switch (this_status) {
		case GOOD: depth -= max(depth / 8, 1U); break;
		case GREAT: depth -= max(depth / 4, 1U); break;
		case BAD: depth++; break;
		case AWFUL: depth += 2; break;
		}
	}
	depth = clamp(depth, 1U, zen_depth[sched_domain]);
	if (depth != orig_depth) sbitmap_queue_resize(&kqd->domain_tokens[sched_domain], depth);
}

static void zen_adjust_other_depth(struct zen_queue_data *kqd, int read_status, int write_status, bool have_samples)
{
	unsigned int orig_depth, depth;
	int status;
	orig_depth = depth = kqd->domain_tokens[ZEN_OTHER].sb.depth;

	if (read_status == NONE && write_status == NONE) depth += 2;
	else if (have_samples) {
		if (read_status == NONE) status = write_status;
		else if (write_status == NONE) status = read_status;
		else status = max(read_status, write_status);
		switch (status) {
		case GREAT: depth += 2; break;
		case GOOD: depth++; break;
		case BAD: depth -= max(depth / 4, 1U); break;
		case AWFUL: depth /= 2; break;
		}
	}
	depth = clamp(depth, 1U, zen_depth[ZEN_OTHER]);
	if (depth != orig_depth) sbitmap_queue_resize(&kqd->domain_tokens[ZEN_OTHER], depth);
}

static void zen_stat_timer_fn(struct blk_stat_callback *cb)
{
	struct zen_queue_data *kqd = cb->data;
	int read_status = zen_lat_status(cb, ZEN_READ, kqd->read_lat_nsec);
	int write_status = zen_lat_status(cb, ZEN_SYNC_WRITE, kqd->write_lat_nsec);

	zen_adjust_rw_depth(kqd, ZEN_READ, read_status, write_status);
	zen_adjust_rw_depth(kqd, ZEN_SYNC_WRITE, write_status, read_status);
	zen_adjust_other_depth(kqd, read_status, write_status, cb->stat[ZEN_OTHER].nr_samples != 0);

	if (!blk_stat_is_active(kqd->cb) && ((IS_BAD(read_status) || IS_BAD(write_status) || kqd->domain_tokens[ZEN_OTHER].sb.depth < zen_depth[ZEN_OTHER])))
		blk_stat_activate_msecs(kqd->cb, 100);
}

static unsigned int zen_sched_tags_shift(struct zen_queue_data *kqd)
{
	return kqd->q->queue_hw_ctx[0]->sched_tags->bitmap_tags.sb.shift;
}

static int zen_bucket_fn(const struct request *rq)
{
	return zen_sched_domain(rq->cmd_flags);
}

static struct zen_queue_data *zen_queue_data_alloc(struct request_queue *q)
{
	struct zen_queue_data *kqd;
	unsigned int max_tokens, shift;
	int ret = -ENOMEM, i;

	kqd = kmalloc_node(sizeof(*kqd), GFP_KERNEL, q->node);
	if (!kqd) return ERR_PTR(-ENOMEM);
	kqd->q = q;

	kqd->cb = blk_stat_alloc_callback(zen_stat_timer_fn, zen_bucket_fn, ZEN_NUM_DOMAINS, kqd);
	if (!kqd->cb) { kfree(kqd); return ERR_PTR(-ENOMEM); }

	max_tokens = max_t(unsigned int, q->tag_set->queue_depth, ZEN_MIN_DEPTH);
	for (i = 0; i < ZEN_NUM_DOMAINS; i++) {
		ret = sbitmap_queue_init_node(&kqd->domain_tokens[i], max_tokens, -1, false, GFP_KERNEL, q->node);
		if (ret) {
			while (--i >= 0) sbitmap_queue_free(&kqd->domain_tokens[i]);
			blk_stat_free_callback(kqd->cb);
			kfree(kqd);
			return ERR_PTR(ret);
		}
		sbitmap_queue_resize(&kqd->domain_tokens[i], zen_depth[i]);
	}

	shift = zen_sched_tags_shift(kqd);
	kqd->async_depth = (1U << shift) * ZEN_ASYNC_PERCENT / 100U;
	kqd->read_lat_nsec = 2000000ULL;
	kqd->write_lat_nsec = 10000000ULL;

	return kqd;
}

static int zen_init_sched(struct request_queue *q, struct elevator_type *e)
{
	struct zen_queue_data *kqd;
	struct elevator_queue *eq = elevator_alloc(q, e);
	if (!eq) return -ENOMEM;

	kqd = zen_queue_data_alloc(q);
	if (IS_ERR(kqd)) { kobject_put(&eq->kobj); return PTR_ERR(kqd); }

	eq->elevator_data = kqd;
	q->elevator = eq;
	blk_stat_add_callback(q, kqd->cb);
	return 0;
}

static void zen_exit_sched(struct elevator_queue *e)
{
	struct zen_queue_data *kqd = e->elevator_data;
	struct request_queue *q = kqd->q;
	int i;
	blk_stat_remove_callback(q, kqd->cb);
	for (i = 0; i < ZEN_NUM_DOMAINS; i++) sbitmap_queue_free(&kqd->domain_tokens[i]);
	blk_stat_free_callback(kqd->cb);
	kfree(kqd);
}

static void zen_ctx_queue_init(struct zen_ctx_queue *kcq)
{
	unsigned int i;
	spin_lock_init(&kcq->lock);
	for (i = 0; i < ZEN_NUM_DOMAINS; i++) INIT_LIST_HEAD(&kcq->rq_list[i]);
}

static int zen_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct zen_queue_data *kqd = hctx->queue->elevator->elevator_data;
	struct zen_hctx_data *khd;
	int i;

	khd = kmalloc_node(sizeof(*khd), GFP_KERNEL, hctx->numa_node);
	if (!khd) return -ENOMEM;

	khd->kcqs = kmalloc_array_node(hctx->nr_ctx, sizeof(struct zen_ctx_queue), GFP_KERNEL, hctx->numa_node);
	if (!khd->kcqs) { kfree(khd); return -ENOMEM; }

	for (i = 0; i < hctx->nr_ctx; i++) zen_ctx_queue_init(&khd->kcqs[i]);

	for (i = 0; i < ZEN_NUM_DOMAINS; i++) {
		if (sbitmap_init_node(&khd->kcq_map[i], hctx->nr_ctx, ilog2(8), GFP_KERNEL, hctx->numa_node)) {
			while (--i >= 0) sbitmap_free(&khd->kcq_map[i]);
			kfree(khd->kcqs); kfree(khd); return -ENOMEM;
		}
	}

	spin_lock_init(&khd->lock);
	for (i = 0; i < ZEN_NUM_DOMAINS; i++) {
		INIT_LIST_HEAD(&khd->rqs[i]);
		init_waitqueue_func_entry(&khd->domain_wait[i], zen_domain_wake);
		khd->domain_wait[i].private = hctx;
		INIT_LIST_HEAD(&khd->domain_wait[i].entry);
		atomic_set(&khd->wait_index[i], 0);
	}

	khd->cur_domain = 0;
	khd->batching = 0;
	hctx->sched_data = khd;
	sbitmap_queue_min_shallow_depth(&hctx->sched_tags->bitmap_tags, kqd->async_depth);
	return 0;
}

static void zen_exit_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct zen_hctx_data *khd = hctx->sched_data;
	int i;
	for (i = 0; i < ZEN_NUM_DOMAINS; i++) sbitmap_free(&khd->kcq_map[i]);
	kfree(khd->kcqs);
	kfree(hctx->sched_data);
}

static int rq_get_domain_token(struct request *rq) { return (long)rq->elv.priv[0]; }
static void rq_set_domain_token(struct request *rq, int token) { rq->elv.priv[0] = (void *)(long)token; }
static void rq_clear_domain_token(struct zen_queue_data *kqd, struct request *rq)
{
	int nr = rq_get_domain_token(rq);
	if (nr != -1) {
		unsigned int sched_domain = zen_sched_domain(rq->cmd_flags);
		sbitmap_queue_clear(&kqd->domain_tokens[sched_domain], nr, rq->mq_ctx->cpu);
	}
}

static void zen_limit_depth(unsigned int op, struct blk_mq_alloc_data *data)
{
	if (!op_is_sync(op)) {
		struct zen_queue_data *kqd = data->q->elevator->elevator_data;
		data->shallow_depth = kqd->async_depth;
	}
}

static bool zen_bio_merge(struct blk_mq_hw_ctx *hctx, struct bio *bio)
{
	struct zen_hctx_data *khd = hctx->sched_data;
	struct blk_mq_ctx *ctx = blk_mq_get_ctx(hctx->queue);
	struct zen_ctx_queue *kcq = &khd->kcqs[ctx->index_hw];
	unsigned int sched_domain = zen_sched_domain(bio->bi_opf);
	bool merged;

	spin_lock(&kcq->lock);
	merged = blk_mq_bio_list_merge(hctx->queue, &kcq->rq_list[sched_domain], bio);
	spin_unlock(&kcq->lock);
	blk_mq_put_ctx(ctx);
	return merged;
}

static void zen_prepare_request(struct request *rq, struct bio *bio) { rq_set_domain_token(rq, -1); }

static void zen_insert_requests(struct blk_mq_hw_ctx *hctx, struct list_head *rq_list, bool at_head)
{
	struct zen_hctx_data *khd = hctx->sched_data;
	struct request *rq, *next;

	list_for_each_entry_safe(rq, next, rq_list, queuelist) {
		unsigned int sched_domain = zen_sched_domain(rq->cmd_flags);
		struct zen_ctx_queue *kcq = &khd->kcqs[rq->mq_ctx->index_hw];
		struct list_head *head = &kcq->rq_list[sched_domain];

		spin_lock(&kcq->lock);
		if (at_head) list_move(&rq->queuelist, head);
		else list_move_tail(&rq->queuelist, head);
		sbitmap_set_bit(&khd->kcq_map[sched_domain], rq->mq_ctx->index_hw);
		blk_mq_sched_request_inserted(rq);
		spin_unlock(&kcq->lock);
	}
}

static void zen_finish_request(struct request *rq)
{
	struct zen_queue_data *kqd = rq->q->elevator->elevator_data;
	rq_clear_domain_token(kqd, rq);
}

static void zen_completed_request(struct request *rq)
{
	struct request_queue *q = rq->q;
	struct zen_queue_data *kqd = q->elevator->elevator_data;
	unsigned int sched_domain = zen_sched_domain(rq->cmd_flags);
	u64 now, latency, target;

	switch (sched_domain) {
	case ZEN_READ: target = kqd->read_lat_nsec; break;
	case ZEN_SYNC_WRITE: target = kqd->write_lat_nsec; break;
	default: return;
	}

	if (blk_stat_is_active(kqd->cb)) return;
	now = ktime_get_ns();
	if (now < rq->io_start_time_ns) return;
	latency = now - rq->io_start_time_ns;

	if (latency > target) blk_stat_activate_msecs(kqd->cb, 10);
}

struct zen_flush_kcq_data {
	struct zen_hctx_data *khd;
	unsigned int sched_domain;
	struct list_head *list;
};

static bool flush_busy_kcq(struct sbitmap *sb, unsigned int bitnr, void *data)
{
	struct zen_flush_kcq_data *flush_data = data;
	struct zen_ctx_queue *kcq = &flush_data->khd->kcqs[bitnr];

	spin_lock(&kcq->lock);
	list_splice_tail_init(&kcq->rq_list[flush_data->sched_domain], flush_data->list);
	sbitmap_clear_bit(sb, bitnr);
	spin_unlock(&kcq->lock);
	return true;
}

static void zen_flush_busy_kcqs(struct zen_hctx_data *khd, unsigned int sched_domain, struct list_head *list)
{
	struct zen_flush_kcq_data data = { .khd = khd, .sched_domain = sched_domain, .list = list };
	sbitmap_for_each_set(&khd->kcq_map[sched_domain], flush_busy_kcq, &data);
}

static int zen_domain_wake(wait_queue_entry_t *wait, unsigned mode, int flags, void *key)
{
	struct blk_mq_hw_ctx *hctx = READ_ONCE(wait->private);
	list_del_init(&wait->entry);
	blk_mq_run_hw_queue(hctx, true);
	return 1;
}

static int zen_get_domain_token(struct zen_queue_data *kqd, struct zen_hctx_data *khd, struct blk_mq_hw_ctx *hctx)
{
	unsigned int sched_domain = khd->cur_domain;
	struct sbitmap_queue *domain_tokens = &kqd->domain_tokens[sched_domain];
	wait_queue_entry_t *wait = &khd->domain_wait[sched_domain];
	struct sbq_wait_state *ws;
	int nr = __sbitmap_queue_get(domain_tokens);

	if (nr < 0 && list_empty_careful(&wait->entry)) {
		ws = sbq_wait_ptr(domain_tokens, &khd->wait_index[sched_domain]);
		khd->domain_ws[sched_domain] = ws;
		add_wait_queue(&ws->wait, wait);
		nr = __sbitmap_queue_get(domain_tokens);
	}

	if (nr >= 0 && !list_empty_careful(&wait->entry)) {
		ws = khd->domain_ws[sched_domain];
		spin_lock_irq(&ws->wait.lock);
		list_del_init(&wait->entry);
		spin_unlock_irq(&ws->wait.lock);
	}
	return nr;
}

static struct request *zen_dispatch_cur_domain(struct zen_queue_data *kqd, struct zen_hctx_data *khd, struct blk_mq_hw_ctx *hctx)
{
	struct list_head *rqs = &khd->rqs[khd->cur_domain];
	struct request *rq;
	int nr;

	rq = list_first_entry_or_null(rqs, struct request, queuelist);
	if (rq) {
		nr = zen_get_domain_token(kqd, khd, hctx);
		if (nr >= 0) {
			khd->batching++;
			rq_set_domain_token(rq, nr);
			list_del_init(&rq->queuelist);
			return rq;
		}
	} else if (sbitmap_any_bit_set(&khd->kcq_map[khd->cur_domain])) {
		nr = zen_get_domain_token(kqd, khd, hctx);
		if (nr >= 0) {
			zen_flush_busy_kcqs(khd, khd->cur_domain, rqs);
			rq = list_first_entry(rqs, struct request, queuelist);
			khd->batching++;
			rq_set_domain_token(rq, nr);
			list_del_init(&rq->queuelist);
			return rq;
		}
	}
	return NULL;
}

static struct request *zen_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct zen_queue_data *kqd = hctx->queue->elevator->elevator_data;
	struct zen_hctx_data *khd = hctx->sched_data;
	struct request *rq;
	int i;

	spin_lock(&khd->lock);
	if (khd->batching < zen_batch_size[khd->cur_domain]) {
		rq = zen_dispatch_cur_domain(kqd, khd, hctx);
		if (rq) goto out;
	}

	khd->batching = 0;
	for (i = 0; i < ZEN_NUM_DOMAINS; i++) {
		if (khd->cur_domain == ZEN_NUM_DOMAINS - 1) khd->cur_domain = 0;
		else khd->cur_domain++;

		rq = zen_dispatch_cur_domain(kqd, khd, hctx);
		if (rq) goto out;
	}
	rq = NULL;
out:
	spin_unlock(&khd->lock);
	return rq;
}

static bool zen_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct zen_hctx_data *khd = hctx->sched_data;
	int i;
	for (i = 0; i < ZEN_NUM_DOMAINS; i++) {
		if (!list_empty_careful(&khd->rqs[i]) || sbitmap_any_bit_set(&khd->kcq_map[i]))
			return true;
	}
	return false;
}

#define ZEN_LAT_SHOW_STORE(op) \
static ssize_t zen_##op##_lat_show(struct elevator_queue *e, char *page) \
{ \
	struct zen_queue_data *kqd = e->elevator_data; \
	return sprintf(page, "%llu\n", kqd->op##_lat_nsec); \
} \
static ssize_t zen_##op##_lat_store(struct elevator_queue *e, const char *page, size_t count) \
{ \
	struct zen_queue_data *kqd = e->elevator_data; \
	unsigned long long nsec; \
	int ret = kstrtoull(page, 10, &nsec); \
	if (ret) return ret; \
	kqd->op##_lat_nsec = nsec; \
	return count; \
}
ZEN_LAT_SHOW_STORE(read);
ZEN_LAT_SHOW_STORE(write);

#define ZEN_LAT_ATTR(op) __ATTR(op##_lat_nsec, 0644, zen_##op##_lat_show, zen_##op##_lat_store)
static struct elv_fs_entry zen_sched_attrs[] = {
	ZEN_LAT_ATTR(read),
	ZEN_LAT_ATTR(write),
	__ATTR_NULL
};

static struct elevator_type iosched_zen_mq = {
	.ops.mq = {
		.init_sched = zen_init_sched,
		.exit_sched = zen_exit_sched,
		.init_hctx = zen_init_hctx,
		.exit_hctx = zen_exit_hctx,
		.limit_depth = zen_limit_depth,
		.bio_merge = zen_bio_merge,
		.prepare_request = zen_prepare_request,
		.insert_requests = zen_insert_requests,
		.finish_request = zen_finish_request,
		.requeue_request = zen_finish_request,
		.completed_request = zen_completed_request,
		.dispatch_request = zen_dispatch_request,
		.has_work = zen_has_work,
	},
	.uses_mq = true,
	.elevator_attrs = zen_sched_attrs,
	.elevator_name = "zen",
	.elevator_owner = THIS_MODULE,
};

static int __init zen_init(void) { return elv_register(&iosched_zen_mq); }
static void __exit zen_exit(void) { elv_unregister(&iosched_zen_mq); }
module_init(zen_init);
module_exit(zen_exit);
MODULE_LICENSE("GPL v2");
