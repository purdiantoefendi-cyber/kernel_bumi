// SPDX-License-Identifier: GPL-2.0
/*
 * Zen I/O Scheduler (Multi-Queue / blk-mq Edition for Kernel 4.19+)
 * Ported from SQ to MQ architecture by Gemini.
 *
 * FCFS, dispatches are back-inserted, deadlines ensure fairness.
 * Synchronous requests have priority over asynchronous.
 */
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/blk-mq.h>

enum zen_data_dir { ASYNC = 0, SYNC = 1 };

/* Konstanta Tenggat Waktu (Hardcoded untuk respons instan) */
static const int zen_sync_expire  = HZ / 2;    /* 0.5 detik maksimal untuk Baca (Sync) */
static const int zen_async_expire = 5 * HZ;    /* 5 detik maksimal untuk Tulis (Async) */
static const int zen_fifo_batch = 1;           /* Batas eksekusi beruntun */

/* Struktur Data Multi-Queue (Dibuat per Hardware Context) */
struct zen_hctx_data {
	struct list_head fifo_list[2];
	unsigned int batching;
	spinlock_t lock;
};

static void zen_insert_requests(struct blk_mq_hw_ctx *hctx,
                                struct list_head *list, bool at_head)
{
	struct zen_hctx_data *zdata = hctx->sched_data;
	struct request *rq, *next;

	spin_lock(&zdata->lock);
	list_for_each_entry_safe(rq, next, list, queuelist) {
		int sync = op_is_sync(rq->cmd_flags) ? SYNC : ASYNC;
		unsigned long expire_time = jiffies + (sync == SYNC ? zen_sync_expire : zen_async_expire);

		list_del_init(&rq->queuelist);

		/* Kita titipkan data waktu kedaluwarsa di memori privat request (elv.priv) */
		rq->elv.priv[0] = (void *)expire_time;

		if (at_head)
			list_add(&rq->queuelist, &zdata->fifo_list[sync]);
		else
			list_add_tail(&rq->queuelist, &zdata->fifo_list[sync]);
	}
	spin_unlock(&zdata->lock);
}

/* Mengambil request pertama yang sudah kedaluwarsa */
static struct request *zen_expired_request(struct zen_hctx_data *zdata, int ddir)
{
	struct request *rq;

	if (list_empty(&zdata->fifo_list[ddir]))
		return NULL;

	rq = list_first_entry(&zdata->fifo_list[ddir], struct request, queuelist);
	if (time_after(jiffies, (unsigned long)rq->elv.priv[0]))
		return rq;

	return NULL;
}

/* Memeriksa antrean apakah ada yang melanggar tenggat waktu */
static struct request *zen_check_fifo(struct zen_hctx_data *zdata)
{
	struct request *rq_sync = zen_expired_request(zdata, SYNC);
	struct request *rq_async = zen_expired_request(zdata, ASYNC);

	if (rq_async && rq_sync) {
		if (time_after((unsigned long)rq_async->elv.priv[0], (unsigned long)rq_sync->elv.priv[0]))
			return rq_sync;
	} else if (rq_sync) {
		return rq_sync;
	} else if (rq_async) {
		return rq_async;
	}

	return NULL;
}

/* Logika Utama: Ambil Sync (Baca) dulu. Jika kosong, baru Async (Tulis) */
static struct request *zen_choose_request(struct zen_hctx_data *zdata)
{
	if (!list_empty(&zdata->fifo_list[SYNC]))
		return list_first_entry(&zdata->fifo_list[SYNC], struct request, queuelist);
	if (!list_empty(&zdata->fifo_list[ASYNC]))
		return list_first_entry(&zdata->fifo_list[ASYNC], struct request, queuelist);

	return NULL;
}

static struct request *zen_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct zen_hctx_data *zdata = hctx->sched_data;
	struct request *rq = NULL;

	spin_lock(&zdata->lock);

	/* 1. Cek apakah ada yang kedaluwarsa (Penyelamatan aplikasi hang) */
	if (zdata->batching > zen_fifo_batch) {
		zdata->batching = 0;
		rq = zen_check_fifo(zdata);
	}

	/* 2. Jika tidak ada yang darurat, jalankan normal (Prioritas BACA absolut) */
	if (!rq) {
		rq = zen_choose_request(zdata);
	}

	/* 3. Keluarkan dari antrean untuk dieksekusi */
	if (rq) {
		list_del_init(&rq->queuelist);
		zdata->batching++;
	}

	spin_unlock(&zdata->lock);
	return rq;
}

static bool zen_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct zen_hctx_data *zdata = hctx->sched_data;
	bool has_work;

	spin_lock(&zdata->lock);
	has_work = !list_empty(&zdata->fifo_list[SYNC]) || !list_empty(&zdata->fifo_list[ASYNC]);
	spin_unlock(&zdata->lock);

	return has_work;
}

static int zen_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct zen_hctx_data *zdata;

	zdata = kzalloc_node(sizeof(*zdata), GFP_KERNEL, hctx->numa_node);
	if (!zdata)
		return -ENOMEM;

	INIT_LIST_HEAD(&zdata->fifo_list[SYNC]);
	INIT_LIST_HEAD(&zdata->fifo_list[ASYNC]);
	zdata->batching = 0;
	spin_lock_init(&zdata->lock);

	hctx->sched_data = zdata;
	return 0;
}

static void zen_exit_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
	struct zen_hctx_data *zdata = hctx->sched_data;
	kfree(zdata);
}

static struct elevator_type iosched_zen_mq = {
	.ops.mq = {
		.insert_requests = zen_insert_requests,
		.dispatch_request = zen_dispatch_request,
		.has_work = zen_has_work,
		.init_hctx = zen_init_hctx,
		.exit_hctx = zen_exit_hctx,
	},
	.elevator_name = "zen",
	.elevator_owner = THIS_MODULE,
};

static int __init zen_init(void)
{
	return elv_register(&iosched_zen_mq);
}

static void __exit zen_exit(void)
{
	elv_unregister(&iosched_zen_mq);
}

module_init(zen_init);
module_exit(zen_exit);

MODULE_AUTHOR("Gemini (Ported from Brandon Berhent's SQ Zen)");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Zen IO scheduler (Multi-Queue Edition)");
MODULE_VERSION("2.0");
