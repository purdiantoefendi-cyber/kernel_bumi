// SPDX-License-Identifier: GPL-2.0
/*
 * Performance I/O Scheduler (blk-mq) - ULTIMATE ANTI-FREEZE EDITION
 */
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/blk-mq.h>

#define PERF_READ_QUANTUM 100
#define PERF_WRITE_QUANTUM 10

struct perf_hctx_data {
        struct list_head vip_list;
        struct list_head read_list;
        struct list_head write_list;
        spinlock_t lock;
        int read_count;
        int write_count;
        int current_prio;
};

static void perf_insert_requests(struct blk_mq_hw_ctx *hctx,
                                 struct list_head *list, bool at_head)
{
        struct perf_hctx_data *hd = hctx->sched_data;
        struct request *rq, *next;

        spin_lock(&hd->lock);
        list_for_each_entry_safe(rq, next, list, queuelist) {
                list_del_init(&rq->queuelist);

                if (at_head) {
                        list_add(&rq->queuelist, &hd->vip_list);
                } else {
                        if (rq_data_dir(rq) == READ)
                                list_add_tail(&rq->queuelist, &hd->read_list);
                        else
                                list_add_tail(&rq->queuelist, &hd->write_list);
                }
        }
        spin_unlock(&hd->lock);
}

static struct request *perf_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
        struct perf_hctx_data *hd = hctx->sched_data;
        struct request *rq = NULL;

        spin_lock(&hd->lock);

        if (!list_empty(&hd->vip_list)) {
                rq = list_first_entry(&hd->vip_list, struct request, queuelist);
                list_del_init(&rq->queuelist);
                goto done;
        }

        if (hd->current_prio == 0) {
                if (!list_empty(&hd->read_list) && hd->read_count < PERF_READ_QUANTUM) {
                        rq = list_first_entry(&hd->read_list, struct request, queuelist);
                        list_del_init(&rq->queuelist);
                        hd->read_count++;
                } else {
                        hd->read_count = 0;
                        if (!list_empty(&hd->write_list)) {
                                hd->current_prio = 1;
                                rq = list_first_entry(&hd->write_list, struct request, queuelist);
                                list_del_init(&rq->queuelist);
                                hd->write_count = 1;
                        } else if (!list_empty(&hd->read_list)) {
                                rq = list_first_entry(&hd->read_list, struct request, queuelist);
                                list_del_init(&rq->queuelist);
                                hd->read_count = 1;
                        }
                }
        } else {
                if (!list_empty(&hd->write_list) && hd->write_count < PERF_WRITE_QUANTUM) {
                        rq = list_first_entry(&hd->write_list, struct request, queuelist);
                        list_del_init(&rq->queuelist);
                        hd->write_count++;
                } else {
                        hd->write_count = 0;
                        if (!list_empty(&hd->read_list)) {
                                hd->current_prio = 0;
                                rq = list_first_entry(&hd->read_list, struct request, queuelist);
                                list_del_init(&rq->queuelist);
                                hd->read_count = 1;
                        } else if (!list_empty(&hd->write_list)) {
                                rq = list_first_entry(&hd->write_list, struct request, queuelist);
                                list_del_init(&rq->queuelist);
                                hd->write_count = 1;
                        }
                }
        }

done:
        spin_unlock(&hd->lock);
        return rq;
}

static bool perf_has_work(struct blk_mq_hw_ctx *hctx)
{
        struct perf_hctx_data *hd = hctx->sched_data;
        return !list_empty_careful(&hd->vip_list) || 
               !list_empty_careful(&hd->read_list) || 
               !list_empty_careful(&hd->write_list);
}

static int perf_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
        struct perf_hctx_data *hd = kzalloc_node(sizeof(*hd), GFP_KERNEL, hctx->numa_node);
        if (!hd) return -ENOMEM;

        INIT_LIST_HEAD(&hd->vip_list);
        INIT_LIST_HEAD(&hd->read_list);
        INIT_LIST_HEAD(&hd->write_list);
        spin_lock_init(&hd->lock);
        hd->read_count = 0;
        hd->write_count = 0;
        hd->current_prio = 0;

        hctx->sched_data = hd;
        return 0;
}

static void perf_exit_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
        kfree(hctx->sched_data);
}

static struct elevator_type perf_sched = {
        .ops.mq = {
                .insert_requests = perf_insert_requests,
                .dispatch_request = perf_dispatch_request,
                .has_work = perf_has_work,
                .init_hctx = perf_init_hctx,
                .exit_hctx = perf_exit_hctx,
        },
        .elevator_name = "performance", 
        .elevator_owner = THIS_MODULE,
        .uses_mq = true,
};

static int __init perf_init(void) { return elv_register(&perf_sched); }
static void __exit perf_exit(void) { elv_unregister(&perf_sched); }
module_init(perf_init);
module_exit(perf_exit);
MODULE_LICENSE("GPL v2");
