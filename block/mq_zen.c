// SPDX-License-Identifier: GPL-2.0
/*
 * Zen I/O Scheduler (blk-mq) - ULTIMATE STABLE EDITION
 * FCFS, VIP bypass for Flush, strict fairness batching.
 */
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/blk-mq.h>

#define ZEN_SYNC_BATCH 16

struct zen_hctx_data {
        struct list_head vip_list;   /* JALUR TOL VIP ANTI-FREEZE */
        struct list_head sync_list;
        struct list_head async_list;
        unsigned int sync_count;
        spinlock_t lock;
};

static void zen_insert_requests(struct blk_mq_hw_ctx *hctx,
                                struct list_head *list, bool at_head)
{
        struct zen_hctx_data *zdata = hctx->sched_data;
        struct request *rq;
        unsigned long flags;

        spin_lock_irqsave(&zdata->lock, flags);

        /* Mengosongkan list bawaan blk-mq dengan aman */
        while (!list_empty(list)) {
                rq = list_first_entry(list, struct request, queuelist);
                list_del_init(&rq->queuelist);

                /* Deteksi perintah VIP / Flush agar Android tidak hang */
                if (at_head || blk_rq_is_passthrough(rq) || op_is_flush(rq->cmd_flags)) {
                        if (at_head) list_add(&rq->queuelist, &zdata->vip_list);
                        else list_add_tail(&rq->queuelist, &zdata->vip_list);
                } 
                else if (op_is_sync(rq->cmd_flags)) {
                        list_add_tail(&rq->queuelist, &zdata->sync_list);
                } else {
                        list_add_tail(&rq->queuelist, &zdata->async_list);
                }
        }
        spin_unlock_irqrestore(&zdata->lock, flags);
}

static struct request *zen_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
        struct zen_hctx_data *zdata = hctx->sched_data;
        struct request *rq = NULL;
        unsigned long flags;

        spin_lock_irqsave(&zdata->lock, flags);

        /* 1. Eksekusi JALUR VIP Terlebih Dahulu! */
        if (!list_empty(&zdata->vip_list)) {
                rq = list_first_entry(&zdata->vip_list, struct request, queuelist);
                list_del_init(&rq->queuelist);
                goto done;
        }

        /* 2. Logika Zen Fairness */
        if (zdata->sync_count >= ZEN_SYNC_BATCH && !list_empty(&zdata->async_list)) {
                rq = list_first_entry(&zdata->async_list, struct request, queuelist);
                list_del_init(&rq->queuelist);
                zdata->sync_count = 0;
        } else if (!list_empty(&zdata->sync_list)) {
                rq = list_first_entry(&zdata->sync_list, struct request, queuelist);
                list_del_init(&rq->queuelist);
                zdata->sync_count++;
        } else if (!list_empty(&zdata->async_list)) {
                rq = list_first_entry(&zdata->async_list, struct request, queuelist);
                list_del_init(&rq->queuelist);
                zdata->sync_count = 0;
        }

done:
        spin_unlock_irqrestore(&zdata->lock, flags);
        return rq;
}

static bool zen_has_work(struct blk_mq_hw_ctx *hctx)
{
        struct zen_hctx_data *zdata = hctx->sched_data;
        bool has_work;
        unsigned long flags;

        spin_lock_irqsave(&zdata->lock, flags);
        has_work = !list_empty(&zdata->vip_list) || 
                   !list_empty(&zdata->sync_list) || 
                   !list_empty(&zdata->async_list);
        spin_unlock_irqrestore(&zdata->lock, flags);

        return has_work;
}

static int zen_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
        struct zen_hctx_data *zdata = kzalloc_node(sizeof(*zdata), GFP_KERNEL, hctx->numa_node);
        if (!zdata) return -ENOMEM;

        INIT_LIST_HEAD(&zdata->vip_list);
        INIT_LIST_HEAD(&zdata->sync_list);
        INIT_LIST_HEAD(&zdata->async_list);
        zdata->sync_count = 0;
        spin_lock_init(&zdata->lock);

        hctx->sched_data = zdata;
        return 0;
}

static void zen_exit_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
        kfree(hctx->sched_data);
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
        .uses_mq = true,
};

static int __init zen_init(void) { return elv_register(&iosched_zen_mq); }
static void __exit zen_exit(void) { elv_unregister(&iosched_zen_mq); }
module_init(zen_init);
module_exit(zen_exit);
MODULE_LICENSE("GPL v2");
