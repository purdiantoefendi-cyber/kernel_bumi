// SPDX-License-Identifier: GPL-2.0
/*
 * Gamer I/O Scheduler (blk-mq) - ULTIMATE STABLE EDITION
 * Smooth read priority to avoid frame drops.
 */
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/bio.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/init.h>
#include <linux/spinlock.h>
#include <linux/blk-mq.h>

#define GAMER_READ_QUANTUM 10
#define GAMER_WRITE_QUANTUM 2

struct gamer_hctx_data {
        struct list_head vip_list;
        struct list_head read_list;
        struct list_head write_list;
        spinlock_t lock;
        int read_count;
        int write_count;
        int current_prio;
};

static void gamer_insert_requests(struct blk_mq_hw_ctx *hctx,
                                  struct list_head *list, bool at_head)
{
        struct gamer_hctx_data *ghd = hctx->sched_data;
        struct request *rq;
        unsigned long flags;

        spin_lock_irqsave(&ghd->lock, flags);

        while (!list_empty(list)) {
                rq = list_first_entry(list, struct request, queuelist);
                list_del_init(&rq->queuelist);

                if (at_head || blk_rq_is_passthrough(rq) || op_is_flush(rq->cmd_flags)) {
                        if (at_head) list_add(&rq->queuelist, &ghd->vip_list);
                        else list_add_tail(&rq->queuelist, &ghd->vip_list);
                } 
                else if (rq_data_dir(rq) == READ) {
                        list_add_tail(&rq->queuelist, &ghd->read_list);
                } else {
                        list_add_tail(&rq->queuelist, &ghd->write_list);
                }
        }
        spin_unlock_irqrestore(&ghd->lock, flags);
}

static struct request *gamer_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
        struct gamer_hctx_data *ghd = hctx->sched_data;
        struct request *rq = NULL;
        unsigned long flags;

        spin_lock_irqsave(&ghd->lock, flags);

        if (!list_empty(&ghd->vip_list)) {
                rq = list_first_entry(&ghd->vip_list, struct request, queuelist);
                list_del_init(&rq->queuelist);
                goto done;
        }

        if (ghd->current_prio == 0) {
                if (!list_empty(&ghd->read_list) && ghd->read_count < GAMER_READ_QUANTUM) {
                        rq = list_first_entry(&ghd->read_list, struct request, queuelist);
                        list_del_init(&rq->queuelist);
                        ghd->read_count++;
                } else {
                        ghd->read_count = 0;
                        if (!list_empty(&ghd->write_list)) {
                                ghd->current_prio = 1;
                                rq = list_first_entry(&ghd->write_list, struct request, queuelist);
                                list_del_init(&rq->queuelist);
                                ghd->write_count = 1;
                        } else if (!list_empty(&ghd->read_list)) {
                                rq = list_first_entry(&ghd->read_list, struct request, queuelist);
                                list_del_init(&rq->queuelist);
                                ghd->read_count = 1;
                        }
                }
        } else {
                if (!list_empty(&ghd->write_list) && ghd->write_count < GAMER_WRITE_QUANTUM) {
                        rq = list_first_entry(&ghd->write_list, struct request, queuelist);
                        list_del_init(&rq->queuelist);
                        ghd->write_count++;
                } else {
                        ghd->write_count = 0;
                        if (!list_empty(&ghd->read_list)) {
                                ghd->current_prio = 0;
                                rq = list_first_entry(&ghd->read_list, struct request, queuelist);
                                list_del_init(&rq->queuelist);
                                ghd->read_count = 1;
                        } else if (!list_empty(&ghd->write_list)) {
                                rq = list_first_entry(&ghd->write_list, struct request, queuelist);
                                list_del_init(&rq->queuelist);
                                ghd->write_count = 1;
                        }
                }
        }

done:
        spin_unlock_irqrestore(&ghd->lock, flags);
        return rq;
}

static bool gamer_has_work(struct blk_mq_hw_ctx *hctx)
{
        struct gamer_hctx_data *ghd = hctx->sched_data;
        bool has_work;
        unsigned long flags;

        spin_lock_irqsave(&ghd->lock, flags);
        has_work = !list_empty(&ghd->vip_list) || 
                   !list_empty(&ghd->read_list) || 
                   !list_empty(&ghd->write_list);
        spin_unlock_irqrestore(&ghd->lock, flags);
        return has_work;
}

static int gamer_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
        struct gamer_hctx_data *ghd = kzalloc_node(sizeof(*ghd), GFP_KERNEL, hctx->numa_node);
        if (!ghd) return -ENOMEM;

        INIT_LIST_HEAD(&ghd->vip_list);
        INIT_LIST_HEAD(&ghd->read_list);
        INIT_LIST_HEAD(&ghd->write_list);
        spin_lock_init(&ghd->lock);
        ghd->read_count = 0;
        ghd->write_count = 0;
        ghd->current_prio = 0;

        hctx->sched_data = ghd;
        return 0;
}

static void gamer_exit_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
        kfree(hctx->sched_data);
}

static struct elevator_type gamer_sched = {
        .ops.mq = {
                .init_hctx = gamer_init_hctx,
                .exit_hctx = gamer_exit_hctx,
                .insert_requests = gamer_insert_requests,
                .dispatch_request = gamer_dispatch_request,
                .has_work = gamer_has_work,
        },
        .elevator_name = "gamer",
        .elevator_owner = THIS_MODULE,
        .uses_mq = true,
};

static int __init gamer_init(void) { return elv_register(&gamer_sched); }
static void __exit gamer_exit(void) { elv_unregister(&gamer_sched); }
module_init(gamer_init);
module_exit(gamer_exit);
MODULE_AUTHOR("Oni");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Gaming-optimized Blk-MQ I/O Scheduler");
