// SPDX-License-Identifier: GPL-2.0
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
#include <linux/interrupt.h>

/* PERUBAHAN UTAMA: Struktur data sekarang terikat per-jalur (HCTX), bukan global */
struct gamer_hctx_data {
        struct list_head read_list;
        struct list_head write_list;
        spinlock_t lock;
        int read_count;
};

static void gamer_insert_requests(struct blk_mq_hw_ctx *hctx,
                                  struct list_head *list, bool at_head)
{
        /* Mengambil data dari sched_data milik HCTX spesifik */
        struct gamer_hctx_data *ghd = hctx->sched_data;
        struct request *rq, *n;
        unsigned long flags;

        spin_lock_irqsave(&ghd->lock, flags);
        
        list_for_each_entry_safe(rq, n, list, queuelist) {
                list_del_init(&rq->queuelist);

                if (rq_data_dir(rq) == READ) {
                        if (at_head)
                                list_add(&rq->queuelist, &ghd->read_list);
                        else
                                list_add_tail(&rq->queuelist, &ghd->read_list);
                } else {
                        if (at_head)
                                list_add(&rq->queuelist, &ghd->write_list);
                        else
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

        /* Logika Prioritas & Anti-Starvation */
        if (!list_empty(&ghd->read_list) && (ghd->read_count < 10 || list_empty(&ghd->write_list))) {
                rq = list_first_entry(&ghd->read_list, struct request, queuelist);
                list_del_init(&rq->queuelist);
                ghd->read_count++;
        } 
        else if (!list_empty(&ghd->write_list)) {
                rq = list_first_entry(&ghd->write_list, struct request, queuelist);
                list_del_init(&rq->queuelist);
                ghd->read_count = 0;
        }

        spin_unlock_irqrestore(&ghd->lock, flags);

        return rq;
}

static bool gamer_has_work(struct blk_mq_hw_ctx *hctx)
{
        struct gamer_hctx_data *ghd = hctx->sched_data;
        bool has_work;
        unsigned long flags;

        spin_lock_irqsave(&ghd->lock, flags);
        has_work = !list_empty(&ghd->read_list) || !list_empty(&ghd->write_list);
        spin_unlock_irqrestore(&ghd->lock, flags);

        return has_work;
}

/* PERUBAHAN UTAMA: Inisialisasi per Hardware Context */
static int gamer_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
        struct gamer_hctx_data *ghd;

        /* Alokasi memori khusus untuk jalur/node ini */
        ghd = kzalloc_node(sizeof(*ghd), GFP_KERNEL, hctx->numa_node);
        if (!ghd)
                return -ENOMEM;

        INIT_LIST_HEAD(&ghd->read_list);
        INIT_LIST_HEAD(&ghd->write_list);
        spin_lock_init(&ghd->lock);
        ghd->read_count = 0;

        /* Pasangkan data ke hctx */
        hctx->sched_data = ghd;
        return 0;
}

/* PERUBAHAN UTAMA: Pembersihan per Hardware Context */
static void gamer_exit_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
        struct gamer_hctx_data *ghd = hctx->sched_data;
        kfree(ghd);
}

static struct elevator_type gamer_sched = {
        .ops.mq = {
                .insert_requests = gamer_insert_requests,
                .dispatch_request = gamer_dispatch_request,
                .has_work = gamer_has_work,
                .init_hctx = gamer_init_hctx, /* Memanggil inisialisasi HCTX */
                .exit_hctx = gamer_exit_hctx, /* Memanggil pembersihan HCTX */
        },
        .elevator_name = "gamer",
        .elevator_owner = THIS_MODULE,
        .uses_mq = true,
};

static int __init gamer_init(void)
{
        pr_info("Gamer I/O Scheduler loaded - Blk-MQ Architecture Ready\n");
        return elv_register(&gamer_sched);
}

static void __exit gamer_exit(void)
{
        elv_unregister(&gamer_sched);
        pr_info("Gamer I/O Scheduler unloaded\n");
}

module_init(gamer_init);
module_exit(gamer_exit);

MODULE_AUTHOR("Oni");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Gaming-optimized Blk-MQ I/O Scheduler");
