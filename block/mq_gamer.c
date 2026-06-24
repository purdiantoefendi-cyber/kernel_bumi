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

/* * Struktur dummy untuk Global Queue. 
 * Ini wajib ada untuk mencegah kernel panic pada custom kernel Android
 * yang mencoba membaca q->elevator->elevator_data.
 */
struct gamer_data {
        int dummy; 
};

/* Struktur data per-Hardware Context (Jalur multi-core) */
struct gamer_hctx_data {
        struct list_head read_list;
        struct list_head write_list;
        spinlock_t lock;
        int read_count;
};

static void gamer_insert_requests(struct blk_mq_hw_ctx *hctx,
                                  struct list_head *list, bool at_head)
{
        struct gamer_hctx_data *ghd = hctx->sched_data;
        struct request *rq, *n;
        unsigned long flags;

        /* Keamanan tambahan: Cegah eksekusi jika inisialisasi gagal/belum siap */
        if (!ghd)
                return;

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

        if (!ghd)
                return NULL;

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
                ghd->read_count = 0; /* Reset counter setelah WRITE dieksekusi */
        }

        spin_unlock_irqrestore(&ghd->lock, flags);

        return rq;
}

static bool gamer_has_work(struct blk_mq_hw_ctx *hctx)
{
        struct gamer_hctx_data *ghd = hctx->sched_data;

        if (!ghd)
                return false;

        /* * PERUBAHAN UTAMA: Menggunakan fungsi lockless (list_empty_careful).
         * Mencegah soft lockup / CPU macet akibat spinlock yang dieksekusi terus-menerus.
         */
        return !list_empty_careful(&ghd->read_list) || !list_empty_careful(&ghd->write_list);
}

/* ==========================================================
 * Inisialisasi Level Global (Mencegah Android Kernel Freeze)
 * ========================================================== */
static int gamer_init_sched(struct request_queue *q, struct elevator_type *e)
{
        struct gamer_data *gd;

        /* Alokasi data global agar q->elevator->elevator_data tidak NULL */
        gd = kzalloc_node(sizeof(*gd), GFP_KERNEL, q->node);
        if (!gd)
                return -ENOMEM;

        q->elevator->elevator_data = gd;
        return 0;
}

static void gamer_exit_sched(struct elevator_queue *e)
{
        struct gamer_data *gd = e->elevator_data;
        kfree(gd);
}

/* ==========================================================
 * Inisialisasi Level Hardware Context (Blk-MQ murni)
 * ========================================================== */
static int gamer_init_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
        struct gamer_hctx_data *ghd;

        ghd = kzalloc_node(sizeof(*ghd), GFP_KERNEL, hctx->numa_node);
        if (!ghd)
                return -ENOMEM;

        INIT_LIST_HEAD(&ghd->read_list);
        INIT_LIST_HEAD(&ghd->write_list);
        spin_lock_init(&ghd->lock);
        ghd->read_count = 0;

        hctx->sched_data = ghd;
        return 0;
}

static void gamer_exit_hctx(struct blk_mq_hw_ctx *hctx, unsigned int hctx_idx)
{
        struct gamer_hctx_data *ghd = hctx->sched_data;
        kfree(ghd);
}

static struct elevator_type gamer_sched = {
        .ops.mq = {
                .init_sched = gamer_init_sched,     /* Wajib ditambahkan */
                .exit_sched = gamer_exit_sched,     /* Wajib ditambahkan */
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
