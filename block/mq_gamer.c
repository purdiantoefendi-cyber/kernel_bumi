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

/* Struktur data utama untuk antrean scheduler */
struct gamer_data {
        struct list_head read_list;
        struct list_head write_list;
        spinlock_t lock;
        int read_count; /* Mekanisme anti-starvation: menghitung jumlah READ beruntun */
};

/* Fungsi untuk memasukkan request I/O ke dalam antrean */
static void gamer_insert_requests(struct blk_mq_hw_ctx *hctx,
                                  struct list_head *list, bool at_head)
{
        struct gamer_data *gd = hctx->queue->elevator->elevator_data;
        struct request *rq, *n;
        unsigned long flags;

        /* spin_lock_irqsave MENCEGAH Hard Deadlock / Kernel Panic */
        spin_lock_irqsave(&gd->lock, flags);
        
        list_for_each_entry_safe(rq, n, list, queuelist) {
                list_del_init(&rq->queuelist);

                if (rq_data_dir(rq) == READ) {
                        if (at_head)
                                list_add(&rq->queuelist, &gd->read_list);
                        else
                                list_add_tail(&rq->queuelist, &gd->read_list);
                } else {
                        if (at_head)
                                list_add(&rq->queuelist, &gd->write_list);
                        else
                                list_add_tail(&rq->queuelist, &gd->write_list);
                }
        }
        
        spin_unlock_irqrestore(&gd->lock, flags);
}

/* Fungsi untuk mengeluarkan/memproses request I/O dari antrean */
static struct request *gamer_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
        struct gamer_data *gd = hctx->queue->elevator->elevator_data;
        struct request *rq = NULL;
        unsigned long flags;

        spin_lock_irqsave(&gd->lock, flags);

        /* * LOGIKA ANTI-STARVATION (Pencegahan UI Freeze)
         * Utamakan READ. Tapi jika READ sudah dikerjakan 10 kali berturut-turut,
         * paksa kerjakan 1 WRITE (jika ada) agar memori sistem tidak macet.
         */
        if (!list_empty(&gd->read_list) && (gd->read_count < 10 || list_empty(&gd->write_list))) {
                rq = list_first_entry(&gd->read_list, struct request, queuelist);
                list_del_init(&rq->queuelist);
                gd->read_count++;
        } 
        else if (!list_empty(&gd->write_list)) {
                rq = list_first_entry(&gd->write_list, struct request, queuelist);
                list_del_init(&rq->queuelist);
                gd->read_count = 0; /* Reset penghitung READ setelah mengerjakan WRITE */
        }

        spin_unlock_irqrestore(&gd->lock, flags);

        return rq;
}

/* Fungsi penanda apakah scheduler memiliki pekerjaan (Wajib untuk BLK-MQ) */
static bool gamer_has_work(struct blk_mq_hw_ctx *hctx)
{
        struct gamer_data *gd = hctx->queue->elevator->elevator_data;
        bool has_work;
        unsigned long flags;

        spin_lock_irqsave(&gd->lock, flags);
        has_work = !list_empty(&gd->read_list) || !list_empty(&gd->write_list);
        spin_unlock_irqrestore(&gd->lock, flags);

        return has_work;
}

/* Fungsi inisialisasi saat scheduler diaktifkan pada partisi */
static int gamer_init_sched(struct request_queue *q, struct elevator_type *e)
{
        struct gamer_data *gd;

        gd = kzalloc(sizeof(*gd), GFP_KERNEL);
        if (!gd)
                return -ENOMEM;

        INIT_LIST_HEAD(&gd->read_list);
        INIT_LIST_HEAD(&gd->write_list);
        spin_lock_init(&gd->lock);
        gd->read_count = 0; /* Mulai perhitungan dari 0 */

        q->elevator->elevator_data = gd;
        return 0;
}

/* Fungsi pembersihan saat scheduler dimatikan atau diganti */
static void gamer_exit_sched(struct elevator_queue *e)
{
        struct gamer_data *gd = e->elevator_data;
        kfree(gd);
}

/* Struktur definisi Elevator/Scheduler */
static struct elevator_type gamer_sched = {
        .ops.mq = {
                .insert_requests = gamer_insert_requests,
                .dispatch_request = gamer_dispatch_request,
                .has_work = gamer_has_work,
                .init_sched = gamer_init_sched,
                .exit_sched = gamer_exit_sched,
        },
        .elevator_name = "gamer",
        .elevator_owner = THIS_MODULE,
        .uses_mq = true,
};

/* Fungsi saat modul dimuat ke Kernel */
static int __init gamer_init(void)
{
        pr_info("Gamer I/O Scheduler loaded - Safe Edition\n");
        return elv_register(&gamer_sched);
}

/* Fungsi saat modul dicopot dari Kernel */
static void __exit gamer_exit(void)
{
        elv_unregister(&gamer_sched);
        pr_info("Gamer I/O Scheduler unloaded\n");
}

module_init(gamer_init);
module_exit(gamer_exit);

MODULE_AUTHOR("Oni");
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Gaming-optimized MQ I/O Scheduler with Anti-Starvation");
