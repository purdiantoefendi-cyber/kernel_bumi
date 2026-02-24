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
#include <linux/blk-mq-sched.h>

struct gamer_data {
	struct list_head read_list;
	struct list_head write_list;
	spinlock_t lock;
};

static int gamer_init_queue(struct request_queue *q, struct elevator_type *e)
{
	struct gamer_data *gd;
	struct elevator_queue *eq;

	eq = elevator_alloc(q, e);
	if (!eq)
		return -ENOMEM;

	gd = kzalloc_node(sizeof(*gd), GFP_KERNEL, q->node);
	if (!gd) {
		kobject_put(&eq->kobj);
		return -ENOMEM;
	}

	INIT_LIST_HEAD(&gd->read_list);
	INIT_LIST_HEAD(&gd->write_list);
	spin_lock_init(&gd->lock);

	eq->elevator_data = gd;
	q->elevator = eq;
	return 0;
}

static void gamer_exit_queue(struct elevator_queue *e)
{
	struct gamer_data *gd = e->elevator_data;
	kfree(gd);
}

static void gamer_insert_requests(struct blk_mq_hw_ctx *hctx,
				  struct list_head *list, bool at_head)
{
	struct gamer_data *gd = hctx->queue->elevator->elevator_data;
	unsigned long flags;

	spin_lock_irqsave(&gd->lock, flags);
	while (!list_empty(list)) {
		struct request *rq = list_first_entry(list, struct request, queuelist);
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

static struct request *gamer_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct gamer_data *gd = hctx->queue->elevator->elevator_data;
	struct request *rq = NULL;
	unsigned long flags;

	spin_lock_irqsave(&gd->lock, flags);
	if (!list_empty(&gd->read_list)) {
		rq = list_first_entry(&gd->read_list, struct request, queuelist);
		list_del_init(&rq->queuelist);
	} else if (!list_empty(&gd->write_list)) {
		rq = list_first_entry(&gd->write_list, struct request, queuelist);
		list_del_init(&rq->queuelist);
	}
	spin_unlock_irqrestore(&gd->lock, flags);

	return rq;
}

static bool gamer_has_work(struct blk_mq_hw_ctx *hctx)
{
	struct gamer_data *gd = hctx->queue->elevator->elevator_data;

	return !list_empty_careful(&gd->read_list) ||
	       !list_empty_careful(&gd->write_list);
}

static struct elevator_type gamer_sched = {
	.ops = {
		.mq_ops = &(struct blk_mq_sched_ops){
			.init_sched         = gamer_init_queue,
			.exit_sched         = gamer_exit_queue,
			.insert_requests    = gamer_insert_requests,
			.dispatch_request   = gamer_dispatch_request,
			.has_work           = gamer_has_work,
		},
	},
	.elevator_name = "gamer",
	.elevator_owner = THIS_MODULE,
};

static int __init gamer_init(void)
{
	pr_info("Gamer I/O Scheduler loaded\n");
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
MODULE_DESCRIPTION("Gaming-optimized MQ I/O Scheduler");
