// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/blkdev.h>
#include <linux/elevator.h>
#include <linux/blk-mq.h>
#include <linux/slab.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/list.h>

struct perf_data {
	struct list_head read_list;
	struct list_head write_list;
	spinlock_t lock;
};

static void perf_insert_requests(struct blk_mq_hw_ctx *hctx,
				 struct list_head *list, bool at_head)
{
	struct perf_data *pd = hctx->queue->elevator->elevator_data;
	struct request *rq, *n;

	spin_lock(&pd->lock);
	list_for_each_entry_safe(rq, n, list, queuelist) {
		list_del_init(&rq->queuelist);
		if (rq_data_dir(rq) == READ)
			list_add_tail(&rq->queuelist, &pd->read_list);
		else
			list_add_tail(&rq->queuelist, &pd->write_list);
	}
	spin_unlock(&pd->lock);
}

static struct request *perf_dispatch_request(struct blk_mq_hw_ctx *hctx)
{
	struct perf_data *pd = hctx->queue->elevator->elevator_data;
	struct request *rq = NULL;

	spin_lock(&pd->lock);
	if (!list_empty(&pd->read_list)) {
		rq = list_first_entry(&pd->read_list, struct request, queuelist);
		list_del_init(&rq->queuelist);
	} else if (!list_empty(&pd->write_list)) {
		rq = list_first_entry(&pd->write_list, struct request, queuelist);
		list_del_init(&rq->queuelist);
	}
	spin_unlock(&pd->lock);

	return rq;
}

static int perf_init_sched(struct request_queue *q, struct elevator_type *e)
{
	struct perf_data *pd;

	pd = kzalloc(sizeof(*pd), GFP_KERNEL);
	if (!pd)
		return -ENOMEM;

	INIT_LIST_HEAD(&pd->read_list);
	INIT_LIST_HEAD(&pd->write_list);
	spin_lock_init(&pd->lock);

	q->elevator->elevator_data = pd;
	return 0;
}

static void perf_exit_sched(struct elevator_queue *e)
{
	struct perf_data *pd = e->elevator_data;
	kfree(pd);
}

static struct elevator_type perf_sched = {
	.ops.mq = {
		.insert_requests = perf_insert_requests,
		.dispatch_request = perf_dispatch_request,
		.init_sched = perf_init_sched,
		.exit_sched = perf_exit_sched,
	},
	.elevator_name = "performance",
	.elevator_owner = THIS_MODULE,
	.uses_mq = true,
};

static int __init perf_init(void)
{
	return elv_register(&perf_sched);
}

static void __exit perf_exit(void)
{
	elv_unregister(&perf_sched);
}

module_init(perf_init);
module_exit(perf_exit);

MODULE_AUTHOR("oni");
MODULE_DESCRIPTION("Performance I/O Scheduler (Gaming Optimized)");
MODULE_LICENSE("GPL");
