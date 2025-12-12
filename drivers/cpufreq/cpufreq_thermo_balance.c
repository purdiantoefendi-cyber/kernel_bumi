// SPDX-License-Identifier: GPL-2.0
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/cpufreq.h>
#include <linux/sched/cpufreq.h>
#include <linux/slab.h>
#include <linux/jiffies.h>
#include <linux/timer.h>
#include <linux/workqueue.h> // Diperlukan untuk timer
/* <linux/cpufreq.h> di atas sudah menyertakan cpufreq_quick_get */

struct thermo_tunables {
	struct gov_attr_set attr_set;
	unsigned int up_rate_limit_us;
	unsigned int down_rate_limit_us;
	unsigned int sampling_rate; // Ditambahkan untuk timer
};

struct thermo_policy {
	struct cpufreq_policy *policy;
	struct thermo_tunables *tunables;
	unsigned int last_freq;
	u64 last_update;
};

static DEFINE_PER_CPU(struct thermo_policy *, thermo_data);
static struct thermo_tunables *global_tunables;
static struct workqueue_struct *thermo_wq;
static void thermo_balance_work_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(thermo_work, thermo_balance_work_fn);
static unsigned int thermo_enable; // Counter untuk start/stop timer

static unsigned int compute_target_freq(struct cpufreq_policy *policy, unsigned int util)
{
	unsigned int max = policy->max;
	unsigned int min = policy->min;

	if (util >= 85)
		return max; // full boost
	else if (util >= 60)
		return max - (max - min) / 4; // 75%
	else if (util >= 30)
		return max - (max - min) / 2; // 50%
	else
		return min; // chill
}

static void thermo_balance_update(struct cpufreq_policy *policy)
{
	struct thermo_policy *tp = per_cpu(thermo_data, policy->cpu);
	unsigned int util;
	unsigned int next_freq;
	u64 now = jiffies;
	u64 delta;

	if (!tp)
		return;

	/* PERBAIKAN: Mengganti sched_cpu_util dengan cpufreq_quick_get */
	util = cpufreq_quick_get(policy->cpu);
	next_freq = compute_target_freq(policy, util);
	delta = jiffies_to_usecs(now - tp->last_update);

	if (next_freq > tp->last_freq &&
	    delta < tp->tunables->up_rate_limit_us)
		return;

	if (next_freq < tp->last_freq &&
	    delta < tp->tunables->down_rate_limit_us)
		return;
	
	if (cpufreq_driver_target(policy, next_freq, CPUFREQ_RELATION_H))
		pr_warn("thermo_balance: cpufreq_driver_target failed for cpu %d\n", policy->cpu);
		
	tp->last_freq = next_freq;
	tp->last_update = now;
}

static void thermo_balance_work_fn(struct work_struct *work)
{
	unsigned int cpu;

	for_each_online_cpu(cpu) {
		struct thermo_policy *tp = per_cpu(thermo_data, cpu);
		if (tp && tp->policy)
			thermo_balance_update(tp->policy);
	}

	queue_delayed_work(thermo_wq, &thermo_work,
			   usecs_to_jiffies(global_tunables->sampling_rate));
}

static int thermo_balance_start(struct cpufreq_policy *policy)
{
	struct thermo_policy *tp;

	tp = kzalloc(sizeof(*tp), GFP_KERNEL);
	if (!tp)
		return -ENOMEM;

	tp->policy = policy;
	tp->last_freq = policy->cur;
	tp->last_update = jiffies;

	thermo_enable++;
	if (thermo_enable == 1) {
		global_tunables = kzalloc(sizeof(*global_tunables), GFP_KERNEL);
		if (!global_tunables) {
			kfree(tp);
			thermo_enable--;
			return -ENOMEM;
		}
		global_tunables->up_rate_limit_us = 20000;
		global_tunables->down_rate_limit_us = 40000;
		global_tunables->sampling_rate = 50000; // Default 50ms

		thermo_wq = create_singlethread_workqueue("thermo_balance_wq");
		queue_delayed_work(thermo_wq, &thermo_work,
				   usecs_to_jiffies(global_tunables->sampling_rate));
	}

	tp->tunables = global_tunables;
	per_cpu(thermo_data, policy->cpu) = tp;

	return 0;
}

static void thermo_balance_stop(struct cpufreq_policy *policy)
{
	struct thermo_policy *tp = per_cpu(thermo_data, policy->cpu);

	thermo_enable--;
	if (thermo_enable == 0) {
		cancel_delayed_work_sync(&thermo_work);
		destroy_workqueue(thermo_wq);
		thermo_wq = NULL;
		kfree(global_tunables);
		global_tunables = NULL;
	}

	if (tp) {
		kfree(tp);
		per_cpu(thermo_data, policy->cpu) = NULL;
	}
}

static void thermo_balance_limits(struct cpufreq_policy *policy)
{
	thermo_balance_update(policy);
}

static struct cpufreq_governor thermo_balance_gov = {
	.name = "thermo_balance",
	.owner = THIS_MODULE,
	.init = thermo_balance_start,
	.exit = thermo_balance_stop,
	.limits = thermo_balance_limits,
};

static int __init thermo_balance_init(void)
{
	return cpufreq_register_governor(&thermo_balance_gov);
}

static void __exit thermo_balance_exit(void)
{
	cpufreq_unregister_governor(&thermo_balance_gov);
}

module_init(thermo_balance_init);
module_exit(thermo_balance_exit);

MODULE_AUTHOR("Jayzee");
MODULE_DESCRIPTION("Battery + Gaming Hybrid CPU Governor");
MODULE_LICENSE("GPL");