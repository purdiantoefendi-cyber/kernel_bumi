/*
 * drivers/cpufreq/cpufreq_lagfree.c
 *
 * Ultra-Safe VIP KThread Lagfree Governor for Kernel 4.19+ (Android 12-16)
 * Combines Deferred Safety with Schedutil's Exclusive KThread Architecture.
 * Built by Gemini.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/smp.h>
#include <linux/init.h>
#include <linux/cpufreq.h>
#include <linux/cpu.h>
#include <linux/percpu-defs.h>
#include <linux/slab.h>
#include <linux/sched/cpufreq.h>
#include <linux/kthread.h>
#include <linux/jiffies.h>
#include <linux/kernel_stat.h>
#include <linux/tick.h>
#include <linux/suspend.h>
#include <linux/mutex.h>

#define FREQ_STEP_DOWN                          (160000)
#define FREQ_SLEEP_MAX                          (320000)
#define FREQ_AWAKE_MIN                          (480000)
#define FREQ_STEP_UP_SLEEP_PERCENT              (20)

unsigned int suspended = 0;

/* ULTRA-SAFE TUNERS */
struct dbs_tuners {
        unsigned int rate_limit_us;
        unsigned int up_threshold;
        unsigned int down_threshold;
};

static struct dbs_tuners tuners = {
        .rate_limit_us = 50000, /* 50ms Ultra-Safe Rate Limit mencegah PMIC Overload */
        .up_threshold = 50,
        .down_threshold = 15,
};

struct lagfree_policy {
        struct cpufreq_policy *policy;
        u64 last_update;
        u64 prev_idle;
        u64 prev_wall;
        unsigned int requested_freq;
        
        /* VIP KThread (Jalur Eksklusif Anti-Watchdog) */
        struct kthread_worker *worker;
        struct kthread_work work;
        struct mutex work_lock;
        bool work_in_progress;
};

struct lagfree_cpu {
        struct update_util_data update_util;
        struct lagfree_policy *lf_policy;
        int cpu;
};

static DEFINE_PER_CPU(struct lagfree_cpu, lagfree_cpus);
static struct lagfree_policy *lf_policies[NR_CPUS];

/************************** SYSFS INTERFACE ************************/
#define show_one(file_name, object)                                        \
static ssize_t show_##file_name(struct cpufreq_policy *unused, char *buf)  \
{                                                                          \
        return sprintf(buf, "%u\n", tuners.object);                        \
}
show_one(rate_limit_us, rate_limit_us);
show_one(up_threshold, up_threshold);
show_one(down_threshold, down_threshold);

static ssize_t store_rate_limit_us(struct cpufreq_policy *unused, const char *buf, size_t count)
{
        unsigned int input;
        if (sscanf(buf, "%u", &input) != 1 || input < 1000) return -EINVAL;
        tuners.rate_limit_us = input;
        return count;
}

static ssize_t store_up_threshold(struct cpufreq_policy *unused, const char *buf, size_t count)
{
        unsigned int input;
        if (sscanf(buf, "%u", &input) != 1 || input > 100 || input <= tuners.down_threshold) return -EINVAL;
        tuners.up_threshold = input;
        return count;
}

static ssize_t store_down_threshold(struct cpufreq_policy *unused, const char *buf, size_t count)
{
        unsigned int input;
        if (sscanf(buf, "%u", &input) != 1 || input >= tuners.up_threshold) return -EINVAL;
        tuners.down_threshold = input;
        return count;
}

#define define_one_rw(_name) \
static struct freq_attr _name = __ATTR(_name, 0644, show_##_name, store_##_name)

define_one_rw(rate_limit_us);
define_one_rw(up_threshold);
define_one_rw(down_threshold);

static struct attribute * dbs_attributes[] = {
        &rate_limit_us.attr,
        &up_threshold.attr,
        &down_threshold.attr,
        NULL
};

static struct attribute_group dbs_attr_group = {
        .attrs = dbs_attributes,
        .name = "Shas_Dream",
};

/************************** CORE LOGIC (VIP KTHREAD) ************************/

/* Fungsi ini berjalan di jalur khususnya sendiri. Jauh dari gangguan Android saat Booting */
static void lagfree_work_func(struct kthread_work *work)
{
        struct lagfree_policy *lf_policy = container_of(work, struct lagfree_policy, work);
        struct cpufreq_policy *policy = lf_policy->policy;
        u64 cur_wall_time, cur_idle_time;
        unsigned int idle_time, wall_time, load, freq_target;

        /* PENGAMAN MUTLAK: Mencegah tabrakan pembacaan memori */
        mutex_lock(&lf_policy->work_lock);

        cur_idle_time = get_cpu_idle_time_us(policy->cpu, &cur_wall_time);
        wall_time = (unsigned int)(cur_wall_time - lf_policy->prev_wall);
        idle_time = (unsigned int)(cur_idle_time - lf_policy->prev_idle);

        lf_policy->prev_wall = cur_wall_time;
        lf_policy->prev_idle = cur_idle_time;

        if (unlikely(!wall_time || wall_time < idle_time)) load = 0;
        else load = 100 * (wall_time - idle_time) / wall_time;

        /* Otak Agresif Lagfree */
        if (load > tuners.up_threshold) { 
                freq_target = suspended ? ((FREQ_STEP_UP_SLEEP_PERCENT * policy->max) / 100) : policy->max;
        } else if (load < tuners.down_threshold) { 
                if (lf_policy->requested_freq > policy->min + FREQ_STEP_DOWN)
                        freq_target = lf_policy->requested_freq - FREQ_STEP_DOWN;
                else freq_target = policy->min;
        } else {
                goto out; /* Beban stabil, tidak perlu ganti frekuensi */
        }

        /* Filter Keamanan Hardware */
        if (unlikely(freq_target == 0)) freq_target = policy->min;
        if (suspended && freq_target > FREQ_SLEEP_MAX) freq_target = FREQ_SLEEP_MAX;
        if (!suspended && freq_target < FREQ_AWAKE_MIN) freq_target = FREQ_AWAKE_MIN;
        if (freq_target < policy->min) freq_target = policy->min;
        if (freq_target > policy->max) freq_target = policy->max;

        if (lf_policy->requested_freq != freq_target) {
                lf_policy->requested_freq = freq_target;
                cpufreq_driver_target(policy, freq_target, CPUFREQ_RELATION_H);
        }

out:
        lf_policy->work_in_progress = false;
        mutex_unlock(&lf_policy->work_lock);
}

/* Sinyal Hook EAS: Sangat ringan, hanya men-trigger KThread lalu langsung pergi */
static void lagfree_update_util(struct update_util_data *data, u64 time, unsigned int flags)
{
        struct lagfree_cpu *lf_cpu = container_of(data, struct lagfree_cpu, update_util);
        struct lagfree_policy *lf_policy = lf_cpu->lf_policy;

        if (!lf_policy || lf_policy->work_in_progress) return;

        /* PENGAMAN OVERLOAD: Rate Limiter 50ms */
        if (time - lf_policy->last_update < ((u64)tuners.rate_limit_us * NSEC_PER_USEC))
                return;

        lf_policy->last_update = time;
        lf_policy->work_in_progress = true;
        
        /* Eksekusi dilempar ke KThread VIP */
        kthread_queue_work(lf_policy->worker, &lf_policy->work);
}

/************************** GOVERNOR API ************************/

static int lagfree_init(struct cpufreq_policy *policy)
{
        struct lagfree_policy *lf_policy = kzalloc(sizeof(*lf_policy), GFP_KERNEL);
        if (!lf_policy) return -ENOMEM;

        lf_policy->policy = policy;
        mutex_init(&lf_policy->work_lock);
        kthread_init_work(&lf_policy->work, lagfree_work_func);
        lf_policies[policy->cpu] = lf_policy;
        
        return sysfs_create_group(&policy->kobj, &dbs_attr_group);
}

static void lagfree_exit(struct cpufreq_policy *policy)
{
        struct lagfree_policy *lf_policy = lf_policies[policy->cpu];
        sysfs_remove_group(&policy->kobj, &dbs_attr_group);
        kfree(lf_policy);
        lf_policies[policy->cpu] = NULL;
}

static int lagfree_start(struct cpufreq_policy *policy)
{
        struct lagfree_policy *lf_policy = lf_policies[policy->cpu];
        int j;

        if (!lf_policy) return -ENODEV;

        lf_policy->requested_freq = policy->cur;
        lf_policy->prev_idle = get_cpu_idle_time_us(policy->cpu, &lf_policy->prev_wall);
        lf_policy->last_update = 0;
        lf_policy->work_in_progress = false;

        /* PENCIPTAAN THREAD VIP: Mengkloning cara kerja Schedutil */
        lf_policy->worker = kthread_create_worker(0, "lagfree_vip_%d", policy->cpu);
        if (IS_ERR(lf_policy->worker)) {
                return PTR_ERR(lf_policy->worker);
        }

        for_each_cpu(j, policy->cpus) {
                struct lagfree_cpu *lf_cpu = &per_cpu(lagfree_cpus, j);
                lf_cpu->cpu = j;
                lf_cpu->lf_policy = lf_policy;
                cpufreq_add_update_util_hook(j, &lf_cpu->update_util, lagfree_update_util);
        }
        return 0;
}

static void lagfree_stop(struct cpufreq_policy *policy)
{
        struct lagfree_policy *lf_policy = lf_policies[policy->cpu];
        int j;

        for_each_cpu(j, policy->cpus) cpufreq_remove_update_util_hook(j);
        
        if (lf_policy->worker) {
                kthread_destroy_worker(lf_policy->worker);
                lf_policy->worker = NULL;
        }
}

static void lagfree_limits(struct cpufreq_policy *policy)
{
        struct lagfree_policy *lf_policy = lf_policies[policy->cpu];
        if (!lf_policy) return;
        if (lf_policy->requested_freq < policy->min) lf_policy->requested_freq = policy->min;
        else if (lf_policy->requested_freq > policy->max) lf_policy->requested_freq = policy->max;
}

struct cpufreq_governor cpufreq_gov_lagfree = {
        .name       = "Shas_Dream",
        .init       = lagfree_init,
        .exit       = lagfree_exit,
        .start      = lagfree_start,
        .stop       = lagfree_stop,
        .limits     = lagfree_limits,
        .owner      = THIS_MODULE,
};

static int lagfree_pm_notify(struct notifier_block *nb, unsigned long action, void *ptr)
{
        switch (action) {
        case PM_SUSPEND_PREPARE: suspended = 1; break;
        case PM_POST_SUSPEND:    suspended = 0; break;
        }
        return NOTIFY_OK;
}
static struct notifier_block lagfree_pm_notifier = { .notifier_call = lagfree_pm_notify };

static int __init cpufreq_gov_lagfree_init(void)
{
        register_pm_notifier(&lagfree_pm_notifier);
        return cpufreq_register_governor(&cpufreq_gov_lagfree);
}
static void __exit cpufreq_gov_lagfree_exit(void)
{
        unregister_pm_notifier(&lagfree_pm_notifier);
        cpufreq_unregister_governor(&cpufreq_gov_lagfree);
}

MODULE_AUTHOR ("Gemini");
MODULE_DESCRIPTION ("Ultra-Safe VIP KThread Lagfree Governor");
MODULE_LICENSE ("GPL");

fs_initcall(cpufreq_gov_lagfree_init);
module_exit(cpufreq_gov_lagfree_exit);
