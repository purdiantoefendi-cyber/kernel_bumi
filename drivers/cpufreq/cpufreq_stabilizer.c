/*
 * CPUFreq Governor: Stabilizer (Versi 11)
 *
 * FIX: Memperbaiki perhitungan 'load_percent' di stabilizer_update_cpu
 * menggunakan (util * 100) / 1024, bukan util / 10.
 * Ini adalah perbaikan untuk bug "selalu lock max".
 *
 * Kernel: 4.19
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/cpufreq.h>
#include <linux/cpu.h>
#include <linux/jiffies.h>
#include <linux/slab.h>
#include <linux/timer.h>
#include <linux/workqueue.h>
#include <linux/sysfs.h>
#include <linux/sched.h>
#include <linux/sched/loadavg.h>
#include <linux/fb.h>          // Untuk fb_notifier
#include <linux/notifier.h>    // Untuk notifier_block
#include <linux/mutex.h>       // Memastikan mutex.h ada

/* --- Variabel Global --- */

static struct workqueue_struct *stabilizer_wq;
static void stabilizer_work_fn(struct work_struct *work);
static DECLARE_DELAYED_WORK(stabilizer_work, stabilizer_work_fn);
static unsigned int stabilizer_enable; // Counter untuk start/stop
static bool screen_is_off;

/* --- Struktur Data Governor --- */

struct stabilizer_dbs_data {
	unsigned int up_threshold;
	unsigned int down_threshold;
	unsigned int sampling_rate;
	unsigned int freq_step;
	unsigned int perf_load_threshold;
	unsigned int little_cap_pct;
};

struct stabilizer_policy_data {
	struct cpufreq_policy *policy;
	struct stabilizer_dbs_data *dbs_data;
};

static struct stabilizer_dbs_data *global_dbs_data;
static DEFINE_PER_CPU(struct stabilizer_policy_data *, stabilizer_data);

/* --- Forward Declaration --- */
static struct cpufreq_governor stabilizer_gov; 

/*
 * ======================================================================
 * BLOK SYSFS (Sudah di posisi yang benar)
 * ======================================================================
 */

/* --- Sysfs Tunables --- */
#define show_one(file_name, var) \
static ssize_t show_##file_name(struct kobject *kobj, \
				struct kobj_attribute *attr, char *buf) \
{ \
	if (!global_dbs_data) return -ENODEV; \
	return sprintf(buf, "%u\n", global_dbs_data->var); \
}
show_one(up_threshold, up_threshold);
show_one(down_threshold, down_threshold);
show_one(sampling_rate, sampling_rate);
show_one(freq_step, freq_step);
show_one(perf_load_threshold, perf_load_threshold);
show_one(little_cap_pct, little_cap_pct);

#define store_one(file_name, var, min, max) \
static ssize_t store_##file_name(struct kobject *kobj, \
				 struct kobj_attribute *attr, \
				 const char *buf, size_t count) \
{ \
	unsigned int input; \
	int ret = kstrtouint(buf, 10, &input); \
	if (ret) return ret; \
	if (input < min || input > max) return -EINVAL; \
	if (!global_dbs_data) return -ENODEV; \
	global_dbs_data->var = input; \
	return count; \
}
store_one(up_threshold, up_threshold, 1, 100);
store_one(down_threshold, down_threshold, 1, 100);
store_one(sampling_rate, sampling_rate, 10, 1000000);
store_one(freq_step, freq_step, 1, 100);
store_one(perf_load_threshold, perf_load_threshold, 1, 100);
store_one(little_cap_pct, little_cap_pct, 1, 100);

static struct kobj_attribute up_threshold_attr =
	__ATTR(up_threshold, 0644, show_up_threshold, store_up_threshold);
static struct kobj_attribute down_threshold_attr =
	__ATTR(down_threshold, 0644, show_down_threshold, store_down_threshold);
static struct kobj_attribute sampling_rate_attr =
	__ATTR(sampling_rate, 0644, show_sampling_rate, store_sampling_rate);
static struct kobj_attribute freq_step_attr =
	__ATTR(freq_step, 0644, show_freq_step, store_freq_step);
static struct kobj_attribute perf_load_threshold_attr =
	__ATTR(perf_load_threshold, 0644, show_perf_load_threshold, store_perf_load_threshold);
static struct kobj_attribute little_cap_pct_attr =
	__ATTR(little_cap_pct, 0644, show_little_cap_pct, store_little_cap_pct);

static struct attribute *dbs_attributes[] = {
	&up_threshold_attr.attr,
	&down_threshold_attr.attr,
	&sampling_rate_attr.attr,
	&freq_step_attr.attr,
	&perf_load_threshold_attr.attr,
	&little_cap_pct_attr.attr,
	NULL
};
static struct attribute_group dbs_attr_group = {
	.attrs = dbs_attributes,
	.name = "stabilizer", 
};

/*
 * ======================================================================
 * AKHIR DARI BLOK SYSFS
 * ======================================================================
 */


/* --- Logika Inti Governor --- */
static void stabilizer_update_cpu(struct cpufreq_policy *policy)
{
	struct stabilizer_dbs_data *dbs_data = global_dbs_data;
	unsigned int util;
	unsigned int load_percent;
	unsigned int target_freq;
	unsigned int cap_freq;
	
	/* Pastikan dbs_data ada sebelum digunakan */
	if (!dbs_data)
		return;

	if (unlikely(screen_is_off)) {
		if (policy->cur != policy->min)
			__cpufreq_driver_target(policy, policy->min, CPUFREQ_RELATION_L);
		return;
	}

	util = cpufreq_quick_get(policy->cpu);
	
	/*
	 * ==================================================
	 * INI ADALAH PERBAIKAN DARI V10 -> V11
	 * Menggunakan matematika persentase yang benar
	 * ==================================================
	 */
	load_percent = (util * 100) / 1024;

	if (load_percent > dbs_data->perf_load_threshold) {
		if (policy->cur != policy->max)
			__cpufreq_driver_target(policy, policy->max, CPUFREQ_RELATION_H);
		return;
	}

	if (cpumask_test_cpu(6, policy->cpus) || cpumask_test_cpu(7, policy->cpus)) {
		if (policy->cur != policy->min)
			__cpufreq_driver_target(policy, policy->min, CPUFREQ_RELATION_L);
		return;
	}
	
	cap_freq = (policy->max * dbs_data->little_cap_pct) / 100;
	target_freq = policy->cur;
	
	if (load_percent > dbs_data->up_threshold) {
		target_freq += (policy->max * dbs_data->freq_step) / 100;
	} else if (load_percent < dbs_data->down_threshold) {
		target_freq -= (policy->max * dbs_data->freq_step) / 100;
	}

	if (target_freq < policy->min)
		target_freq = policy->min;
	if (target_freq > cap_freq)
		target_freq = cap_freq;

	if (target_freq != policy->cur)
		__cpufreq_driver_target(policy, target_freq, CPUFREQ_RELATION_C);
}

/* --- Fungsi Kerja (Worker) --- */
static void stabilizer_work_fn(struct work_struct *work)
{
	unsigned int cpu;

	/* Pastikan dbs_data ada sebelum menjadwalkan ulang */
	if (!global_dbs_data)
		return;

	for_each_online_cpu(cpu) {
		struct stabilizer_policy_data *tp = per_cpu(stabilizer_data, cpu);
		if (tp && tp->policy)
			stabilizer_update_cpu(tp->policy);
	}

	queue_delayed_work(stabilizer_wq, &stabilizer_work,
			msecs_to_jiffies(global_dbs_data->sampling_rate));
}

/* --- Notifier Status Layar (Event-Driven) --- */
static int stabilizer_fb_notifier_cb(struct notifier_block *self,
				  unsigned long event, void *data)
{
	struct fb_event *evdata = data;

	if (event != FB_EVENT_BLANK) return 0;
	if (*(int *)evdata->data == FB_BLANK_UNBLANK)
		screen_is_off = false;
	else
		screen_is_off = true;

	pr_info("Stabilizer: Screen state change: %s\n",
		screen_is_off ? "OFF" : "ON");

	if (stabilizer_wq) {
		cancel_delayed_work_sync(&stabilizer_work);
		queue_delayed_work(stabilizer_wq, &stabilizer_work, 0);
	}
	
	return 0;
}

static struct notifier_block stabilizer_fb_notifier = {
	.notifier_call = stabilizer_fb_notifier_cb,
};

/* --- Fungsi Start/Stop/Limits Governor --- */

static int stabilizer_start(struct cpufreq_policy *policy)
{
	struct stabilizer_policy_data *tp;

	tp = kzalloc(sizeof(*tp), GFP_KERNEL);
	if (!tp)
		return -ENOMEM;

	tp->policy = policy;

	stabilizer_enable++;
	if (stabilizer_enable == 1) {
		pr_info("Stabilizer: Memulai global worker...\n");
		global_dbs_data = kzalloc(sizeof(*global_dbs_data), GFP_KERNEL);
		if (!global_dbs_data) {
			kfree(tp);
			stabilizer_enable--;
			return -ENOMEM;
		}

		global_dbs_data->up_threshold = 80;
		global_dbs_data->down_threshold = 30;
		global_dbs_data->sampling_rate = 20; 
		global_dbs_data->freq_step = 5; 
		global_dbs_data->perf_load_threshold = 85; 
		global_dbs_data->little_cap_pct = 70;

		if (sysfs_create_group(cpufreq_global_kobject, &dbs_attr_group)) {
			pr_err("Stabilizer: Gagal membuat sysfs group\n");
			kfree(global_dbs_data);
			kfree(tp);
			stabilizer_enable--;
			return -EAGAIN;
		}

		stabilizer_wq = create_singlethread_workqueue("stabilizer_wq");
		queue_delayed_work(stabilizer_wq, &stabilizer_work,
			msecs_to_jiffies(global_dbs_data->sampling_rate));
	}

	tp->dbs_data = global_dbs_data;
	per_cpu(stabilizer_data, policy->cpu) = tp;

	return 0;
}

static void stabilizer_stop(struct cpufreq_policy *policy)
{
	struct stabilizer_policy_data *tp = per_cpu(stabilizer_data, policy->cpu);

	stabilizer_enable--;
	if (stabilizer_enable == 0) {
		pr_info("Stabilizer: Menghentikan global worker...\n");
		cancel_delayed_work_sync(&stabilizer_work);
		destroy_workqueue(stabilizer_wq);
		stabilizer_wq = NULL;
		
		sysfs_remove_group(cpufreq_global_kobject, &dbs_attr_group);
		kfree(global_dbs_data);
		global_dbs_data = NULL;
	}

	if (tp) {
		kfree(tp);
		per_cpu(stabilizer_data, policy->cpu) = NULL;
	}
}

static void stabilizer_limits(struct cpufreq_policy *policy)
{
	if (per_cpu(stabilizer_data, policy->cpu))
		stabilizer_update_cpu(policy);
}

/* --- Definisi Governor --- */
static struct cpufreq_governor stabilizer_gov = {
	.name			= "stabilizer",
	.owner			= THIS_MODULE,
	.start			= stabilizer_start,
	.stop			= stabilizer_stop,
	.limits			= stabilizer_limits,
};

/* --- Inisialisasi Modul --- */
static int __init stabilizer_init(void)
{
	int ret;
	
	ret = fb_register_client(&stabilizer_fb_notifier);
	if (ret) {
		pr_err("Stabilizer: Gagal mendaftar fb_notifier: %d\n", ret);
		return ret;
	}

	ret = cpufreq_register_governor(&stabilizer_gov);
	if (ret) {
		pr_err("Stabilizer: Gagal mendaftar governor: %d\n", ret);
		fb_unregister_client(&stabilizer_fb_notifier);
	}

	pr_info("CPUFreq governor 'stabilizer' (v11) berhasil dimuat.\n");
	return ret;
}

static void __exit stabilizer_exit(void)
{
	cpufreq_unregister_governor(&stabilizer_gov);
	fb_unregister_client(&stabilizer_fb_notifier);
	pr_info("CPUFreq governor 'stabilizer' berhasil dibongkar.\n");
}

MODULE_AUTHOR("Gemini & DianTk (Struktur 'thermo' + Logika 'stabilizer')");
MODULE_DESCRIPTION("Stabilizer CPUFreq Governor (big.LITTLE, Screen-Aware, v11)");
MODULE_LICENSE("GPL");

module_init(stabilizer_init);
module_exit(stabilizer_exit);
