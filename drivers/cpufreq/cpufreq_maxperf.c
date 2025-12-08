// linux/drivers/cpufreq/cpufreq_maxperf.c

#include <linux/cpufreq.h>
#include <linux/init.h>
#include <linux/module.h>

static void cpufreq_gov_maxperf_limits(struct cpufreq_policy *policy)
{
	__cpufreq_driver_target(policy, policy->max, CPUFREQ_RELATION_H);
}

static struct cpufreq_governor cpufreq_gov_maxperf = {
	.name		= "maxperf",
	.owner		= THIS_MODULE,
	.limits		= cpufreq_gov_maxperf_limits,
};

static int __init cpufreq_gov_maxperf_init(void)
{
	return cpufreq_register_governor(&cpufreq_gov_maxperf);
}

static void __exit cpufreq_gov_maxperf_exit(void)
{
	cpufreq_unregister_governor(&cpufreq_gov_maxperf);
}

module_init(cpufreq_gov_maxperf_init);
module_exit(cpufreq_gov_maxperf_exit);

MODULE_AUTHOR("yorurai");
MODULE_DESCRIPTION("Aggressive CPU governor 'maxperf'");
MODULE_LICENSE("GPL");
