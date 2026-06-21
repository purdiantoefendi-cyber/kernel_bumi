// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 MediaTek Inc.
 * Modified with Lagfree Logic by Gemini
 */

static unsigned int get_next_freq(struct sugov_policy *sg_policy,
				  unsigned long util, unsigned long max)
{
	struct cpufreq_policy *policy = sg_policy->policy;
	int cpu = policy->cpu;
	unsigned int freq = arch_scale_freq_invariant() ?
				policy->cpuinfo.max_freq : policy->cur;
	unsigned long load_pct = 0;

	/* Kalkulasi Beban (Persentase) dari EAS */
	if (max > 0)
		load_pct = (util * 100) / max;

	/* --- INJEKSI LOGIKA LAGFREE --- */
	if (load_pct >= 50) {
		/* Threshold 50%: Beban menengah ke atas, Gas pol ke Max Freq! */
		freq = policy->max;
	} else if (load_pct <= 15) {
		/* Threshold 15%: Mode hemat saat layar diam (Min Freq) */
		freq = policy->min;
	} else {
		/* Di antara 16% - 49%: Gunakan kalkulasi bawaan MediaTek 
		 * agar transisi tetap halus dan sistem tidak curiga */
		freq = mtk_map_util_freq(cpu, util);
	}

	sg_policy->cached_raw_freq = freq;
	return cpufreq_driver_resolve_freq(policy, freq);
}
