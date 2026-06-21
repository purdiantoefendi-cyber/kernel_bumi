// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 MediaTek Inc.
 * Modified with Lagfree (70-30) & Soft-Disable Logic by Gemini
 */

/* Mengambil data sensor layar dari file utama */
extern bool sugov_suspended; 

static unsigned int get_next_freq(struct sugov_policy *sg_policy,
				  unsigned long util, unsigned long max)
{
	struct cpufreq_policy *policy = sg_policy->policy;
	int cpu = policy->cpu;
	unsigned int freq = arch_scale_freq_invariant() ?
				policy->cpuinfo.max_freq : policy->cur;
	unsigned long load_pct = 0;

	/* --- MODE STANDBY: SAAT LAYAR MATI --- */
	if (unlikely(sugov_suspended)) {
		/* Big Cluster (6 & 7) sudah di-Hard Disable oleh Hotplug.
		 * Untuk core yang tersisa (LITTLE Cluster), kita paksa 
		 * berjalan di frekuensi paling pelan (Soft Disable). */
		freq = policy->min;
		sg_policy->cached_raw_freq = freq;
		return cpufreq_driver_resolve_freq(policy, freq);
	}
	/* ------------------------------------- */

	/* --- MODE AKTIF: SAAT LAYAR MENYALA --- */
	if (max > 0)
		load_pct = (util * 100) / max;

	if (load_pct >= 70) {
		/* Threshold 70%: Beban berat, langsung RATA KANAN (Max Freq) */
		freq = policy->max;
	} else if (load_pct <= 30) {
		/* Threshold 30%: Beban ringan, langsung MODE HEMAT (Min Freq) */
		freq = policy->min;
	} else {
		/* Di antara 31% - 69%: Transisi halus dari MediaTek */
		freq = mtk_map_util_freq(cpu, util);
	}
	/* -------------------------------------- */

	sg_policy->cached_raw_freq = freq;
	return cpufreq_driver_resolve_freq(policy, freq);
}
