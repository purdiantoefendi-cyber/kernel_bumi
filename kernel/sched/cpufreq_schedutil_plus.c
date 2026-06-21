// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 MediaTek Inc.
 * Modified with Lagfree & Big Cluster Sleep Logic by Gemini
 */

/* Mengambil data sensor layar mati dari cpufreq_schedutil.c */
extern bool sugov_suspended; 

static unsigned int get_next_freq(struct sugov_policy *sg_policy,
				  unsigned long util, unsigned long max)
{
	struct cpufreq_policy *policy = sg_policy->policy;
	int cpu = policy->cpu;
	unsigned int freq = arch_scale_freq_invariant() ?
				policy->cpuinfo.max_freq : policy->cur;
	unsigned long load_pct = 0;

	/* --- FITUR BARU: SOFT-DISABLE BIG CLUSTER SAAT LAYAR MATI --- */
	if (unlikely(sugov_suspended)) {
		/* * Di chipset MediaTek (Helio G85), cluster CPU terbagi dua:
		 * cpu == 0 adalah LITTLE cluster (Core 0-5)
		 * cpu != 0 (biasanya 6) adalah Big cluster (Core 6-7)
		 */
		if (cpu != 0) {
			/* Layar mati: Paksa Big Cluster tidur di frekuensi dasar (Soft-Disable) */
			sg_policy->cached_raw_freq = policy->min;
			return cpufreq_driver_resolve_freq(policy, policy->min);
		} else {
			/* Layar mati: LITTLE cluster dibatasi ke minimal agar baterai super awet */
			freq = policy->min;
			sg_policy->cached_raw_freq = freq;
			return cpufreq_driver_resolve_freq(policy, freq);
		}
	}
	/* ------------------------------------------------------------- */

	/* Kalkulasi Beban (Persentase) dari EAS untuk Mode Layar Nyala */
	if (max > 0)
		load_pct = (util * 100) / max;

	/* --- INJEKSI LOGIKA LAGFREE (RATA KANAN) --- */
	if (load_pct >= 70) {
		/* Threshold 70%: Beban sangat berat, Gas pol ke Max Freq! */
		freq = policy->max;
	} else if (load_pct <= 30) {
		/* Threshold 30%: Beban ringan saat layar menyala, drop ke mode hemat */
		freq = policy->min;
	} else {
		/* Di antara 31% - 69%: Transisi mulus bawaan MediaTek */
		freq = mtk_map_util_freq(cpu, util);
	}

	sg_policy->cached_raw_freq = freq;
	return cpufreq_driver_resolve_freq(policy, freq);
}
