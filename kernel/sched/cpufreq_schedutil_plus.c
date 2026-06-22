// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 MediaTek Inc.
 * Modified: Earth Kernel OPPs + Lagfree ABS + MTK Smoothness by Gemini
 */

/* Konstanta Dikalibrasi untuk Earth Kernel */
#define FREQ_STEP_DOWN 167000  /* Rem ABS ~167 MHz per tahap */
#define FREQ_SLEEP_MAX 850000  /* Batas hardware paling bawah Earth Kernel */
#define FREQ_AWAKE_MIN 1295000 /* Anti-stutter UI Earth Kernel */

extern bool sugov_suspended; 

static unsigned int get_next_freq(struct sugov_policy *sg_policy,
				  unsigned long util, unsigned long max)
{
	struct cpufreq_policy *policy = sg_policy->policy;
	int cpu = policy->cpu;
	
	/* Ambil frekuensi terakhir untuk perhitungan Step-Down */
	unsigned int freq = sg_policy->cached_raw_freq ? sg_policy->cached_raw_freq : policy->cur; 
	unsigned long load_pct = 0;

	if (max > 0)
		load_pct = (util * 100) / max;

	/* --- MODE STANDBY: SAAT LAYAR MATI --- */
	if (unlikely(sugov_suspended)) {
		/* Big Cluster mati total. LITTLE Cluster DIKUNCI MUTLAK di batas bawah.
		 * Tidak ada lagi toleransi Step-Up 20% untuk aplikasi latar belakang. */
		freq = policy->min;

		/* Pastikan tidak melebihi 850 MHz */
		if (freq > FREQ_SLEEP_MAX)
			freq = FREQ_SLEEP_MAX;

		sg_policy->cached_raw_freq = freq;
		return cpufreq_driver_resolve_freq(policy, freq);
	}
	/* ------------------------------------- */

	/* --- MODE AKTIF: SAAT LAYAR MENYALA --- */
	if (load_pct >= 50) {
		/* Threshold 50%: Langsung RATA KANAN (2.3GHz / 2.5GHz)! */
		freq = policy->max;
	} else if (load_pct <= 15) {
		/* Threshold 15%: Turun perlahan dengan rem ABS mengikuti Step OPP */
		if (freq > policy->min + FREQ_STEP_DOWN)
			freq -= FREQ_STEP_DOWN;
		else
			freq = policy->min;
	} else {
		/* Di antara 16% - 49%: KEMBALIKAN RUMUS MTK SMOOTHNESS.
		 * Transisi harian akan kembali natural dan hemat daya. */
		freq = mtk_map_util_freq(cpu, util);
	}

	/* Batasan Mutlak Lagfree Awake: DILARANG turun di bawah 1.29 GHz saat layar nyala */
	if (freq < FREQ_AWAKE_MIN)
		freq = FREQ_AWAKE_MIN;
	if (freq > policy->max)
		freq = policy->max;
	/* -------------------------------------- */

	sg_policy->cached_raw_freq = freq;
	return cpufreq_driver_resolve_freq(policy, freq);
}
