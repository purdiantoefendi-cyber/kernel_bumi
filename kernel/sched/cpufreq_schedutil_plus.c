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
extern unsigned int mtk_map_util_freq(int cpu, unsigned long util);

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
		freq = policy->min;
		if (freq > FREQ_SLEEP_MAX)
			freq = FREQ_SLEEP_MAX;

		sg_policy->cached_raw_freq = freq;
		return cpufreq_driver_resolve_freq(policy, freq);
	}
	/* ------------------------------------- */

	/* --- MODE AKTIF: SAAT LAYAR MENYALA --- */
	if (load_pct >= 60) {
		/* BEBAN >= 60%: Langsung Rata Kanan (Max Performance) */
		freq = policy->max;
	} 
	else if (load_pct < 30) {
		/* BEBAN < 30%: Terjun Bebas (Langsung drop ke batas bawah tanpa rem) */
		freq = policy->min;
	} 
	else {
		/* BEBAN 30% - 59%: Zona MTK Smoothness & Rem ABS */
		unsigned int target_freq = mtk_map_util_freq(cpu, util);
		
		/* Jika frekuensi saat ini jauh lebih tinggi dari target (contoh: turun dari 100%),
		 * aplikasikan Rem ABS (turun perlahan 167MHz) agar tidak stuttering. */
		if (freq > target_freq + FREQ_STEP_DOWN) {
			freq -= FREQ_STEP_DOWN;
		} else {
			/* Jika sudah dekat atau di bawah target, langsung ikuti target util */
			freq = target_freq;
		}
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
