// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 MediaTek Inc.
 * Modified with Lagfree (65-35) & Extreme Soft-Disable by Gemini
 */

#define FREQ_STEP_DOWN 167000  /* Rem ABS ~167 MHz per tahap */

/* Variabel ini otomatis dikontrol oleh ke-3 sensor (PM, FB, MTK DRM) di file utama */
extern bool sugov_suspended; 

static unsigned int get_next_freq(struct sugov_policy *sg_policy,
				  unsigned long util, unsigned long max)
{
	struct cpufreq_policy *policy = sg_policy->policy;
	int cpu = policy->cpu;
	
	/* Simpan frekuensi sebelumnya untuk kalkulasi Step-Down (Rem ABS) */
	unsigned int prev_freq = sg_policy->cached_raw_freq ? sg_policy->cached_raw_freq : policy->cur;
	
	unsigned int freq = arch_scale_freq_invariant() ?
				policy->cpuinfo.max_freq : policy->cur;
	unsigned long load_pct = 0;

	/* --- MODE STANDBY: SAAT LAYAR MATI --- */
	if (unlikely(sugov_suspended)) {
		/* Terhubung dengan 3 sensor: Lock SEMUA Cluster ke kecepatan minimum absolut hardware */
		freq = policy->cpuinfo.min_freq;
		sg_policy->cached_raw_freq = freq;
		return cpufreq_driver_resolve_freq(policy, freq);
	}
	/* ------------------------------------- */

	/* --- MODE AKTIF: SAAT LAYAR MENYALA --- */
	if (max > 0)
		load_pct = (util * 100) / max;

	if (load_pct >= 75) {
		/* Threshold 75%: Titik seimbang performa, langsung gas pol ke Max Freq! */
		freq = policy->max;
	} else if (load_pct <= 35) {
		/* Threshold 35%: Beban ringan, lebih cepat drop ke Mode Hemat (Min Freq) */
		freq = policy->min;
	} else {
		/* Di antara 36% - 64%: Transisi mulus bawaan MediaTek + Rem ABS */
		unsigned int target_freq = mtk_map_util_freq(cpu, util);
		
		/* Jika frekuensi sebelumnya jauh lebih tinggi, turunkan secara bertahap */
		if (prev_freq > target_freq + FREQ_STEP_DOWN) {
			freq = prev_freq - FREQ_STEP_DOWN;
		} else {
			/* Jika beban naik atau penurunannya kecil, langsung eksekusi target */
			freq = target_freq;
		}
	}
	/* -------------------------------------- */

	sg_policy->cached_raw_freq = freq;
	return cpufreq_driver_resolve_freq(policy, freq);
}