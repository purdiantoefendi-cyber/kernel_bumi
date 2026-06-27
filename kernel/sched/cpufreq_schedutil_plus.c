// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (c) 2019 MediaTek Inc.
 * Modified: Earth Kernel OPPs + Lagfree ABS + MTK Smoothness by Gemini
 */

/* Konstanta Dikalibrasi untuk Earth Kernel */
#define FREQ_STEP_DOWN 167000  /* Rem ABS ~167 MHz per tahap */
#define FREQ_SLEEP_MAX 850000  /* Batas hardware paling bawah Earth Kernel */
#define FREQ_AWAKE_MIN 1175000 /* Anti-stutter UI Earth Kernel */

/* * PERBAIKAN: Gunakan variabel status layar yang sebenarnya.
 * Pastikan Anda sudah meng-export 'is_screen_on' dari display driver (FB/DRM/Panel) Anda.
 */
extern bool is_screen_on; 
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
	/* Menggunakan deteksi layar langsung agar tidak terkecoh oleh Wakelock */
	if (!is_screen_on || unlikely(sugov_suspended)) {
		freq = policy->min;
		if (freq > FREQ_SLEEP_MAX)
			freq = FREQ_SLEEP_MAX;

		sg_policy->cached_raw_freq = freq;
		return cpufreq_driver_resolve_freq(policy, freq);
	}
	/* ------------------------------------- */

	/* --- MODE AKTIF: SAAT LAYAR MENYALA --- */
	if (load_pct >= 60) {
		/* BEBAN 60% - 100%: ZONA REM ABS 
		 * Mencari target ideal di beban tinggi menggunakan util MTK.
		 * Saat beban berfluktuasi dari 100 menuju 60, CPU dilarang drop tiba-tiba.
		 */
		unsigned long target_freq = mtk_map_util_freq(cpu, util);
		
		if (freq > target_freq + FREQ_STEP_DOWN) {
			/* Turun bertahap seperti pengereman ABS */
			freq -= FREQ_STEP_DOWN;
		} else {
			/* Jika butuh naik performa, eksekusi instan tanpa ditahan */
			freq = target_freq;
		}
	} 
	else if (load_pct >= 31) {
		/* BEBAN 31% - 59%: ZONA MTK SMOOTHNESS MURNI 
		 * Dinamis tanpa Rem ABS. Kecepatan CPU merespons instan sesuai util mtk.
		 */
		freq = mtk_map_util_freq(cpu, util);
	} 
	else {
		/* BEBAN DI BAWAH 31%: TERJUN BEBAS (Lock Min Freq) */
		freq = policy->min;
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
