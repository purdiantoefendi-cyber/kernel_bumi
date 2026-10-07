// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h> // Dibutuhkan untuk kmalloc dan kfree

static int cmdline_proc_show(struct seq_file *m, void *v)
{
	char *spoofed_cmdline;
	char *p;

	// Alokasi memori sementara untuk memanipulasi string
	spoofed_cmdline = kmalloc(strlen(saved_command_line) + 1, GFP_KERNEL);
	
	// Jika alokasi memori gagal (sangat jarang terjadi), kembalikan cmdline asli
	if (!spoofed_cmdline) {
		seq_puts(m, saved_command_line);
		seq_putc(m, '\n');
		return 0;
	}

	// Salin command line asli ke dalam memori sementara
	strcpy(spoofed_cmdline, saved_command_line);

	// --- PROSES SPOOFING DIMULAI ---
	
	// 1. Ubah verifiedbootstate dari orange (unlocked) menjadi green (locked/aman)
	p = strstr(spoofed_cmdline, "androidboot.verifiedbootstate=orange");
	if (p) strncpy(p, "androidboot.verifiedbootstate=green ", 36);

	// 2. Ubah status flash dari 0 (unlocked) menjadi 1 (locked)
	p = strstr(spoofed_cmdline, "androidboot.flash.locked=0");
	if (p) strncpy(p, "androidboot.flash.locked=1", 26);

	// 3. Ubah status vbmeta dari unlocked menjadi locked
	p = strstr(spoofed_cmdline, "androidboot.vbmeta.device_state=unlocked");
	if (p) strncpy(p, "androidboot.vbmeta.device_state=locked  ", 40);

	// --- PROSES SPOOFING SELESAI ---

	// Cetak command line yang sudah dimanipulasi ke /proc/cmdline
	seq_puts(m, spoofed_cmdline);
	seq_putc(m, '\n');

	// Bebaskan memori sementara agar tidak terjadi memory leak
	kfree(spoofed_cmdline);

	return 0;
}

static int __init proc_cmdline_init(void)
{
	proc_create_single("cmdline", 0, NULL, cmdline_proc_show);
	return 0;
}
fs_initcall(proc_cmdline_init);
