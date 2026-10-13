// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/utsname.h>
#include <linux/uidgid.h>  /* Tambahan untuk membaca UID */
#include <linux/cred.h>    /* Tambahan untuk namespace dan user credentials */

static int version_proc_show(struct seq_file *m, void *v)
{
	/* Mulai: Spoofing /proc/version untuk aplikasi pengguna (UID >= 10000) */
	if (from_kuid_munged(current_user_ns(), current_uid()) >= 10000) {
		seq_printf(m, "Linux version 4.19.0-perf (builder@localhost) (gcc version 4.9.x) #1 SMP PREEMPT\n");
		return 0;
	}
	/* Selesai: Spoofing /proc/version */

	/* Jika yang mengakses adalah sistem inti (root), berikan versi aslinya */
	seq_printf(m, linux_proc_banner,
		utsname()->sysname,
		utsname()->release,
		utsname()->version);
	return 0;
}

static int __init proc_version_init(void)
{
	proc_create_single("version", 0, NULL, version_proc_show);
	return 0;
}
fs_initcall(proc_version_init);
