// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/uidgid.h> // Ditambahkan untuk membaca UID current_uid()

#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
extern int susfs_spoof_cmdline_or_bootconfig(struct seq_file *m);
#endif

static int cmdline_proc_show(struct seq_file *m, void *v)
{
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	if (!susfs_spoof_cmdline_or_bootconfig(m)) {
		seq_putc(m, '\n');
		return 0;
	}
#endif

	/* Mulai: Hardcoded UBL / Bootloader State Spoofing */
	if (current_uid().val >= 10000) {
		/* Mengirimkan parameter CMDLINE palsu yang menyatakan perangkat terkunci (Locked/Green) */
		seq_puts(m, "androidboot.verifiedbootstate=green androidboot.vbmeta.device_state=locked androidboot.flash.locked=1");
		seq_putc(m, '\n');
		return 0;
	}
	/* Selesai: Hardcoded UBL / Bootloader State Spoofing */

	seq_puts(m, saved_command_line);
	seq_putc(m, '\n');
	return 0;
}

static int __init proc_cmdline_init(void)
{
	proc_create_single("cmdline", 0, NULL, cmdline_proc_show);
	return 0;
}
fs_initcall(proc_cmdline_init);
