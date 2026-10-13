// SPDX-License-Identifier: GPL-2.0
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>

#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
extern int susfs_spoof_cmdline_or_bootconfig(struct seq_file *m);
#endif

static int cmdline_proc_show(struct seq_file *m, void *v)
{
	char *fake_cmdline;
	char *p;

#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
	if (!susfs_spoof_cmdline_or_bootconfig(m)) {
		seq_putc(m, '\n');
		return 0;
	}
#endif

	/* Mulai: Hardcode Spoofing Cmdline secara Global */
	fake_cmdline = kstrdup(saved_command_line, GFP_KERNEL);
	
	if (fake_cmdline) {
		/* Ubah Orange State menjadi Green (Verified) */
		p = strstr(fake_cmdline, "androidboot.verifiedbootstate=orange");
		if (p) strncpy(p, "androidboot.verifiedbootstate=green ", 36);

		/* Ubah Unlocked menjadi Locked */
		p = strstr(fake_cmdline, "androidboot.vbmeta.device_state=unlocked");
		if (p) strncpy(p, "androidboot.vbmeta.device_state=locked  ", 40);

		/* Ubah status flash locked */
		p = strstr(fake_cmdline, "androidboot.flash.locked=0");
		if (p) strncpy(p, "androidboot.flash.locked=1", 26);

		/* Ubah warranty bit jika ada (misal Samsung Knox) */
		p = strstr(fake_cmdline, "androidboot.warranty_bit=1");
		if (p) strncpy(p, "androidboot.warranty_bit=0", 26);

		seq_puts(m, fake_cmdline);
		kfree(fake_cmdline);
	} else {
		/* Failsafe jika gagal alokasi memori */
		seq_puts(m, saved_command_line);
	}
	/* Selesai: Hardcode Spoofing Cmdline */

	seq_putc(m, '\n');
	return 0;
}

static int __init proc_cmdline_init(void)
{
	proc_create_single("cmdline", 0, NULL, cmdline_proc_show);
	return 0;
}
fs_initcall(proc_cmdline_init);
