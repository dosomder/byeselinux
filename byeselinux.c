#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/kmod.h>

MODULE_AUTHOR("zxz0O0");
MODULE_DESCRIPTION("Say bye to SELinux at boot time to allow dualrecovery");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");

void load_orig_module(void)
{
	char* envp[] = { NULL };
	char* argv[] = { "/system/bin/sh", "-c", "/system/bin/insmod /system/lib/modules/mhl_sii8620_8061_drv_orig.ko", NULL };

	pr_info("byeselinux: trying to load original module");
	call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}

static bool (*_selinux_is_enabled)(void);
unsigned long enabled;
unsigned long enforcing;
unsigned long* _selinux_enabled;
unsigned long* _selinux_enforcing;

static int __init byeselinux_init(void)
{
	pr_info("byeselinux: module loaded\n");
	_selinux_is_enabled = (void*)kallsyms_lookup_name("selinux_is_enabled");
	_selinux_enabled = (unsigned long*)kallsyms_lookup_name("selinux_enabled");
	_selinux_enforcing = (unsigned long*)kallsyms_lookup_name("selinux_enforcing");

	pr_info("byeselinux: old selinux_enabled %d\n", _selinux_is_enabled());
	pr_info("byeselinux: old selinux_enforcing: %lu\n", *_selinux_enforcing);

	enabled = *_selinux_enabled;
	*_selinux_enabled = 0;
	enforcing = *_selinux_enforcing;
	*_selinux_enforcing = 0;

	pr_info("byeselinux: current selinux_enabled %d\n", _selinux_is_enabled());
	pr_info("byeselinux: current selinux_enforcing: %lu\n", *_selinux_enforcing);

	load_orig_module();

	return 0;
}

void cleanup_module(void)
{
	*_selinux_enabled = enabled;
	*_selinux_enforcing = enforcing;
	pr_info("byeselinux: module unloaded\n");
}

module_init(byeselinux_init)
