#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/kallsyms.h>
#include <linux/kmod.h>

MODULE_AUTHOR("zxz0O0");
MODULE_DESCRIPTION("Say bye to SELinux at boot time to allow dualrecovery");
MODULE_VERSION("1.1");
MODULE_LICENSE("GPL");

#ifdef REPLACE_MODULE
void load_orig_module(void)
{
	char* envp[] = { NULL };
	char* argv[] = { "/system/bin/sh", "-c", "/system/bin/insmod /system/lib/modules/mhl_sii8620_8061_drv_orig.ko", NULL };

	pr_info("byeselinux: trying to load original module\n");
	call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
}
#endif

static bool (*_selinux_is_enabled)(void);
unsigned int enabled;
unsigned int enforcing;
unsigned int* _selinux_enabled = NULL;
unsigned int* _selinux_enforcing = NULL;

unsigned int* findEnabled(void)
{
#if !defined(__LP64__) || !__LP64__
	int i = 0;
	//0x1e,0xff,0x2f,0xe1 --> bx lr
	const char asm_bx[] = { 0x1E, 0xFF, 0x2F, 0xE1 };
	char* p = (char*)kallsyms_lookup_name("selinux_is_enabled");
	for(i = 0; i < 64; i++)
	{
		if(memcmp(&p[i], asm_bx, 4) == 0)
			return *(unsigned int**)&p[i+4];
	}
#endif

	return 0;
}

unsigned int* findEnforcing(void)
{
#if !defined(__LP64__) || !__LP64__
	int i = 0;
	//0xf0,0x80,0xbd,0xe8 --> LDMFD SP!, {R4-R7,PC}
	const char asm_ldmfd[] = { 0xF0, 0x80, 0xBD, 0xE8 };
	char* p = (char*)kallsyms_lookup_name("sel_read_enforce");
	if(p == NULL)
		return 0;
	for(i = 0; i < 128; i++)
	{
		if(memcmp(&p[i], asm_ldmfd, 4) == 0)
			return *(unsigned int**)&p[i+12];
	}
#endif

	return 0;
}

static int __init byeselinux_init(void)
{
	pr_info("byeselinux: module loaded\n");
	_selinux_is_enabled = (void*)kallsyms_lookup_name("selinux_is_enabled");
	if(_selinux_is_enabled == NULL)
	{
		pr_info("byeselinux: Error finding selinux_is_enabled\n");
		return 1;
	}

	enabled = _selinux_is_enabled();
	pr_info("byeselinux: old selinux_enabled %u\n", enabled);

	_selinux_enabled = (unsigned int*)kallsyms_lookup_name("selinux_enabled");
	if(_selinux_enabled == NULL)
	{
		pr_info("byeselinux: Could not find selinux_enabled in kallsyms\n");
		pr_info("byeselinux: Trying to find it in memory\n");
		_selinux_enabled = findEnabled();
		if(_selinux_enabled == NULL)
		{
			pr_info("byeselinux: Could not find selinux_enabled address\n");
			return 1;
		}
	}

	*_selinux_enabled = 0;
	pr_info("byeselinux: current selinux_enabled %u\n", _selinux_is_enabled());

	_selinux_enforcing = (unsigned int*)kallsyms_lookup_name("selinux_enforcing");
	if(_selinux_enforcing == NULL)
	{
		pr_info("byeselinux: Could not find selinux_enforcing in kallsyms\n");
		pr_info("byeselinux: Trying to find it in memory\n");
		_selinux_enforcing = findEnforcing();
	}
	if(_selinux_enforcing == NULL)
		pr_info("byeselinux: can not find enforcing address\n");
	else
	{
		enforcing = *_selinux_enforcing;
		pr_info("byeselinux: old selinux_enforcing: %u\n", enforcing);
		*_selinux_enforcing = 0;
		pr_info("byeselinux: current selinux_enforcing: %u\n", *_selinux_enforcing);
	}

#ifdef REPLACE_MODULE
	load_orig_module();
#endif
	
	return 0;
}

void cleanup_module(void)
{
	if(_selinux_enabled != NULL)
		*_selinux_enabled = enabled;

	if(_selinux_enforcing != NULL)
		*_selinux_enforcing = enforcing;

	pr_info("byeselinux: module unloaded\n");
}

module_init(byeselinux_init)
