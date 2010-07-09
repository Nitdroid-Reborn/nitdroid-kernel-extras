/* Copyright (c) 2009-2010 Nokia Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 or
 * (at your option) any later version of the License.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>

#include "kfgles2_hcalls.h"

static int debug = 0;

#define KFGLES2_PRINT(format, args...) do { if (debug) printk(KERN_DEBUG "kfgles2: DEBUG: " format, ##args); } while (0)

#define KFGLES2_DEVICE "kfgles2"
static int KFGLES2_MINOR = 128;
static unsigned long KFGLES2_HWBASE = 0x4f000000;
static unsigned int KFGLES2_HWSIZE = 0x00100000;

/* Client specific data holder. */
struct kfgles2_client {
	uint32_t nr;
	void* offset;
	unsigned long buffer;
};

void __iomem *kfgles2_base;
static DEFINE_MUTEX(kfgles2_mutex);

/* Release a mapped register area, and disconnect the client. */
static void kfgles2_vclose(struct vm_area_struct *vma)
{
	struct kfgles2_client *client = vma->vm_private_data;

	KFGLES2_PRINT("munmap called!\n");

	if (client) {
		mutex_lock(&kfgles2_mutex);

		KFGLES2_PRINT("Exiting client ID %d.\n", client->nr);
		kfgles2_host_exit(client->nr);

		mutex_unlock(&kfgles2_mutex);
		
		KFGLES2_PRINT("Freeing...\n");
		kfree(client);
	}
	
	vma->vm_private_data = 0;
}

/* Operations for kernel to deal with a mapped register area. */
static struct vm_operations_struct kfgles2_vops =
{
	.close = kfgles2_vclose,
};

/* Nothing to do when opening the file. */
static int kfgles2_open(struct inode *inode, struct file *filep)
{
	return 0;
}

/* Nothing to do when closing the file. */
static int kfgles2_release(struct inode *inode, struct file *filep)
{
	return 0;
}

/* Map a register area for connecting client. */
static int kfgles2_mmap(struct file *filep, struct vm_area_struct *vma)
{
	struct kfgles2_client *client;
	int ret;

	KFGLES2_PRINT("mmap called!\n");

	if (!vma->vm_pgoff) {
		KFGLES2_PRINT("Root requested!\n");
		client = 0;
	} else {
		KFGLES2_PRINT("Client requested!\n");

		if (!(client = kmalloc(sizeof(*client), GFP_KERNEL))) {
			return -ENOMEM;
		}

		/* This will be used in next version. */
#if 0
		client->buffer = __get_free_pages(GFP_USER, 512);

		if (!client->buffer) {
			ret = -ENOMEM;
			goto failure;
		}

		KFGLES2_PRINT("Got framebuffer at %p..\n", (void*)client->buffer);
		
		for(i = 0; i < 512; ++i)
			SetPageReserved(virt_to_page(client->buffer + i*PAGE_SIZE));
#endif // 0
		
		mutex_lock(&kfgles2_mutex);

		KFGLES2_PRINT("Requesting client ID..\n");
		client->nr = kfgles2_host_init();
		KFGLES2_PRINT("-> Got %d!\n", client->nr);

		mutex_unlock(&kfgles2_mutex);
	}
	
	vma->vm_flags |= VM_IO | VM_RESERVED;
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);

	if ((ret = remap_pfn_range(vma,
		vma->vm_start,
		(KFGLES2_HWBASE >> PAGE_SHIFT) + (client ? client->nr : 0) + 1,
		vma->vm_end - vma->vm_start,
		vma->vm_page_prot)) < 0)
	{
		KFGLES2_PRINT("remap failed!\n");
		goto failure;
	}

	vma->vm_ops = &kfgles2_vops;
	vma->vm_private_data = client;

	if (client)
		KFGLES2_PRINT("remap successfull for client %d!\n", client->nr);
	else
		KFGLES2_PRINT("remap successfull for root!\n");
	
	return 0;
failure:
	kfree(client);
	return ret;
}

/* Operations for kernel to deal with the device file. */
static const struct file_operations kfgles2_fops = {
.owner          = THIS_MODULE,
.open           = kfgles2_open,
.release        = kfgles2_release,
.mmap           = kfgles2_mmap,
};

static struct miscdevice kfgles2_miscdev = {
	.name = KFGLES2_DEVICE,
	.fops = &kfgles2_fops
};

/* Module initialization. */
static int __init kfgles2_init(void)
{
	int err = 0;

	printk(KERN_INFO "loading kfgles2 module.\n");

	kfgles2_miscdev.minor = KFGLES2_MINOR;

	if (!(kfgles2_base = ioremap(KFGLES2_HWBASE, KFGLES2_HWSIZE))) {
		KFGLES2_PRINT("ERROR: failed to map hardware area.\n");
		return -ENOMEM;
	}

	if (misc_register(&kfgles2_miscdev) < 0)
		goto out_map;

	mutex_init(&kfgles2_mutex);

	goto out;

out_map:
	iounmap(kfgles2_base);
out:
	return err;
}

/* Module cleanup. */ 
static void __exit kfgles2_exit(void)
{
	printk(KERN_INFO "kfgles2 module removed.\n");
	misc_deregister(&kfgles2_miscdev);
	if(kfgles2_base) {
		iounmap(kfgles2_base);
		kfgles2_base = 0;
	}
}

module_init(kfgles2_init);
module_exit(kfgles2_exit);

module_param(debug, bool, 0644);
MODULE_PARM_DESC(debug, "enable debug prints");

module_param(KFGLES2_MINOR, uint, 0444);
MODULE_PARM_DESC(KFGLES2_MINOR, "Minor number to be used when registering miscdev");

module_param(KFGLES2_HWBASE, ulong, 0444);
MODULE_PARM_DESC(KFGLES2_HWBASE, "HW base address for kfgles2 gateway");

module_param(KFGLES2_HWSIZE, uint, 0444);
MODULE_PARM_DESC(KFGLES2_HWSIZE, "size of kfgles2 gateway");

MODULE_AUTHOR("Joonas Lahtinen <joonas.lahtinen at nomovok.com>");
MODULE_AUTHOR("Pablo Virolainen <pablo.virolainen at nomovok.com>");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("QEMU OpenGL ES 2.0 accelerator module");
