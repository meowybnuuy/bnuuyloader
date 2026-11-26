// SPDX-License-Identifier: GPL-2.0
/*
 * seclog_dump: a read-only debugfs file with the raw sec_log ring at 0x25fff000
 * (8 header bytes + 2 MiB), the RAM log S-Boot starts and the kernel's sec_log
 * console goes on writing.  For debugging the bootloader from Linux.
 */
#include <linux/module.h>
#include <linux/init.h>
#include <linux/io.h>
#include <linux/debugfs.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#define RING_PHYS   0x25fff000UL
#define RING_SIZE   (2UL << 20)

static void __iomem *ring;
static struct dentry *file;

static ssize_t dump_read(struct file *f, char __user *buf, size_t count, loff_t *ppos)
{
	size_t left;

	if (*ppos >= RING_SIZE)
		return 0;
	left = RING_SIZE - (size_t)*ppos;
	if (count > left)
		count = left;
	if (copy_to_user(buf, ring + *ppos, count))
		return -EFAULT;
	*ppos += count;
	return count;
}

static const struct file_operations dump_fops = {
	.owner = THIS_MODULE,
	.read = dump_read,
	.llseek = default_llseek,
};

static int __init seclog_dump_init(void)
{
	ring = ioremap_wc(RING_PHYS, RING_SIZE);	/* the mapping the sec_log console uses too */
	if (!ring)
		return -ENOMEM;
	file = debugfs_create_file("seclog_dump", 0400, NULL, NULL, &dump_fops);
	if (IS_ERR(file)) {
		iounmap(ring);
		return PTR_ERR(file);
	}
	pr_info("seclog_dump: ring at phys %#lx, %lu bytes, /sys/kernel/debug/seclog_dump\n",
		RING_PHYS, RING_SIZE);
	return 0;
}

static void __exit seclog_dump_exit(void)
{
	debugfs_remove(file);
	iounmap(ring);
}

module_init(seclog_dump_init);
module_exit(seclog_dump_exit);
MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Read-only view of the sec_log ring");
