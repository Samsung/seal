/*
 * SEAL - utility for collecting information about files in runtime
 * Copyright (C) 2023 Samsung Electronics Co., Ltd.
 */

#define pr_fmt(fmt) "seal: " fmt

#include <asm/cpufeature.h>
#include <asm/syscall.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/hashtable.h>
#include <linux/kernel.h>
#include <linux/kprobes.h>
#include <linux/minmax.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/ptrace.h>
#include <linux/slab.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>

#include "seal_ioctl.h"
#include "seal_passthrough.h"

#define SEAL_VERSION 1

MODULE_DESCRIPTION("<Filesystem entries> to <file_operations handlers> mapper");
MODULE_AUTHOR("SRPOL.MB.SEC");
MODULE_LICENSE("GPL");

#define DEV_NAME "seal"
#define MAX_PROBED_FUNCS 100000
#define MAX_FUNC_NAME_LEN 512
#define HASH_KEY_BITS 8

static int client_pid = 0;
module_param(client_pid, int, 0 /* don't show in sysfs */);

struct hlist_entry {
	struct kprobe probe;
	struct hlist_node node;
	bool consumed;
};

static int dev_major;
static struct class *dev_class;
static struct hlist_entry *last_visited_kprobe;
static char *names_buf;
static DEFINE_MUTEX(file_access_mutex);
static DECLARE_HASHTABLE(kprobes, HASH_KEY_BITS);

static int kprobe_pre_handler(struct kprobe *kp, struct pt_regs *regs)
{
	if (current->pid != client_pid)
		return 0;

	// Check if the client is calling write() with an fd in the range 0-3.
	// This indicates a write to STDIN/STDOUT/STDERR/out file and is not
	// a part of filesystem tree walk (and returning -ECANCELED here would
	// prevent the client from writing anything to the console or output
	// file).
	if (syscall_get_nr(current, task_pt_regs(current)) == __NR_write) {
		unsigned long args[SYSCALL_MAX_ARGS];
		syscall_get_arguments(current, task_pt_regs(current), args);

		if (args[0] <= 3)
			return 0;
	}

	// 1. save function name somewhere
	last_visited_kprobe = container_of(kp, struct hlist_entry, probe);

	// 2. skip function body, set return value to -ECANCELED

	regs->regs[0] = (u64) -ECANCELED;
	regs->pc = regs->regs[30]; // lr -> pc

	// Normally, the probed function would be called using BL/BLR
	// instruction. After returning from this probe handler, Kprobe
	// subsystem will most likely just jump to the address indicated in pc
	// register set above. This triggers BTI (Branch Target Identification)
	// feature which expects different type of jump. To make it happy, the
	// line below sets PSTATE.BTYPE value (used by BTI) to 0 to make BTI
	// expect a plain jump instead of function return.
	if (system_supports_bti()) {
		regs->pstate &= 0xFFFFFFFFFFFFF3FF; // clear bits 11-10
	}

	return -1; // pc was changed, just return to given address
}

static int kprobe_pre_handler_passthrough(struct kprobe *kp,
					struct pt_regs *regs)
{
	if (current->pid != client_pid)
		return 0;

	// Check if this is our client trying to write its output (see
	// corresponding code in kprobe_pre_handler() for more details)
	if (syscall_get_nr(current, task_pt_regs(current)) == __NR_write) {
		unsigned long args[SYSCALL_MAX_ARGS];
		syscall_get_arguments(current, task_pt_regs(current), args);

		if (args[0] <= 3)
			return 0;
	}

	// save function name
	last_visited_kprobe = container_of(kp, struct hlist_entry, probe);

	// passthrough - allow further execution without any changes
	return 0;
}

bool should_passthrough(const char *fname)
{
	size_t i = 0;

	for (; i < ARRAY_SIZE(passthrough_functions); i++) {
		if (!strcmp(passthrough_functions[i], fname)) {
			pr_info("PASSTHROUGH: %s", fname);
			return true;
		}
	}

	return false;
}

int hash(char *str, size_t len) {
	int result = 0, i = 0;
	for (; i < len; i++) {
		result += str[i];
		result &= (1 << HASH_KEY_BITS) - 1;
	}
	return result;
}

bool exists_in_map(char *str, size_t len) {
	struct hlist_entry *entry;

	hash_for_each_possible(kprobes, entry, node, hash(str, len)) {
		if (!strcmp(entry->probe.symbol_name, str))
		return true;
	}
	return false;
}

// handling of /dev/seal

static int seal_file_open(struct inode *inode, struct file *file)
{
	return 0;
}

static int seal_file_release(struct inode *inode, struct file *file)
{
	return 0;
}

static ssize_t seal_file_read(struct file *file, char __user *buf, size_t count,
				loff_t *offset)
{
	size_t func_name_size, to_copy;
	struct kprobe *kp;

	if(mutex_lock_interruptible(&file_access_mutex)) {
		return -EINTR;
	}

	if (!last_visited_kprobe) {
		mutex_unlock(&file_access_mutex);
		return 0;
	}

	kp = &last_visited_kprobe->probe;

	func_name_size = strlen(kp->symbol_name) + 1;
	to_copy = min_t(size_t, count, func_name_size);

	if (copy_to_user(buf, kp->symbol_name, to_copy)) {
		pr_err("copy_to_user() failed");
		mutex_unlock(&file_access_mutex);
		return -EINVAL;
	}

	last_visited_kprobe->consumed = true;
	last_visited_kprobe = NULL;
	mutex_unlock(&file_access_mutex);
	return to_copy;
}


/*
 * Buffer format: <null-terminated-string1><null-terminated-string2>...
 */
static ssize_t seal_file_write_locked(struct file *file,
				const char __user *ubuf, size_t count,
				loff_t *offset)
{
	int ret, retval = -EINVAL;
	char *iter;
	size_t func_count = 0, successes = 0;

	if (names_buf) {
		pr_err("Currently, functions to attach can be specified only once");
		retval = -EINVAL;
		goto out;
	}

	if (count > (MAX_PROBED_FUNCS * MAX_FUNC_NAME_LEN)) {
		pr_err("Count too big: %ld", count);
		retval = -EINVAL;
		goto out;
	}
	pr_debug("count is: %ld", count);

	names_buf = vmalloc(count);
	if (!names_buf) {
		pr_err("Failed to allocate memory for names_buf");
		retval = -ENOMEM;
		goto out;
	}

	if (copy_from_user(names_buf, ubuf, count)) {
		pr_err("copy_from_user() failed");
		retval = -EINVAL;
		goto clear_names_buf;
	}

	if (names_buf[count-1] != 0x0) {
		pr_err("Malformed names_buffer: last byte should be 0");
		retval = -EINVAL;
		goto clear_names_buf;
	}

	iter = names_buf;
	while (iter < (names_buf + count)) {
		size_t len;
		len = strnlen(iter, MAX_FUNC_NAME_LEN);  // TODO: +1?
		if (!len || len == MAX_FUNC_NAME_LEN) {
			pr_err("Invalid function name length: %ld chars", len);
			retval = -EINVAL;
			goto clear_names_buf;
		}
		pr_debug("Got string (%ld) %s", len, iter);
		func_count++;
		iter += (len + 1);
	}

	if (!func_count) {
		pr_err("No function names found in buffer");
		retval = -EINVAL;
		goto clear_names_buf;
	}

	// TODO: if multiple writes are allowed, this should take into account
	// already registered probes
	if (func_count > MAX_PROBED_FUNCS) {
		pr_err("Too many functions to probe: %ld", func_count);
		retval = -EINVAL;
		goto clear_names_buf;
	}

	pr_info("Got %ld functions", func_count);

	iter = names_buf;
	while (iter < (names_buf + count)) {
		struct hlist_entry *entry;
		size_t len = 0;
		len = strlen(iter); // we checked earlier that the string is ok

		if (exists_in_map(iter, len)) {
			pr_warn("Kprobe for '%s' is already registered, skipping",
				iter);
			iter += (len + 1);
			continue;
		}

		entry = kzalloc(sizeof(struct hlist_entry), GFP_KERNEL);
		if (!entry) {
			pr_err("Failed to allocate memory for kprobe");
			iter += (len + 1);
			continue;
		}

		entry->probe.symbol_name = iter;
		entry->probe.pre_handler = should_passthrough(iter) ?
						kprobe_pre_handler_passthrough :
						kprobe_pre_handler;

		ret = register_kprobe(&entry->probe);
		if (ret < 0) {
			pr_err("Failed to register kprobe for '%s': %d",
				iter, ret);
			kfree(entry);
			iter += (len + 1);
			continue;
		}
		hash_add(kprobes, &entry->node, hash(iter, len));
		iter += (len + 1);
		successes++;
	}
	pr_info("Registered %d out of %d kprobes", successes, func_count);
	retval = count;
	goto out;

clear_names_buf:
	vfree(names_buf);
	names_buf = NULL;
out:
	return retval;
}

static ssize_t seal_file_write(struct file *file, const char __user *ubuf,
				size_t count , loff_t *offset)
{
	ssize_t retval;

	if(mutex_lock_interruptible(&file_access_mutex)) {
		return -EINTR;
	}

	retval = seal_file_write_locked(file, ubuf, count, offset);

	mutex_unlock(&file_access_mutex);

	return retval;
}

static long seal_file_ioctl(struct file *f, unsigned int cmd, unsigned long arg)
{
	void __user *uarg = (void __user*)arg;
	struct seal_insert_kprobes_param param;
	struct hlist_entry *entry;
	struct hlist_node *tmp;
	int bkt;
	int ret = 0;

	if(mutex_lock_interruptible(&file_access_mutex)) {
		return -EINTR;
	}

	switch (cmd) {
	case SEAL_INSERT_KPROBES:
		pr_info("ioctl: SEAL_INSERT_KPROBES");
		ret = copy_from_user(&param, uarg, sizeof(param));
		if (ret) {
			pr_err("copy_from_user() failed");
			ret = -EINVAL;
			goto out;
		}
		ret = seal_file_write_locked(f, param.buf, param.buf_size, 0);
		break;

	case SEAL_DISABLE_ALL_PROBES:
		pr_info("ioctl: SEAL_DISABLE_ALL_PROBES");

		hash_for_each_safe(kprobes, bkt, tmp, entry, node) {
			if (!entry->consumed &&
				!should_passthrough(entry->probe.symbol_name)) {

				pr_warn("Unconsumed function: %s",
					entry->probe.symbol_name);
			}
			disable_kprobe(&entry->probe);
		}
		break;
	case SEAL_NEEDS_WORKAROUND:
#ifdef CONFIG_RKP
		ret = 1;
#else
		ret = 0;
#endif
		break;
	}
out:
	mutex_unlock(&file_access_mutex);
	return ret;
}

static const struct file_operations seal_fops = {
	.owner = THIS_MODULE,
	.write = seal_file_write,
	.read = seal_file_read,
	.unlocked_ioctl = seal_file_ioctl,
	.open = seal_file_open,
	.release = seal_file_release,
};

static int seal_init(void)
{
	pr_info("Security-oriented Entrypoint Analyzer for Linux, ver %d",
			SEAL_VERSION);

	hash_init(kprobes);

	if (!client_pid) {
		pr_err("Please specify a valid PID of client app via client_pid parameter");
		return -EINVAL;
	}

	dev_major = register_chrdev(0, DEV_NAME, &seal_fops);
	if (dev_major < 0) {
		pr_err("Failed to register char device: %d", dev_major);
		return dev_major;
	}

	dev_class = class_create(THIS_MODULE, DEV_NAME);
	if (IS_ERR(dev_class)) {
		pr_err("Failed to create dev_class for device");
		unregister_chrdev(dev_major, DEV_NAME);
		return -ENODEV;
	}

	if(IS_ERR(device_create(dev_class, NULL, MKDEV(dev_major, 0), NULL,
							DEV_NAME))) {
		pr_err("Failed to create device");
		class_destroy(dev_class);
		unregister_chrdev(dev_major, DEV_NAME);
		return -ENODEV;
	}

	return 0;

}
module_init(seal_init);


static void seal_exit(void)
{
	struct hlist_entry *entry;
	struct hlist_node *tmp;
	int bkt;

#ifdef CONFIG_RKP
	pr_warn("WARNING: this kernel is compiled with RKP, which seems to");
	pr_warn("cause problems when kprobes-related pages are being freed.");
	pr_warn("This device will probably crash now.");
#endif

	device_destroy(dev_class, MKDEV(dev_major, 0));
	class_destroy(dev_class);
	unregister_chrdev(dev_major, DEV_NAME);

	hash_for_each_safe(kprobes, bkt, tmp, entry, node) {
		if (!entry->consumed) {
			pr_warn("Unconsumed function: %s",
					entry->probe.symbol_name);
		}
		unregister_kprobe(&entry->probe);
		hash_del(&entry->node);
		kfree(entry);
	}
	vfree(names_buf);
	pr_info("Exiting");
}
module_exit(seal_exit);
