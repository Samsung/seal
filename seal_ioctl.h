/*
 * SEAL - utility for collecting information about files in runtime
 * Copyright (C) 2023 Samsung Electronics Co., Ltd.
 */

#ifndef SEAL_IOCTL_H
#define SEAL_IOCTL_H

struct seal_insert_kprobes_param {
	size_t buf_size;
	unsigned long inserted;
	char __user *buf;
};

#define SEAL_IOCTL_MAGIC 's'

#define SEAL_INSERT_KPROBES _IOWR(SEAL_IOCTL_MAGIC, 1, \
				struct seal_insert_kprobes_param)
#define SEAL_DISABLE_ALL_PROBES _IO(SEAL_IOCTL_MAGIC, 2)
#define SEAL_NEEDS_WORKAROUND _IOR(SEAL_IOCTL_MAGIC, 3, unsigned long)

#endif /* SEAL_IOCTL_H */
