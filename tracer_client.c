/*
 * SEAL - utility for collecting information about files in runtime
 * Copyright (C) 2023 Samsung Electronics Co., Ltd.
 */

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <grp.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <regex.h>
#include <unistd.h>
#include <linux/module.h>
#include <sys/capability.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/xattr.h>

#include "seal_ioctl.h"

static bool termcodes_on = true;
static bool verbose_output = false;
static bool compat_output = false;

#define C_WHITE "\e[1;97m"
#define C_GREEN "\e[1;32m"
#define C_YELLOW "\e[1;33m"
#define C_RED "\e[1;31m"
#define C_CLEAR "\e[0m"
#define C_CR "\e[2K\r"

#define VERBOSE(fmt, args...) \
	if (verbose_output) do { printf((termcodes_on ? \
		C_WHITE "[*] %s: " fmt "\n" C_CLEAR : \
		"[*] %s: " fmt "\n"), __func__, ##args); fflush(stdout); \
	} while (0)
#define INFO(fmt, args...) \
	printf((termcodes_on ? \
		C_WHITE "[*] %s: " fmt "\n" C_CLEAR : \
		"[*] %s: " fmt "\n"), __func__, ##args); fflush(stdout)
#define RINFO(fmt, args...) \
	printf((termcodes_on ? \
		C_CR C_WHITE "[*] %s: " fmt C_CLEAR : \
		"[*] %s: " fmt "\n"), __func__, ##args); fflush(stdout)
#define OK(fmt, args...) \
	printf((termcodes_on ? \
		C_GREEN "[+] %s: " fmt "\n" C_CLEAR : \
		"[+] %s: " fmt "\n"), __func__, ##args); fflush(stdout)
#define WARN(fmt, args...) \
	printf((termcodes_on ? \
		C_YELLOW "[!] %s: " fmt "\n" C_CLEAR : \
		"[!] %s: " fmt "\n"), __func__, ##args); fflush(stdout)
#define ERR(fmt, args...) \
	printf((termcodes_on ? \
		C_RED "[-] %s: " fmt "\n" C_CLEAR : \
		"[-] %s: " fmt "\n"), __func__, ##args); fflush(stdout)
#define ERR_NO(fmt, args...) \
	printf((termcodes_on ? \
		C_RED "[-] %s: " fmt ": %d (%s)\n" C_CLEAR : \
		"[-] %s: " fmt ": %d (%s)\n"), __func__, ##args, \
		errno, strerror(errno)); fflush(stdout)


#define MODULE_NAME "tracer"
#define MODULE_FILE_NAME "tracer.ko"
#define TRACER_FILE_NAME "/dev/seal"
#define SYSCALL_TIMEOUT 5 // in seconds
#define FUNCNAME_MAX_SIZE 512
#define USERSTR_MAX_SIZE 256 // max size of user/group name
#define SELINUX_CTX_MAX_SIZE 512

typedef enum {
	POKE_READ,
	POKE_WRITE,
	POKE_IOCTL,
	POKE_MMAP_R,
	POKE_MMAP_W,
} POKE_TYPE;

struct entry {
	// all sizes INCLUDE null byte
	size_t path_size;
	const char* path;
	size_t read_func_size;
	char read_func[FUNCNAME_MAX_SIZE];
	size_t write_func_size;
	char write_func[FUNCNAME_MAX_SIZE];
	size_t ioctl_func_size;
	char ioctl_func[FUNCNAME_MAX_SIZE];
	size_t mmap_func_size;
	char mmap_func[FUNCNAME_MAX_SIZE];
	mode_t st_mode;
	uid_t st_uid;
	gid_t st_gid;
	size_t user_str_size;
	char user_str[USERSTR_MAX_SIZE];
	size_t group_str_size;
	char group_str[USERSTR_MAX_SIZE];
	size_t selinux_ctx_size;
	char selinux_ctx[SELINUX_CTX_MAX_SIZE];
};

const char *default_exclude_patterns[] = {
	"^/proc/[0-9]+/.*",
	"^" TRACER_FILE_NAME,
	"^/dev/block/.*",
	"^/sys/dev/block/.*",
};
#define ARR_SIZE(arr) (sizeof(arr) / sizeof(arr[0]))

static regex_t *compiled_exclude_patterns;
static size_t exclude_patterns_count;
static int out_fd = -1;
static int tracer_fd = -1;

static char unknown_func_str[] = "<unknown>";
static size_t unknown_func_sz = sizeof(unknown_func_str);

int finit_module(int fd, const char * param_values, int flags) {
	return (int) syscall(SYS_finit_module, fd, param_values, flags);
}

int delete_module(const char *name, int flags) {
	return (int) syscall(SYS_delete_module, name, flags);
}


int load_tracer_module(bool skip_checks) {
	int ret;
	int mod_fd;
	int init_flags = 0;
	pid_t pid;
	char param_buf[256];

	// try to remove module first. Just call delete_module() - if it was not
	// loaded, it will simply return ENOENT.
	ret = delete_module(MODULE_NAME, O_NONBLOCK);
	if (ret < 0 && errno != ENOENT) {
		ERR_NO("Failed to remove loaded tracer module");
		return -1;
	}

	// prepare module params
	pid = getpid();
	memset(param_buf, 0, sizeof(param_buf));
	ret = snprintf(param_buf, sizeof(param_buf), "client_pid=%d", pid);
	if (ret < 0 || ret >= sizeof(param_buf)) {
		ERR("Failed to prepare params for tracer module");
		return -1;
	}

	if (skip_checks) {
		init_flags = MODULE_INIT_IGNORE_MODVERSIONS |
				MODULE_INIT_IGNORE_VERMAGIC;
	}

	// open the module file
	mod_fd = open(MODULE_FILE_NAME, O_RDONLY);
	if (mod_fd < 0) {
		ERR_NO("Failed to open tracer module file");
		return -1;
	}

	// load the module
	ret = finit_module(mod_fd, param_buf, init_flags);
	if (ret < 0) {
		ERR_NO("Failed to load tracer module");
		close(mod_fd);
		return -1;
	}

	close(mod_fd);

	return 0;
}

int unload_tracer_module() {
	int ret;
	ret = delete_module(MODULE_NAME, O_NONBLOCK);
	if (ret < 0 && errno != ENOENT) {
		ERR_NO("Failed to remove loaded tracer module");
		return -1;
	}
	return 0;
}

int open_tracer_control_file() {
	int try_count = 100;

	if (tracer_fd != -1)
		return 0;

	while (try_count-- != 0) {
		usleep(100);
		tracer_fd = open(TRACER_FILE_NAME, O_RDWR);
		if (tracer_fd >= 0 || errno != ENOENT)
			break;
	}

	if (tracer_fd < 0) {
		ERR_NO("Failed to open tracer control file");
		tracer_fd = -1;
		return -1;
	}

	return 0;

}

void close_tracer_control_file() {
	if (tracer_fd != -1)
		close(tracer_fd);
}

void maybe_unload_tracer_module() {
	int ret;
	ret = ioctl(tracer_fd, SEAL_NEEDS_WORKAROUND, 0);
        if (ret < 0) {
		WARN("Failed to get info from module, assuming unload is safe");
		close_tracer_control_file();
		unload_tracer_module();
		return;
	}
	if (ret) {
		WARN("Workaround for unload active: module won't be unloaded, device will be rebooted");
		ret = ioctl(tracer_fd, SEAL_DISABLE_ALL_PROBES, 0);
		if (ret)
			WARN("Failed to disable probes");

		INFO("Rebooting device...");
		system("reboot");

	} else {
		close_tracer_control_file();
		unload_tracer_module();
	}
}

/*
 * Expects correct array of null-terminated strings - does not check for too
 * long / non-terminated strings and has no way of checking if funcs_count
 * matches the data in funcs[]
 */
int attach_to_functions(char *funcs[], size_t funcs_count) {
	struct seal_insert_kprobes_param param;
	size_t buf_size = 0;
	ssize_t written;
	char *buf, *iter;

	if (!funcs_count) {
		ERR("funcs_count == 0");
		return -1;
	}

	for (size_t i = 0; i < funcs_count; i++) {
		buf_size += strlen(funcs[i]) + 1 /* null-byte */;
	}

	buf = malloc(buf_size);
	if (!buf) {
		ERR("Failed to allocate memory for write buffer");
		return -1;
	}

	iter = buf;
	for (size_t i = 0; i < funcs_count; i++) {
		size_t size = strlen(funcs[i]) + 1;
		strcpy(iter, funcs[i]);
		iter += size;
	}

	memset(&param, 0, sizeof(param));
	param.buf_size = buf_size;
	param.buf = buf;

	written = ioctl(tracer_fd, SEAL_INSERT_KPROBES, &param);

	if (written < buf_size) {
		WARN("Incomplete write to tracer control file (%ld out of %ld bytes)",
			written, buf_size);
	}

	free(buf);
	return 0;
}

int open_output_file(char *path, bool truncate) {
	int flags, mode;

	if (out_fd != -1) {
		ERR("Output file is already opened");
		return -1;
	}

	flags = O_WRONLY | O_CREAT;
	flags |= truncate ? O_TRUNC : O_EXCL;
	mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;

	out_fd = open(path, flags, mode);
	if (out_fd < 0) {
		ERR_NO("Failed to open output file");
		return -1;
	}
	// The output file fd has to be whitelisted in the tracer module code
	// for the client to be able to write to it while kprobes are attached.
	// Because of that the fd has to be precisely the next one after stdin,
	// stdout and stderr (i.e. equal to 3). For more details, check kprobe
	// handler code in tracer module sources.
	if (out_fd != 3) {
		ERR("Output file's fd is %d instead of 3", out_fd);
		return -1;
	}

	if (compat_output) {
		int ret = dprintf(out_fd, "{\n");
		if (ret <= 0)
			WARN("Failed to print initial '{' to output file");
	}
	return 0;
}

int write_fully(int fd, const char* data, size_t len) {
	ssize_t written;
	size_t idx = 0, remains = len;

	while (remains) {
		written = write(fd, data + idx, remains);
		if (written < 0) {
			ERR_NO("Failed to write");
			return -1;
		}
		assert(remains >= written);
		remains -= written;
		idx += written;
	}
	return 0;
}

int save_entry_as_raw_text(struct entry *e) {
	ssize_t ret;
	char mode_buf[16] = {0};

	if (out_fd == -1) {
		ERR("Output file is not opened");
		return -1;
	}

	if (!e->path_size) {
		ERR("Invalid path size");
		return -1;
	}

	ret = snprintf(mode_buf, sizeof(mode_buf), "%o", e->st_mode);
	if (ret < 0 || ret >= sizeof(mode_buf)) {
		ERR("Failed to stringify st_mode, ret = %ld", ret);
		return -1;
	}

#define WRITE_VAL_OR_UNKNOWN(val, valsize) \
	write_fully(out_fd, (valsize) ? (val) : unknown_func_str, \
			(valsize) ? ((valsize) - 1) : unknown_func_sz - 1)

#define WRITE_NEWLINE() write_fully(out_fd, "\n", 1)

	// write strings without a null byte - put '\n' instead
	if (write_fully(out_fd, e->path, e->path_size - 1) != 0)
		return -1;
	if (WRITE_NEWLINE() != 0)
		return -1;
	if (WRITE_VAL_OR_UNKNOWN(e->read_func, e->read_func_size) != 0)
		return -1;
	if (WRITE_NEWLINE() != 0)
		return -1;
	if (WRITE_VAL_OR_UNKNOWN(e->write_func, e->write_func_size) != 0)
		return -1;
	if (WRITE_NEWLINE() != 0)
		return -1;
	if (WRITE_VAL_OR_UNKNOWN(e->ioctl_func, e->ioctl_func_size) != 0)
		return -1;
	if (WRITE_NEWLINE() != 0)
		return -1;
	if (WRITE_VAL_OR_UNKNOWN(e->mmap_func, e->mmap_func_size) != 0)
		return -1;
	if (WRITE_NEWLINE() != 0)
		return -1;
	if (WRITE_VAL_OR_UNKNOWN(mode_buf, ret + 1) != 0)
		return -1;
	if (WRITE_NEWLINE() != 0)
		return -1;
	if (WRITE_VAL_OR_UNKNOWN(e->user_str, e->user_str_size) != 0)
		return -1;
	if (WRITE_NEWLINE() != 0)
		return -1;
	if (WRITE_VAL_OR_UNKNOWN(e->group_str, e->group_str_size) != 0)
		return -1;
	if (WRITE_NEWLINE() != 0)
		return -1;
	if (WRITE_VAL_OR_UNKNOWN(e->selinux_ctx, e->selinux_ctx_size) != 0)
		return -1;
	if (WRITE_NEWLINE() != 0)
		return -1;
	if (WRITE_NEWLINE() != 0)
		return -1;


	return 0;
}

int save_entry_as_json(struct entry *e) {
	int ret;
	static bool first = true;
	static const char json_fmt[] =
		"    \"%s\": {\n"
		"        \"read\": [\n"
		"            \"%s\"\n"
		"        ],\n"
		"        \"read_branch\": [\n"
		"            \"-1\"\n"
		"        ],\n"
		"        \"write\": [\n"
		"            \"%s\"\n"
		"        ],\n"
		"        \"write_branch\": [\n"
		"            \"-1\"\n"
		"        ],\n"
		"        \"mmap\": [\n"
		"            \"%s\"\n"
		"        ],\n"
		"        \"mmap_branch\": [\n"
		"            \"-1\"\n"
		"        ],\n"
		"        \"ioctl\": [\n"
		"            \"%s\"\n"
		"        ],\n"
		"        \"ioctl_branch\": [\n"
		"            \"-1\"\n"
		"        ],\n"
		"        \"ioctl_c\": [\n"
		"            \"0x0\"\n"
		"        ],\n"
		"        \"ioctl_c_branch\": [\n"
		"            \"-1\"\n"
		"        ],\n"
		"        \"perm\": \"%o\",\n"
		"        \"user\": \"%s\",\n"
		"        \"group\": \"%s\"\n"
		"    }";

	if (out_fd == -1) {
		ERR("Output file is not opened");
		return -1;
	}

	if (!e->path_size) {
		ERR("Invalid path size");
		return -1;
	}

	if (!first) {
		ret = dprintf(out_fd, ",\n");
		if (ret <= 0)
			return -1;
	}

	ret = dprintf(out_fd, json_fmt, e->path,
			e->read_func_size ? e->read_func : unknown_func_str,
			e->write_func_size ? e->write_func : unknown_func_str,
			e->mmap_func_size ? e->mmap_func : unknown_func_str,
			e->ioctl_func_size ? e->ioctl_func : unknown_func_str,
			e->st_mode,
			e->user_str_size ? e->user_str : unknown_func_str,
			e->group_str_size ? e->group_str : unknown_func_str);
	if (ret > 0) {
		first = false;
		return 0;
	} else {
		return -1;
	}
}

int save_single_entry(struct entry *e) {
	if (compat_output)
		return save_entry_as_json(e);
	else
		return save_entry_as_raw_text(e);
}

void close_output_file() {
	if (out_fd != -1) {
		if (compat_output)
			dprintf(out_fd, "\n}\n"); // ignore errors
		close(out_fd);
	}
}

ssize_t read_catched_function(char* retbuf, size_t retbuf_size) {
	ssize_t nread;

	if (!retbuf || !retbuf_size) {
		ERR("Invalid parameters");
		return -1;
	}

	nread = read(tracer_fd, retbuf, retbuf_size);
	if (nread < 0) {
		ERR_NO("Failed to read from tracer control file");
		return -1;
	}

	if (!nread) {
		WARN("Seems like no kprobe was triggered");
		return -1;
	}

	//INFO("Read %ld bytes from tracer control file", nread);
	return nread;
}

/* input file format:
 * func1\n
 * func2\n
 * ...
 * funcN[\n]
 *
 * Expects \0 at the end of data
 */
int parse_input_file(char* data, char **funcs[], size_t *funcs_count) {
	size_t fcount = 0, idx;
	char *newline, *ptr;
	char **funcs_arr;

	// count the strings
	ptr = data;
	while (true) {
		newline = strchr(ptr, '\n');
		if (!newline) {
			if (*ptr)
				fcount++;
			break;
		}
		if (newline != ptr) // don't count empty strings (...\n\n...)
			fcount++;
		ptr = newline + 1;
	}

	if (!fcount) {
		ERR("No functions found");
		return -1;
	}

	INFO("Counted %ld functions", fcount);

	funcs_arr = malloc(sizeof(char*) * fcount);
	if (!funcs_arr) {
		ERR("Failed to allocate memory for functions array");
		return -1;
	}

	ptr = data;
	idx = 0;
	while (true) {
		if (!*ptr)
			break;

		if (*ptr == '\n') {
			ptr++;
			continue;
		}
		assert(idx < fcount);
		funcs_arr[idx++] = ptr;
		newline = strchr(ptr, '\n');
		if (!newline)
			break;

		*newline = '\0';
		ptr = newline + 1;
	}

	INFO("Read %ld functions from input file", idx);

	*funcs = funcs_arr;
	*funcs_count = idx;

	return 0;

}

int read_input_file(char* filename, char **funcs[], size_t *funcs_count) {
	int fd;
	size_t fsize, nread, idx;
	off_t tmp;
	char* data;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		ERR_NO("Failed to open input file");
	}

	tmp = lseek(fd, 0, SEEK_END);
	if (tmp < 0) {
		ERR_NO("Failed to get file size");
		close(fd);
		return -1;
	}

	fsize = (size_t) tmp;

	tmp = lseek(fd, 0, SEEK_SET);
	if (tmp < 0) {
		ERR_NO("Failed to rewind input file");
		close(fd);
		return -1;
	}

	if (!fsize) {
		ERR("File is empty");
		close(fd);
		return -1;
	}

	data = malloc(fsize + 1 /* NUL byte */);
	if (!data) {
		ERR("Failed to allocate memory for file contents");
		close(fd);
		return -1;
	}

	idx = 0;
	while (idx < fsize) {
		nread = read(fd, data + idx, fsize - idx);
		if (nread < 0) {
			ERR_NO("Failed to read from input file");
			close(fd);
			free(data);
			return -1;
		} else if (!nread) {
			WARN("Unexpected EOF when reading input file");
			break;
		}
		idx += nread;
	}
	INFO("Read %ld bytes from input file", idx);

	// make sure the buffer ends with (additional) NUL byte, before parsing
	// it with str*() functions
	data[fsize] = '\0';

	close(fd);

	if (parse_input_file(data, funcs, funcs_count) != 0) {
		ERR("Failed to parse input file");
		free(data);
		return -1;
	}

	return 0;

}

void prepare_exclude_patterns() {
	size_t i;

	compiled_exclude_patterns = malloc(sizeof(regex_t) *
					ARR_SIZE(default_exclude_patterns));
	if (!compiled_exclude_patterns) {
		ERR("Failed to allocate memory for exclude patterns");
		return;
	}

	for (i = 0; i < ARR_SIZE(default_exclude_patterns); i++) {
		if (regcomp(&compiled_exclude_patterns[exclude_patterns_count],
				default_exclude_patterns[i],
				REG_NOSUB | REG_EXTENDED) != 0) {
			WARN("Failed to compile regex '%s'",
				default_exclude_patterns[i]);
			continue;
		}
		exclude_patterns_count++;
	}
	INFO("Loaded %ld path exclude patterns", exclude_patterns_count);
}

bool is_excluded(const char *path) {
	size_t i;

	if (!exclude_patterns_count)
		return false;

	for (i = 0; i < exclude_patterns_count; i++) {
		if (!regexec(&compiled_exclude_patterns[i], path, 0, NULL, 0)) {
			//INFO("Excluded %s", path);
			return true;
		}
	}
	return false;
}

void collect_file_stats(const char *fpath, const struct stat *sb,
			struct entry *e) {
	struct passwd *pw;
	struct group *gr;
	bool success = false;
	ssize_t ret;

	e->st_mode = sb->st_mode;
	e->st_uid = sb->st_uid;
	e->st_gid = sb->st_gid;

	errno = 0;
	pw = getpwuid(sb->st_uid);
	if (pw) {
		size_t name_len = strnlen(pw->pw_name, USERSTR_MAX_SIZE - 1);
		if (name_len) {
			e->user_str_size = name_len + 1;
			strncpy(e->user_str, pw->pw_name, e->user_str_size);
			success = true;
		} else {
			WARN("Empty user name string for id %u", sb->st_uid);
		}
	} else {
		WARN("Failed to get user name for id %u: %d (%s)",
			sb->st_uid, errno, strerror(errno));
	}
	if (!success) {
		ssize_t ret;
		// fallback to numerical id
		ret = snprintf(e->user_str, USERSTR_MAX_SIZE,
				"%u", sb->st_uid);
		if (ret >= USERSTR_MAX_SIZE) {
			WARN("String representation of numeric uid exceeds USERSTR_MAX_SIZE (!?)");
			e->user_str_size = USERSTR_MAX_SIZE;
		} else if (ret < 0) {
			WARN("Failed to stringify numeric uid");
		} else {
			e->user_str_size = ret + 1;
		}
	}

	errno = 0;
	success = false;
	gr = getgrgid(sb->st_gid);
	if (gr) {
		size_t group_len = strnlen(gr->gr_name, USERSTR_MAX_SIZE - 1);
		if (group_len) {
			e->group_str_size = group_len + 1;
			strncpy(e->group_str, gr->gr_name, e->group_str_size);
			success = true;
		} else {
			WARN("Empty group name string for id %u", sb->st_gid);
		}
	} else {
		WARN("Failed to get group name for id %u: %d (%s)",
			sb->st_uid, errno, strerror(errno));
	}
	if (!success) {
		ssize_t ret;
		// fallback to numerical id
		ret = snprintf(e->group_str, USERSTR_MAX_SIZE,
				"%u", sb->st_gid);
		if (ret >= USERSTR_MAX_SIZE) {
			WARN("String representation of numeric gid exceeds USERSTR_MAX_SIZE (!?)");
			e->group_str_size = USERSTR_MAX_SIZE;
		} else if (ret < 0) {
			WARN("Failed to stringify numeric gid");
		} else {
			e->group_str_size = ret + 1;
		}
	}

	// SELinux
	ret = getxattr(fpath, "security.selinux", e->selinux_ctx,
			SELINUX_CTX_MAX_SIZE - 1);

	// we don't care about other errors - SELinux context is collected on
	// "best effort" basis and it's ok if it fails
	if (ret < 0 && errno == ERANGE) {
		WARN("SELinux context bigger than %d bytes",
			SELINUX_CTX_MAX_SIZE);
	} else if (ret > 0) {
		e->selinux_ctx_size = ret;
	}

}

char *type_to_str(POKE_TYPE type) {
	switch (type) {
	case POKE_READ: return "read()";
	case POKE_WRITE: return "write()";
	case POKE_IOCTL: return "ioctl()";
	case POKE_MMAP_R: return "mmap(R)";
	case POKE_MMAP_W: return "mmap(W)";
	default: return "<unknown>";
	}
	return "<unknown>";
}

int poke_file(int fd, POKE_TYPE type) {
	char buf[4096];
	char *ptr;
	ssize_t nread, written;
	bool success;

	switch (type) {
	case POKE_READ:
		alarm(SYSCALL_TIMEOUT);
		nread = read(fd, buf, 1);
		alarm(0);
		success = (nread >= 0);
		break;
	case POKE_WRITE:
		memset(buf, 0, sizeof(buf));
		alarm(SYSCALL_TIMEOUT);
		written = write(fd, buf, 1);
		alarm(0);
		success = (written >= 0);
		break;
	case POKE_IOCTL:
		alarm(SYSCALL_TIMEOUT);
		success = ioctl(fd, 0xabad1dea) != -1;
		alarm(0);
		break;
	case POKE_MMAP_R:
	case POKE_MMAP_W:
		ptr = MAP_FAILED;
		alarm(SYSCALL_TIMEOUT);
		ptr = mmap(NULL, 1,
				type == POKE_MMAP_R ? PROT_READ : PROT_WRITE,
				MAP_PRIVATE, fd, 0);
		alarm(0);
		success = ptr != MAP_FAILED;
		if (success)
			munmap(ptr, 1); // TODO: do we care about failure?
		break;
	default:
		success = false;
		break;
	}

	if (!success && errno != ECANCELED) {
		VERBOSE("Failed to call '%s' on file: %d (%s)",
			type_to_str(type), errno, strerror(errno));
		return -1;
	}
		return 0;
}

int analyze_single_file(const char *fpath, const struct stat *sb) {
	int fd;
	ssize_t nread;
	char func_buf[512];
	struct entry e;
	bool ioctl_done = false, mmap_done = false;

	memset(&e, 0, sizeof(struct entry));

	RINFO("Processing: %s ", fpath);

	e.path_size = strlen(fpath) + 1;
	e.path = fpath;

	alarm(SYSCALL_TIMEOUT);
	fd = open(fpath, O_RDONLY | O_NONBLOCK);
	alarm(0);
	if (fd < 0) {
		VERBOSE("open(RD) failed: %d (%s)", errno, strerror(errno));
	} else {
		if (poke_file(fd, POKE_READ) == 0) {
			nread = read_catched_function(e.read_func,
							sizeof(e.read_func));
			if (nread > 0)
				e.read_func_size = nread;
		}
		if (poke_file(fd, POKE_IOCTL) == 0) {
			nread = read_catched_function(e.ioctl_func,
							sizeof(e.ioctl_func));
			if (nread > 0) {
				e.ioctl_func_size = nread;
				ioctl_done = true;
			}
		}
		if (poke_file(fd, POKE_MMAP_R) == 0) {
			nread = read_catched_function(e.mmap_func,
							sizeof(e.mmap_func));
			if (nread > 0) {
				e.mmap_func_size = nread;
				mmap_done = true;
			}
		}

		close(fd);
	}

	alarm(SYSCALL_TIMEOUT);
	fd = open(fpath, O_WRONLY | O_NONBLOCK);
	alarm(0);
	if (fd < 0) {
		VERBOSE("open(WR) failed: %d (%s)", errno, strerror(errno));
		// continue
	} else {
		if (poke_file(fd, POKE_WRITE) == 0) {
			nread = read_catched_function(e.write_func,
							sizeof(e.write_func));
			if (nread > 0)
				e.write_func_size = nread;
		}
		if (!ioctl_done && poke_file(fd, POKE_IOCTL) == 0) {
			nread = read_catched_function(e.ioctl_func,
							sizeof(e.ioctl_func));
			if (nread > 0) {
				e.ioctl_func_size = nread;
			}
		}
		if (!mmap_done && poke_file(fd, POKE_MMAP_W) == 0) {
			nread = read_catched_function(e.mmap_func,
							sizeof(e.mmap_func));
			if (nread > 0) {
				e.mmap_func_size = nread;
			}
		}
	}

	collect_file_stats(fpath, sb, &e);

	if (save_single_entry(&e) != 0) {
		WARN("Failed to write entry to output file");
	}
	close(fd);
	return 0;
}

int visit_file(const char *fpath, const struct stat *sb, int typeflag,
		struct FTW *ftwbuf) {
	if (is_excluded(fpath))
		return 0;

	switch (typeflag) {
	case FTW_F:
		analyze_single_file(fpath, sb);
		break;
	}
	return 0;
}

void traverse_filesystem(char *traverse_root) {
	int ret;

	INFO("Starting filesystem traversal\n");
	ret = nftw(traverse_root, visit_file, 100 /* nopenfd */, FTW_PHYS);
	if (ret < 0) {
		ERR("Failed to traverse filesystem");
	}
	RINFO("Finished filesystem traversal\n");
}

void print_usage(char* progname) {
	ERR("Usage: %s [-v][-c] -f filename (-o|-O) out_filename [-t file]",
		progname);
}

void sigalrm_handler(int signal_no) {
	return;
}

int check_my_permissions() {
	struct __user_cap_header_struct uchs = {0};
	struct __user_cap_data_struct ucds[2];
	int ret;

	memset(&ucds, 0, sizeof(ucds));
	uchs.version = _LINUX_CAPABILITY_VERSION_3;
	uchs.pid = getpid();

	ret = capget(&uchs, ucds);
	if (ret < 0) {
		ERR_NO("Failed to check process' capabilities set");
		return -1;
	}

	if (!((ucds[0].effective >> CAP_DAC_OVERRIDE) & 0x1)) {
		ERR("Process doesn't have CAP_DAC_OVERRIDE capability.");
		return -1;
	}
	return 0;
}

int main(int argc, char** argv) {
	char* fname = NULL, *out_fname = NULL, *traverse_root = "/" ;
	bool truncate = false;
	char **funcs;
	size_t funcs_count;
	int opt;
	struct sigaction sa;

	if (!isatty(1)) {
		termcodes_on = false;
	}

	INFO("Tracer client app v0.1");

	if (check_my_permissions() != 0) {
		return 1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = sigalrm_handler;

	if (sigaction(SIGALRM, &sa, NULL) != 0) {
		ERR_NO("Failed to install SIGALRM handler");
		return 1;
	}

	while ((opt = getopt(argc, argv, "cf:o:O:t:v")) != -1) {
		switch(opt) {
		case 'c':
			compat_output = true;
			break;
		case 'f':
			fname = optarg;
			break;
		case 'o':
			out_fname = optarg;
			truncate = false;
			break;
		case 'O':
			out_fname = optarg;
			truncate = true;
			break;
		case 't':
			traverse_root = optarg;
			break;
		case 'v':
			verbose_output = true;
			break;
		default:
			print_usage(argv[0]);
			return 1;
		}
	}

	if (!fname) {
		ERR("Missing input file name");
		print_usage(argv[0]);
		return 1;
	}

	if (!out_fname) {
		ERR("Missing output file name");
		print_usage(argv[0]);
		return 1;
	}

	if (read_input_file(fname, &funcs, &funcs_count) != 0) {
		ERR("Failed to parse input file");
		return 1;
	}
	OK("Parsed input file");

	if (open_output_file(out_fname, truncate) != 0) {
		ERR("Failed to open output file");
		return 1;
	}
	OK("Opened output file");

	prepare_exclude_patterns();

	if (load_tracer_module(false) != 0) {
		ERR("Failed to prepare tracer module");
		close_output_file();
		return 1;
	}
	OK("Loaded tracer module");

	if (open_tracer_control_file() != 0) {
		ERR("Failed to open tracer control file");
		close_output_file();
		return 1;
	}

	if (attach_to_functions(funcs, funcs_count) != 0) {
		ERR("Failed to attach to functions");
		close_tracer_control_file();
		unload_tracer_module(); // disregard return value
		close_output_file();
		return 1;
	}
	OK("Attached to functions");

	traverse_filesystem(traverse_root);

	maybe_unload_tracer_module();
	close_output_file();
	return 0;
}
