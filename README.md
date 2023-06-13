## SEAL
This tool collects information about files on a running Linux system that may be useful e.g. during security assessment. Apart from gathering basic characteristics of files (permissions, owner, group) it tries to link a user-provided set of Linux kernel functions with selected operations (read, write, mmap, etc.) of each analyzed file, facilitating quick lookup of a file on filesystem based on its handler in the kernel and vice-versa.

### Build
Currently, SEAL supports only ARM64 architecture. Before build, make sure you have:
- Clang with ARM64 support
- Linux kernel source or headers

To build SEAL, set a few variables first:
```bash
$ cd SEAL
$ export KERNEL_PATH=...  # path to Linux kernel headers or source root, used for module build
$ export LLVM_PATH=...  # path to directory that contains Clang with support for ARM64 architecture
$ export CROSS_COMPILE_TRIPLET=...  # target triplet (prefix of Clang binary name, e.g. 'aarch64-linux-android-')
```
Then, start the build:
```bash
$ make all
```
This should produce two executable files:
- `tracer_client` - userspace part of SEAL;
- `tracer.ko` - Linux kernel module;

### Prepare list of tracked kernel functions
SEAL will only track (react to) kernel functions from a user-supplied list. This list is a simple text file that contains kernel function names - one name per line. The best and recommended way to prepare such list is to generate a FTDB file for analyzed kernel beforehand using [CAS](https://github.com/Samsung/CAS) and then to use `get_fops_from_dbjson.py` script from `utils` directory:
```bash
$ python3 utils/get_fops_from_dbjson.py path/to/vmlinux_db.json > fops_list.txt
```

Alternatively one can also use `/proc/kallsyms` to prepare a tailored list of analyzed functions or prepare one fully by hand. This can be especially useful in case of selective analysis of single files or a filesystem subtree.

### Run
**WARNING: this tool loads additional kernel module, attempts to open all specified files and tries to read from, write to, map and call ioctl() on each file. Don't run it on production systems or your main machine. Though in typical usage most effects of files probing should be blocked, some may, and most likely will, still slip through. Data loss and corruption, kernel panics or even device bricking may occur!**

Before running, make sure that `tracer.ko` file is in your working directory.

To start SEAL, run `tracer_client` binary. It will load `tracer.ko` module into the kernel and will require `CAP_DAC_OVERRIDE` capability, so make sure that it has the relevant permissions or run it as root user.
Typical usage looks as follows:
```bash
# ./tracer_client -f fops_list.txt -o output.txt
```
This will cause SEAL to read functions to trace from `fops_list.txt` file, walk the whole root filesystem tree and save results in output.txt file.

### Output
The output file will contain records like below for every analyzed file:
```
<absolute file path>
<detected read() implementation>
<detected write() implementation>
<detected ioctl() implementation>
<detected mmap() implementation>
<file permissions>
<owner>
<group>
<SELinux context>

```
e.g.:
```
/dev/urandom
urandom_read
random_write
random_ioctl
<unknown>
20666
root
root
u:object_r:random_device:s0

```
If SEAL couldn't obtain given info about file, `<unknown>` is printed instead.

### Command line reference
Main SEAL binary, `tracer_client` accepts following arguments:
```bash
./tracer_client [-v][-c] -f filename (-o|-O) out_filename [-t file]

-v              - verbose output to stdout
-c              - compatibility mode - change output format to json
-f filename     - read traced kernel functions from 'filename'; mandatory
-o out_filename - save output to 'out_filename'; fail if file exists
-O out_filename - save output to 'out_filename'; replace contents if file exists
-t file         - use 'file' as the root of filesystem walk, instead of '/'
```

### Technical details
In principle, SEAL detects connections between files visible in userspace and kernel functions that implement their operations by performing each operation on each analyzed file and observing which kernel functions (from the set of analyzed functions) were triggered. The detection of called functions is done by attaching Linux kernel's kprobe to each of them. Every time such kprobe is triggered (and only if the caller is our client program), the function name associated with it is stored and can be retrieved later by client program via typical filesystem interface exposed by module. To, at least partially, avoid side effects arising from calling multiple operations on files, SEAL attempts to bypass execution of triggered kernel function. It does so by "manually" setting program counter and return value registers at the start of the probed function such that it returns immediately.

