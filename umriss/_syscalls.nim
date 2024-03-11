import std/tables

const syscallTable* = {
  "semctl": "semaphore control operations",
  "munmap": "map/unmap files/devices into memory",
  "mq_notify": "register for notification when message is available",
  "rload": "Load file onto LAM remote node",
  "readlinkat": "read value of symbolic link relative to directory file descriptor",
  "lsetxattr": "set extended attrib value",
  "capset": "set/get capabilities of thread",
  "getsockopt": "get/set options on sockets",
  "mpx": "unimplemented system calls",
  "sched_get_priority_min": "static priority range",
  "alloc_hugepages": "allocate/free huge pages",
  "chdir": "change working directory",
  "create_module": "create loadable module entry",
  "kstate": "synchronization status of LAM process",
  "faccessat": "check user's permissions of file relative to directory file descriptor",
  "socketcall": "socket system calls",
  "statvfs": "file system statistics",
  "timerfd_gettime": "timers that notify via file descriptors",
  "_sysctl": "read/write system parameters",
  "cacheflush": "flush contents of instruction/data cache",
  "io_submit": "submit asynchronous I/O blocks for processing",
  "nfsservctl": "syscall interface to kernel nfs daemon",
  "timer_create": "create POSIX per-process timer",
  "ksr": "Send/receive local node LAM messages",
  "read": "read from file descriptor",
  "_llseek": "reposition read/write file offset",
  "fstat": "file status",
  "fstat64": "file status",
  "setfsgid32": "set group identity used for file system checks",
  "outsl": "port I/O",
  "eventfd": "create file descriptor for event notification",
  "rename": "change name/location of file",
  "rget": "Find tagged storage on LAM remote node",
  "rpgo": "Create LAM process on remote node from tagged storage",
  "rpwt": "Wait for child LAM process to terminate",
  "io_getevents": "read asynchronous I/O events from completion queue",
  "prcvo": "LAM physical layer message passing",
  "fstatfs": "file system statistics",
  "psndo": "LAM physical layer message passing",
  "arch_prctl": "set architecture-specific thread state",
  "select": "synchronous I/O multiplexing",
  "keyctl": "change kernel's key management facility",
  "putpmsg": "unimplemented system calls",
  "getresuid32": "real, effective and saved user/group IDs",
  "getresgid": "real, effective and saved user/group IDs",
  "kdetach": "Attach/detach process to/from local LAM daemon",
  "readv": "read/write data into multiple buffers",
  "rt_tgsigqueueinfo": "queue signal/data",
  "sethostid": "get/set unique identifier of current host",
  "pciconfig_read": "pci device info handling",
  "kexit": "Terminate LAM process",
  "kill": "send signal to process",
  "clone2": "create child process",
  "lamf_rfwrite": "Read/write data from/to remote file",
  "trcv": "Send/receive LAM transport messages",
  "fsync": "synchronize file's in-core state with storage device",
  "get_robust_list": "get/set list of robust futexes",
  "mount": "mount file system",
  "mprotect": "set protection on region of memory",
  "lam_rtrstore": "Store LAM trace data",
  "fork": "create child process",
  "nprobe": "Report if LAM bufferd network message is ready to be received",
  "getjones": "array of LAM node identifiers",
  "mmap2": "map files/devices into memory",
  "recvmmsg": "receive multiple messages on socket",
  "setresuid": "set real, effective and saved user or group ID",
  "umount": "unmount file system",
  "personality": "set process execution domain",
  "atkexit": "Terminate LAM process",
  "getnjones": "info on LAM nodes",
  "socket": "create endpoint for communication",
  "lam_rfstat": "LAM POSIX-like remote file service",
  "ssetmask": "change of signal mask",
  "rbfudie": "Control LAM remote buffers",
  "waitpid": "wait for process to change state",
  "dup2": "duplicate file descriptor",
  "getpeername": "name of connected peer socket",
  "setregid": "set real/effective user/group ID",
  "stat": "file status",
  "prlimit": "get/set resource limits",
  "sbrk": "change data segment size",
  "process_vm_readv": "transfer data between process address spaces",
  "chown32": "change ownership of file",
  "setns": "reassociate thread with namespace",
  "setup": "setup devices and file systems, mount root file system",
  "ignall": "info on LAM nodes",
  "stty": "unimplemented system calls",
  "lchown32": "change ownership of file",
  "setfsuid32": "set user identity used for file system checks",
  "symlinkat": "create symbolic link relative to directory file descriptor",
  "fchown": "change ownership of file",
  "getunwind": "copy unwind data to caller's buffer",
  "dup3": "duplicate file descriptor",
  "mq_unlink": "remove message queue",
  "setsid": "creates session/sets process group ID",
  "tsend": "Send/receive LAM transport messages",
  "utime": "change file last access/modification times",
  "getntype": "info on LAM nodes",
  "fadvise": "Give advice about file access",
  "rt_sigsuspend": "wait for signal",
  "getroute2": "LAM route info",
  "nal_address_new": "libnal addressing functions",
  "setgroups": "get/set list of supplementary group IDs",
  "io_cancel": "cancel outstanding asynchronous I/O operation",
  "lam_ksigsetretry": "change LAM signal handling policy",
  "nanosleep": "high-resolution sleep",
  "fchmod": "change permissions of file",
  "timerfd_create": "timers that notify via file descriptors",
  "removexattr": "remove extended attrib",
  "wait": "wait for process to change state",
  "lgetxattr": "extended attrib value",
  "getmsg": "unimplemented system calls",
  "_newselect": "synchronous I/O multiplexing",
  "sendmsg": "send message on socket",
  "set_robust_list": "get/set list of robust futexes",
  "getcwd": "current working directory",
  "timer_gettime": "arm/disarm/fetch state of POSIX per-process timer",
  "lpdetach": "Attach, detach LAM process from remote process management",
  "setgid": "set group identity",
  "subpage_prot": "define subpage protection for address range",
  "lamf_rfclose": "Open/close remote file",
  "send": "send message on socket",
  "mlockall": "lock/unlock memory",
  "ugetrlimit": "get/set resource limits",
  "sched_setscheduler": "set/get scheduling policy/parameters",
  "umask": "set file mode creation mask",
  "setresuid32": "set real, effective and saved user or group ID",
  "multiplexer": "unimplemented system calls",
  "geteuid": "user identity",
  "setreuid32": "set real/effective user/group ID",
  "rt_sigpending": "examine pending signals",
  "unshare": "disassociate parts of process execution context",
  "nal_buffer_new": "libnal buffer functions",
  "getxattr": "extended attrib value",
  "nal_decode_uint32": "libnal serialisation functions",
  "fstatvfs": "file system statistics",
  "epoll_create": "open epoll file descriptor",
  "getegid": "group identity",
  "getrentc": "LAM route info",
  "rbfwipe": "Control LAM remote buffers",
  "timer_getoverrun": "overrun count for POSIX per-process timer",
  "dc_plug_new": "basic DC_PLUG functions",
  "epoll_ctl": "control interface for epoll descriptor",
  "fgetxattr": "extended attrib value",
  "unlink": "delete name/possibly file it refers to",
  "igndid": "info on LAM nodes",
  "vm86": "enter virtual 8086 mode",
  "mkdirat": "create directory relative to directory file descriptor",
  "utimes": "change file last access/modification times",
  "gotbs": "array of LAM node identifiers",
  "uname": "name/info about current kernel",
  "nrecv": "Send/receive LAM network messages",
  "init_module": "load kernel module",
  "lam_ksigblock": "change LAM signal handling policy",
  "mq_timedsend": "send message to message queue",
  "uselib": "load shared library",
  "get_mempolicy": "NUMA memory policy for process",
  "flock": "apply/remove advisory lock on open file",
  "eventfd2": "create file descriptor for event notification",
  "lam_ksigsetmask": "change LAM signal handling policy",
  "msync": "synchronize file with memory map",
  "fstatat64": "file status relative to directory file descriptor",
  "recvfrom": "receive message from socket",
  "writev": "read/write data into multiple buffers",
  "getuid": "user identity",
  "tux": "interact with TUX kernel subsystem",
  "sched_setparam": "set/get scheduling parameters",
  "sigaction": "examine/change signal action",
  "unlinkat": "remove directory entry relative to directory file descriptor",
  "fcntl64": "change file descriptor",
  "mincore": "determine whether pages are resident in memory",
  "ftruncate": "truncate file to specified length",
  "outl": "port I/O",
  "nsend": "Send/receive LAM network messages",
  "kenter": "Enter process into LAM session",
  "recvmsg": "receive message from socket",
  "wait3": "wait for process to change state, BSD style",
  "fcntl": "change file descriptor",
  "msgrcv": "message operations",
  "psndc": "LAM physical layer message passing",
  "inl": "port I/O",
  "sigtimedwait": "synchronously wait for queued signals",
  "vhangup": "virtually hangup current terminal",
  "rt_sigqueueinfo": "queue signal/data",
  "setregid32": "set real/effective user/group ID",
  "nprob": "Report if LAM bufferd network message is ready to be received",
  "sched_rr_get_interval": "SCHED_RR interval for named process",
  "flistxattr": "extended attrib names",
  "tkill": "send signal to thread",
  "chroot": "change root directory",
  "igndtp": "info on LAM nodes",
  "setresgid32": "set real, effective and saved user or group ID",
  "insw": "port I/O",
  "fchdir": "change working directory",
  "mremap": "remap virtual memory address",
  "pipe2": "create pipe",
  "sigblock": "change signal mask",
  "gnodes": "array of LAM node identifiers",
  "lam_rfclose": "LAM POSIX-like remote file service",
  "semop": "semaphore operations",
  "igorgn": "info on LAM nodes",
  "rpcreate": "Create LAM process on remote node",
  "timer_delete": "delete POSIX per-process timer",
  "inl_p": "port I/O",
  "insb": "port I/O",
  "psnd": "LAM physical layer message passing",
  "setsockopt": "get/set options on sockets",
  "getgid32": "group identity",
  "setgid32": "set group identity",
  "rpwait": "Wait for child LAM process to terminate",
  "arm_sync_file_range": "sync file segment with disk",
  "fchmodat": "change permissions of file relative to directory file descriptor",
  "lam_rtrforget": "Unload LAM trace data",
  "linkat": "create file link relative to directory file descriptors",
  "getegid32": "group identity",
  "s390_runtime_instr": "enable/disable s390 CPU run-time instrumentation",
  "sstk": "change stack size",
  "vmsplice": "splice user pages into pipe",
  "gethostname": "get/set hostname",
  "nal_selector_new": "libnal selector functions",
  "fattach": "unimplemented system calls",
  "setpgrp": "set/get process group",
  "getpagesize": "memory page size",
  "semget": "semaphore set identifier",
  "syncfs": "commit buffer cache to disk",
  "msgctl": "message control operations",
  "phys": "unimplemented system calls",
  "statfs64": "file system statistics",
  "mlock": "lock/unlock memory",
  "setdomainname": "get/set NIS domain name",
  "syscall": "indirect system call",
  "pause": "wait for signal",
  "rtas": "Allows userspace to call RTAS",
  "setcontext": "get/set user context",
  "sigaltstack": "set/get signal stack context",
  "gjones": "array of LAM node identifiers",
  "ioctl_list": "ioctl calls in /i386 kernel",
  "kcreate": "Create LAM process from executable program",
  "spu_create": "create new spu context",
  "isastream": "unimplemented system calls",
  "vserver": "unimplemented system calls",
  "pivot_root": "change root file system",
  "clone": "create child process",
  "gtty": "unimplemented system calls",
  "lookup_dcookie": "return directory entry's path",
  "oldstat": "file status",
  "getrtype": "LAM route info",
  "setrlimit": "get/set resource limits",
  "lam_ksigretry": "change LAM signal handling policy",
  "futex": "fast user-space locking",
  "lam_kpause": "change LAM signal handling policy",
  "undocumented": "undocumented system calls",
  "ioprio_get": "get/set I/O scheduling class/priority",
  "shmctl": "shared memory control",
  "finit_module": "load kernel module",
  "getpmsg": "unimplemented system calls",
  "tsnd": "Send/receive LAM transport messages",
  "oldfstat": "file status",
  "perfmonctl": "interface to IA-64 performance monitoring unit",
  "accept": "accept connection on socket",
  "close": "close file descriptor",
  "open": "open/possibly create file/device",
  "madvise": "give advice about use of memory",
  "sched_get_priority_max": "static priority range",
  "umount2": "unmount file system",
  "_syscall": "invoking system call without library support",
  "getcpu": "determine CPU/NUMA node on which calling thread is running",
  "acct": "switch process accounting on/off",
  "rmdir": "delete directory",
  "sigpending": "examine pending signals",
  "getroute": "LAM route info",
  "sigsetmask": "change signal mask",
  "lam_rfwrite": "LAM POSIX-like remote file service",
  "sigpause": "atomically release blocked signals/wait for interrupt",
  "dup": "duplicate file descriptor",
  "olduname": "name/info about current kernel",
  "sysfs": "file system type info",
  "break": "unimplemented system calls",
  "rt_sigtimedwait": "synchronously wait for queued signals",
  "sigwaitinfo": "synchronously wait for queued signals",
  "timerfd_settime": "timers that notify via file descriptors",
  "tuxcall": "unimplemented system calls",
  "path_resolution": "find file referred to by filename",
  "ignjon": "info on LAM nodes",
  "setpgid": "set/get process group",
  "query_module": "query kernel for various bits pertaining to modules",
  "getgroups32": "get/set list of supplementary group IDs",
  "sync": "commit buffer cache to disk",
  "ipc": "System V IPC system calls",
  "lam_rfrmfd": "Control LAM specific file daemon services",
  "lseek": "reposition read/write file offset",
  "prcvc": "LAM physical layer message passing",
  "lchown": "change ownership of file",
  "waitid": "wait for process to change state",
  "lamf_rfopen": "Open/close remote file",
  "pwrite64": "read from/write to file descriptor at given offset",
  "swapoff": "start/stop swapping to file/device",
  "getgroups": "get/set list of supplementary group IDs",
  "statfs": "file system statistics",
  "fstatfs64": "file system statistics",
  "inotify_init1": "initialize inotify instance",
  "io_destroy": "destroy asynchronous I/O context",
  "ptrace": "process trace",
  "setgroups32": "get/set list of supplementary group IDs",
  "rt_sigreturn": "return from signal handler/cleanup stack frame",
  "outw": "port I/O",
  "fdetach": "unimplemented system calls",
  "putmsg": "unimplemented system calls",
  "signalfd4": "create file descriptor for accepting signals",
  "stime": "set time",
  "rflclean": "Tag/load storage on LAM remote nodes",
  "unimplemented": "unimplemented system calls",
  "dc_ctx_new": "distcache blocking client API",
  "epoll_create1": "open epoll file descriptor",
  "ioperm": "set port input/output permissions",
  "sigmask": "change signal mask",
  "pwritev": "read/write data into multiple buffers",
  "epoll_wait": "wait for I/O event on epoll file descriptor",
  "munlock": "lock/unlock memory",
  "perf_event_open": "set up performance monitoring",
  "pread": "read from/write to file descriptor at given offset",
  "gcomps": "array of LAM node identifiers",
  "restart_syscall": "Restart system call",
  "rt_sigaction": "examine/change signal action",
  "get_kernel_syms": "exported kernel/module symbols",
  "sgetmask": "change of signal mask",
  "psend": "LAM physical layer message passing",
  "sysinfo": "returns info on overall system statistics",
  "syslog": "read/clear kernel message ring buffer; set console_loglevel",
  "llistxattr": "extended attrib names",
  "chown": "change ownership of file",
  "getnodeid": "info on LAM nodes",
  "delete_module": "unload kernel module",
  "getotbs": "array of LAM node identifiers",
  "link": "make new name for file",
  "lock": "unimplemented system calls",
  "getsid": "session ID",
  "sigprocmask": "examine/change blocked signals",
  "get_thread_area": "thread-local storage area",
  "mq_timedreceive": "receive message from message queue",
  "sendfile": "transfer data between file descriptors",
  "gall": "array of LAM node identifiers",
  "rforget": "Find tagged storage on LAM remote node",
  "sync_file_range": "sync file segment with disk",
  "gethostid": "get/set unique identifier of current host",
  "times": "process times",
  "_kexit": "Terminate LAM process",
  "inw_p": "port I/O",
  "creat": "open/possibly create file/device",
  "igncmp": "info on LAM nodes",
  "mmap": "map/unmap files/devices into memory",
  "rpstate": "Report status of LAM processes on remote node",
  "getcomps": "array of LAM node identifiers",
  "iopl": "change I/O privilege level",
  "futimesat": "change timestamps of file relative to directory file descriptor",
  "setegid": "set effective user/group ID",
  "getppid": "process identification",
  "krecv": "Send/receive local node LAM messages",
  "shmdt": "shared memory operations",
  "shutdown": "shut down part of full-duplex connection",
  "drecv": "Send/receive LAM datalink messages",
  "getdents64": "directory entries",
  "madvise1": "unimplemented system calls",
  "mknodat": "create special/ordinary file relative to directory file descriptor",
  "prof": "unimplemented system calls",
  "inotify_rm_watch": "remove existing watch from inotify instance",
  "recv": "receive message from socket",
  "fchownat": "change ownership of file relative to directory file descriptor",
  "shmat": "shared memory operations",
  "lamf_rfread": "Read/write data from/to remote file",
  "msgop": "message operations",
  "introc": "introduction to LAM C programming functions",
  "lam_rtrsweep": "Remove LAM trace data",
  "truncate64": "truncate file to specified length",
  "lam_ksignal": "Specify signal handler for LAM signal",
  "insl": "port I/O",
  "security": "unimplemented system calls",
  "setpriority": "get/set program scheduling priority",
  "ustat": "file system statistics",
  "getrusage": "resource usage",
  "lam_rtrfforget": "Unload LAM trace data",
  "sysctl": "read/write system parameters",
  "alarm": "set alarm clock for delivery of signal",
  "exit_group": "exit all threads in process",
  "rflat": "Tag/load storage on LAM remote nodes",
  "mq_open": "open message queue",
  "wait4": "wait for process to change state, BSD style",
  "write": "to file descriptor",
  "accept4": "accept connection on socket",
  "getrent": "LAM route info",
  "dc_plug_read": "DC_PLUG read/write functions",
  "getnotb": "info on LAM nodes",
  "outsw": "port I/O",
  "reboot": "reboot/enable/disable Ctrl-Alt-Del",
  "chmod": "change permissions of file",
  "ksend": "Send/receive local node LAM messages",
  "move_pages": "move individual pages of process to another node",
  "mq_getsetattr": "get/set message queue attribs",
  "setresgid": "set real, effective and saved user or group ID",
  "fchown32": "change ownership of file",
  "getall": "array of LAM node identifiers",
  "lremovexattr": "remove extended attrib",
  "sigsuspend": "wait for signal",
  "syscalls": "system calls",
  "clock_gettime": "clock/time functions",
  "prctl": "operations on process",
  "rpspawn": "Spawn LAM process onto remote node",
  "lam_rtrwipe": "Remove LAM trace data",
  "fattch": "unimplemented system calls",
  "semtimedop": "semaphore operations",
  "oldlstat": "file status",
  "ftruncate64": "truncate file to specified length",
  "setreuid": "set real/effective user/group ID",
  "obsolete": "obsolete system calls",
  "epoll_pwait": "wait for I/O event on epoll file descriptor",
  "pwrite": "read from/write to file descriptor at given offset",
  "inb": "port I/O",
  "sched_setaffinity": "set/get process's CPU affinity mask",
  "add_key": "add key to kernel's key management facility",
  "sendto": "send message on socket",
  "set_thread_area": "set thread local storage area",
  "tgkill": "send signal to thread",
  "gettimeofday": "get/set time",
  "readahead": "perform file readahead into page cache",
  "renameat": "rename file relative to directory file descriptors",
  "sigqueue": "queue signal/data to process",
  "kattach": "Attach/detach process to/from local LAM daemon",
  "_exit": "terminate calling process",
  "readlink": "read value of symbolic link",
  "access": "check real user's permissions for file",
  "modify_ldt": "get/set ldt",
  "getresgid32": "real, effective and saved user/group IDs",
  "setfsgid": "set group identity used for file system checks",
  "ioprio_set": "get/set I/O scheduling class/priority",
  "llseek": "reposition read/write file offset",
  "splice": "splice data to/from pipe",
  "spu_run": "execute SPU context",
  "__clone2": "create child process",
  "introf": "introduction to LAM Fortran programming routines",
  "exit": "terminate calling process",
  "fremovexattr": "remove extended attrib",
  "lam_rfstate": "Report status of remote LAM file descriptors",
  "sendfile64": "transfer data between file descriptors",
  "kcmp": "compare two processes to determine if they share kernel resource",
  "setuid": "set user identity",
  "shmget": "allocates shared memory segment",
  "outb_p": "port I/O",
  "sigvec": "BSD software signal facilities",
  "pipe": "create pipe",
  "signal": "ANSI C signal handling",
  "mkdir": "create directory",
  "set_tid_address": "set pointer to thread ID",
  "bdflush": "start, flush, or tune buffer-dirty-flush daemon",
  "ignotb": "info on LAM nodes",
  "killpg": "send signal to process group",
  "munlockall": "lock/unlock memory",
  "geteuid32": "user identity",
  "sendmmsg": "send multiple messages on socket",
  "swapon": "start/stop swapping to file/device",
  "getdents": "directory entries",
  "truncate": "truncate file to specified length",
  "shmop": "shared memory operations",
  "migrate_pages": "move all pages in process to another set of nodes",
  "getnodes": "array of LAM node identifiers",
  "rploadgo": "Load/execute LAM program on remote node",
  "free_hugepages": "allocate/free huge pages",
  "clock_getres": "clock/time functions",
  "outl_p": "port I/O",
  "nal_connection_new": "libnal connection functions",
  "trecv": "Send/receive LAM transport messages",
  "rt_sigprocmask": "examine/change blocked signals",
  "kexec_load": "load new kernel for later execution",
  "outsb": "port I/O",
  "seteuid": "set effective user/group ID",
  "lam_rfread": "LAM POSIX-like remote file service",
  "listxattr": "extended attrib names",
  "clock_nanosleep": "high-resolution sleep with specifiable clock",
  "getresuid": "real, effective and saved user/group IDs",
  "getrlimit": "get/set resource limits",
  "msgget": "message queue identifier",
  "rrsetrents": "Set LAM route info",
  "socketpair": "create pair of connected sockets",
  "tee": "duplicating pipe content",
  "setitimer": "get/set value of interval timer",
  "nsnd": "Send/receive LAM network messages",
  "execve": "execute program",
  "lstat64": "file status",
  "getpriority": "get/set program scheduling priority",
  "adjtimex": "tune kernel clock",
  "intro": "introduction to system calls",
  "posix_fadvise": "predeclare access pattern for file data",
  "process_vm_writev": "transfer data between process address spaces",
  "arm_fadvise": "predeclare access pattern for file data",
  "pread64": "read from/write to file descriptor at given offset",
  "settimeofday": "get/set time",
  "getsockname": "socket name",
  "lam_rflseek": "LAM POSIX-like remote file service",
  "outw_p": "port I/O",
  "idle": "make process 0 idle",
  "inotify_init": "initialize inotify instance",
  "kxit": "Terminate LAM process",
  "nal_listener_new": "libnal listener functions",
  "arm_fadvise64_64": "predeclare access pattern for file data",
  "openat": "open file relative to directory file descriptor",
  "preadv": "read/write data into multiple buffers",
  "getpid": "process identification",
  "rbfparms": "Control LAM remote buffers",
  "setfsuid": "set user identity used for file system checks",
  "fadvise64_64": "predeclare access pattern for file data",
  "utimensat": "change file timestamps with nanosecond precision",
  "lam_rtrfget": "Unload LAM trace data",
  "recho": "Send messages to LAM echo server",
  "getnall": "info on LAM nodes",
  "fsetxattr": "set extended attrib value",
  "inw": "port I/O",
  "mknod": "create special/ordinary file",
  "msgsnd": "message operations",
  "prcv": "LAM physical layer message passing",
  "set_mempolicy": "set default NUMA memory policy for process/its children",
  "getpgrp": "set/get process group",
  "getdtablesize": "descriptor table size",
  "remap_file_pages": "create nonlinear file mapping",
  "nice": "change process priority",
  "rbflook": "copy of buffered LAM message packet",
  "kinit": "Initialize LAM process",
  "afs_syscall": "unimplemented system calls",
  "getdomainname": "get/set NIS domain name",
  "inotify_add_watch": "add watch to initialized inotify instance",
  "sched_getparam": "set/get scheduling parameters",
  "kdoom": "Deliver signal to LAM process",
  "readdir": "read directory entry",
  "sched_getaffinity": "set/get process's CPU affinity mask",
  "fdatasync": "synchronize file's in-core state with storage device",
  "igntp": "info on LAM nodes",
  "sigreturn": "return from signal handler/cleanup stack frame",
  "lam_rtrget": "Unload LAM trace data",
  "rpldgo": "Load/execute LAM program on remote node",
  "rbfsweep": "Control LAM remote buffers",
  "lpattach": "Attach, detach LAM process from remote process management",
  "request_key": "request key from kernel's key management facility",
  "pselect6": "synchronous I/O multiplexing",
  "mbind": "set memory policy for memory range",
  "pselect": "synchronous I/O multiplexing",
  "vfork": "create child process/block parent",
  "ioctl": "control device",
  "setuid32": "set user identity",
  "sched_getscheduler": "set/get scheduling policy/parameters",
  "bind": "bind name to socket",
  "brk": "change data segment size",
  "spufs": "SPU file system",
  "connect": "initiate connection on socket",
  "lam_rtrudie": "Remove LAM trace data",
  "listen": "listen for connections on socket",
  "time": "time in seconds",
  "pciconfig_write": "pci device info handling",
  "pciconfig_iobase": "pci device info handling",
  "fadvise64": "predeclare access pattern for file data",
  "getnodetype": "info on LAM nodes",
  "nrcv": "Send/receive LAM network messages",
  "igrtp": "LAM route info",
  "select_tut": "synchronous I/O multiplexing",
  "sethostname": "get/set hostname",
  "lam_rfopen": "LAM POSIX-like remote file service",
  "oldolduname": "name/info about current kernel",
  "getgid": "group identity",
  "outb": "port I/O",
  "clock_settime": "clock/time functions",
  "getpgid": "set/get process group",
  "dc_server_new": "distcache server API",
  "ppoll": "wait for some event on file descriptor",
  "timer_settime": "arm/disarm/fetch state of POSIX per-process timer",
  "capget": "set/get capabilities of thread",
  "lam_rfposix": "LAM POSIX-like remote file service",
  "precv": "LAM physical layer message passing",
  "symlink": "make new name for file",
  "lstat": "file status",
  "getorigin": "info on LAM nodes",
  "signalfd": "create file descriptor for accepting signals",
  "getuid32": "user identity",
  "vm86old": "enter virtual 8086 mode",
  "sync_file_range2": "sync file segment with disk",
  "siggetmask": "change signal mask",
  "setxattr": "set extended attrib value",
  "poll": "wait for some event on file descriptor",
  "swapcontext": "Swap out old context with new context",
  "io_setup": "create asynchronous I/O context",
  "kentr": "Enter process into LAM session",
  "fstatat": "file status relative to directory file descriptor",
  "trror": "Print LAM system error message",
  "rbfstate": "Report status of remote LAM buffers",
  "sched_yield": "yield processor",
  "lam_rfincr": "Control LAM specific file daemon services",
  "dsend": "Send/receive LAM datalink messages",
  "rpdoom": "Signal LAM processes on remote node",
  "stat64": "file status",
  "getitimer": "get/set value of interval timer",
  "inb_p": "port I/O",
  "gettid": "thread identification",
  "fallocate": "change file space",
  "getcontext": "get/set user context",
  "quotactl": "change disk quotas",
}.toTable()