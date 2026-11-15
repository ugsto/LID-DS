/* collector.h: record layout shared by collector.bpf.c, collector.c and decode.py.
 * All integers little endian. A record is: struct hdr, a kind-specific fixed
 * part, then blobs until hdr.size. Each blob is struct blob + len bytes, and
 * the next blob starts at the next multiple of 8. */
#ifndef COLLECTOR_H
#define COLLECTOR_H

enum kind { R_ENTER = 1, R_EXIT, R_FILE, R_EXEC, R_FORK, R_PEXIT, R_SOCK };
enum scope { S_FOCUS = 1, S_OTHER = 2 };

struct hdr {
	__u32 size;        /* whole record, bytes */
	__u16 kind;
	__u8 scope;
	__u8 pad;
	__u64 seq;         /* per-CPU, starts at 0, +1 per record emitted on that CPU */
	__u32 cpu;
	__u32 pad2;
	__u64 ts;          /* bpf_ktime_get_boot_ns */
	__u32 tid, tgid;   /* host pid namespace */
	__u32 nstid, nstgid; /* the task's own pid namespace */
	__u32 ppid;        /* real_parent tgid, host */
	__u32 uid, gid;
	__u32 pidns, mntns, netns; /* namespace inode numbers */
	__u64 cgid;        /* cgroup v2 id */
	__u64 pstart;      /* group leader start_time (ns since boot): process identity with tgid */
	char comm[16];
};

/* Kernel object identity of an inode (and socket endpoints if it is one). */
struct ident {
	__u64 ino;
	__u64 magic;       /* superblock magic: tells overlayfs, pipefs, sockfs, ... */
	__u64 real_ino;    /* overlayfs upper inode, when ovl == 1 */
	__u32 dev, gen, mode, nlink;
	__u32 real_dev;
	__u8 ovl;          /* 0 not overlayfs, 1 upper (written/copied up at runtime), 2 lower (image layer) */
	__u8 pad;
	__u16 family, stype, lport, rport; /* sockets; ports in host order */
	__u16 pad2;
	__u8 laddr[16], raddr[16]; /* inet/inet6 addresses; unix: raddr holds the peer socket inode (u64) */
};

struct blob {
	__u8 arg;          /* argument index, or object index for R_FILE */
	__u8 type;         /* enum btype */
	__u16 flags;       /* F_* */
	__u32 len;
};
enum btype {
	B_STR = 1,   /* user string as passed (path, symlink target, xattr name...) */
	B_BASE,      /* a directory, by dentry walk: for R_ENTER the base of a relative path (dirfd or cwd),
				for R_FILE the parent dir of the object; components leaf first, NUL separated */
	B_IDENT,     /* struct ident of an fd argument, the returned fd, or an object */
	B_SADDR,     /* sockaddr bytes */
	B_BYTES,     /* raw struct bytes: open_how, int[2] fds of pipe/socketpair */
	B_ARGV,      /* one argv/envp element (one blob per element) */
	B_KPATH,     /* kernel-resolved path (bpf_d_path), relative to the task's root */
	B_NAME,      /* dentry name (last component) */
	B_MEM,       /* raw user memory: exec argv/envp area, NUL separated */
};
enum { F_TRUNC = 1, F_FAULT = 2 };
#define ARG_RET 7    /* blob.arg for the returned fd */

struct enter { struct hdr h; __u64 nr; __u64 args[6]; };
struct exit { struct hdr h; __u64 nr; __s64 ret; };
struct file_rec { struct hdr h; __u32 op; __u32 a; __u64 b; };
enum fop { O_OPEN = 1, O_MMAP, O_UNLINK, O_RMDIR, O_MKDIR, O_MKNOD, O_SYMLINK, O_LINK, O_RENAME, O_TRUNCATE, O_CHMOD, O_CHOWN };
struct exec_rec { struct hdr h; __u32 old_pid; __u32 pad; };
struct fork_rec { struct hdr h; __u32 tid, tgid, nstid, nstgid; __u64 start; };
struct pexit_rec { struct hdr h; __s32 code; __u32 live; }; /* live: signal->live at exit; 0 = last thread */
struct sock_rec { struct hdr h; __u32 op; __u32 pad; };
enum sop { K_CONNECT = 1, K_BIND };

/* Counters, per CPU. Proof of no loss: seen == ok, fail == busy == 0,
 * and the reader received ok records with no per-CPU sequence gaps.
 * C_FAULT counts user reads that faulted; C_REFETCHED those recovered at sys_exit
 * (the R_EXIT record then carries the string as a B_STR blob). */
enum { C_SEEN, C_OK, C_FAIL, C_BUSY, C_TRUNC, C_FAULT, C_REFETCHED, NCOUNTERS };

/* Argument types per syscall. Enter types in bits 0-23 (4 bits per arg),
 * exit (output) types in bits 24-47, bit 63: the return value is a new fd. */
enum atype { T_PATH = 1, T_STR, T_FD, T_DIRFD, T_SADDR, T_MSG, T_HOW, T_ARGV, T_SADDRO, T_MSGO, T_FD2O };
#define A(a, b, c, d, e, f) ((__u64)(a) | (__u64)(b) << 4 | (__u64)(c) << 8 | (__u64)(d) << 12 | (__u64)(e) << 16 | (__u64)(f) << 20)
#define O(a, b, c, d, e, f) (A(a, b, c, d, e, f) << 24)
#define RETFD (1ULL << 63)
#define P T_PATH
#define S T_STR
#define F T_FD
#define D T_DIRFD

#define NSYS 512
static const __u64 argtab[NSYS] = {
	[__NR_read] = A(F,0,0,0,0,0), [__NR_write] = A(F,0,0,0,0,0),
	[__NR_open] = A(P,0,0,0,0,0) | RETFD, [__NR_close] = A(F,0,0,0,0,0),
	[__NR_stat] = A(P,0,0,0,0,0), [__NR_fstat] = A(F,0,0,0,0,0), [__NR_lstat] = A(P,0,0,0,0,0),
	[__NR_lseek] = A(F,0,0,0,0,0), [__NR_mmap] = A(0,0,0,0,F,0), [__NR_ioctl] = A(F,0,0,0,0,0),
	[__NR_pread64] = A(F,0,0,0,0,0), [__NR_pwrite64] = A(F,0,0,0,0,0),
	[__NR_readv] = A(F,0,0,0,0,0), [__NR_writev] = A(F,0,0,0,0,0),
	[__NR_access] = A(P,0,0,0,0,0), [__NR_pipe] = O(T_FD2O,0,0,0,0,0),
	[__NR_dup] = A(F,0,0,0,0,0) | RETFD, [__NR_dup2] = A(F,0,0,0,0,0) | RETFD,
	[__NR_sendfile] = A(F,F,0,0,0,0),
	[__NR_socket] = RETFD, [__NR_connect] = A(F,T_SADDR,0,0,0,0),
	[__NR_accept] = A(F,0,0,0,0,0) | O(0,T_SADDRO,0,0,0,0) | RETFD,
	[__NR_sendto] = A(F,0,0,0,T_SADDR,0), [__NR_recvfrom] = A(F,0,0,0,0,0) | O(0,0,0,0,T_SADDRO,0),
	[__NR_sendmsg] = A(F,T_MSG,0,0,0,0), [__NR_recvmsg] = A(F,0,0,0,0,0) | O(0,T_MSGO,0,0,0,0),
	[__NR_shutdown] = A(F,0,0,0,0,0), [__NR_bind] = A(F,T_SADDR,0,0,0,0), [__NR_listen] = A(F,0,0,0,0,0),
	[__NR_getsockname] = A(F,0,0,0,0,0) | O(0,T_SADDRO,0,0,0,0),
	[__NR_getpeername] = A(F,0,0,0,0,0) | O(0,T_SADDRO,0,0,0,0),
	[__NR_socketpair] = O(0,0,0,T_FD2O,0,0),
	[__NR_setsockopt] = A(F,0,0,0,0,0), [__NR_getsockopt] = A(F,0,0,0,0,0),
	[__NR_execve] = A(P,T_ARGV,T_ARGV,0,0,0),
	[__NR_fcntl] = A(F,0,0,0,0,0), [__NR_flock] = A(F,0,0,0,0,0),
	[__NR_fsync] = A(F,0,0,0,0,0), [__NR_fdatasync] = A(F,0,0,0,0,0),
	[__NR_truncate] = A(P,0,0,0,0,0), [__NR_ftruncate] = A(F,0,0,0,0,0),
	[__NR_getdents] = A(F,0,0,0,0,0), [__NR_getdents64] = A(F,0,0,0,0,0),
	[__NR_chdir] = A(P,0,0,0,0,0), [__NR_fchdir] = A(F,0,0,0,0,0),
	[__NR_rename] = A(P,P,0,0,0,0), [__NR_mkdir] = A(P,0,0,0,0,0), [__NR_rmdir] = A(P,0,0,0,0,0),
	[__NR_creat] = A(P,0,0,0,0,0) | RETFD, [__NR_link] = A(P,P,0,0,0,0), [__NR_unlink] = A(P,0,0,0,0,0),
	[__NR_symlink] = A(S,P,0,0,0,0), [__NR_readlink] = A(P,0,0,0,0,0),
	[__NR_chmod] = A(P,0,0,0,0,0), [__NR_fchmod] = A(F,0,0,0,0,0),
	[__NR_chown] = A(P,0,0,0,0,0), [__NR_fchown] = A(F,0,0,0,0,0), [__NR_lchown] = A(P,0,0,0,0,0),
	[__NR_utime] = A(P,0,0,0,0,0), [__NR_mknod] = A(P,0,0,0,0,0), [__NR_uselib] = A(P,0,0,0,0,0),
	[__NR_statfs] = A(P,0,0,0,0,0), [__NR_fstatfs] = A(F,0,0,0,0,0),
	[__NR_pivot_root] = A(P,P,0,0,0,0), [__NR_chroot] = A(P,0,0,0,0,0), [__NR_acct] = A(P,0,0,0,0,0),
	[__NR_mount] = A(S,P,S,0,0,0), [__NR_umount2] = A(P,0,0,0,0,0),
	[__NR_swapon] = A(P,0,0,0,0,0), [__NR_swapoff] = A(P,0,0,0,0,0),
	[__NR_readahead] = A(F,0,0,0,0,0),
	[__NR_setxattr] = A(P,S,0,0,0,0), [__NR_lsetxattr] = A(P,S,0,0,0,0), [__NR_fsetxattr] = A(F,S,0,0,0,0),
	[__NR_getxattr] = A(P,S,0,0,0,0), [__NR_lgetxattr] = A(P,S,0,0,0,0), [__NR_fgetxattr] = A(F,S,0,0,0,0),
	[__NR_listxattr] = A(P,0,0,0,0,0), [__NR_llistxattr] = A(P,0,0,0,0,0), [__NR_flistxattr] = A(F,0,0,0,0,0),
	[__NR_removexattr] = A(P,S,0,0,0,0), [__NR_lremovexattr] = A(P,S,0,0,0,0), [__NR_fremovexattr] = A(F,S,0,0,0,0),
	[__NR_epoll_create] = RETFD, [__NR_fadvise64] = A(F,0,0,0,0,0),
	[__NR_epoll_wait] = A(F,0,0,0,0,0), [__NR_epoll_ctl] = A(F,0,F,0,0,0),
	[__NR_utimes] = A(P,0,0,0,0,0),
	[__NR_inotify_init] = RETFD, [__NR_inotify_add_watch] = A(F,P,0,0,0,0), [__NR_inotify_rm_watch] = A(F,0,0,0,0,0),
	[__NR_openat] = A(D,P,0,0,0,0) | RETFD, [__NR_mkdirat] = A(D,P,0,0,0,0), [__NR_mknodat] = A(D,P,0,0,0,0),
	[__NR_fchownat] = A(D,P,0,0,0,0), [__NR_futimesat] = A(D,P,0,0,0,0), [__NR_newfstatat] = A(D,P,0,0,0,0),
	[__NR_unlinkat] = A(D,P,0,0,0,0), [__NR_renameat] = A(D,P,D,P,0,0), [__NR_linkat] = A(D,P,D,P,0,0),
	[__NR_symlinkat] = A(S,D,P,0,0,0), [__NR_readlinkat] = A(D,P,0,0,0,0), [__NR_fchmodat] = A(D,P,0,0,0,0),
	[__NR_faccessat] = A(D,P,0,0,0,0),
	[__NR_splice] = A(F,0,F,0,0,0), [__NR_tee] = A(F,F,0,0,0,0), [__NR_sync_file_range] = A(F,0,0,0,0,0),
	[__NR_vmsplice] = A(F,0,0,0,0,0), [__NR_utimensat] = A(D,P,0,0,0,0), [__NR_epoll_pwait] = A(F,0,0,0,0,0),
	[__NR_signalfd] = A(F,0,0,0,0,0) | RETFD, [__NR_timerfd_create] = RETFD, [__NR_eventfd] = RETFD,
	[__NR_fallocate] = A(F,0,0,0,0,0),
	[__NR_accept4] = A(F,0,0,0,0,0) | O(0,T_SADDRO,0,0,0,0) | RETFD,
	[__NR_signalfd4] = A(F,0,0,0,0,0) | RETFD, [__NR_eventfd2] = RETFD, [__NR_epoll_create1] = RETFD,
	[__NR_dup3] = A(F,0,0,0,0,0) | RETFD, [__NR_pipe2] = O(T_FD2O,0,0,0,0,0), [__NR_inotify_init1] = RETFD,
	[__NR_preadv] = A(F,0,0,0,0,0), [__NR_pwritev] = A(F,0,0,0,0,0),
	[__NR_perf_event_open] = RETFD, [__NR_recvmmsg] = A(F,0,0,0,0,0),
	[__NR_fanotify_init] = RETFD, [__NR_fanotify_mark] = A(F,0,0,D,P,0),
	[__NR_name_to_handle_at] = A(D,P,0,0,0,0), [__NR_open_by_handle_at] = A(F,0,0,0,0,0) | RETFD,
	[__NR_syncfs] = A(F,0,0,0,0,0), [__NR_sendmmsg] = A(F,0,0,0,0,0), [__NR_setns] = A(F,0,0,0,0,0),
	[__NR_finit_module] = A(F,S,0,0,0,0), [__NR_renameat2] = A(D,P,D,P,0,0),
	[__NR_memfd_create] = A(S,0,0,0,0,0) | RETFD, [__NR_kexec_file_load] = A(F,F,0,S,0,0),
	[__NR_execveat] = A(D,P,T_ARGV,T_ARGV,0,0), [__NR_userfaultfd] = RETFD,
	[__NR_copy_file_range] = A(F,0,F,0,0,0), [__NR_preadv2] = A(F,0,0,0,0,0), [__NR_pwritev2] = A(F,0,0,0,0,0),
	[__NR_statx] = A(D,P,0,0,0,0),
	[__NR_pidfd_send_signal] = A(F,0,0,0,0,0), [__NR_open_tree] = A(D,P,0,0,0,0) | RETFD,
	[__NR_move_mount] = A(D,P,D,P,0,0), [__NR_fsopen] = A(S,0,0,0,0,0) | RETFD, [__NR_fspick] = A(D,P,0,0,0,0) | RETFD,
	[__NR_pidfd_open] = RETFD, [__NR_openat2] = A(D,P,T_HOW,0,0,0) | RETFD,
	[__NR_pidfd_getfd] = A(F,0,0,0,0,0) | RETFD, [__NR_faccessat2] = A(D,P,0,0,0,0),
	[__NR_epoll_pwait2] = A(F,0,0,0,0,0), [__NR_mount_setattr] = A(D,P,0,0,0,0),
	[__NR_fchmodat2] = A(D,P,0,0,0,0),
};
#undef P
#undef S
#undef F
#undef D
#endif
