// collector.bpf.c: every syscall (enter + exit) plus kernel-resolved file,
// exec, fork, exit and socket objects, for tasks in the two scope cgroups.
// One record per event, written to one ring buffer; every outcome is counted.
#include "vmlinux.h"
#include <asm/unistd_64.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "collector.h"

char LICENSE[] SEC("license") = "GPL";

#define HALF (1 << 17)          /* records are built below this offset ... */
#define BUFSZ (HALF + 8192)     /* ... and a blob may reach past it by up to 8 KiB */
#define STRMAX 4096
#define MAXARGV 256
#define MAXDEPTH 64
#define AT_FDCWD -100
#define S_IFMT 0170000
#define S_IFSOCK 0140000
#define OVERLAYFS_SUPER_MAGIC 0x794c7630
#define AF_UNIX 1
#define AF_INET 2
#define AF_INET6 10
#ifndef __arg_nonnull
#define __arg_nonnull __attribute__((btf_decl_tag("arg:nonnull")))
#endif
#define AT(arg, type) ((arg) | (type) << 8)
#ifndef container_of
#define container_of(p, T, m) ((T *)((void *)(p) - bpf_core_field_offset(T, m)))
#endif

struct scratch { __u64 seq; __u32 busy; __u32 pad; __u8 buf[BUFSZ]; };

/* 1 GiB, set by the loader: as a BTF array size here it would overflow the kernel BTF check. */
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 20); } rb SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_CGROUP_ARRAY); __uint(max_entries, 2); __type(key, __u32); __type(value, __u32); } scopes SEC(".maps");
/* Plain array indexed by CPU (per-CPU maps cap values at 32 KiB); max_entries set by the loader. */
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, struct scratch); } scratch SEC(".maps");
/* Per task: bitmask of string args whose read faulted at sys_enter; sys_exit reads them again. */
struct { __uint(type, BPF_MAP_TYPE_TASK_STORAGE); __uint(map_flags, BPF_F_NO_PREALLOC); __type(key, int); __type(value, __u32); } faulted SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY); __uint(max_entries, NCOUNTERS); __type(key, __u32); __type(value, __u64); } counters SEC(".maps");

/* overlayfs is a module, so its inode type is not in vmlinux.h; CO-RE finds it in the module BTF. */
struct ovl_inode { struct inode vfs_inode; struct dentry *__upperdentry; } __attribute__((preserve_access_index));

/* A kernel pointer as a plain number, for global functions (they take scalars, not typed pointers). */
static __always_inline __u64 scalar(const void *p)
{
	__u64 v = 0;
	bpf_probe_read_kernel(&v, sizeof(v), &p);
	return v;
}

static __always_inline void cnt(__u32 i)
{
	__u64 *v = bpf_map_lookup_elem(&counters, &i);
	if (v) *v += 1;
}

const volatile __u32 self_tgid;   /* set by the loader: never record the collector itself */

/* 1 = in the focus cgroup (scopes[0]), 2 = in scopes[1] (the loader passes the cgroup root: everything else). */
static __always_inline int scope(void)
{
	if (bpf_get_current_pid_tgid() >> 32 == self_tgid) return 0;
	if (bpf_current_task_under_cgroup(&scopes, 0) == 1) return S_FOCUS;
	if (bpf_current_task_under_cgroup(&scopes, 1) == 1) return S_OTHER;
	return 0;
}

static __always_inline __u32 pidnr(struct pid *p, __u32 *ns)
{
	__u32 lvl = BPF_CORE_READ(p, level);
	struct upid up = {};
	bpf_probe_read_kernel(&up, sizeof(up), &p->numbers[lvl & 31]);
	if (ns) *ns = BPF_CORE_READ(up.ns, ns.inum);
	return up.nr;
}

/* Start a record: NULL if out of scope or the CPU's scratch is busy (counted). */
static __always_inline struct scratch *begin(__u16 kind)
{
	int sc = scope();
	if (!sc) return 0;
	cnt(C_SEEN);
	__u32 cpu = bpf_get_smp_processor_id();
	struct scratch *s = bpf_map_lookup_elem(&scratch, &cpu);
	if (!s) return 0;
	if (s->busy) { cnt(C_BUSY); return 0; }
	s->busy = 1;
	struct hdr *h = (void *)s->buf;
	struct task_struct *t = bpf_get_current_task_btf();
	__u64 pt = bpf_get_current_pid_tgid(), ug = bpf_get_current_uid_gid();
	h->kind = kind; h->scope = sc; h->pad = 0; h->cpu = cpu; h->pad2 = 0;
	h->ts = bpf_ktime_get_boot_ns();
	h->tid = (__u32)pt; h->tgid = pt >> 32;
	h->nstid = pidnr(BPF_CORE_READ(t, thread_pid), &h->pidns);
	h->nstgid = pidnr(BPF_CORE_READ(t, group_leader, thread_pid), 0);
	h->ppid = BPF_CORE_READ(t, real_parent, tgid);
	h->uid = (__u32)ug; h->gid = ug >> 32;
	h->mntns = BPF_CORE_READ(t, nsproxy, mnt_ns, ns.inum);
	h->netns = BPF_CORE_READ(t, nsproxy, net_ns, ns.inum);
	h->cgid = bpf_get_current_cgroup_id();
	h->pstart = BPF_CORE_READ(t, group_leader, start_time);
	bpf_get_current_comm(h->comm, sizeof(h->comm));
	return s;
}

static __always_inline void finish(struct scratch *s, __u32 off)
{
	struct hdr *h = (void *)s->buf;
	if (off > BUFSZ) off = BUFSZ;
	h->size = off;
	h->seq = s->seq++;   /* assigned even if output fails, so a failure is also a gap */
	if (bpf_ringbuf_output(&rb, s->buf, off, BPF_RB_NO_WAKEUP) == 0) cnt(C_OK);
	else cnt(C_FAIL);
	s->busy = 0;
}

/* Open a blob at off; the caller writes up to STRMAX bytes after it. */
static __always_inline struct blob *blob(struct scratch *s, __u32 off, __u8 arg, __u8 type)
{
	if (off >= HALF - STRMAX - 64) { cnt(C_TRUNC); return 0; }
	struct blob *b = (void *)&s->buf[off & (HALF - 1)];
	b->arg = arg; b->type = type; b->flags = 0; b->len = 0;
	return b;
}

static __always_inline __u32 close_blob(struct blob *b, __u32 off, long n)
{
	if (n < 0) { b->flags |= F_FAULT; cnt(C_FAULT); n = 0; }
	if (n > STRMAX) n = STRMAX;
	b->len = n;
	return (off + sizeof(*b) + n + 7) & ~7;
}

/* The put_* helpers are global functions: the verifier checks each once and treats
 * the returned offset as opaque, which keeps verification linear. Pointers to kernel
 * or user memory are passed as __u64. Each returns the offset after its blob. */

__noinline __u32 put_ustr(struct scratch *s __arg_nonnull, __u32 off, __u32 at, __u64 p)
{
	struct blob *b = blob(s, off, at & 0xff, at >> 8);
	if (!b) return off;
	long n = bpf_probe_read_user_str(b + 1, STRMAX, (void *)p);
	if (n == STRMAX) { b->flags |= F_TRUNC; cnt(C_TRUNC); }
	return close_blob(b, off, n);
}

__noinline __u32 put_kstr(struct scratch *s __arg_nonnull, __u32 off, __u32 at, __u64 p)
{
	struct blob *b = blob(s, off, at & 0xff, at >> 8);
	if (!b) return off;
	return close_blob(b, off, bpf_probe_read_kernel_str(b + 1, STRMAX, (void *)p));
}

__noinline __u32 put_ubytes(struct scratch *s __arg_nonnull, __u32 off, __u32 at, __u64 p, __u64 len)
{
	struct blob *b = blob(s, off, at & 0xff, at >> 8);
	if (!b) return off;
	if (len > STRMAX) { b->flags |= F_TRUNC; cnt(C_TRUNC); len = STRMAX; }
	asm volatile("%0 &= 8191" : "+r"(len));   /* no-op the compiler cannot drop: a bound the verifier keeps */
	return close_blob(b, off, bpf_probe_read_user(b + 1, len, (void *)p) ? -1 : len);
}

__noinline __u32 put_kbytes(struct scratch *s __arg_nonnull, __u32 off, __u32 at, __u64 p, __u64 len)
{
	struct blob *b = blob(s, off, at & 0xff, at >> 8);
	if (!b) return off;
	if (len > 128) len = 128;
	asm volatile("%0 &= 255" : "+r"(len));
	return close_blob(b, off, bpf_probe_read_kernel(b + 1, len, (void *)p) ? -1 : len);
}

/* User memory range in STRMAX chunks (one B_MEM blob each), up to 8 chunks. */
__noinline __u32 put_umem(struct scratch *s __arg_nonnull, __u32 off, __u32 arg, __u64 p, __u64 end)
{
	for (int i = 0; i < 8 && p < end; i++) {
		__u64 n = end - p;
		if (n > STRMAX) n = STRMAX;
		off = put_ubytes(s, off, AT(arg, B_MEM), p, n);
		p += n;
	}
	if (p < end) cnt(C_TRUNC);
	return off;
}

/* Directory path: walk dentries up to the task's root, crossing mounts. One
 * walk_step per dentry, as a global function so the loop verifies linearly. Components are written leaf first, NUL separated; decode.py reverses. */
struct walk { __u64 d, vm, rootd, rootm; __u32 base, len, flags, pad; };

__noinline long walk_step(struct scratch *s __arg_nonnull, struct walk *w __arg_nonnull)
{
	struct dentry *d = (void *)w->d;
	struct vfsmount *vm = (void *)w->vm;
	if (w->d == w->rootd && w->vm == w->rootm) return 1;
	struct dentry *parent = BPF_CORE_READ(d, d_parent);
	if (d == BPF_CORE_READ(vm, mnt_root) || d == parent) {
		struct mount *m = container_of(vm, struct mount, mnt);
		struct mount *mp = BPF_CORE_READ(m, mnt_parent);
		if (mp == m) return 1;
		w->d = (__u64)BPF_CORE_READ(m, mnt_mountpoint);
		w->vm = (__u64)&mp->mnt;
		return 0;
	}
	if (w->len > STRMAX - 256) { w->flags |= F_TRUNC; return 1; }
	long n = bpf_probe_read_kernel_str(&s->buf[(w->base + w->len) & (HALF - 1)], 256, BPF_CORE_READ(d, d_name.name));
	if (n <= 0) return 1;
	w->len += n;
	w->d = (__u64)parent;
	return 0;
}

__noinline __u32 put_walk(struct scratch *s __arg_nonnull, __u32 off, __u32 arg, __u64 d, __u64 vm)
{
	struct blob *b = blob(s, off, arg, B_BASE);
	if (!b) return off;
	struct task_struct *t = (void *)bpf_get_current_task();
	struct walk w = { .d = d, .vm = vm, .base = (off & (HALF - 1)) + sizeof(*b),
			  .rootd = (__u64)BPF_CORE_READ(t, fs, root.dentry), .rootm = (__u64)BPF_CORE_READ(t, fs, root.mnt) };
	for (int i = 0; i < MAXDEPTH; i++)
		if (walk_step(s, &w)) break;
	if (w.flags) { b->flags |= F_TRUNC; cnt(C_TRUNC); }
	return close_blob(b, off, w.len);
}

static __always_inline void ident_sk(struct ident *id, struct sock *sk)
{
	id->family = BPF_CORE_READ(sk, __sk_common.skc_family);
	id->stype = BPF_CORE_READ(sk, sk_type);
	id->lport = BPF_CORE_READ(sk, __sk_common.skc_num);
	id->rport = __builtin_bswap16(BPF_CORE_READ(sk, __sk_common.skc_dport));
	/* BPF_CORE_READ_INTO copies sizeof(*dst): cast, or a __u8[] dst gets only 1 byte */
	if (id->family == AF_INET) {
		BPF_CORE_READ_INTO((__be32 *)id->laddr, sk, __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO((__be32 *)id->raddr, sk, __sk_common.skc_daddr);
	} else if (id->family == AF_INET6) {
		BPF_CORE_READ_INTO((struct in6_addr *)id->laddr, sk, __sk_common.skc_v6_rcv_saddr);
		BPF_CORE_READ_INTO((struct in6_addr *)id->raddr, sk, __sk_common.skc_v6_daddr);
	} else if (id->family == AF_UNIX) {
		struct sock *peer = BPF_CORE_READ((struct unix_sock *)sk, peer);
		__u64 pino = peer ? BPF_CORE_READ(peer, sk_socket, file, f_inode, i_ino) : 0;
		__builtin_memcpy(id->raddr, &pino, 8);
	}
}

__noinline __u32 put_ident(struct scratch *s __arg_nonnull, __u32 off, __u32 arg, __u64 inop, __u64 sockp)
{
	struct blob *b = blob(s, off, arg, B_IDENT);
	if (!b) return off;
	struct inode *ino = (void *)inop;
	struct ident *id = (void *)(b + 1);
	__builtin_memset(id, 0, sizeof(*id));
	if (ino) {
		struct super_block *sb = BPF_CORE_READ(ino, i_sb);
		id->ino = BPF_CORE_READ(ino, i_ino);
		id->dev = BPF_CORE_READ(sb, s_dev);
		id->magic = BPF_CORE_READ(sb, s_magic);
		id->gen = BPF_CORE_READ(ino, i_generation);
		id->mode = BPF_CORE_READ(ino, i_mode);
		id->nlink = BPF_CORE_READ(ino, __i_nlink);
		if (id->magic == OVERLAYFS_SUPER_MAGIC) {
			struct ovl_inode *oi = (void *)ino - bpf_core_field_offset(struct ovl_inode, vfs_inode);
			struct dentry *up = BPF_CORE_READ(oi, __upperdentry);
			id->ovl = up ? 1 : 2;
			if (up) {
				id->real_ino = BPF_CORE_READ(up, d_inode, i_ino);
				id->real_dev = BPF_CORE_READ(up, d_sb, s_dev);
			}
		}
	}
	if (sockp) ident_sk(id, BPF_CORE_READ((struct socket *)sockp, sk));
	return close_blob(b, off, sizeof(*id));
}

__noinline __u32 put_file(struct scratch *s __arg_nonnull, __u32 off, __u32 arg, __u64 fp)
{
	struct file *f = (void *)fp;
	struct inode *ino = BPF_CORE_READ(f, f_inode);
	__u32 mode = BPF_CORE_READ(ino, i_mode);
	__u64 sock = (mode & S_IFMT) == S_IFSOCK ? (__u64)BPF_CORE_READ(f, private_data) : 0;
	return put_ident(s, off, arg, (__u64)ino, sock);
}

static __always_inline __u64 fd_file(long fd)
{
	struct task_struct *t = (void *)bpf_get_current_task();
	struct fdtable *fdt = BPF_CORE_READ(t, files, fdt);
	struct file **fds = BPF_CORE_READ(fdt, fd);
	struct file *f = 0;
	if (fd < 0 || fd >= BPF_CORE_READ(fdt, max_fds)) return 0;
	bpf_probe_read_kernel(&f, sizeof(f), &fds[fd]);
	return (__u64)f;
}

__noinline __u32 put_fd(struct scratch *s __arg_nonnull, __u32 off, __u32 arg, long fd)
{
	__u64 f = fd_file(fd);
	return f ? put_file(s, off, arg, f) : off;
}

/* Base directory for a relative path argument: the dirfd before it, or cwd. */
__noinline __u32 put_base(struct scratch *s __arg_nonnull, __u32 off, __u32 arg, long dirfd)
{
	struct task_struct *t = (void *)bpf_get_current_task();
	if (dirfd == AT_FDCWD)
		return put_walk(s, off, arg, (__u64)BPF_CORE_READ(t, fs, pwd.dentry), (__u64)BPF_CORE_READ(t, fs, pwd.mnt));
	struct file *f = (void *)fd_file(dirfd);
	if (!f) return off;
	return put_walk(s, off, arg, (__u64)BPF_CORE_READ(f, f_path.dentry), (__u64)BPF_CORE_READ(f, f_path.mnt));
}

__noinline __u32 put_argv(struct scratch *s __arg_nonnull, __u32 off, __u32 arg, __u64 argv)
{
	if (!argv) return off;
	for (int i = 0; i < MAXARGV; i++) {
		__u64 p = 0;
		if (bpf_probe_read_user(&p, sizeof(p), (void *)(argv + 8 * i)) || !p) return off;
		off = put_ustr(s, off, AT(arg, B_ARGV), p);
	}
	cnt(C_TRUNC);
	return off;
}

__noinline __u32 put_saddr_out(struct scratch *s __arg_nonnull, __u32 off, __u32 arg, __u64 addr, __u64 lenp)
{
	int len = 0;
	if (!addr || !lenp || bpf_probe_read_user(&len, sizeof(len), (void *)lenp)) return off;
	return put_ubytes(s, off, AT(arg, B_SADDR), addr, len > 128 ? 128 : len < 0 ? 0 : len);
}

__noinline __u32 put_msg(struct scratch *s __arg_nonnull, __u32 off, __u32 arg, __u64 m)
{
	struct user_msghdr um = {};
	if (!m || bpf_probe_read_user(&um, sizeof(um), (void *)m) || !um.msg_name) return off;
	return put_ubytes(s, off, AT(arg, B_SADDR), (__u64)um.msg_name, um.msg_namelen > 128 ? 128 : um.msg_namelen);
}

SEC("tp_btf/sys_enter")
int BPF_PROG(sys_enter, struct pt_regs *regs, long nr)
{
	__u32 off;
	struct scratch *s = begin(R_ENTER);
	if (!s) return 0;
	struct enter *e = (void *)s->buf;
	e->nr = nr;
	e->args[0] = BPF_CORE_READ(regs, di); e->args[1] = BPF_CORE_READ(regs, si);
	e->args[2] = BPF_CORE_READ(regs, dx); e->args[3] = BPF_CORE_READ(regs, r10);
	e->args[4] = BPF_CORE_READ(regs, r8); e->args[5] = BPF_CORE_READ(regs, r9);
	off = sizeof(*e);
	__u64 tab = nr >= 0 && nr < NSYS ? argtab[nr] : 0;
	__u32 mask = 0;
	for (int i = 0; i < 6; i++) {
		__u64 a = e->args[i];
		switch ((tab >> (4 * i)) & 15) {
		case T_PATH: {
			char c = 0;
			__u32 at = off;
			off = put_ustr(s, off, AT(i, B_STR), a);
			if (((struct blob *)&s->buf[at & (HALF - 1)])->flags & F_FAULT) mask |= 1 << i;
			bpf_probe_read_user(&c, 1, (void *)a);
			if (c != '/') {
				long dfd = i > 0 && ((tab >> (4 * (i - 1))) & 15) == T_DIRFD ? (int)e->args[(i - 1) % 6] : AT_FDCWD;
				off = put_base(s, off, i, dfd);
			}
			break;
		}
		case T_STR: {
			__u32 at = off;
			off = put_ustr(s, off, AT(i, B_STR), a);
			if (((struct blob *)&s->buf[at & (HALF - 1)])->flags & F_FAULT) mask |= 1 << i;
			break;
		}
		case T_FD: off = put_fd(s, off, i, (int)a); break;
		case T_DIRFD: if ((int)a != AT_FDCWD) off = put_fd(s, off, i, (int)a); break;
		case T_SADDR: off = put_ubytes(s, off, AT(i, B_SADDR), a, i < 5 && e->args[(i + 1) % 6] < 128 ? e->args[(i + 1) % 6] : 128); break;
		case T_MSG: off = put_msg(s, off, i, a); break;
		case T_HOW: off = put_ubytes(s, off, AT(i, B_BYTES), a, i < 5 && e->args[(i + 1) % 6] < 64 ? e->args[(i + 1) % 6] : 64); break;
		case T_ARGV: off = put_argv(s, off, i, a); break;
		}
	}
	if (mask) {
		__u32 *m = bpf_task_storage_get(&faulted, bpf_get_current_task_btf(), 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
		if (m) *m = mask;
	}
	finish(s, off);
	return 0;
}

SEC("tp_btf/sys_exit")
int BPF_PROG(sys_exit, struct pt_regs *regs, long ret)
{
	__u32 off;
	struct scratch *s = begin(R_EXIT);
	if (!s) return 0;
	struct exit *x = (void *)s->buf;
	long nr = BPF_CORE_READ(regs, orig_ax);
	x->nr = nr; x->ret = ret;
	off = sizeof(*x);
	__u64 tab = nr >= 0 && nr < NSYS ? argtab[nr] : 0;
	/* x86-64 keeps the argument registers intact across the syscall. */
	__u64 args[6] = { BPF_CORE_READ(regs, di), BPF_CORE_READ(regs, si), BPF_CORE_READ(regs, dx),
			  BPF_CORE_READ(regs, r10), BPF_CORE_READ(regs, r8), BPF_CORE_READ(regs, r9) };
	if (ret >= 0) {
		for (int i = 0; i < 6; i++) {
			__u64 a = args[i % 6];
			switch ((tab >> (24 + 4 * i)) & 15) {
			case T_SADDRO: off = put_saddr_out(s, off, i, a, i < 5 ? args[(i + 1) % 6] : 0); break;
			case T_MSGO: off = put_msg(s, off, i, a); break;
			case T_FD2O: off = put_ubytes(s, off, AT(i, B_BYTES), a, 8); break;
			}
		}
		if (tab & RETFD) off = put_fd(s, off, ARG_RET, ret);
	}
	/* Strings that faulted at entry: the kernel has paged them in by now (not after a successful exec: new memory). */
	__u32 *m = bpf_task_storage_get(&faulted, bpf_get_current_task_btf(), 0, 0);
	if (m && *m) {
		if (!((nr == __NR_execve || nr == __NR_execveat) && ret == 0)) {
			for (int i = 0; i < 6; i++) {
				if (!(*m & (1 << i))) continue;
				__u32 at = off;
				off = put_ustr(s, off, AT(i, B_STR), args[i]);
				if (!(((struct blob *)&s->buf[at & (HALF - 1)])->flags & F_FAULT)) cnt(C_REFETCHED);
			}
		}
		*m = 0;
	}
	finish(s, off);
	return 0;
}

/* ---- kernel objects (BPF-LSM: observe only, always allow) ---- */

static __always_inline __u32 put_obj(struct scratch *s, __u32 off, __u8 i, const struct path *dir, struct dentry *d)
{
	/* bpf_d_path is not allowed in every path_* hook, so walk the directory instead. */
	if (dir) off = put_walk(s, off, i, (__u64)BPF_CORE_READ(dir, dentry), (__u64)BPF_CORE_READ(dir, mnt));
	if (d) {
		off = put_kstr(s, off, AT(i, B_NAME), (__u64)BPF_CORE_READ(d, d_name.name));
		struct inode *ino = BPF_CORE_READ(d, d_inode);
		if (ino) off = put_ident(s, off, i, (__u64)ino, 0);
	}
	return off;
}

static __always_inline int file_rec(__u32 op, __u32 a, __u64 b, const struct path *p0, struct dentry *d0,
				    const struct path *p1, struct dentry *d1, int two)
{
	__u32 off;
	struct scratch *s = begin(R_FILE);
	if (!s) return 0;
	struct file_rec *r = (void *)s->buf;
	r->op = op; r->a = a; r->b = b;
	off = put_obj(s, sizeof(*r), 0, p0, d0);
	if (two) off = put_obj(s, off, 1, p1, d1);
	finish(s, off);
	return 0;
}

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *f)
{
	__u32 off;
	struct scratch *s = begin(R_FILE);
	if (!s) return 0;
	struct file_rec *r = (void *)s->buf;
	r->op = O_OPEN; r->a = f->f_flags; r->b = f->f_mode;
	off = sizeof(*r);
	struct blob *b = blob(s, off, 0, B_KPATH);
	if (b) off = close_blob(b, off, bpf_d_path(&f->f_path, (char *)(b + 1), STRMAX));
	off = put_file(s, off, 0, scalar(f));
	finish(s, off);
	return 0;
}

SEC("lsm/mmap_file")
int BPF_PROG(mmap_file, struct file *f, unsigned long reqprot, unsigned long prot, unsigned long flags)
{
	if (!f) return 0;
	__u32 off;
	struct scratch *s = begin(R_FILE);
	if (!s) return 0;
	struct file_rec *r = (void *)s->buf;
	r->op = O_MMAP; r->a = prot; r->b = flags;
	off = sizeof(*r);
	struct blob *b = blob(s, off, 0, B_KPATH);
	if (b) off = close_blob(b, off, bpf_d_path(&f->f_path, (char *)(b + 1), STRMAX));
	off = put_file(s, off, 0, scalar(f));
	finish(s, off);
	return 0;
}

SEC("lsm/path_unlink") int BPF_PROG(path_unlink, const struct path *dir, struct dentry *d) { return file_rec(O_UNLINK, 0, 0, dir, d, 0, 0, 0); }
SEC("lsm/path_rmdir") int BPF_PROG(path_rmdir, const struct path *dir, struct dentry *d) { return file_rec(O_RMDIR, 0, 0, dir, d, 0, 0, 0); }
SEC("lsm/path_mkdir") int BPF_PROG(path_mkdir, const struct path *dir, struct dentry *d, umode_t mode) { return file_rec(O_MKDIR, mode, 0, dir, d, 0, 0, 0); }
SEC("lsm/path_mknod") int BPF_PROG(path_mknod, const struct path *dir, struct dentry *d, umode_t mode, unsigned int dev) { return file_rec(O_MKNOD, mode, dev, dir, d, 0, 0, 0); }
SEC("lsm/path_symlink") int BPF_PROG(path_symlink, const struct path *dir, struct dentry *d, const char *old) { return file_rec(O_SYMLINK, 0, 0, dir, d, 0, 0, 0); }
SEC("lsm/path_link") int BPF_PROG(path_link, struct dentry *old, const struct path *dir, struct dentry *d) { return file_rec(O_LINK, 0, 0, 0, old, dir, d, 1); }
SEC("lsm/path_rename") int BPF_PROG(path_rename, const struct path *odir, struct dentry *od, const struct path *ndir, struct dentry *nd, unsigned int flags) { return file_rec(O_RENAME, flags, 0, odir, od, ndir, nd, 1); }
SEC("lsm/path_truncate") int BPF_PROG(path_truncate, const struct path *p) { return file_rec(O_TRUNCATE, 0, 0, p, BPF_CORE_READ(p, dentry), 0, 0, 0); }
SEC("lsm/path_chmod") int BPF_PROG(path_chmod, const struct path *p, umode_t mode) { return file_rec(O_CHMOD, mode, 0, p, BPF_CORE_READ(p, dentry), 0, 0, 0); }
SEC("lsm/path_chown") int BPF_PROG(path_chown, const struct path *p, __u64 uid, __u64 gid) { return file_rec(O_CHOWN, (__u32)uid, (__u32)gid, p, BPF_CORE_READ(p, dentry), 0, 0, 0); }

static __always_inline int sock_rec(__u32 op, struct socket *sock, struct sockaddr *addr, int len)
{
	__u32 off;
	struct scratch *s = begin(R_SOCK);
	if (!s) return 0;
	struct sock_rec *r = (void *)s->buf;
	r->op = op; r->pad = 0;
	off = put_ident(s, sizeof(*r), 0, (__u64)BPF_CORE_READ(sock, file, f_inode), scalar(sock));
	off = put_kbytes(s, off, AT(0, B_SADDR), scalar(addr), len < 0 ? 0 : len);
	finish(s, off);
	return 0;
}
SEC("lsm/socket_connect") int BPF_PROG(socket_connect, struct socket *sock, struct sockaddr *a, int len) { return sock_rec(K_CONNECT, sock, a, len); }
SEC("lsm/socket_bind") int BPF_PROG(socket_bind, struct socket *sock, struct sockaddr *a, int len) { return sock_rec(K_BIND, sock, a, len); }

/* ---- process lineage ---- */

SEC("tp_btf/sched_process_fork")
int BPF_PROG(sched_fork, struct task_struct *parent, struct task_struct *child)
{
	__u32 off;
	struct scratch *s = begin(R_FORK);
	if (!s) return 0;
	struct fork_rec *r = (void *)s->buf;
	r->tid = child->pid; r->tgid = child->tgid;
	r->nstid = pidnr(BPF_CORE_READ(child, thread_pid), 0);
	r->nstgid = pidnr(BPF_CORE_READ(child, group_leader, thread_pid), 0);
	r->start = child->start_time;
	finish(s, sizeof(*r));
	return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(sched_exec, struct task_struct *p, pid_t old_pid, struct linux_binprm *bprm)
{
	__u32 off;
	struct scratch *s = begin(R_EXEC);
	if (!s) return 0;
	struct exec_rec *r = (void *)s->buf;
	r->old_pid = old_pid; r->pad = 0;
	off = put_kstr(s, sizeof(*r), AT(0, B_STR), scalar(bprm->filename));
	off = put_kstr(s, off, AT(1, B_STR), scalar(bprm->interp));
	off = put_file(s, off, 0, scalar(bprm->file));
	struct mm_struct *mm = BPF_CORE_READ(p, mm);
	__u64 as = BPF_CORE_READ(mm, arg_start), ae = BPF_CORE_READ(mm, arg_end);
	__u64 es = BPF_CORE_READ(mm, env_start), ee = BPF_CORE_READ(mm, env_end);
	off = put_umem(s, off, 2, as, ae);
	off = put_umem(s, off, 3, es, ee);
	finish(s, off);
	return 0;
}

SEC("tp_btf/sched_process_exit")
int BPF_PROG(sched_exit, struct task_struct *p)
{
	__u32 off;
	struct scratch *s = begin(R_PEXIT);
	if (!s) return 0;
	struct pexit_rec *r = (void *)s->buf;
	r->code = p->exit_code;
	r->live = BPF_CORE_READ(p, signal, live.counter);
	finish(s, sizeof(*r));
	return 0;
}
