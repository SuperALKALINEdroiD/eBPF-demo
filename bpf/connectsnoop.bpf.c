typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

/*
 * This file is compiled with clang -target bpf. It runs in kernel context, so it
 * cannot use libc, malloc, printf, normal headers, or arbitrary pointer access.
 * The tiny typedefs and structs below are only the ABI pieces this program uses.
 *
 * Think of this C file as a small function the kernel calls every time a process
 * enters connect(2). It is not a normal userspace program: there is no main(),
 * no heap, and no direct access to the calling process memory.
 */
#define SEC(name) __attribute__((section(name), used))
#define AF_INET 2
#define AF_INET6 10

/*
 * SEC(name) puts the following function or variable into a named ELF section.
 * The Go loader searches for this exact section name and sends only that bytecode
 * to the kernel verifier. The "used" attribute prevents clang from deleting the
 * function just because nothing in this C file calls it directly.
 */

/*
 * Tracepoint programs receive a context struct defined by the tracepoint format.
 * For sys_enter_* tracepoints, args[] holds the syscall arguments.
 *
 * connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
 *   ctx->args[0] = fd
 *   ctx->args[1] = userspace pointer to sockaddr
 *   ctx->args[2] = addrlen
 *
 * The first two fields are part of the tracepoint record header. This program
 * only cares about args[], but the offsets still need to match what the kernel
 * passes to a sys_enter tracepoint program.
 */
struct trace_event_raw_sys_enter {
	__u64 unused;
	long id;
	unsigned long args[6];
};

/*
 * Minimal socket address layouts. A normal C program would include headers like
 * <sys/socket.h> and <netinet/in.h>, but this sample avoids external headers so
 * it is easy to compile with plain clang -target bpf.
 *
 * These structs must match the userspace ABI layout, because the pointer passed
 * to connect(2) points at userspace memory containing one of these layouts.
 */
struct in_addr {
	__u32 s_addr;
};

struct sockaddr_in {
	__u16 sin_family;       /* AF_INET */
	__u16 sin_port;         /* destination port, stored in network byte order */
	struct in_addr sin_addr; /* destination IPv4 address */
	unsigned char sin_zero[8];
};

struct in6_addr {
	__u8 s6_addr[16];
};

struct sockaddr_in6 {
	__u16 sin6_family; /* AF_INET6 */
	__u16 sin6_port;   /* destination port, stored in network byte order */
	__u32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	__u32 sin6_scope_id;
};

/*
 * eBPF helper calls are exposed as fixed helper IDs. libbpf normally hides this
 * boilerplate; this minimal sample declares just the helpers it needs.
 *
 * bpf_probe_read_user(dst, size, ptr) safely copies bytes from the traced
 * process. Directly doing something like user_sockaddr->sa_family would be
 * rejected by the verifier, because userspace pointers can be invalid.
 *
 * bpf_trace_printk(fmt, size, ...) writes a debugging line to trace_pipe. It is
 * useful for learning, but production tools usually send events through a ring
 * buffer or perf event array instead.
 */
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)112;
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *)6;

/*
 * Ports in sockaddr are network byte order, which is big-endian. x86_64 hosts
 * are little-endian, so a port like 443 would otherwise print as the swapped
 * value. This tiny htons/ntohs-style helper swaps the two bytes.
 */
static __u16 ntohs(__u16 value)
{
	return (value >> 8) | (value << 8);
}

/*
 * The SEC name decides where this program can attach. Userspace loads this ELF
 * section and attaches it to /sys/kernel/tracing/events/syscalls/sys_enter_connect.
 */
SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect(struct trace_event_raw_sys_enter *ctx)
{
	/*
	 * Grab the first two connect(2) arguments from the tracepoint context.
	 *
	 * fd is just an integer, so it is safe to copy directly.
	 * user_sockaddr is an address in the traced process, so it must only be
	 * read through bpf_probe_read_user().
	 */
	void *user_sockaddr = (void *)ctx->args[1];
	int fd = ctx->args[0];
	__u16 family = 0;

	/*
	 * Read only the address family first. The first two bytes of all sockaddr
	 * variants are the family, so this tells us whether the rest of the memory
	 * should be interpreted as IPv4, IPv6, Unix socket, or something else.
	 *
	 * Returning 0 means "let the syscall continue normally". eBPF tracing
	 * programs are observers here; this sample does not block or modify connect.
	 */
	if (bpf_probe_read_user(&family, sizeof(family), user_sockaddr) < 0)
		return 0;

	if (family == AF_INET) {
		/*
		 * For IPv4, copy the userspace sockaddr_in into eBPF stack memory.
		 * After this copy, reading addr.sin_port and addr.sin_addr is safe
		 * because addr is local verifier-tracked memory.
		 */
		struct sockaddr_in addr = {};
		char fmt[] = "connect fd=%d dst=%pI4:%d\n";

		/* Copy the whole IPv4 sockaddr locally before reading fields from it. */
		if (bpf_probe_read_user(&addr, sizeof(addr), user_sockaddr) < 0)
			return 0;

		/*
		 * %pI4 is a kernel printk formatter for an IPv4 address. It expects a
		 * pointer to 4 bytes, so pass the address of addr.sin_addr.s_addr.
		 */
		bpf_trace_printk(fmt, sizeof(fmt), fd, &addr.sin_addr.s_addr, ntohs(addr.sin_port));
		return 0;
	}

	if (family == AF_INET6) {
		/*
		 * IPv6 is the same idea, but the address field is 16 bytes and the
		 * printk formatter is different.
		 */
		struct sockaddr_in6 addr6 = {};
		char fmt[] = "connect fd=%d dst=[%pI6c]:%d\n";

		/* Copy the whole IPv6 sockaddr locally before reading fields from it. */
		if (bpf_probe_read_user(&addr6, sizeof(addr6), user_sockaddr) < 0)
			return 0;

		/*
		 * %pI6c prints a compressed IPv6 address, like ::1 instead of the full
		 * eight-group representation. The array name already decays to a
		 * pointer to its first byte, so no & is needed here.
		 */
		bpf_trace_printk(fmt, sizeof(fmt), fd, addr6.sin6_addr.s6_addr, ntohs(addr6.sin6_port));
		return 0;
	}

	{
		/*
		 * Other address families are still useful to see while learning. For
		 * example, AF_UNIX sockets also use connect(2), but they do not have an
		 * IP address or TCP/UDP port to print.
		 */
		char fmt[] = "connect fd=%d unsupported_family=%d\n";
		bpf_trace_printk(fmt, sizeof(fmt), fd, family);
	}
	return 0;
}

/*
 * The loader reads this ELF section and passes the license string to
 * BPF_PROG_LOAD. GPL is required for some helpers and is conventional for eBPF
 * tracing examples.
 */
char LICENSE[] SEC("license") = "GPL";
