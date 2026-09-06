typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

/*
 * This file is compiled with clang -target bpf. It runs in kernel context, so it
 * cannot use libc, malloc, printf, normal headers, or arbitrary pointer access.
 * The tiny typedefs and structs below are only the ABI pieces this program uses.
 */
#define SEC(name) __attribute__((section(name), used))
#define AF_INET 2
#define AF_INET6 10

/*
 * Tracepoint programs receive a context struct defined by the tracepoint format.
 * For sys_enter_* tracepoints, args[] holds the syscall arguments.
 *
 * connect(int fd, const struct sockaddr *addr, socklen_t addrlen)
 *   ctx->args[0] = fd
 *   ctx->args[1] = userspace pointer to sockaddr
 *   ctx->args[2] = addrlen
 */
struct trace_event_raw_sys_enter {
	__u64 unused;
	long id;
	unsigned long args[6];
};

/* Minimal socket address layouts. Avoid including kernel headers in this sample. */
struct in_addr {
	__u32 s_addr;
};

struct sockaddr_in {
	__u16 sin_family;
	__u16 sin_port;
	struct in_addr sin_addr;
	unsigned char sin_zero[8];
};

struct in6_addr {
	__u8 s6_addr[16];
};

struct sockaddr_in6 {
	__u16 sin6_family;
	__u16 sin6_port;
	__u32 sin6_flowinfo;
	struct in6_addr sin6_addr;
	__u32 sin6_scope_id;
};

/*
 * eBPF helper calls are exposed as fixed helper IDs. libbpf normally hides this
 * boilerplate; this minimal sample declares just the helpers it needs.
 */
static long (*bpf_probe_read_user)(void *dst, __u32 size, const void *unsafe_ptr) = (void *)112;
static long (*bpf_trace_printk)(const char *fmt, __u32 fmt_size, ...) = (void *)6;

/* Ports in sockaddr are network byte order, so convert them before printing. */
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
	void *user_sockaddr = (void *)ctx->args[1];
	int fd = ctx->args[0];
	__u16 family = 0;

	/*
	 * The sockaddr pointer belongs to the calling process, not the kernel.
	 * The verifier requires bpf_probe_read_user() for this memory.
	 */
	if (bpf_probe_read_user(&family, sizeof(family), user_sockaddr) < 0)
		return 0;

	if (family == AF_INET) {
		struct sockaddr_in addr = {};
		char fmt[] = "connect fd=%d dst=%pI4:%d\n";

		/* Copy the whole IPv4 sockaddr locally before reading fields from it. */
		if (bpf_probe_read_user(&addr, sizeof(addr), user_sockaddr) < 0)
			return 0;

		/* %pI4 is a kernel printk formatter for an IPv4 address. */
		bpf_trace_printk(fmt, sizeof(fmt), fd, &addr.sin_addr.s_addr, ntohs(addr.sin_port));
		return 0;
	}

	if (family == AF_INET6) {
		struct sockaddr_in6 addr6 = {};
		char fmt[] = "connect fd=%d dst=[%pI6c]:%d\n";

		/* Copy the whole IPv6 sockaddr locally before reading fields from it. */
		if (bpf_probe_read_user(&addr6, sizeof(addr6), user_sockaddr) < 0)
			return 0;

		/* %pI6c is a kernel printk formatter for a compressed IPv6 address. */
		bpf_trace_printk(fmt, sizeof(fmt), fd, addr6.sin6_addr.s6_addr, ntohs(addr6.sin6_port));
		return 0;
	}

	{
		/* Keep unknown families visible so Unix sockets or odd calls are not silent. */
		char fmt[] = "connect fd=%d unsupported_family=%d\n";
		bpf_trace_printk(fmt, sizeof(fmt), fd, family);
	}
	return 0;
}

/* GPL is required for some helpers and is conventional for eBPF examples. */
char LICENSE[] SEC("license") = "GPL";
