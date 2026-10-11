typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;
typedef int __s32;
typedef long long __s64;

#define SEC(name) __attribute__((section(name), used))
#define __uint(name, value) int (*name)[value]
#define __type(name, value) value *name
#define CORE __attribute__((preserve_access_index))
#define INLINE static __attribute__((always_inline)) inline
#define READ_INTO(dst, src) bpf_probe_read_kernel((dst), sizeof(*(dst)), __builtin_preserve_access_index(src))

#define AF_INET 2
#define AF_INET6 10
#define IPPROTO_TCP 6
#define TCP_ESTABLISHED 1
#define TCP_SYN_RECV 3
#define TCP_CLOSE 7
#define MSG_PEEK 2
#define PARTIAL_START 1
#define MAX_CONNECTIONS 16384

const volatile __u16 target_port = 0;
const volatile __u32 recv_flags_arg = 3;

/* Only the named fields are needed; CO-RE resolves their kernel offsets. */
struct in6_addr {
	__u8 bytes[16];
};

struct proto {
	char name[32];
} CORE;

struct sock_common {
	__u32 skc_daddr;
	__u32 skc_rcv_saddr;
	__u16 skc_dport;
	__u16 skc_num;
	__u16 skc_family;
	struct proto *skc_prot;
	struct in6_addr skc_v6_daddr;
	struct in6_addr skc_v6_rcv_saddr;
} CORE;

struct sock {
	struct sock_common __sk_common;
	int sk_err;
} CORE;

/* x86-64 kprobe register ABI. */
struct pt_regs {
	unsigned long r15, r14, r13, r12, bp, bx, r11, r10, r9, r8;
	unsigned long ax, cx, dx, si, di, orig_ax, ip, cs, flags, sp, ss;
};

struct trace_event_raw_inet_sock_set_state {
	__u64 common;
	const void *skaddr;
	int oldstate;
	int newstate;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u16 protocol;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
} CORE;

enum event_type {
	EVENT_STATE = 1,
	EVENT_ACCEPT = 2,
	EVENT_READ = 3,
	EVENT_WRITE = 4,
	EVENT_RETRANSMIT = 5,
	EVENT_INGRESS = 6,
};

struct event {
	__u64 timestamp_ns;
	__u64 id;
	__u64 started_ns;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__s64 result;
	__u32 type;
	__u32 pid;
	__u32 tid;
	__u32 old_state;
	__u32 new_state;
	__s32 fd;
	__u16 family;
	__u16 local_port;
	__u16 remote_port;
	__u16 flags;
	__u8 local_addr[16];
	__u8 remote_addr[16];
	char comm[16];
};

_Static_assert(sizeof(struct event) == 128, "event ABI must be 128 bytes");

struct connection {
	__u64 id;
	__u64 started_ns;
	__u64 rx_bytes;
	__u64 tx_bytes;
	__u64 first_data_ns;
	__u16 family;
	__u16 local_port;
	__u16 remote_port;
	__u16 flags;
	__u8 local_addr[16];
	__u8 remote_addr[16];
};

struct io_args {
	__u64 sk;
	__u64 id;
	__u32 flags;
};

struct {
	__uint(type, 27); /* BPF_MAP_TYPE_RINGBUF */
	__uint(max_entries, 1 << 22);
} events SEC(".maps");

struct {
	__uint(type, 1); /* BPF_MAP_TYPE_HASH */
	__uint(max_entries, MAX_CONNECTIONS);
	__type(key, __u64);
	__type(value, struct connection);
} connections SEC(".maps");

struct {
	__uint(type, 1);
	__uint(max_entries, MAX_CONNECTIONS);
	__type(key, __u64);
	__type(value, struct io_args);
} read_args SEC(".maps"), write_args SEC(".maps");

struct {
	__uint(type, 2); /* BPF_MAP_TYPE_ARRAY */
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} sequence SEC(".maps");

/* 0: ring-buffer reserve failures; 1: map or pending-I/O correlation failures. */
struct {
	__uint(type, 2);
	__uint(max_entries, 2);
	__type(key, __u32);
	__type(value, __u64);
} stats SEC(".maps");

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *)2;
static long (*bpf_map_delete_elem)(void *map, const void *key) = (void *)3;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)5;
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_get_current_comm)(void *buf, __u32 size) = (void *)16;
static long (*bpf_probe_read_kernel)(void *dst, __u32 size, const void *src) = (void *)113;
static void *(*bpf_ringbuf_reserve)(void *map, __u64 size, __u64 flags) = (void *)131;
static void (*bpf_ringbuf_submit)(void *data, __u64 flags) = (void *)132;

INLINE void count_failure(__u32 index)
{
	__u64 *value = bpf_map_lookup_elem(&stats, &index);
	if (value)
		__sync_fetch_and_add(value, 1);
}

INLINE __u64 next_id(void)
{
	__u32 zero = 0;
	__u64 *value = bpf_map_lookup_elem(&sequence, &zero);
	return value ? __sync_fetch_and_add(value, 1) + 1 : 0;
}

INLINE void emit(struct connection *conn, __u32 type, __s64 result,
		 __u32 old_state, __u32 new_state, int actor)
{
	struct event *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		count_failure(0);
		return;
	}
	__builtin_memset(event, 0, sizeof(*event));
	event->timestamp_ns = bpf_ktime_get_ns();
	event->id = conn->id;
	event->started_ns = conn->started_ns;
	event->rx_bytes = conn->rx_bytes;
	event->tx_bytes = conn->tx_bytes;
	event->result = result;
	event->type = type;
	event->old_state = old_state;
	event->new_state = new_state;
	event->fd = -1;
	event->family = conn->family;
	event->local_port = conn->local_port;
	event->remote_port = conn->remote_port;
	event->flags = conn->flags;
	__builtin_memcpy(event->local_addr, conn->local_addr, 16);
	__builtin_memcpy(event->remote_addr, conn->remote_addr, 16);
	if (actor) {
		__u64 pid_tgid = bpf_get_current_pid_tgid();
		event->pid = pid_tgid >> 32;
		event->tid = (__u32)pid_tgid;
		bpf_get_current_comm(event->comm, sizeof(event->comm));
	}
	bpf_ringbuf_submit(event, 0);
}

INLINE struct connection *insert_connection(__u64 sk, struct connection *conn)
{
	conn->id = next_id();
	conn->started_ns = bpf_ktime_get_ns();
	if (bpf_map_update_elem(&connections, &sk, conn, 1) < 0) {
		/* An accept and a state transition can discover the same socket. */
		struct connection *existing = bpf_map_lookup_elem(&connections, &sk);
		if (!existing)
			count_failure(1);
		return existing;
	}
	return bpf_map_lookup_elem(&connections, &sk);
}

INLINE __s64 socket_error(__u64 sk_key)
{
	struct sock *sk = (struct sock *)sk_key;
	int error = 0;
	READ_INTO(&error, &sk->sk_err);
	return error > 0 ? -(__s64)error : 0;
}

SEC("tracepoint/sock/inet_sock_set_state")
int trace_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
	if (ctx->protocol != IPPROTO_TCP)
		return 0;
	__u64 sk = (__u64)ctx->skaddr;
	struct connection *conn = bpf_map_lookup_elem(&connections, &sk);
	if (!conn) {
		if (ctx->oldstate != TCP_SYN_RECV || ctx->newstate != TCP_ESTABLISHED)
			return 0;
		if ((ctx->family != AF_INET && ctx->family != AF_INET6) ||
		    (target_port && target_port != ctx->sport))
			return 0;
		struct connection initial = {};
		initial.family = ctx->family;
		initial.local_port = ctx->sport;
		initial.remote_port = ctx->dport;
		if (ctx->family == AF_INET) {
			__builtin_memcpy(initial.local_addr, ctx->saddr, 4);
			__builtin_memcpy(initial.remote_addr, ctx->daddr, 4);
		} else {
			__builtin_memcpy(initial.local_addr, ctx->saddr_v6, 16);
			__builtin_memcpy(initial.remote_addr, ctx->daddr_v6, 16);
		}
		conn = insert_connection(sk, &initial);
		if (!conn)
			return 0;
	}
	__s64 result = ctx->newstate == TCP_CLOSE ? socket_error(sk) : 0;
	emit(conn, EVENT_STATE, result, ctx->oldstate, ctx->newstate, 0);
	if (ctx->newstate == TCP_CLOSE)
		bpf_map_delete_elem(&connections, &sk);
	return 0;
}

/* The return value is stable across changes to inet_csk_accept arguments. */
SEC("kretprobe/inet_csk_accept")
int trace_accept(struct pt_regs *ctx)
{
	__u64 sk_key = ctx->ax;
	if (!sk_key || sk_key >= (__u64)-4095)
		return 0;
	struct connection *conn = bpf_map_lookup_elem(&connections, &sk_key);
	if (!conn) {
		struct sock *sk = (struct sock *)sk_key;
		struct connection initial = {};
		struct proto *proto = 0;
		char protocol[6] = {};
		if (READ_INTO(&proto, &sk->__sk_common.skc_prot) < 0 || !proto ||
		    bpf_probe_read_kernel(protocol, sizeof(protocol),
		    __builtin_preserve_access_index(&proto->name)) < 0)
			return 0;
		if (protocol[0] != 'T' || protocol[1] != 'C' || protocol[2] != 'P' ||
		    (protocol[3] != 0 &&
		     (protocol[3] != 'v' || protocol[4] != '6' || protocol[5] != 0)))
			return 0;
		if (READ_INTO(&initial.family, &sk->__sk_common.skc_family) < 0 ||
		    READ_INTO(&initial.local_port, &sk->__sk_common.skc_num) < 0 ||
		    READ_INTO(&initial.remote_port, &sk->__sk_common.skc_dport) < 0)
			return 0;
		if ((initial.family != AF_INET && initial.family != AF_INET6) ||
		    (target_port && initial.local_port != target_port))
			return 0;
		initial.remote_port = __builtin_bswap16(initial.remote_port);
		initial.flags = PARTIAL_START;
		if (initial.family == AF_INET) {
			if (bpf_probe_read_kernel(initial.local_addr, 4,
			    __builtin_preserve_access_index(&sk->__sk_common.skc_rcv_saddr)) < 0 ||
			    bpf_probe_read_kernel(initial.remote_addr, 4,
			    __builtin_preserve_access_index(&sk->__sk_common.skc_daddr)) < 0)
				return 0;
		} else {
			if (bpf_probe_read_kernel(initial.local_addr, 16,
			    __builtin_preserve_access_index(&sk->__sk_common.skc_v6_rcv_saddr)) < 0 ||
			    bpf_probe_read_kernel(initial.remote_addr, 16,
			    __builtin_preserve_access_index(&sk->__sk_common.skc_v6_daddr)) < 0)
				return 0;
		}
		conn = insert_connection(sk_key, &initial);
		if (!conn)
			return 0;
	}
	emit(conn, EVENT_ACCEPT, 0, 0, 0, 1);
	return 0;
}

/* tcp_data_queue runs when inbound TCP payload is queued on a socket. */
SEC("kprobe/tcp_data_queue")
int trace_data_queue(struct pt_regs *ctx)
{
	__u64 sk = ctx->di;
	struct connection *conn = bpf_map_lookup_elem(&connections, &sk);
	if (!conn)
		return 0;
	if (__sync_val_compare_and_swap(&conn->first_data_ns, 0, bpf_ktime_get_ns()) != 0)
		return 0;
	emit(conn, EVENT_INGRESS, 0, 0, 0, 0);
	return 0;
}

INLINE int io_enter(struct pt_regs *ctx, void *args_map, __u32 flags, int skip)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	/* A missed return must not be attributed to this thread's next socket. */
	if (bpf_map_lookup_elem(args_map, &pid_tgid)) {
		bpf_map_delete_elem(args_map, &pid_tgid);
		count_failure(1);
	}
	if (skip)
		return 0;
	__u64 sk = ctx->di;
	struct connection *conn = bpf_map_lookup_elem(&connections, &sk);
	if (!conn)
		return 0;
	struct io_args args = { .sk = sk, .id = conn->id, .flags = flags };
	if (bpf_map_update_elem(args_map, &pid_tgid, &args, 0) < 0)
		count_failure(1);
	return 0;
}

INLINE int io_exit(struct pt_regs *ctx, void *args_map, __u32 type)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	struct io_args *pending = bpf_map_lookup_elem(args_map, &pid_tgid);
	if (!pending)
		return 0;
	struct io_args args = *pending;
	bpf_map_delete_elem(args_map, &pid_tgid);
	struct connection *conn = bpf_map_lookup_elem(&connections, &args.sk);
	if (!conn || conn->id != args.id)
		return 0;
	/* tcp_{recv,send}msg return int; AX may contain a zero-extended errno. */
	__s64 result = (__s32)ctx->ax;
	if (result > 0) {
		if (type == EVENT_READ && !(args.flags & MSG_PEEK))
			__sync_fetch_and_add(&conn->rx_bytes, (__u64)result);
		if (type == EVENT_WRITE)
			__sync_fetch_and_add(&conn->tx_bytes, (__u64)result);
	}
	emit(conn, type, result, 0, 0, 1);
	return 0;
}

SEC("kprobe/tcp_recvmsg")
int trace_read_enter(struct pt_regs *ctx)
{
	/* A successful zero-length receive does not indicate peer EOF. */
	__u32 flags = recv_flags_arg == 4 ? (__u32)ctx->r8 : (__u32)ctx->cx;
	return io_enter(ctx, &read_args, flags, !ctx->dx);
}

SEC("kretprobe/tcp_recvmsg")
int trace_read_exit(struct pt_regs *ctx)
{
	return io_exit(ctx, &read_args, EVENT_READ);
}

SEC("kprobe/tcp_sendmsg")
int trace_write_enter(struct pt_regs *ctx)
{
	return io_enter(ctx, &write_args, 0, 0);
}

SEC("kretprobe/tcp_sendmsg")
int trace_write_exit(struct pt_regs *ctx)
{
	return io_exit(ctx, &write_args, EVENT_WRITE);
}

SEC("kprobe/tcp_retransmit_skb")
int trace_retransmit(struct pt_regs *ctx)
{
	__u64 sk = ctx->di;
	struct connection *conn = bpf_map_lookup_elem(&connections, &sk);
	if (conn)
		emit(conn, EVENT_RETRANSMIT, 0, 0, 0, 0);
	return 0;
}

/* Final destruction also reclaims entries if a close transition was missed. */
SEC("kprobe/tcp_destroy_sock")
int trace_destroy(struct pt_regs *ctx)
{
	__u64 sk = ctx->di;
	struct connection *conn = bpf_map_lookup_elem(&connections, &sk);
	if (conn) {
		emit(conn, EVENT_STATE, socket_error(sk), 0, TCP_CLOSE, 0);
		bpf_map_delete_elem(&connections, &sk);
	}
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int trace_thread_exit(void *ctx)
{
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	if (bpf_map_lookup_elem(&read_args, &pid_tgid)) {
		bpf_map_delete_elem(&read_args, &pid_tgid);
		count_failure(1);
	}
	if (bpf_map_lookup_elem(&write_args, &pid_tgid)) {
		bpf_map_delete_elem(&write_args, &pid_tgid);
		count_failure(1);
	}
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
