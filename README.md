# Connectsnoop

Trace incoming TCP connections to a local port and follow their kernel/process
lifecycle. Each connection gets an ID shared by its state changes, accept,
reads, writes, retransmission attempts, and close summary.

The original outbound `connect(2)` attempt logger remains available with
`--mode outbound`.

## Build

Inbound tracing requires Linux amd64, kernel 5.12+ with BTF, tracepoints and
kprobes enabled, Clang with the BPF target, and Go 1.22+. Root or equivalent BPF
and performance-monitoring privileges are required to capture live events.
Kernel lockdown policies may restrict probes even for root.

On Debian/Ubuntu, install the compiler tools with:

```sh
sudo apt-get install -y clang llvm make
make build
```

The Go build downloads the pinned
[cilium/ebpf](https://github.com/cilium/ebpf/tree/v0.17.3) loader dependency.
The C programs use small local ABI definitions; no libbpf headers or generated
`vmlinux.h` are required. CO-RE relocations resolve socket fields using the
running kernel's `/sys/kernel/btf/vmlinux`. The loader checks the kernel's
`tcp_recvmsg` signature to locate its flags argument.

## Trace A Port

Start a local server in one terminal:

```sh
python3 -m http.server 8080 --bind 127.0.0.1
```

## Go HTTP Timing Demo

The bundled Go server gives the tracer a small, observable HTTP target. It
prints JSON Lines for the accepted connection and each completed request, with
monotonic timestamps for handler start, first response write, and handler
completion. The demo closes each connection after one request so the app log
and eBPF timeline can be paired by local and remote endpoint.

Start the server in one terminal:

```sh
./bin/httpserver --addr 127.0.0.1:8080
```

Start the kernel tracer in another terminal and make a request in a third:

```sh
sudo ./bin/connectsnoop --port 8080 --format json
curl --http1.1 -H 'Connection: close' http://127.0.0.1:8080/
```

The kernel timeline reports the first inbound TCP payload queued on the
connection, the successful server accept, and the first completed
`tcp_sendmsg` (the response bytes being accepted by the TCP stack). The app
timeline reports handler entry, response write, and handler completion. Kernel
event timestamps use `bpf_ktime_get_ns`; the demo
uses `CLOCK_MONOTONIC`, so both clocks share a monotonic time base on Linux.
`first_data_after_ns` and `first_write_after_ns` in a connection summary are
elapsed from the observed TCP handshake completion. The first inbound payload
is a connection-level arrival marker, not an HTTP parser timestamp; TLS,
keep-alive, and multiple requests per connection need additional correlation.

Start the tracer in another terminal, then send traffic from a third:

```sh
sudo ./bin/connectsnoop --port 8080
```

```sh
curl http://127.0.0.1:8080/
```

The timeline reports:

- Local and remote IPv4/IPv6 endpoints and a connection ID unique within the capture.
- The observed passive TCP handshake completion and later TCP state changes.
- The process name, PID, and thread ID at kernel accept and each read/write.
- Successful read/write byte totals, EOF, errno values, and socket errors at close.
- Retransmission attempts when the optional retransmit probe is available.
- A close summary, including the accepting process, observed duration, and totals.

Network-state callbacks have no attributed process because they can execute in
interrupt context. An I/O event's actor can differ from the accepting process.
An accept means `inet_csk_accept` returned a socket; it does not guarantee that
the enclosing syscall subsequently published an FD. FDs are currently unknown.

Stop with `Ctrl-C`, or set a capture duration:

```sh
sudo ./bin/connectsnoop --port 8080 --duration 30s
sudo ./bin/connectsnoop --port 8080 --duration 30s --format json > capture.jsonl
```

JSON output is newline-delimited JSON only. Startup notices and diagnostics go
to stderr. Records have `kind` values `event`, `connection_summary`, or
`capture_summary`. Filter one connection with:

```sh
jq 'select(.connection_id == "0000000000000001")' capture.jsonl
jq 'select(.kind == "connection_summary")' capture.jsonl
```

JSON summaries also expose `accepted_after_ns`, `first_data_after_ns`,
`first_read_after_ns`, and `first_write_after_ns`. These measure elapsed time
from the first observed connection state, not network round-trip or application
handler duration.
`timestamp_ns` is kernel monotonic time, not a Unix timestamp.

## Options

| Option | Meaning |
| --- | --- |
| `--mode inbound` | Incoming TCP lifecycle; the default. |
| `--mode outbound` | Original destination logging at `sys_enter_connect`. |
| `--port N` | Local server port for inbound; destination port for outbound. Zero means all. |
| `--format text\|json` | Inbound timeline format. Outbound supports text. |
| `--duration 30s` | Stop and summarize after the duration; zero waits for a signal. |
| `--max-connections 16384` | Maximum active connections in kernel/userspace state. |
| `--obj path.o` | Override the mode's default BPF object. A positional path also works. |

Inbound filtering occurs in the kernel. State is bounded; map capacity failures
and ring-buffer losses are counted in the final capture summary. Userspace
evictions emit an incomplete connection summary. Shutdown detaches producers,
drains queued records, and summarizes still-open connections as incomplete.

## Observation Limits

This is a host TCP lifecycle trace, not distributed application tracing.
HTTP keep-alive/multiplexing, TLS contents, application functions, and downstream
request relationships require additional application instrumentation.

Capture starts at the passive `SYN_RECV -> ESTABLISHED` transition. Raw SYNs,
handshake failures, firewall drops, and connections refused before a server
socket exists are outside these hooks. A connection first seen at accept is
marked `partial_start`; already accepted sockets at startup are not discovered.
TCP Fast Open may also produce partial starts.

Byte totals cover completed `tcp_recvmsg` and `tcp_sendmsg` calls. They exclude
peeked reads and zero-length read calls, and do not cover every zero-copy,
splice/sendfile, kernel TLS, or io_uring path. Writes mean bytes accepted by the
TCP stack, not proof of peer delivery. Reads/errors after the TCP socket reaches
`CLOSE` may not be observed. State errors reflect `sk_err` when available, not a
guaranteed diagnosis of every reset or close cause.

Ring-buffer ordering follows record reservation; concurrent calls may finish
out of timestamp order. Totals use the maximum observed cumulative counters.
Late records after a summary are labeled and make the final capture incomplete;
they cannot revise an already emitted summary. Summarized IDs are retained in a
bounded history, so extremely delayed events can appear as partial connections.
Final loss counters apply to the whole capture, including earlier summaries.
Kernel kretprobe capacity limits can also miss callbacks; stale pending calls
are counted when detected, but not every probe miss can be detected.

## Outbound Mode

```sh
sudo ./bin/connectsnoop --mode outbound --port 443
curl https://example.com
```

This retains the original process/destination summary and `bpf_trace_printk`
reader. It logs attempts, not successful connections. Its port filter runs in
Go, and reading the shared `trace_pipe` consumes tracing output. Inbound mode
uses its own ring buffer instead. If tracefs is not mounted:

```sh
sudo mount -t tracefs tracefs /sys/kernel/tracing
```

## Verification

```sh
make test
make test-integration
```

`make test` compiles both BPF programs and runs unprivileged unit tests. The
opt-in integration suite requires root and a compatible kernel, attaches the
real tracer, and checks loopback traffic and shutdown. Once opted in, attachment
failures fail the suite rather than silently skipping live verification.

See [LIFECYCLE.md](LIFECYCLE.md) for the capture flow and source layout.
