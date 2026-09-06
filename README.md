# eBPF Connect Snoop Starter

Small starter project with:

- kernel-space eBPF code in C
- userspace loader/reader in Go
- a tracepoint hook for `sys_enter_connect`
- IPv4/IPv6 destination logging
- no third-party Go packages

The Go program is intentionally minimal. It loads one no-map/no-relocation eBPF
ELF section with the raw `bpf(2)` syscall, attaches it to a tracepoint with
`perf_event_open(2)`, then tails `trace_pipe`.

## Prerequisites

Install a recent Linux kernel with eBPF tracepoint support plus:

```sh
sudo apt-get install -y clang llvm make
```

You also need Go 1.22+. This sample currently hard-codes the Linux amd64
`bpf(2)` syscall number to avoid importing `golang.org/x/sys/unix`.

## Build And Run

Build the eBPF object and userspace binary:

```sh
make build
```

Run it as root:

```sh
sudo ./bin/connectsnoop
```

In another shell, start a network connection:

```sh
curl https://example.com
```

You should see connection attempts printed by the Go program. The kernel
`trace_pipe` prefix includes the process name and PID, and the eBPF message adds
the socket fd plus destination IP and port.

This starter uses `bpf_trace_printk`, which is useful for learning but not for
production telemetry. Once the flow is clear, replace it with a ring buffer or
perf event array.

If `/sys/kernel/tracing` is not mounted, mount tracefs first:

```sh
sudo mount -t tracefs tracefs /sys/kernel/tracing
```

## Layout

```text
bpf/connectsnoop.bpf.c      eBPF C program loaded into the kernel
cmd/connectsnoop/main.go    minimal Go loader, attach logic, and trace_pipe reader
```
