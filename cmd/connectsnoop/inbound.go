package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"example.com/ebpf-starter/internal/lifecycle"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type lifecycleHook struct {
	program, kind, target string
	optional              bool
}

var lifecycleHooks = []lifecycleHook{
	{"trace_state", "tracepoint", "sock/inet_sock_set_state", false},
	{"trace_accept", "kretprobe", "inet_csk_accept", false},
	{"trace_data_queue", "kprobe", "tcp_data_queue", true},
	{"trace_read_exit", "kretprobe", "tcp_recvmsg", false},
	{"trace_read_enter", "kprobe", "tcp_recvmsg", false},
	{"trace_write_exit", "kretprobe", "tcp_sendmsg", false},
	{"trace_write_enter", "kprobe", "tcp_sendmsg", false},
	{"trace_thread_exit", "tracepoint", "sched/sched_process_exit", false},
	{"trace_retransmit", "kprobe", "tcp_retransmit_skb", true},
	{"trace_destroy", "kprobe", "tcp_destroy_sock", true},
}

func runInbound(ctx context.Context, opts options, output, diagnostics io.Writer) error {
	tracker, err := lifecycle.NewTracker(output, opts.format, opts.maxConnections)
	if err != nil {
		return err
	}
	spec, err := ebpf.LoadCollectionSpec(opts.objPath)
	if err != nil {
		return fmt.Errorf("read lifecycle object (run make build first): %w", err)
	}
	if err := configureLifecycleSpec(spec, opts); err != nil {
		return err
	}
	if err := configureKernelABI(spec); err != nil {
		return err
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("prepare eBPF memory limit (run as root): %w", err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return fmt.Errorf("load lifecycle eBPF (requires root, kernel BTF and Linux 5.12+): %+v", err)
	}
	defer collection.Close()
	reader, err := ringbuf.NewReader(collection.Maps["events"])
	if err != nil {
		return fmt.Errorf("open lifecycle ring buffer: %w", err)
	}
	defer reader.Close()
	var links []link.Link
	var detachOnce sync.Once
	detach := func() {
		detachOnce.Do(func() {
			for i := len(links) - 1; i >= 0; i-- {
				if err := links[i].Close(); err != nil {
					fmt.Fprintf(diagnostics, "detach lifecycle hook: %v\n", err)
				}
			}
		})
	}
	defer detach()
	for _, hook := range lifecycleHooks {
		attached, err := attachLifecycleHook(hook, collection.Programs[hook.program])
		if err != nil {
			if hook.optional {
				fmt.Fprintf(diagnostics, "optional hook %s unavailable: %v\n", hook.target, err)
				continue
			}
			return fmt.Errorf("attach %s to %s: %w", hook.kind, hook.target, err)
		}
		links = append(links, attached)
	}
	fmt.Fprintf(diagnostics, "tracking inbound TCP local port=%d (0=all); %d hooks attached; press Ctrl-C to stop\n", opts.port, len(links))
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			// Stop producers before draining, so shutdown retains queued final events.
			detach()
			if err := reader.Flush(); err != nil {
				_ = reader.Close()
			}
		case <-done:
		}
	}()
	var record ringbuf.Record
	var invalid uint64
	var readErr error
	for {
		if err := reader.ReadInto(&record); err != nil {
			if !errors.Is(err, ringbuf.ErrFlushed) && !errors.Is(err, ringbuf.ErrClosed) {
				readErr = fmt.Errorf("read lifecycle events: %w", err)
			}
			break
		}
		event, err := lifecycle.Decode(record.RawSample)
		if err != nil {
			invalid++
			fmt.Fprintf(diagnostics, "invalid lifecycle event: %v\n", err)
			continue
		}
		if err := tracker.Handle(event); err != nil {
			return fmt.Errorf("write lifecycle output: %w", err)
		}
	}
	detach()
	var drops, mapFailures uint64
	for key, value := range []*uint64{&drops, &mapFailures} {
		if err := collection.Maps["stats"].Lookup(uint32(key), value); err != nil {
			readErr = errors.Join(readErr, fmt.Errorf("read event loss counters: %w", err))
		}
	}
	if drops+mapFailures+invalid > 0 {
		fmt.Fprintf(diagnostics, "capture incomplete: ring_buffer_drops=%d map_failures=%d invalid_events=%d\n", drops, mapFailures, invalid)
	}
	reason := "stopped"
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		reason = "duration_elapsed"
	} else if readErr != nil {
		reason = "capture_error"
	}
	return errors.Join(readErr, tracker.Finish(reason, drops+mapFailures+invalid))
}

func configureLifecycleSpec(spec *ebpf.CollectionSpec, opts options) error {
	for _, name := range []string{"events", "connections", "stats"} {
		if spec.Maps[name] == nil {
			return fmt.Errorf("lifecycle object missing map %q; use --mode outbound for the old object", name)
		}
	}
	for _, hook := range lifecycleHooks {
		if spec.Programs[hook.program] == nil {
			return fmt.Errorf("lifecycle object missing program %q", hook.program)
		}
	}
	spec.Maps["connections"].MaxEntries = uint32(opts.maxConnections)
	portFilter := spec.Variables["target_port"]
	if portFilter == nil {
		return errors.New("lifecycle object missing global variable \"target_port\"")
	}
	if err := portFilter.Set(uint16(opts.port)); err != nil {
		return fmt.Errorf("configure local port filter: %w", err)
	}
	return nil
}

func attachLifecycleHook(hook lifecycleHook, program *ebpf.Program) (link.Link, error) {
	switch hook.kind {
	case "tracepoint":
		group, name, ok := strings.Cut(hook.target, "/")
		if !ok {
			return nil, fmt.Errorf("invalid tracepoint %q", hook.target)
		}
		return link.Tracepoint(group, name, program, nil)
	case "kprobe":
		return link.Kprobe(hook.target, program, nil)
	case "kretprobe":
		return link.Kretprobe(hook.target, program, nil)
	default:
		return nil, fmt.Errorf("unknown hook kind %q", hook.kind)
	}
}

func configureKernelABI(spec *ebpf.CollectionSpec) error {
	kernel, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("read kernel BTF for TCP hooks: %w", err)
	}
	var receive *btf.Func
	if err := kernel.TypeByName("tcp_recvmsg", &receive); err != nil {
		return fmt.Errorf("find tcp_recvmsg signature in kernel BTF: %w", err)
	}
	proto, ok := receive.Type.(*btf.FuncProto)
	if !ok {
		return errors.New("tcp_recvmsg has no BTF function prototype")
	}
	// The nonblock argument was removed in newer kernels, shifting flags.
	for index, param := range proto.Params {
		if param.Name == "flags" && (index == 3 || index == 4) {
			flagsArg := spec.Variables["recv_flags_arg"]
			if flagsArg == nil {
				return errors.New("lifecycle object missing global variable \"recv_flags_arg\"")
			}
			return flagsArg.Set(uint32(index))
		}
	}
	return errors.New("unsupported tcp_recvmsg signature: expected flags as argument 4 or 5")
}
