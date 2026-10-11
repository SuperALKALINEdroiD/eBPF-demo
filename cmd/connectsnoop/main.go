package main

import (
	"bufio"
	"context"
	"debug/elf"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	// Minimal sample note: syscall numbers are architecture-specific. This is
	// Linux amd64. Import golang.org/x/sys/unix if you want portability.
	sysBPF = 321

	// Constants from linux/bpf.h.
	bpfProgLoad       = 5
	bpfProgTracepoint = 5

	// Constants from linux/perf_event.h.
	perfTypeTracepoint = 2
	perfFlagDisabled   = 1

	// ioctl request numbers for enabling a perf event and attaching a BPF prog.
	perfEventIOCEnable = 0x2400
	perfEventIOCSetBPF = 0x40042408

	// These paths come from tracefs. tracepointIDPath identifies the kernel
	// tracepoint, and tracePipePath is where bpf_trace_printk messages appear.
	tracepointSection = "tracepoint/syscalls/sys_enter_connect"
	tracepointIDPath  = "/sys/kernel/tracing/events/syscalls/sys_enter_connect/id"
	tracePipePath     = "/sys/kernel/tracing/trace_pipe"
)

// bpfProgLoadAttr mirrors the beginning of union bpf_attr for BPF_PROG_LOAD.
// Only the fields needed by this sample are included.
type bpfProgLoadAttr struct {
	ProgType           uint32
	InsnCnt            uint32
	Insns              uint64
	License            uint64
	LogLevel           uint32
	LogSize            uint32
	LogBuf             uint64
	KernVersion        uint32
	ProgFlags          uint32
	ProgName           [16]byte
	ProgIfIndex        uint32
	ExpectedAttachType uint32
}

// perfEventAttr mirrors the beginning of struct perf_event_attr. Opening one
// perf event per CPU is the old, dependency-free way to attach tracepoint BPF.
type perfEventAttr struct {
	Type         uint32
	Size         uint32
	Config       uint64
	SamplePeriod uint64
	SampleType   uint64
	ReadFormat   uint64
	Flags        uint64
	WakeupEvents uint32
	BPType       uint32
	BPAddr       uint64
	BPLen        uint64
}

type options struct {
	objPath        string
	port           int
	mode           string
	format         string
	duration       time.Duration
	maxConnections int
}

type connectEvent struct {
	Process string
	PID     string
	FD      string
	Dst     string
	Port    int
	Raw     string
}

type connectStats struct {
	Total     int
	ByProcess map[string]int
	ByDst     map[string]int
}

func main() {
	if err := run(); err != nil && !errors.Is(err, flag.ErrHelp) {
		log.Fatal(err)
	}
}

func run() error {
	opts, err := parseOptions(os.Args[1:])
	if err != nil {
		return err
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		return errors.New("connectsnoop currently requires Linux amd64")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if opts.duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, opts.duration)
		defer cancel()
	}
	if opts.mode == "inbound" {
		return runInbound(ctx, opts, os.Stdout, os.Stderr)
	}
	return runOutbound(ctx, opts)
}

func runOutbound(ctx context.Context, opts options) error {

	// Pull raw eBPF bytecode and license text out of the ELF object.
	insns, license, err := readBPFObject(opts.objPath, tracepointSection)
	if err != nil {
		return err
	}

	// Ask the kernel verifier to validate and load the program.
	progFD, verifierLog, err := loadBPFProgram(insns, license)
	if err != nil {
		if verifierLog != "" {
			return fmt.Errorf("load eBPF program: %w\nverifier log:\n%s", err, verifierLog)
		}
		return fmt.Errorf("load eBPF program: %w", err)
	}
	defer syscall.Close(progFD)

	// Tracepoints are addressed by numeric IDs exposed by tracefs.
	tracepointID, err := readUint(tracepointIDPath)
	if err != nil {
		return err
	}

	// Open perf events for the tracepoint and attach the loaded eBPF program.
	perfFDs, err := attachTracepoint(progFD, tracepointID)
	if err != nil {
		return err
	}
	defer closeAll(perfFDs)

	if opts.port > 0 {
		fmt.Printf("attached to sys_enter_connect; tracking destination port %d; press Ctrl-C to stop\n", opts.port)
	} else {
		fmt.Println("attached to sys_enter_connect; tracking all destination ports; press Ctrl-C to stop")
	}
	return tailTracePipe(ctx, tracePipePath, opts.port)
}

func parseOptions(args []string) (options, error) {
	var opts options

	flags := flag.NewFlagSet("connectsnoop", flag.ContinueOnError)
	flags.StringVar(&opts.objPath, "obj", opts.objPath, "path to eBPF object file")
	flags.IntVar(&opts.port, "port", 0, "local server port (inbound) or destination port (outbound); 0 for all")
	flags.StringVar(&opts.mode, "mode", "inbound", "inbound lifecycle or outbound connect attempts")
	flags.StringVar(&opts.format, "format", "text", "inbound output format: text or json (JSON Lines)")
	flags.DurationVar(&opts.duration, "duration", 0, "stop after this duration, e.g. 30s; 0 waits for Ctrl-C")
	flags.IntVar(&opts.maxConnections, "max-connections", 16384, "maximum concurrently tracked inbound connections")
	if err := flags.Parse(args); err != nil {
		return opts, err
	}

	// Keep the old positional form working: sudo ./bin/connectsnoop bpf/file.o.
	if flags.NArg() > 1 {
		return opts, fmt.Errorf("usage: connectsnoop [-port N] [-obj bpf/connectsnoop.bpf.o]")
	}
	if flags.NArg() == 1 {
		opts.objPath = flags.Arg(0)
	}

	if opts.port < 0 || opts.port > 65535 {
		return opts, fmt.Errorf("port must be between 0 and 65535")
	}
	if opts.mode != "inbound" && opts.mode != "outbound" {
		return opts, errors.New("mode must be inbound or outbound")
	}
	if opts.format != "text" && opts.format != "json" {
		return opts, errors.New("format must be text or json")
	}
	if opts.mode == "outbound" && opts.format != "text" {
		return opts, errors.New("outbound mode only supports text output")
	}
	if opts.duration < 0 {
		return opts, errors.New("duration must not be negative")
	}
	if opts.maxConnections < 1 || opts.maxConnections > 1048576 {
		return opts, errors.New("max-connections must be between 1 and 1048576")
	}
	if opts.objPath == "" {
		opts.objPath = "bpf/lifecycle.bpf.o"
		if opts.mode == "outbound" {
			opts.objPath = "bpf/connectsnoop.bpf.o"
		}
	}
	return opts, nil
}

func readBPFObject(path, sectionName string) ([]byte, string, error) {
	// debug/elf is enough here because the C program has no maps or relocations.
	// Real loaders must handle relocations, maps, BTF, CO-RE, and more.
	file, err := elf.Open(path)
	if err != nil {
		return nil, "", fmt.Errorf("open eBPF object %q: %w", path, err)
	}
	defer file.Close()

	section := file.Section(sectionName)
	if section == nil {
		return nil, "", fmt.Errorf("section %q not found in %s", sectionName, path)
	}

	// The section contains raw struct bpf_insn instructions, 8 bytes each.
	insns, err := section.Data()
	if err != nil {
		return nil, "", fmt.Errorf("read eBPF instructions: %w", err)
	}
	if len(insns) == 0 || len(insns)%8 != 0 {
		return nil, "", fmt.Errorf("invalid eBPF instruction byte length %d", len(insns))
	}

	// The kernel uses the license string to decide whether GPL-only helpers are allowed.
	licenseSection := file.Section("license")
	if licenseSection == nil {
		return nil, "", errors.New("license section not found")
	}

	licenseBytes, err := licenseSection.Data()
	if err != nil {
		return nil, "", fmt.Errorf("read license section: %w", err)
	}

	return insns, strings.TrimRight(string(licenseBytes), "\x00"), nil
}

func loadBPFProgram(insns []byte, license string) (int, string, error) {
	// Verifier errors are hard to diagnose without this log buffer.
	logBuf := make([]byte, 64*1024)
	licenseBytes := append([]byte(license), 0)

	// bpf(BPF_PROG_LOAD, &attr, sizeof(attr)) returns a program file descriptor.
	attr := bpfProgLoadAttr{
		ProgType: bpfProgTracepoint,
		InsnCnt:  uint32(len(insns) / 8),
		Insns:    uint64(uintptr(unsafe.Pointer(&insns[0]))),
		License:  uint64(uintptr(unsafe.Pointer(&licenseBytes[0]))),
		LogLevel: 1,
		LogSize:  uint32(len(logBuf)),
		LogBuf:   uint64(uintptr(unsafe.Pointer(&logBuf[0]))),
	}
	copy(attr.ProgName[:], "connectsnoop")

	fd, _, errno := syscall.Syscall(
		sysBPF,
		uintptr(bpfProgLoad),
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
	)
	if errno != 0 {
		return -1, strings.TrimRight(string(logBuf), "\x00"), errno
	}

	return int(fd), "", nil
}

func attachTracepoint(progFD int, tracepointID uint64) ([]int, error) {
	// A tracepoint perf-event fd acts as the attachment anchor. libbpf opens a
	// single fd on CPU 0 for tracepoint programs; attaching the same program to
	// one fd per CPU can fail with EEXIST on newer kernels.
	fd, err := openTracepointPerfEvent(tracepointID, 0)
	if err != nil {
		return nil, err
	}

	// PERF_EVENT_IOC_SET_BPF links the loaded eBPF program to this event.
	if err := ioctl(fd, perfEventIOCSetBPF, uintptr(progFD)); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("attach eBPF program to tracepoint: %w", err)
	}

	// The event starts disabled so we can attach first, then enable it.
	if err := ioctl(fd, perfEventIOCEnable, 0); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("enable tracepoint perf event: %w", err)
	}

	return []int{fd}, nil
}

func openTracepointPerfEvent(tracepointID uint64, cpu int) (int, error) {
	// pid=-1 means all processes. cpu=N means attach this event on that CPU.
	attr := perfEventAttr{
		Type:   perfTypeTracepoint,
		Size:   uint32(unsafe.Sizeof(perfEventAttr{})),
		Config: tracepointID,
		Flags:  perfFlagDisabled,
	}

	fd, _, errno := syscall.Syscall6(
		syscall.SYS_PERF_EVENT_OPEN,
		uintptr(unsafe.Pointer(&attr)),
		uintptr(^uint(0)),
		uintptr(cpu),
		uintptr(^uint(0)),
		0,
		0,
	)
	if errno != 0 {
		return -1, fmt.Errorf("perf_event_open cpu %d: %w", cpu, errno)
	}

	return int(fd), nil
}

func tailTracePipe(ctx context.Context, path string, portFilter int) error {
	// bpf_trace_printk writes into trace_pipe. Reading it consumes the stream.
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	stats := connectStats{
		ByProcess: make(map[string]int),
		ByDst:     make(map[string]int),
	}

	// Closing trace_pipe unblocks Scanner on a signal or capture deadline.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = file.Close()
		case <-done:
		}
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		event, ok := parseConnectEvent(line)
		if !ok {
			continue
		}
		if portFilter > 0 && event.Port != portFilter {
			continue
		}

		stats.Add(event)
		fmt.Printf("%s pid=%s fd=%s dst=%s port=%d\n", event.Process, event.PID, event.FD, event.Dst, event.Port)
	}

	if err := scanner.Err(); err != nil && !errors.Is(err, os.ErrClosed) {
		return fmt.Errorf("read trace_pipe: %w", err)
	}
	stats.Print(portFilter)
	return nil
}

func parseConnectEvent(line string) (connectEvent, bool) {
	idx := strings.Index(line, "connect fd=")
	if idx < 0 {
		return connectEvent{}, false
	}

	event := connectEvent{
		Process: "unknown",
		PID:     "unknown",
		Raw:     line,
	}
	event.Process, event.PID = parseTracePipeProcess(line[:idx])

	fields := strings.Fields(line[idx:])
	if len(fields) < 3 || fields[0] != "connect" {
		return connectEvent{}, false
	}

	fd, ok := strings.CutPrefix(fields[1], "fd=")
	if !ok {
		return connectEvent{}, false
	}
	event.FD = fd

	dst, ok := strings.CutPrefix(fields[2], "dst=")
	if !ok {
		return connectEvent{}, false
	}

	host, port, ok := splitHostPort(dst)
	if !ok {
		return connectEvent{}, false
	}
	event.Dst = host
	event.Port = port

	return event, true
}

func parseTracePipeProcess(prefix string) (string, string) {
	beforeCPU, _, ok := strings.Cut(prefix, "[")
	if !ok {
		return "unknown", "unknown"
	}

	commPID := strings.TrimSpace(beforeCPU)
	dash := strings.LastIndex(commPID, "-")
	if dash <= 0 || dash == len(commPID)-1 {
		return commPID, "unknown"
	}

	return commPID[:dash], commPID[dash+1:]
}

func splitHostPort(dst string) (string, int, bool) {
	if strings.HasPrefix(dst, "[") {
		closeBracket := strings.LastIndex(dst, "]:")
		if closeBracket < 0 {
			return "", 0, false
		}
		port, err := strconv.Atoi(dst[closeBracket+2:])
		if err != nil {
			return "", 0, false
		}
		return dst[:closeBracket+1], port, true
	}

	colon := strings.LastIndex(dst, ":")
	if colon < 0 {
		return "", 0, false
	}
	port, err := strconv.Atoi(dst[colon+1:])
	if err != nil {
		return "", 0, false
	}
	return dst[:colon], port, true
}

func (s *connectStats) Add(event connectEvent) {
	s.Total++
	s.ByProcess[event.Process]++
	s.ByDst[event.Dst]++
}

func (s connectStats) Print(portFilter int) {
	if portFilter > 0 {
		fmt.Printf("\nsummary for destination port %d\n", portFilter)
	} else {
		fmt.Println("\nsummary for all destination ports")
	}
	fmt.Printf("total connect attempts: %d\n", s.Total)

	printTop("by process", s.ByProcess)
	printTop("by destination", s.ByDst)
}

func printTop(title string, values map[string]int) {
	if len(values) == 0 {
		return
	}

	type entry struct {
		Name  string
		Count int
	}
	entries := make([]entry, 0, len(values))
	for name, count := range values {
		entries = append(entries, entry{Name: name, Count: count})
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Count == entries[j].Count {
			return entries[i].Name < entries[j].Name
		}
		return entries[i].Count > entries[j].Count
	})

	fmt.Println(title + ":")
	for i, entry := range entries {
		if i == 5 {
			break
		}
		fmt.Printf("  %s: %d\n", entry.Name, entry.Count)
	}
}

func onlineCPUs() ([]int, error) {
	// Example content: "0-3" or "0-1,4-5".
	raw, err := os.ReadFile("/sys/devices/system/cpu/online")
	if err != nil {
		return nil, fmt.Errorf("read online CPUs: %w", err)
	}
	return parseCPUList(strings.TrimSpace(string(raw)))
}

func parseCPUList(raw string) ([]int, error) {
	var cpus []int
	for _, part := range strings.Split(raw, ",") {
		if strings.Contains(part, "-") {
			bounds := strings.SplitN(part, "-", 2)
			start, err := strconv.Atoi(bounds[0])
			if err != nil {
				return nil, fmt.Errorf("parse cpu list %q: %w", raw, err)
			}
			end, err := strconv.Atoi(bounds[1])
			if err != nil {
				return nil, fmt.Errorf("parse cpu list %q: %w", raw, err)
			}
			for cpu := start; cpu <= end; cpu++ {
				cpus = append(cpus, cpu)
			}
			continue
		}

		cpu, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("parse cpu list %q: %w", raw, err)
		}
		cpus = append(cpus, cpu)
	}

	if len(cpus) == 0 {
		return nil, fmt.Errorf("no online CPUs parsed from %q", raw)
	}
	return cpus, nil
}

func readUint(path string) (uint64, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	value, err := strconv.ParseUint(strings.TrimSpace(string(raw)), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse %s: %w", path, err)
	}
	return value, nil
}

func ioctl(fd int, req uintptr, arg uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), req, arg)
	if errno != 0 {
		return errno
	}
	return nil
}

func closeAll(fds []int) {
	for _, fd := range fds {
		_ = syscall.Close(fd)
	}
}
