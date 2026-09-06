package main

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
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

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// The Makefile builds this object from bpf/connectsnoop.bpf.c.
	objPath := "bpf/connectsnoop.bpf.o"
	if len(os.Args) > 1 {
		objPath = os.Args[1]
	}

	// Pull raw eBPF bytecode and license text out of the ELF object.
	insns, license, err := readBPFObject(objPath, tracepointSection)
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

	fmt.Println("attached to sys_enter_connect; press Ctrl-C to stop")
	return tailTracePipe(tracePipePath)
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

func tailTracePipe(path string) error {
	// bpf_trace_printk writes into trace_pipe. Reading it consumes the stream.
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer file.Close()

	// Closing trace_pipe unblocks Scanner when Ctrl-C arrives.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		_ = file.Close()
	}()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		// trace_pipe includes all tracing output, so show only this sample's lines.
		if strings.Contains(line, "connect fd=") {
			fmt.Println(line)
		}
	}

	if err := scanner.Err(); err != nil && !errors.Is(err, os.ErrClosed) {
		return fmt.Errorf("read trace_pipe: %w", err)
	}
	return nil
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
