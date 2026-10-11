package main

import (
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
)

func TestParseInboundOptions(t *testing.T) {
	opts, err := parseOptions(nil)
	if err != nil {
		t.Fatal(err)
	}
	if opts.mode != "inbound" || opts.objPath != "bpf/lifecycle.bpf.o" || opts.format != "text" || opts.maxConnections != 16384 {
		t.Fatalf("unexpected defaults: %+v", opts)
	}
	opts, err = parseOptions([]string{"--port", "8443", "--format", "json", "--duration", "2s", "--max-connections", "32", "--obj", "custom.o"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.port != 8443 || opts.format != "json" || opts.duration != 2*time.Second || opts.maxConnections != 32 || opts.objPath != "custom.o" {
		t.Fatalf("unexpected explicit options: %+v", opts)
	}
}

func TestParseOutboundOptions(t *testing.T) {
	opts, err := parseOptions([]string{"--mode", "outbound", "--port", "443"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.mode != "outbound" || opts.objPath != "bpf/connectsnoop.bpf.o" || opts.port != 443 {
		t.Fatalf("unexpected outbound options: %+v", opts)
	}
}

func TestParseInboundOptionsInvalid(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{"negative port", []string{"--port", "-1"}, "port must"},
		{"port overflow", []string{"--port", "65536"}, "port must"},
		{"mode", []string{"--mode", "unknown"}, "mode must"},
		{"format", []string{"--format", "csv"}, "format must"},
		{"outbound json", []string{"--mode", "outbound", "--format", "json"}, "outbound mode only supports text"},
		{"negative duration", []string{"--duration", "-1s"}, "duration must"},
		{"zero capacity", []string{"--max-connections", "0"}, "max-connections must"},
		{"capacity overflow", []string{"--max-connections", "1048577"}, "max-connections must"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseOptions(tc.args); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestConfigureLifecycleSpecRejectsMissingMaps(t *testing.T) {
	for _, missing := range []string{"events", "connections", "stats"} {
		t.Run(missing, func(t *testing.T) {
			spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{}}
			for _, name := range []string{"events", "connections", "stats"} {
				if name != missing {
					spec.Maps[name] = &ebpf.MapSpec{}
				}
			}
			err := configureLifecycleSpec(spec, options{maxConnections: 32})
			if err == nil || !strings.Contains(err.Error(), "missing map \""+missing+"\"") {
				t.Fatalf("error = %v, want missing map %q", err, missing)
			}
		})
	}
}

func TestConfigureLifecycleSpecRejectsMissingPrograms(t *testing.T) {
	for _, missing := range lifecycleHooks {
		t.Run(missing.program, func(t *testing.T) {
			spec := &ebpf.CollectionSpec{
				Maps:     map[string]*ebpf.MapSpec{"events": {}, "connections": {}, "stats": {}},
				Programs: map[string]*ebpf.ProgramSpec{},
			}
			for _, hook := range lifecycleHooks {
				if hook.program != missing.program {
					spec.Programs[hook.program] = &ebpf.ProgramSpec{}
				}
			}
			err := configureLifecycleSpec(spec, options{maxConnections: 32})
			if err == nil || !strings.Contains(err.Error(), "missing program \""+missing.program+"\"") {
				t.Fatalf("error = %v, want missing program %q", err, missing.program)
			}
		})
	}
}
