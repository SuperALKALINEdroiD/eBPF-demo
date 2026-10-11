package main

import "testing"

func TestParseConnectEventIPv4(t *testing.T) {
	line := "curl-1234    [002] d...1 12.345678: bpf_trace_printk: connect fd=3 dst=93.184.216.34:443"

	event, ok := parseConnectEvent(line)
	if !ok {
		t.Fatal("expected event to parse")
	}
	if event.Process != "curl" {
		t.Fatalf("process = %q, want curl", event.Process)
	}
	if event.PID != "1234" {
		t.Fatalf("pid = %q, want 1234", event.PID)
	}
	if event.FD != "3" {
		t.Fatalf("fd = %q, want 3", event.FD)
	}
	if event.Dst != "93.184.216.34" {
		t.Fatalf("dst = %q, want 93.184.216.34", event.Dst)
	}
	if event.Port != 443 {
		t.Fatalf("port = %d, want 443", event.Port)
	}
}

func TestParseConnectEventIPv6(t *testing.T) {
	line := "app-worker-99 [001] d...1 12.345678: bpf_trace_printk: connect fd=9 dst=[::1]:8080"

	event, ok := parseConnectEvent(line)
	if !ok {
		t.Fatal("expected event to parse")
	}
	if event.Process != "app-worker" {
		t.Fatalf("process = %q, want app-worker", event.Process)
	}
	if event.PID != "99" {
		t.Fatalf("pid = %q, want 99", event.PID)
	}
	if event.Dst != "[::1]" {
		t.Fatalf("dst = %q, want [::1]", event.Dst)
	}
	if event.Port != 8080 {
		t.Fatalf("port = %d, want 8080", event.Port)
	}
}

func TestParseConnectEventUnsupportedFamily(t *testing.T) {
	line := "nc-77 [000] d...1 12.345678: bpf_trace_printk: connect fd=4 unsupported_family=1"

	_, ok := parseConnectEvent(line)
	if ok {
		t.Fatal("unsupported family event should not parse as destination-port event")
	}
}
