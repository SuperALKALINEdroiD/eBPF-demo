package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Run with make test-integration on a host with the required eBPF privileges.
func TestInboundIntegrationLifecycle(t *testing.T) {
	requireInboundIntegration(t)
	for _, tc := range []struct {
		name, network, address string
	}{
		{"IPv4", "tcp4", "127.0.0.1:0"},
		{"IPv6", "tcp6", "[::1]:0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listener, err := net.Listen(tc.network, tc.address)
			if err != nil {
				if tc.network == "tcp6" {
					t.Skipf("IPv6 loopback unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer listener.Close()
			unrelated, err := net.Listen(tc.network, tc.address)
			if err != nil {
				t.Fatal(err)
			}
			defer unrelated.Close()
			trace := startInboundIntegration(t, listener.Addr().(*net.TCPAddr).Port)
			request := []byte("inbound integration request: 0123456789\n")
			response := []byte("inbound integration response: accepted and processed\n")
			peer, err := exchangeInboundPayload(tc.network, listener, request, response)
			if err != nil {
				t.Fatalf("target exchange: %v", err)
			}
			if _, err := exchangeInboundPayload(tc.network, unrelated, []byte("excluded request"), []byte("excluded response")); err != nil {
				t.Fatalf("unrelated exchange: %v", err)
			}
			select {
			case <-trace.output.matched:
			case <-trace.done:
				t.Fatalf("tracer exited before connection closed: %v\n%s", trace.err, trace.diagnostics.String())
			case <-time.After(10 * time.Second):
				t.Fatalf("no closed connection summary\n%s\n%s", trace.output.String(), trace.diagnostics.String())
			}
			records := trace.finish(t)
			assertInboundLifecycle(t, records, listener.Addr().String(), peer, len(request), len(response))
		})
	}
}

func TestInboundIntegrationCancelWithoutTraffic(t *testing.T) {
	requireInboundIntegration(t)
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	trace := startInboundIntegration(t, listener.Addr().(*net.TCPAddr).Port)
	records := trace.finish(t)
	if len(records) != 1 {
		t.Fatalf("idle capture produced %d records, want one capture summary: %+v", len(records), records)
	}
	summary := records[0]
	if summary.Kind != "capture_summary" || summary.Reason != "stopped" || summary.Events != 0 || summary.Connections != 0 || summary.Incomplete {
		t.Fatalf("unexpected idle capture summary: %+v", summary)
	}
}

func requireInboundIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("CONNECTSNOOP_INTEGRATION") != "1" {
		t.Skip("set CONNECTSNOOP_INTEGRATION=1 after make build to run privileged TCP lifecycle tests")
	}
}

type inboundIntegrationProcess struct {
	PID  int    `json:"pid"`
	TID  int    `json:"tid"`
	Name string `json:"name"`
}

type inboundIntegrationRecord struct {
	Kind             string                     `json:"kind"`
	ConnectionID     string                     `json:"connection_id"`
	Event            string                     `json:"event"`
	Local            string                     `json:"local"`
	Remote           string                     `json:"remote"`
	State            string                     `json:"state"`
	Reason           string                     `json:"reason"`
	Actor            *inboundIntegrationProcess `json:"actor"`
	AcceptingProcess *inboundIntegrationProcess `json:"accepting_process"`
	Bytes            uint64                     `json:"bytes"`
	RXBytes          uint64                     `json:"rx_bytes"`
	TXBytes          uint64                     `json:"tx_bytes"`
	Accepted         bool                       `json:"accepted"`
	EOF              bool                       `json:"eof"`
	EOFObserved      bool                       `json:"eof_observed"`
	PartialStart     bool                       `json:"partial_start"`
	Incomplete       bool                       `json:"incomplete"`
	Events           uint64                     `json:"events"`
	Connections      uint64                     `json:"connections"`
	Closed           uint64                     `json:"closed"`
	Evicted          uint64                     `json:"evicted"`
	Unfinished       uint64                     `json:"unfinished"`
	DroppedEvents    uint64                     `json:"dropped_events"`
	Errors           uint64                     `json:"errors"`
}

type inboundIntegrationWriter struct {
	mu      sync.Mutex
	buffer  bytes.Buffer
	needle  []byte
	matched chan struct{}
	once    sync.Once
}

func newInboundIntegrationWriter(needle string) *inboundIntegrationWriter {
	return &inboundIntegrationWriter{needle: []byte(needle), matched: make(chan struct{})}
}

func (w *inboundIntegrationWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.buffer.Write(p)
	if bytes.Contains(w.buffer.Bytes(), w.needle) {
		w.once.Do(func() { close(w.matched) })
	}
	return n, err
}

func (w *inboundIntegrationWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buffer.String()
}

type inboundIntegrationTrace struct {
	output, diagnostics *inboundIntegrationWriter
	cancel              context.CancelFunc
	done                chan struct{}
	err                 error
}

func startInboundIntegration(t *testing.T, port int) *inboundIntegrationTrace {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	trace := &inboundIntegrationTrace{
		output:      newInboundIntegrationWriter(`"kind":"connection_summary"`),
		diagnostics: newInboundIntegrationWriter("hooks attached"),
		cancel:      cancel, done: make(chan struct{}),
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-trace.done:
		case <-time.After(10 * time.Second):
			t.Error("tracer did not terminate after cancellation")
		}
	})
	go func() {
		trace.err = runInbound(ctx, options{
			mode: "inbound", port: port, format: "json",
			objPath: "../../bpf/lifecycle.bpf.o", maxConnections: 64,
		}, trace.output, trace.diagnostics)
		close(trace.done)
	}()
	select {
	case <-trace.diagnostics.matched:
		return trace
	case <-trace.done:
		t.Fatalf("cannot start privileged tracer: %v\n%s", trace.err, trace.diagnostics.String())
	case <-time.After(15 * time.Second):
		t.Fatalf("tracer hooks did not attach\n%s", trace.diagnostics.String())
	}
	return nil
}

func (trace *inboundIntegrationTrace) finish(t *testing.T) []inboundIntegrationRecord {
	t.Helper()
	trace.cancel()
	select {
	case <-trace.done:
		if trace.err != nil {
			t.Fatalf("tracer failed: %v\n%s", trace.err, trace.diagnostics.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("tracer did not stop after cancellation")
	}
	var records []inboundIntegrationRecord
	decoder := json.NewDecoder(bytes.NewBufferString(trace.output.String()))
	for {
		var record inboundIntegrationRecord
		if err := decoder.Decode(&record); err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("invalid JSON output: %v\n%s", err, trace.output.String())
		}
		records = append(records, record)
	}
	return records
}

func exchangeInboundPayload(network string, listener net.Listener, request, response []byte) (string, error) {
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- func() error {
			conn, err := listener.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
				return err
			}
			got := make([]byte, len(request))
			if _, err := io.ReadFull(conn, got); err != nil {
				return fmt.Errorf("server read: %w", err)
			}
			if !bytes.Equal(got, request) {
				return fmt.Errorf("server received %q, want %q", got, request)
			}
			if _, err := io.Copy(conn, bytes.NewReader(response)); err != nil {
				return fmt.Errorf("server write: %w", err)
			}
			// Read the client's FIN before closing, so the accepted socket reaches CLOSE.
			n, err := io.Copy(io.Discard, conn)
			if err != nil || n != 0 {
				return fmt.Errorf("server EOF: bytes=%d error=%v", n, err)
			}
			return nil
		}()
	}()
	clientConn, err := net.DialTimeout(network, listener.Addr().String(), 5*time.Second)
	if err != nil {
		_ = listener.Close()
		<-serverDone
		return "", err
	}
	client := clientConn.(*net.TCPConn)
	defer client.Close()
	if err := client.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return "", err
	}
	peer := client.LocalAddr().String()
	if _, err := io.Copy(client, bytes.NewReader(request)); err != nil {
		return "", fmt.Errorf("client write: %w", err)
	}
	got := make([]byte, len(response))
	if _, err := io.ReadFull(client, got); err != nil {
		return "", fmt.Errorf("client read: %w", err)
	}
	if !bytes.Equal(got, response) {
		return "", fmt.Errorf("client received %q, want %q", got, response)
	}
	if err := client.CloseWrite(); err != nil {
		return "", err
	}
	if n, err := io.Copy(io.Discard, client); err != nil || n != 0 {
		return "", fmt.Errorf("client EOF: bytes=%d error=%v", n, err)
	}
	if err := <-serverDone; err != nil {
		return "", err
	}
	return peer, nil
}

func assertInboundLifecycle(t *testing.T, records []inboundIntegrationRecord, local, peer string, requestBytes, responseBytes int) {
	t.Helper()
	var id string
	var events, summaries, captures, readBytes, writeBytes uint64
	seen := map[string]bool{}
	for i, record := range records {
		if record.Kind == "capture_summary" {
			captures++
			if i != len(records)-1 || record.Reason != "stopped" || record.Connections != 1 || record.Closed != 1 || record.Events != events || record.Unfinished != 0 || record.Evicted != 0 || record.DroppedEvents != 0 || record.Incomplete {
				t.Errorf("unexpected final capture summary: %+v", record)
			}
			continue
		}
		if id == "" {
			id = record.ConnectionID
			if parsed, err := strconv.ParseUint(id, 16, 64); err != nil || parsed == 0 || len(id) != 16 {
				t.Errorf("invalid connection ID %q", id)
			}
		}
		if record.ConnectionID != id || record.Local != local || record.Remote != peer {
			t.Errorf("unexpected connection or endpoint (port filter or socket correlation failed): %+v; want id=%s local=%s remote=%s", record, id, local, peer)
		}
		switch record.Kind {
		case "event":
			events++
			seen[record.Event] = true
			if record.Event == "state" {
				seen[record.State] = true
			}
			if record.Event == "accept" || record.Event == "read" || record.Event == "write" {
				if record.Actor == nil || record.Actor.PID != os.Getpid() || record.Actor.TID == 0 || record.Actor.Name == "" {
					t.Errorf("event missing current process identity: %+v", record)
				}
			}
			if record.Event == "read" {
				readBytes += record.Bytes
				seen["eof"] = seen["eof"] || record.EOF
			}
			if record.Event == "write" {
				writeBytes += record.Bytes
			}
		case "connection_summary":
			summaries++
			if record.Reason != "closed" || record.State != "CLOSE" || !record.Accepted || !record.EOFObserved || record.PartialStart || record.Incomplete || record.Errors != 0 {
				t.Errorf("unexpected connection summary: %+v", record)
			}
			if record.AcceptingProcess == nil || record.AcceptingProcess.PID != os.Getpid() {
				t.Errorf("wrong accepting process: %+v", record.AcceptingProcess)
			}
			if record.RXBytes != uint64(requestBytes) || record.TXBytes != uint64(responseBytes) {
				t.Errorf("summary bytes rx=%d tx=%d, want rx=%d tx=%d", record.RXBytes, record.TXBytes, requestBytes, responseBytes)
			}
		default:
			t.Errorf("unexpected record kind %q", record.Kind)
		}
	}
	if summaries != 1 || captures != 1 {
		t.Errorf("connection summaries=%d capture summaries=%d, want one each", summaries, captures)
	}
	for _, event := range []string{"state", "ESTABLISHED", "accept", "read", "write", "eof", "CLOSE"} {
		if !seen[event] {
			t.Errorf("missing lifecycle observation %q", event)
		}
	}
	if readBytes != uint64(requestBytes) || writeBytes != uint64(responseBytes) {
		t.Errorf("event bytes read=%d write=%d, want read=%d write=%d", readBytes, writeBytes, requestBytes, responseBytes)
	}
}
