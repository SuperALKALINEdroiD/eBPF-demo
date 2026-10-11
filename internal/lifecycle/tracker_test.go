package lifecycle

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"syscall"
	"testing"
)

func testEvent(id uint64, kind uint32, timestamp uint64) Event {
	e := Event{
		ID: id, Type: kind, TimestampNS: timestamp, StartedNS: 100, FD: -1,
		Family: 2, LocalPort: 8080, RemotePort: uint16(50000 + id), OldState: 3, NewState: 1,
		LocalAddr: [16]byte{127, 0, 0, 1}, RemoteAddr: [16]byte{192, 0, 2, 1},
	}
	if isSyscall(kind) {
		e.PID, e.TID, e.FD = 1000, 1001, 7
		copy(e.Comm[:], "server")
	}
	return e
}

func newJSONTracker(t *testing.T, limit int) (*Tracker, *bytes.Buffer) {
	t.Helper()
	output := &bytes.Buffer{}
	tracker, err := NewTracker(output, "json", limit)
	if err != nil {
		t.Fatal(err)
	}
	return tracker, output
}

func handleEvents(t *testing.T, tracker *Tracker, events ...Event) {
	t.Helper()
	for _, event := range events {
		if err := tracker.Handle(event); err != nil {
			t.Fatal(err)
		}
	}
}

func decodeRecords(t *testing.T, output *bytes.Buffer) []map[string]json.RawMessage {
	t.Helper()
	var records []map[string]json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(output.Bytes()))
	for {
		var record map[string]json.RawMessage
		if err := decoder.Decode(&record); err == io.EOF {
			break
		} else if err != nil {
			t.Fatalf("non-JSON output: %v", err)
		}
		records = append(records, record)
	}
	return records
}

func recordsOfKind(t *testing.T, output *bytes.Buffer, kind string) []map[string]json.RawMessage {
	t.Helper()
	var matches []map[string]json.RawMessage
	for _, record := range decodeRecords(t, output) {
		var got string
		if err := json.Unmarshal(record["kind"], &got); err != nil {
			t.Fatal(err)
		}
		if got == kind {
			matches = append(matches, record)
		}
	}
	return matches
}

func assertField(t *testing.T, record map[string]json.RawMessage, key, want string) {
	t.Helper()
	if got := string(record[key]); got != want {
		t.Errorf("%s = %s, want %s", key, got, want)
	}
}

func TestConnectionTimelineActorsErrorsEOFAndClose(t *testing.T) {
	tracker, output := newJSONTracker(t, 10)
	established := testEvent(0xfedcba9876543210, TypeState, 100)
	accept := testEvent(established.ID, TypeAccept, 120)
	read := testEvent(established.ID, TypeRead, 150)
	read.Result, read.RXBytes = 30, 30
	read.PID, read.TID = 2000, 2001
	copy(read.Comm[:], "worker")
	again := testEvent(established.ID, TypeRead, 160)
	again.Result, again.RXBytes = -int64(syscall.EAGAIN), 30
	intr := again
	intr.TimestampNS, intr.Result = 165, -int64(syscall.EINTR)
	write := testEvent(established.ID, TypeWrite, 170)
	write.Result, write.RXBytes, write.TXBytes = 50, 30, 50
	failedWrite := write
	failedWrite.TimestampNS, failedWrite.Result = 180, -int64(syscall.EPIPE)
	eof := testEvent(established.ID, TypeRead, 190)
	eof.RXBytes, eof.TXBytes = 30, 50
	retransmit := testEvent(established.ID, TypeRetransmit, 195)
	closeEvent := testEvent(established.ID, TypeState, 200)
	closeEvent.OldState, closeEvent.NewState, closeEvent.RXBytes, closeEvent.TXBytes = 8, 7, 30, 50
	handleEvents(t, tracker, established, accept, read, again, intr, write, failedWrite, eof, retransmit)
	if len(recordsOfKind(t, output, "connection_summary")) != 0 {
		t.Fatal("I/O errors or EOF prematurely finalized the connection")
	}
	handleEvents(t, tracker, closeEvent)
	if err := tracker.Finish("interrupted", 0); err != nil {
		t.Fatal(err)
	}
	events := recordsOfKind(t, output, "event")
	if len(events) != 10 {
		t.Fatalf("got %d events, want 10", len(events))
	}
	assertField(t, events[0], "connection_id", `"fedcba9876543210"`)
	if _, ok := events[0]["actor"]; ok {
		t.Error("network state callback attributed to a process")
	}
	assertField(t, events[2], "actor", `{"pid":2000,"tid":2001,"name":"worker"}`)
	assertField(t, events[2], "accepting_process", `{"pid":1000,"tid":1001,"name":"server"}`)
	assertField(t, events[3], "error", `{"errno":11,"message":"resource temporarily unavailable","transient":true}`)
	assertField(t, events[7], "eof", `true`)
	summaries := recordsOfKind(t, output, "connection_summary")
	if len(summaries) != 1 {
		t.Fatalf("got %d connection summaries, want one", len(summaries))
	}
	summary := summaries[0]
	for key, want := range map[string]string{
		"reason": `"closed"`, "accepted": "true", "rx_bytes": "30", "tx_bytes": "50",
		"accepted_after_ns": "20", "first_read_after_ns": "50", "first_write_after_ns": "70", "duration_ns": "100",
		"read_calls": "4", "write_calls": "2", "errors": "1", "transient_errors": "2", "retransmits": "1",
		"eof_observed": "true", "incomplete": "false", "partial_start": "false",
	} {
		assertField(t, summary, key, want)
	}
	if len(tracker.active) != 0 {
		t.Fatal("closed connection retained as active")
	}
}

func TestConcurrentIDsAndShuffledCumulativeCounters(t *testing.T) {
	tracker, output := newJSONTracker(t, 4)
	handleEvents(t, tracker, testEvent(1, TypeState, 100), testEvent(2, TypeState, 100))
	read := testEvent(1, TypeRead, 180)
	read.Result, read.RXBytes, read.TXBytes = 5, 100, 60
	olderRead := read
	olderRead.TimestampNS, olderRead.RXBytes, olderRead.TXBytes = 150, 40, 10
	otherRead := testEvent(2, TypeRead, 160)
	otherRead.Result, otherRead.RXBytes = 80, 80
	accept := testEvent(1, TypeAccept, 120)
	handleEvents(t, tracker, read, otherRead, olderRead, accept)
	closeEvent := testEvent(1, TypeState, 200)
	closeEvent.NewState, closeEvent.RXBytes, closeEvent.TXBytes = 7, 90, 50
	handleEvents(t, tracker, closeEvent)
	if err := tracker.Finish("shutdown", 0); err != nil {
		t.Fatal(err)
	}
	summaries := recordsOfKind(t, output, "connection_summary")
	if len(summaries) != 2 {
		t.Fatalf("got %d summaries, want 2", len(summaries))
	}
	assertField(t, summaries[0], "connection_id", `"0000000000000001"`)
	assertField(t, summaries[0], "rx_bytes", "100")
	assertField(t, summaries[0], "tx_bytes", "60")
	assertField(t, summaries[0], "first_read_after_ns", "50")
	assertField(t, summaries[1], "connection_id", `"0000000000000002"`)
	assertField(t, summaries[1], "rx_bytes", "80")
	assertField(t, summaries[1], "incomplete", "true")
}

func TestLateEventsCannotReopenSummarizedConnection(t *testing.T) {
	tracker, output := newJSONTracker(t, 2)
	closeEvent := testEvent(1, TypeState, 200)
	closeEvent.NewState = 7
	handleEvents(t, tracker, testEvent(1, TypeState, 100), closeEvent, testEvent(1, TypeAccept, 150), testEvent(1, TypeRead, 160))
	if len(tracker.active) != 0 {
		t.Fatal("late event reopened a closed connection")
	}
	if err := tracker.Finish("shutdown", 0); err != nil {
		t.Fatal(err)
	}
	summaries := recordsOfKind(t, output, "connection_summary")
	if len(summaries) != 1 {
		t.Fatalf("got %d summaries for one ID", len(summaries))
	}
	assertField(t, summaries[0], "accepted", "false")
	assertField(t, summaries[0], "reason", `"closed"`)
	events := recordsOfKind(t, output, "event")
	assertField(t, events[2], "late_after_summary", "true")
	assertField(t, events[2], "prior_summary_reason", `"closed"`)
	capture := recordsOfKind(t, output, "capture_summary")[0]
	assertField(t, capture, "late_events", "2")
	assertField(t, capture, "incomplete", "true")
}

func TestBoundedConnectionsAndTombstonesReportEvictions(t *testing.T) {
	tracker, output := newJSONTracker(t, 2)
	for id := uint64(1); id <= 12; id++ {
		handleEvents(t, tracker, testEvent(id, TypeState, 100+id))
		if len(tracker.active) > 2 || tracker.order.Len() > 2 || len(tracker.tombstones) > 2 || len(tracker.tombstoneIDs) > 2 {
			t.Fatalf("tracker exceeded configured bounds at ID %d", id)
		}
	}
	handleEvents(t, tracker, testEvent(10, TypeRead, 130))
	if len(tracker.active) != 2 {
		t.Error("late event for evicted connection changed active count")
	}
	if err := tracker.Finish("interrupted", 3); err != nil {
		t.Fatal(err)
	}
	summaries := recordsOfKind(t, output, "connection_summary")
	if len(summaries) != 12 {
		t.Fatalf("got %d summaries, want all 12 connections", len(summaries))
	}
	assertField(t, summaries[0], "reason", `"evicted"`)
	assertField(t, summaries[0], "incomplete", "true")
	assertField(t, summaries[10], "reason", `"interrupted"`)
	capture := recordsOfKind(t, output, "capture_summary")[0]
	for key, want := range map[string]string{"connections": "12", "evicted": "10", "unfinished": "2", "late_events": "1", "dropped_events": "3", "incomplete": "true"} {
		assertField(t, capture, key, want)
	}
}

func TestUnmatchedPartialConnectionAndStateError(t *testing.T) {
	tracker, output := newJSONTracker(t, 2)
	read := testEvent(1, TypeRead, 150)
	read.StartedNS, read.Flags, read.Result, read.RXBytes = 0, FlagPartialStart, 20, 20
	closeEvent := testEvent(1, TypeState, 200)
	closeEvent.StartedNS, closeEvent.NewState, closeEvent.Result = 0, 7, -int64(syscall.ECONNRESET)
	handleEvents(t, tracker, read, closeEvent)
	summary := recordsOfKind(t, output, "connection_summary")[0]
	assertField(t, summary, "partial_start", "true")
	assertField(t, summary, "incomplete", "true")
	assertField(t, summary, "duration_ns", "50")
	assertField(t, summary, "accepted", "false")
	assertField(t, summary, "errors", "1")
	state := recordsOfKind(t, output, "event")[1]
	assertField(t, state, "error", `{"errno":104,"message":"connection reset by peer","transient":false}`)
	if _, ok := state["actor"]; ok {
		t.Error("state error should not have an invented actor")
	}
}

func TestTextOutputDoesNotInferRefusalAndEscapesProcessName(t *testing.T) {
	var output bytes.Buffer
	tracker, err := NewTracker(&output, "text", 2)
	if err != nil {
		t.Fatal(err)
	}
	closeEvent := testEvent(1, TypeState, 200)
	closeEvent.NewState = 7
	accept := testEvent(2, TypeAccept, 150)
	copy(accept.Comm[:], "a\nb\x1b[0m")
	handleEvents(t, tracker, closeEvent, accept)
	if err := tracker.Finish("shutdown", 0); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if strings.Contains(text, "refused") || !strings.Contains(text, "accepted=not_observed") {
		t.Fatalf("misleading close summary: %s", text)
	}
	if strings.Contains(text, "a\nb") || strings.Contains(text, "\x1b") || !strings.Contains(text, `a\nb\x1b[0m`) {
		t.Fatalf("process name escaped incorrectly: %s", text)
	}
	if !strings.Contains(text, "capture summary shutdown") {
		t.Fatalf("missing capture summary: %s", text)
	}
}

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestConfigurationWriterErrorsAndFinishLifecycle(t *testing.T) {
	for _, format := range []string{"", "yaml", "JSON"} {
		if _, err := NewTracker(io.Discard, format, 1); err == nil {
			t.Errorf("accepted format %q", format)
		}
	}
	if _, err := NewTracker(nil, "text", 1); err == nil {
		t.Error("accepted nil writer")
	}
	if _, err := NewTracker(io.Discard, "text", 0); err == nil {
		t.Error("accepted zero capacity")
	}
	tracker, err := NewTracker(failingWriter{}, "json", 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := tracker.Handle(testEvent(1, TypeState, 100)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Handle writer error = %v", err)
	}
	if err := tracker.Finish("shutdown", 0); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Finish writer error = %v", err)
	}
	tracker, output := newJSONTracker(t, 2)
	if err := tracker.Finish("shutdown", 0); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Finish("shutdown", 0); err != nil {
		t.Fatal(err)
	}
	if err := tracker.Handle(testEvent(1, TypeState, 100)); err == nil {
		t.Error("accepted events after finish")
	}
	if len(recordsOfKind(t, output, "capture_summary")) != 1 {
		t.Error("Finish emitted a duplicate summary")
	}
}
