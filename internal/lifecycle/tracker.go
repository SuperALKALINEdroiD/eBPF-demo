package lifecycle

import (
	"container/list"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"syscall"
)

type process struct {
	PID  uint32 `json:"pid"`
	TID  uint32 `json:"tid"`
	Name string `json:"name"`
}

type operationError struct {
	Errno     int64  `json:"errno"`
	Message   string `json:"message"`
	Transient bool   `json:"transient"`
}

type eventRecord struct {
	Kind               string          `json:"kind"`
	ConnectionID       string          `json:"connection_id"`
	Event              string          `json:"event"`
	TimestampNS        uint64          `json:"timestamp_ns"`
	ElapsedNS          uint64          `json:"elapsed_ns"`
	Local              string          `json:"local"`
	Remote             string          `json:"remote"`
	PreviousState      string          `json:"previous_state,omitempty"`
	State              string          `json:"state,omitempty"`
	Actor              *process        `json:"actor,omitempty"`
	AcceptingProcess   *process        `json:"accepting_process,omitempty"`
	FD                 *int32          `json:"fd,omitempty"`
	Result             *int64          `json:"result,omitempty"`
	Bytes              uint64          `json:"bytes,omitempty"`
	RXBytes            uint64          `json:"rx_bytes"`
	TXBytes            uint64          `json:"tx_bytes"`
	Error              *operationError `json:"error,omitempty"`
	EOF                bool            `json:"eof,omitempty"`
	PartialStart       bool            `json:"partial_start"`
	LateAfterSummary   bool            `json:"late_after_summary,omitempty"`
	PriorSummaryReason string          `json:"prior_summary_reason,omitempty"`
}

type connectionSummary struct {
	Kind              string   `json:"kind"`
	ConnectionID      string   `json:"connection_id"`
	Reason            string   `json:"reason"`
	Local             string   `json:"local"`
	Remote            string   `json:"remote"`
	StartedNS         uint64   `json:"started_ns"`
	LastEventNS       uint64   `json:"last_event_ns"`
	DurationNS        uint64   `json:"duration_ns"`
	State             string   `json:"state,omitempty"`
	Accepted          bool     `json:"accepted"`
	AcceptingProcess  *process `json:"accepting_process,omitempty"`
	AcceptedAfterNS   *uint64  `json:"accepted_after_ns,omitempty"`
	FirstReadAfterNS  *uint64  `json:"first_read_after_ns,omitempty"`
	FirstWriteAfterNS *uint64  `json:"first_write_after_ns,omitempty"`
	FirstDataAfterNS  *uint64  `json:"first_data_after_ns,omitempty"`
	RXBytes           uint64   `json:"rx_bytes"`
	TXBytes           uint64   `json:"tx_bytes"`
	ReadCalls         uint64   `json:"read_calls"`
	WriteCalls        uint64   `json:"write_calls"`
	Errors            uint64   `json:"errors"`
	TransientErrors   uint64   `json:"transient_errors"`
	Retransmits       uint64   `json:"retransmits"`
	EOFObserved       bool     `json:"eof_observed"`
	PartialStart      bool     `json:"partial_start"`
	Incomplete        bool     `json:"incomplete"`
}

type captureSummary struct {
	Kind          string `json:"kind"`
	Reason        string `json:"reason"`
	Events        uint64 `json:"events"`
	Connections   uint64 `json:"connections"`
	Closed        uint64 `json:"closed"`
	Evicted       uint64 `json:"evicted"`
	Unfinished    uint64 `json:"unfinished"`
	LateEvents    uint64 `json:"late_events"`
	DroppedEvents uint64 `json:"dropped_events"`
	Incomplete    bool   `json:"incomplete"`
}

type connection struct {
	id                                                                  uint64
	local, remote                                                       string
	started, last, lastStateAt                                          uint64
	state                                                               uint32
	acceptor                                                            *process
	acceptedAt, firstReadAt, firstWriteAt, firstDataAt                  uint64
	rx, tx, readCalls, writeCalls, errors, transientErrors, retransmits uint64
	eof, partial                                                        bool
}

type tombstone struct {
	started uint64
	reason  string
}

// Tracker is a single-consumer, bounded stream processor. It retains at most
// maxConnections active connections and the same number of summarized IDs.
// Events arriving after a summary are rendered but cannot revise that summary.
// Extremely delayed events beyond the bounded ID history can appear as partial
// connections again. Counters are observations, not proof that no event was lost.
type Tracker struct {
	writer         io.Writer
	encoder        *json.Encoder
	maxConnections int
	active         map[uint64]*list.Element
	order          list.List
	tombstones     map[uint64]tombstone
	tombstoneIDs   []uint64
	tombstoneNext  int
	stats          captureSummary
	finished       bool
}

func NewTracker(writer io.Writer, format string, maxConnections int) (*Tracker, error) {
	if writer == nil {
		return nil, errors.New("connection tracker: output writer is required")
	}
	if format != "text" && format != "json" {
		return nil, fmt.Errorf("connection tracker: unsupported format %q (want text or json)", format)
	}
	if maxConnections <= 0 {
		return nil, errors.New("connection tracker: max connections must be positive")
	}
	t := &Tracker{
		writer: writer, maxConnections: maxConnections,
		active: make(map[uint64]*list.Element), tombstones: make(map[uint64]tombstone),
		stats: captureSummary{Kind: "capture_summary"},
	}
	if format == "json" {
		t.encoder = json.NewEncoder(writer)
	}
	return t, nil
}

func (t *Tracker) Handle(e Event) error {
	if t.finished {
		return errors.New("connection tracker: capture already finished")
	}
	if err := e.validate(); err != nil {
		return err
	}
	t.stats.Events++
	if prior, ok := t.tombstones[e.ID]; ok {
		t.stats.LateEvents++
		record := newEventRecord(e, prior.started)
		record.LateAfterSummary = true
		record.PriorSummaryReason = prior.reason
		return t.emit(record)
	}
	entry := t.active[e.ID]
	if entry == nil {
		if len(t.active) == t.maxConnections {
			if err := t.summarize(t.order.Front(), "evicted"); err != nil {
				return err
			}
		}
		started := e.StartedNS
		if started == 0 || started > e.TimestampNS {
			started = e.TimestampNS
		}
		c := &connection{
			id: e.ID, local: e.LocalEndpoint(), remote: e.RemoteEndpoint(), started: started,
			partial: e.Flags&FlagPartialStart != 0 || e.StartedNS == 0 || e.Type != TypeState,
		}
		entry = t.order.PushBack(c)
		t.active[e.ID] = entry
		t.stats.Connections++
	} else {
		t.order.MoveToBack(entry)
	}
	c := entry.Value.(*connection)
	c.update(e)
	record := newEventRecord(e, c.started)
	record.PartialStart = c.partial
	record.AcceptingProcess = c.acceptor
	record.RXBytes, record.TXBytes = c.rx, c.tx
	if err := t.emit(record); err != nil {
		return err
	}
	if e.Type == TypeState && e.NewState == 7 {
		return t.summarize(entry, "closed")
	}
	return nil
}

func (c *connection) update(e Event) {
	if e.StartedNS != 0 && e.StartedNS < c.started {
		c.started = e.StartedNS
	}
	if e.TimestampNS < c.started {
		c.started = e.TimestampNS
	}
	c.last = max(c.last, e.TimestampNS)
	c.rx, c.tx = max(c.rx, e.RXBytes), max(c.tx, e.TXBytes)
	c.partial = c.partial || e.Flags&FlagPartialStart != 0
	switch e.Type {
	case TypeState:
		if e.TimestampNS >= c.lastStateAt {
			c.state, c.lastStateAt = e.NewState, e.TimestampNS
		}
	case TypeAccept:
		if e.Result >= 0 && (c.acceptor == nil || e.TimestampNS < c.acceptedAt) {
			c.acceptor, c.acceptedAt = eventActor(e), e.TimestampNS
		}
	case TypeRead:
		c.readCalls++
		if e.Result > 0 && (c.firstReadAt == 0 || e.TimestampNS < c.firstReadAt) {
			c.firstReadAt = e.TimestampNS
		}
		c.eof = c.eof || e.Result == 0
	case TypeWrite:
		c.writeCalls++
		if e.Result > 0 && (c.firstWriteAt == 0 || e.TimestampNS < c.firstWriteAt) {
			c.firstWriteAt = e.TimestampNS
		}
	case TypeRetransmit:
		c.retransmits++
	case TypeIngress:
		if c.firstDataAt == 0 || e.TimestampNS < c.firstDataAt {
			c.firstDataAt = e.TimestampNS
		}
	}
	if e.Result < 0 {
		if transient(e.Result) {
			c.transientErrors++
		} else {
			c.errors++
		}
	}
}

// Finish summarizes connections that have not closed and reports BPF event
// drops. A nonzero dropped count means earlier summaries may also be incomplete.
func (t *Tracker) Finish(reason string, dropped uint64) error {
	if t.finished {
		return nil
	}
	if reason == "" {
		reason = "shutdown"
	}
	for t.order.Len() > 0 {
		if err := t.summarize(t.order.Front(), reason); err != nil {
			return err
		}
	}
	t.stats.Reason = reason
	t.stats.DroppedEvents = dropped
	t.stats.Incomplete = dropped > 0 || t.stats.Evicted > 0 || t.stats.Unfinished > 0 || t.stats.LateEvents > 0 || t.stats.Incomplete
	if err := t.emit(t.stats); err != nil {
		return err
	}
	t.finished = true
	return nil
}

func (t *Tracker) summarize(entry *list.Element, reason string) error {
	c := entry.Value.(*connection)
	r := connectionSummary{
		Kind: "connection_summary", ConnectionID: connectionID(c.id), Reason: reason,
		Local: c.local, Remote: c.remote, StartedNS: c.started, LastEventNS: c.last,
		DurationNS: elapsed(c.last, c.started), Accepted: c.acceptor != nil, AcceptingProcess: c.acceptor,
		RXBytes: c.rx, TXBytes: c.tx, ReadCalls: c.readCalls, WriteCalls: c.writeCalls,
		Errors: c.errors, TransientErrors: c.transientErrors, Retransmits: c.retransmits,
		EOFObserved: c.eof, PartialStart: c.partial, Incomplete: reason != "closed" || c.partial,
	}
	if c.state != 0 {
		r.State = StateName(c.state)
	}
	if c.acceptor != nil {
		value := elapsed(c.acceptedAt, c.started)
		r.AcceptedAfterNS = &value
	}
	if c.firstReadAt != 0 {
		value := elapsed(c.firstReadAt, c.started)
		r.FirstReadAfterNS = &value
	}
	if c.firstWriteAt != 0 {
		value := elapsed(c.firstWriteAt, c.started)
		r.FirstWriteAfterNS = &value
	}
	if c.firstDataAt != 0 {
		value := elapsed(c.firstDataAt, c.started)
		r.FirstDataAfterNS = &value
	}
	if err := t.emit(r); err != nil {
		return err
	}
	switch reason {
	case "closed":
		t.stats.Closed++
	case "evicted":
		t.stats.Evicted++
	default:
		t.stats.Unfinished++
	}
	t.stats.Incomplete = t.stats.Incomplete || r.Incomplete
	t.remember(c.id, tombstone{started: c.started, reason: reason})
	delete(t.active, c.id)
	t.order.Remove(entry)
	return nil
}

func (t *Tracker) remember(id uint64, value tombstone) {
	if len(t.tombstoneIDs) < t.maxConnections {
		t.tombstoneIDs = append(t.tombstoneIDs, id)
	} else {
		delete(t.tombstones, t.tombstoneIDs[t.tombstoneNext])
		t.tombstoneIDs[t.tombstoneNext] = id
		t.tombstoneNext = (t.tombstoneNext + 1) % t.maxConnections
	}
	t.tombstones[id] = value
}

func newEventRecord(e Event, started uint64) eventRecord {
	r := eventRecord{
		Kind: "event", ConnectionID: connectionID(e.ID), TimestampNS: e.TimestampNS,
		ElapsedNS: elapsed(e.TimestampNS, started), Local: e.LocalEndpoint(), Remote: e.RemoteEndpoint(),
		RXBytes: e.RXBytes, TXBytes: e.TXBytes, PartialStart: e.Flags&FlagPartialStart != 0,
	}
	switch e.Type {
	case TypeState:
		r.Event, r.PreviousState, r.State = "state", StateName(e.OldState), StateName(e.NewState)
	case TypeAccept:
		r.Event = "accept"
	case TypeRead:
		r.Event, r.EOF = "read", e.Result == 0
	case TypeWrite:
		r.Event = "write"
	case TypeRetransmit:
		r.Event = "retransmit"
	case TypeIngress:
		r.Event = "first_inbound_data"
	}
	if isSyscall(e.Type) {
		r.Actor = eventActor(e)
		r.FD, r.Result = &e.FD, &e.Result
		if e.Result >= 0 && (e.Type == TypeRead || e.Type == TypeWrite) {
			r.Bytes = uint64(e.Result)
		}
	}
	if e.Result < 0 {
		r.Result = &e.Result
		r.Error = &operationError{Errno: -e.Result, Message: syscall.Errno(-e.Result).Error(), Transient: transient(e.Result)}
	}
	return r
}

func eventActor(e Event) *process { return &process{PID: e.PID, TID: e.TID, Name: e.ProcessName()} }
func isSyscall(kind uint32) bool  { return kind == TypeAccept || kind == TypeRead || kind == TypeWrite }
func transient(result int64) bool {
	return result == -int64(syscall.EAGAIN) || result == -int64(syscall.EINTR)
}
func connectionID(id uint64) string { return fmt.Sprintf("%016x", id) }
func elapsed(timestamp, started uint64) uint64 {
	if timestamp <= started {
		return 0
	}
	return timestamp - started
}
