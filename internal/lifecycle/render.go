package lifecycle

import (
	"fmt"
	"strings"
	"time"
)

func (t *Tracker) emit(record any) error {
	if t.encoder != nil {
		return t.encoder.Encode(record)
	}
	var line string
	switch r := record.(type) {
	case eventRecord:
		var detail strings.Builder
		fmt.Fprintf(&detail, "%s +%s %s <- %s %s", r.ConnectionID, duration(r.ElapsedNS), r.Local, r.Remote, r.Event)
		if r.State != "" {
			fmt.Fprintf(&detail, " %s -> %s", r.PreviousState, r.State)
		}
		if r.Actor != nil {
			fmt.Fprintf(&detail, " actor=%s", actorText(r.Actor))
		}
		if r.FD != nil {
			fmt.Fprintf(&detail, " fd=%d", *r.FD)
		}
		if r.Result != nil {
			fmt.Fprintf(&detail, " result=%d", *r.Result)
		}
		if r.Error != nil {
			fmt.Fprintf(&detail, " errno=%d(%s) transient=%t", r.Error.Errno, r.Error.Message, r.Error.Transient)
		}
		if r.EOF {
			detail.WriteString(" eof")
		}
		fmt.Fprintf(&detail, " rx=%d tx=%d", r.RXBytes, r.TXBytes)
		if r.PartialStart {
			detail.WriteString(" partial_start")
		}
		if r.LateAfterSummary {
			fmt.Fprintf(&detail, " late_after_summary=%s", r.PriorSummaryReason)
		}
		line = detail.String()
	case connectionSummary:
		accepted := "not_observed"
		if r.AcceptingProcess != nil {
			accepted = actorText(r.AcceptingProcess)
		}
		line = fmt.Sprintf("%s summary %s %s <- %s accepted=%s duration=%s first_data=%s first_write=%s rx=%d tx=%d reads=%d writes=%d errors=%d transient_errors=%d retransmits=%d eof=%t partial_start=%t incomplete=%t",
			r.ConnectionID, r.Reason, r.Local, r.Remote, accepted, duration(r.DurationNS), elapsedText(r.FirstDataAfterNS), elapsedText(r.FirstWriteAfterNS), r.RXBytes, r.TXBytes,
			r.ReadCalls, r.WriteCalls, r.Errors, r.TransientErrors, r.Retransmits, r.EOFObserved, r.PartialStart, r.Incomplete)
	case captureSummary:
		line = fmt.Sprintf("capture summary %s events=%d connections=%d closed=%d evicted=%d unfinished=%d late_events=%d dropped_events=%d incomplete=%t",
			r.Reason, r.Events, r.Connections, r.Closed, r.Evicted, r.Unfinished, r.LateEvents, r.DroppedEvents, r.Incomplete)
	default:
		return fmt.Errorf("connection tracker: unsupported output record %T", record)
	}
	_, err := fmt.Fprintln(t.writer, line)
	return err
}

func elapsedText(value *uint64) string {
	if value == nil {
		return "not_observed"
	}
	return duration(*value)
}

func actorText(p *process) string {
	return fmt.Sprintf("%q(pid=%d,tid=%d)", p.Name, p.PID, p.TID)
}

func duration(ns uint64) string {
	if ns > uint64(1<<63-1) {
		return fmt.Sprintf("%dns", ns)
	}
	return time.Duration(ns).String()
}
