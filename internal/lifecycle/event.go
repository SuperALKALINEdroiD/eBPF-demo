// Package lifecycle correlates TCP socket events into connection timelines.
// A TCP connection is not an individual HTTP request: keep-alive, multiplexing,
// TLS, and work performed after an I/O syscall are outside this event stream.
package lifecycle

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
)

const (
	EventSize               = 128
	TypeState        uint32 = 1
	TypeAccept       uint32 = 2
	TypeRead         uint32 = 3
	TypeWrite        uint32 = 4
	TypeRetransmit   uint32 = 5
	TypeIngress      uint32 = 6
	FlagPartialStart uint16 = 1
)

// Event is the fixed-width, little-endian event emitted by the BPF program.
// Addresses contain network-order bytes; port fields contain host-order values.
// PID, TID, and Comm identify the syscall actor, never a network-state callback.
type Event struct {
	TimestampNS uint64
	ID          uint64
	StartedNS   uint64
	RXBytes     uint64
	TXBytes     uint64
	Result      int64
	Type        uint32
	PID         uint32
	TID         uint32
	OldState    uint32
	NewState    uint32
	FD          int32
	Family      uint16
	LocalPort   uint16
	RemotePort  uint16
	Flags       uint16
	LocalAddr   [16]byte
	RemoteAddr  [16]byte
	Comm        [16]byte
}

func Decode(raw []byte) (Event, error) {
	if len(raw) != EventSize {
		return Event{}, fmt.Errorf("connection event: got %d bytes, want %d", len(raw), EventSize)
	}
	u64, u32, u16 := binary.LittleEndian.Uint64, binary.LittleEndian.Uint32, binary.LittleEndian.Uint16
	e := Event{
		TimestampNS: u64(raw[0:8]), ID: u64(raw[8:16]), StartedNS: u64(raw[16:24]),
		RXBytes: u64(raw[24:32]), TXBytes: u64(raw[32:40]), Result: int64(u64(raw[40:48])),
		Type: u32(raw[48:52]), PID: u32(raw[52:56]), TID: u32(raw[56:60]),
		OldState: u32(raw[60:64]), NewState: u32(raw[64:68]), FD: int32(u32(raw[68:72])),
		Family: u16(raw[72:74]), LocalPort: u16(raw[74:76]), RemotePort: u16(raw[76:78]), Flags: u16(raw[78:80]),
	}
	copy(e.LocalAddr[:], raw[80:96])
	copy(e.RemoteAddr[:], raw[96:112])
	copy(e.Comm[:], raw[112:128])
	if err := e.validate(); err != nil {
		return Event{}, err
	}
	return e, nil
}

func (e Event) validate() error {
	if e.Family != 2 && e.Family != 10 {
		return fmt.Errorf("connection event: unsupported address family %d", e.Family)
	}
	if e.Type < TypeState || e.Type > TypeIngress {
		return fmt.Errorf("connection event: unknown type %d", e.Type)
	}
	return nil
}

func (e Event) LocalEndpoint() string  { return endpoint(e.Family, e.LocalAddr, e.LocalPort) }
func (e Event) RemoteEndpoint() string { return endpoint(e.Family, e.RemoteAddr, e.RemotePort) }

func endpoint(family uint16, raw [16]byte, port uint16) string {
	addr := netip.AddrFrom16(raw)
	if family == 2 {
		addr = netip.AddrFrom4([4]byte(raw[:4]))
	}
	return netip.AddrPortFrom(addr, port).String()
}

func (e Event) ProcessName() string {
	if end := bytes.IndexByte(e.Comm[:], 0); end >= 0 {
		return string(e.Comm[:end])
	}
	return string(e.Comm[:])
}

func StateName(state uint32) string {
	switch state {
	case 1:
		return "ESTABLISHED"
	case 2:
		return "SYN_SENT"
	case 3:
		return "SYN_RECV"
	case 4:
		return "FIN_WAIT1"
	case 5:
		return "FIN_WAIT2"
	case 6:
		return "TIME_WAIT"
	case 7:
		return "CLOSE"
	case 8:
		return "CLOSE_WAIT"
	case 9:
		return "LAST_ACK"
	case 10:
		return "LISTEN"
	case 11:
		return "CLOSING"
	case 12:
		return "NEW_SYN_RECV"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", state)
	}
}
