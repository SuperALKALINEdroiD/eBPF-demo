package lifecycle

import (
	"encoding/binary"
	"testing"
)

func TestDecodeWireLayoutIPv4(t *testing.T) {
	raw := make([]byte, EventSize)
	binary.LittleEndian.PutUint64(raw[0:8], 9876543210)
	binary.LittleEndian.PutUint64(raw[8:16], 0xfedcba9876543210)
	binary.LittleEndian.PutUint64(raw[16:24], 9876540000)
	binary.LittleEndian.PutUint64(raw[24:32], 1234)
	binary.LittleEndian.PutUint64(raw[32:40], 5678)
	binary.LittleEndian.PutUint64(raw[40:48], ^uint64(10))
	binary.LittleEndian.PutUint32(raw[48:52], TypeRead)
	binary.LittleEndian.PutUint32(raw[52:56], 1001)
	binary.LittleEndian.PutUint32(raw[56:60], 1002)
	binary.LittleEndian.PutUint32(raw[60:64], 3)
	binary.LittleEndian.PutUint32(raw[64:68], 1)
	binary.LittleEndian.PutUint32(raw[68:72], ^uint32(0))
	binary.LittleEndian.PutUint16(raw[72:74], 2)
	binary.LittleEndian.PutUint16(raw[74:76], 8080)
	binary.LittleEndian.PutUint16(raw[76:78], 54321)
	binary.LittleEndian.PutUint16(raw[78:80], FlagPartialStart)
	copy(raw[80:96], []byte{127, 0, 0, 1})
	copy(raw[96:112], []byte{192, 0, 2, 10})
	copy(raw[112:128], "api-worker")
	e, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if e.TimestampNS != 9876543210 || e.ID != 0xfedcba9876543210 || e.StartedNS != 9876540000 || e.RXBytes != 1234 || e.TXBytes != 5678 {
		t.Fatalf("64-bit fields decoded incorrectly: %+v", e)
	}
	if e.Result != -11 || e.Type != TypeRead || e.PID != 1001 || e.TID != 1002 || e.OldState != 3 || e.NewState != 1 || e.FD != -1 || e.Flags != FlagPartialStart {
		t.Fatalf("scalar fields decoded incorrectly: %+v", e)
	}
	if e.LocalEndpoint() != "127.0.0.1:8080" || e.RemoteEndpoint() != "192.0.2.10:54321" || e.ProcessName() != "api-worker" {
		t.Fatalf("endpoint or process fields decoded incorrectly: %+v", e)
	}
}

func TestDecodeIPv6AndFullLengthComm(t *testing.T) {
	raw := make([]byte, EventSize)
	binary.LittleEndian.PutUint32(raw[48:52], TypeAccept)
	binary.LittleEndian.PutUint16(raw[72:74], 10)
	binary.LittleEndian.PutUint16(raw[74:76], 443)
	binary.LittleEndian.PutUint16(raw[76:78], 60000)
	raw[95] = 1
	copy(raw[96:112], []byte{0x20, 0x01, 0x0d, 0xb8})
	raw[111] = 2
	copy(raw[112:128], "1234567890abcdef")
	e, err := Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	if e.LocalEndpoint() != "[::1]:443" || e.RemoteEndpoint() != "[2001:db8::2]:60000" || e.ProcessName() != "1234567890abcdef" {
		t.Fatalf("unexpected IPv6 decode: %+v", e)
	}
}

func TestDecodeRejectsMalformedEvents(t *testing.T) {
	for _, length := range []int{0, 127, 129} {
		if _, err := Decode(make([]byte, length)); err == nil {
			t.Errorf("accepted %d-byte record", length)
		}
	}
	raw := make([]byte, EventSize)
	binary.LittleEndian.PutUint32(raw[48:52], TypeState)
	binary.LittleEndian.PutUint16(raw[72:74], 1)
	if _, err := Decode(raw); err == nil {
		t.Error("accepted non-IP address family")
	}
	binary.LittleEndian.PutUint16(raw[72:74], 2)
	for _, kind := range []uint32{0, 7, ^uint32(0)} {
		binary.LittleEndian.PutUint32(raw[48:52], kind)
		if _, err := Decode(raw); err == nil {
			t.Errorf("accepted unknown event type %d", kind)
		}
	}
}
