package netlink

import (
	"bytes"
	"reflect"
	"syscall"
	"testing"
)

func TestEncodeAttrs(t *testing.T) {
	got := EncodeAttrs([]Attr{{Type: 3, Data: []byte("eth0\x00")}, {Type: 10, Data: []byte{7, 0, 0, 0}}})
	want := []byte{
		9, 0, 3, 0, 'e', 't', 'h', '0', 0, 0, 0, 0, // len 9, padded to 12
		8, 0, 10, 0, 7, 0, 0, 0,
	}
	if !bytes.Equal(got, want) {
		t.Errorf("EncodeAttrs = %v, want %v", got, want)
	}
}

func TestParseAttrsErrors(t *testing.T) {
	for _, b := range [][]byte{
		{1, 0},             // short header
		{3, 0, 1, 0},       // length below header size
		{9, 0, 1, 0, 1, 2}, // length beyond buffer
	} {
		if _, err := ParseAttrs(b); err == nil {
			t.Errorf("ParseAttrs(%v) succeeded, want error", b)
		}
	}
}

func TestAckError(t *testing.T) {
	if err := ackError([]byte{0, 0, 0, 0}); err != nil {
		t.Errorf("ack 0: %v", err)
	}
	b := make([]byte, 4)
	errno := -int32(syscall.EEXIST)
	native.PutUint32(b, uint32(errno))
	if err := ackError(b); err != syscall.EEXIST {
		t.Errorf("ack -EEXIST = %v", err)
	}
	if err := ackError([]byte{1}); err == nil {
		t.Error("truncated ack accepted")
	}
}

func FuzzAttrsRoundTrip(f *testing.F) {
	f.Add(EncodeAttrs([]Attr{{Type: 3, Data: []byte("kiln0\x00")}}))
	f.Add(EncodeAttrs([]Attr{{Type: 18, Data: EncodeAttrs([]Attr{{Type: 1, Data: []byte("veth")}})}}))
	f.Add([]byte{5, 0, 1, 0, 'x'}) // unpadded final attribute
	f.Fuzz(func(t *testing.T, b []byte) {
		attrs, err := ParseAttrs(b)
		if err != nil {
			return
		}
		again, err := ParseAttrs(EncodeAttrs(attrs))
		if err != nil {
			t.Fatalf("re-parse: %v", err)
		}
		if !attrsEqual(attrs, again) {
			t.Fatalf("round trip changed attrs:\n got %v\nwant %v", again, attrs)
		}
	})
}

func FuzzMessagesRoundTrip(f *testing.F) {
	f.Add(EncodeMessage(Message{Type: 2, Seq: 1, Data: []byte{0, 0, 0, 0}}))
	f.Add(append(EncodeMessage(Message{Type: 16, Data: []byte("abc")}), EncodeMessage(Message{Type: 3})...))
	f.Fuzz(func(t *testing.T, b []byte) {
		msgs, err := ParseMessages(b)
		if err != nil {
			return
		}
		var enc []byte
		for _, m := range msgs {
			enc = append(enc, EncodeMessage(m)...)
		}
		again, err := ParseMessages(enc)
		if err != nil {
			t.Fatalf("re-parse: %v", err)
		}
		if len(again) != len(msgs) {
			t.Fatalf("got %d messages, want %d", len(again), len(msgs))
		}
		for i := range msgs {
			a, b := msgs[i], again[i]
			if a.Type != b.Type || a.Flags != b.Flags || a.Seq != b.Seq || a.PID != b.PID || !bytes.Equal(a.Data, b.Data) {
				t.Fatalf("message %d changed:\n got %+v\nwant %+v", i, b, a)
			}
		}
	})
}

func attrsEqual(a, b []Attr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Type != b[i].Type || !bytes.Equal(a[i].Data, b[i].Data) {
			return false
		}
	}
	return true
}

// TestVethRequestShape checks the nesting the kernel expects for a veth with
// its peer in another namespace: IFLA_LINKINFO{KIND, DATA{PEER{ifinfomsg, attrs}}}.
func TestVethRequestShape(t *testing.T) {
	peer := append(ifinfomsg(0, 0, 0), EncodeAttrs([]Attr{
		{Type: syscall.IFLA_IFNAME, Data: cstring("eth0")},
		{Type: syscall.IFLA_NET_NS_PID, Data: u32(42)},
	})...)
	li := linkinfo("veth", []Attr{{Type: vethInfoPeer, Data: peer}})

	info, err := ParseAttrs(li.Data)
	if err != nil {
		t.Fatal(err)
	}
	if len(info) != 2 || string(info[0].Data) != "veth" || info[1].Type != iflaInfoData {
		t.Fatalf("linkinfo = %v", info)
	}
	data, err := ParseAttrs(info[1].Data)
	if err != nil || len(data) != 1 || data[0].Type != vethInfoPeer {
		t.Fatalf("info data = %v, %v", data, err)
	}
	peerAttrs, err := ParseAttrs(data[0].Data[syscall.SizeofIfInfomsg:])
	if err != nil {
		t.Fatal(err)
	}
	want := []Attr{
		{Type: syscall.IFLA_IFNAME, Data: []byte("eth0\x00")},
		{Type: syscall.IFLA_NET_NS_PID, Data: u32(42)},
	}
	if !reflect.DeepEqual(peerAttrs, want) {
		t.Errorf("peer attrs = %v, want %v", peerAttrs, want)
	}
}
