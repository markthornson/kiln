// Package netlink is a minimal rtnetlink client: just enough to create
// bridges and veth pairs, move a veth end into another network namespace,
// and configure addresses and routes. It is what `ip link`/`ip addr`/`ip
// route` do under the hood.
//
// A netlink message is a 16-byte header followed by a family-specific struct
// (ifinfomsg, ifaddrmsg, rtmsg) and then a list of type-length-value
// attributes, each padded to 4 bytes. Attributes can nest: the data of one is
// itself a list of attributes.
package netlink

import (
	"encoding/binary"
	"errors"
	"fmt"
)

var native = binary.NativeEndian

// Attr is one rtattr. Nested attributes are encoded into Data with
// EncodeAttrs.
type Attr struct {
	Type uint16
	Data []byte
}

const maxAttrData = 0xffff - 4

func align4(n int) int { return (n + 3) &^ 3 }

// EncodeAttrs serializes attrs, padding each to 4 bytes.
// It panics if an attribute's data exceeds what the 16-bit length can hold;
// every attribute kiln sends is small and fixed.
func EncodeAttrs(attrs []Attr) []byte {
	var b []byte
	for _, a := range attrs {
		if len(a.Data) > maxAttrData {
			panic(fmt.Sprintf("netlink: attribute %d too long (%d bytes)", a.Type, len(a.Data)))
		}
		hdr := make([]byte, 4)
		native.PutUint16(hdr[0:], uint16(4+len(a.Data)))
		native.PutUint16(hdr[2:], a.Type)
		b = append(b, hdr...)
		b = append(b, a.Data...)
		b = append(b, make([]byte, align4(len(a.Data))-len(a.Data))...)
	}
	return b
}

// ParseAttrs splits b into attributes. Padding after the last attribute may
// be absent.
func ParseAttrs(b []byte) ([]Attr, error) {
	var attrs []Attr
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, errors.New("netlink: truncated attribute header")
		}
		n := int(native.Uint16(b[0:]))
		if n < 4 || n > len(b) {
			return nil, fmt.Errorf("netlink: attribute length %d out of range (have %d bytes)", n, len(b))
		}
		attrs = append(attrs, Attr{Type: native.Uint16(b[2:]), Data: b[4:n]})
		b = b[min(align4(n), len(b)):]
	}
	return attrs, nil
}

// Message is one netlink message: header fields plus payload.
type Message struct {
	Type  uint16
	Flags uint16
	Seq   uint32
	PID   uint32
	Data  []byte
}

const headerLen = 16

// EncodeMessage serializes m with its header.
func EncodeMessage(m Message) []byte {
	b := make([]byte, headerLen, headerLen+align4(len(m.Data)))
	native.PutUint32(b[0:], uint32(headerLen+len(m.Data)))
	native.PutUint16(b[4:], m.Type)
	native.PutUint16(b[6:], m.Flags)
	native.PutUint32(b[8:], m.Seq)
	native.PutUint32(b[12:], m.PID)
	b = append(b, m.Data...)
	return append(b, make([]byte, align4(len(m.Data))-len(m.Data))...)
}

// ParseMessages splits a datagram received from the kernel into messages.
func ParseMessages(b []byte) ([]Message, error) {
	var msgs []Message
	for len(b) > 0 {
		if len(b) < headerLen {
			return nil, errors.New("netlink: truncated message header")
		}
		n := int(native.Uint32(b[0:]))
		if n < headerLen || n > len(b) {
			return nil, fmt.Errorf("netlink: message length %d out of range (have %d bytes)", n, len(b))
		}
		msgs = append(msgs, Message{
			Type:  native.Uint16(b[4:]),
			Flags: native.Uint16(b[6:]),
			Seq:   native.Uint32(b[8:]),
			PID:   native.Uint32(b[12:]),
			Data:  b[headerLen:n],
		})
		b = b[min(align4(n), len(b)):]
	}
	return msgs, nil
}
