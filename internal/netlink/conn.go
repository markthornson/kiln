package netlink

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

// Attribute and message constants missing from package syscall
// (linux/if_link.h, linux/veth.h).
const (
	iflaInfoKind = 1
	iflaInfoData = 2
	vethInfoPeer = 1
)

// Conn is a NETLINK_ROUTE socket bound to the network namespace of the thread
// that opened it.
type Conn struct {
	fd  int
	seq uint32
}

// Dial opens a route netlink socket.
func Dial() (*Conn, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC, syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("netlink socket: %w", err)
	}
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("netlink bind: %w", err)
	}
	return &Conn{fd: fd}, nil
}

// Close closes the socket.
func (c *Conn) Close() error { return syscall.Close(c.fd) }

// request sends one message and waits for the kernel's acknowledgement.
// Kernel errors are returned as syscall.Errno, so callers can test them with
// errors.Is (e.g. syscall.EEXIST).
func (c *Conn) request(typ, flags uint16, body []byte) error {
	c.seq++
	msg := EncodeMessage(Message{Type: typ, Flags: flags | syscall.NLM_F_REQUEST | syscall.NLM_F_ACK, Seq: c.seq, Data: body})
	if err := syscall.Sendto(c.fd, msg, 0, &syscall.SockaddrNetlink{Family: syscall.AF_NETLINK}); err != nil {
		return fmt.Errorf("netlink send: %w", err)
	}
	buf := make([]byte, 1<<16)
	for {
		n, _, err := syscall.Recvfrom(c.fd, buf, 0)
		if err != nil {
			return fmt.Errorf("netlink recv: %w", err)
		}
		msgs, err := ParseMessages(buf[:n])
		if err != nil {
			return err
		}
		for _, m := range msgs {
			if m.Seq != c.seq || m.Type != syscall.NLMSG_ERROR {
				continue
			}
			return ackError(m.Data)
		}
	}
}

// ackError decodes an NLMSG_ERROR payload: a negative errno, 0 for success.
func ackError(data []byte) error {
	if len(data) < 4 {
		return errors.New("netlink: truncated ack")
	}
	if errno := int32(native.Uint32(data)); errno != 0 {
		return syscall.Errno(-errno)
	}
	return nil
}

// ifinfomsg builds the fixed header of link messages.
func ifinfomsg(index int, flags, change uint32) []byte {
	b := make([]byte, syscall.SizeofIfInfomsg)
	b[0] = syscall.AF_UNSPEC
	native.PutUint32(b[4:], uint32(int32(index)))
	native.PutUint32(b[8:], flags)
	native.PutUint32(b[12:], change)
	return b
}

func cstring(s string) []byte { return append([]byte(s), 0) }

func u32(v uint32) []byte {
	b := make([]byte, 4)
	native.PutUint32(b, v)
	return b
}

func linkinfo(kind string, data []Attr) Attr {
	info := []Attr{{Type: iflaInfoKind, Data: []byte(kind)}}
	if data != nil {
		info = append(info, Attr{Type: iflaInfoData, Data: EncodeAttrs(data)})
	}
	return Attr{Type: syscall.IFLA_LINKINFO, Data: EncodeAttrs(info)}
}

// CreateBridge creates a bridge interface (`ip link add NAME type bridge`).
func (c *Conn) CreateBridge(name string) error {
	body := append(ifinfomsg(0, 0, 0), EncodeAttrs([]Attr{
		{Type: syscall.IFLA_IFNAME, Data: cstring(name)},
		linkinfo("bridge", nil),
	})...)
	return c.request(syscall.RTM_NEWLINK, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, body)
}

// CreateVeth creates a veth pair. The peer is created directly inside the
// network namespace of process peerPID, under the name peer.
func (c *Conn) CreateVeth(name, peer string, peerPID int) error {
	peerMsg := append(ifinfomsg(0, 0, 0), EncodeAttrs([]Attr{
		{Type: syscall.IFLA_IFNAME, Data: cstring(peer)},
		{Type: syscall.IFLA_NET_NS_PID, Data: u32(uint32(peerPID))},
	})...)
	body := append(ifinfomsg(0, 0, 0), EncodeAttrs([]Attr{
		{Type: syscall.IFLA_IFNAME, Data: cstring(name)},
		linkinfo("veth", []Attr{{Type: vethInfoPeer, Data: peerMsg}}),
	})...)
	return c.request(syscall.RTM_NEWLINK, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, body)
}

// DeleteLink deletes the named interface. Deleting one end of a veth pair
// deletes both.
func (c *Conn) DeleteLink(name string) error {
	body := append(ifinfomsg(0, 0, 0), EncodeAttrs([]Attr{
		{Type: syscall.IFLA_IFNAME, Data: cstring(name)},
	})...)
	return c.request(syscall.RTM_DELLINK, 0, body)
}

// SetUp brings the named interface up.
func (c *Conn) SetUp(name string) error {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	return c.request(syscall.RTM_NEWLINK, 0, ifinfomsg(ifi.Index, syscall.IFF_UP, syscall.IFF_UP))
}

// SetMaster attaches the named interface to a bridge.
func (c *Conn) SetMaster(name, bridge string) error {
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	br, err := net.InterfaceByName(bridge)
	if err != nil {
		return err
	}
	body := append(ifinfomsg(ifi.Index, 0, 0), EncodeAttrs([]Attr{
		{Type: syscall.IFLA_MASTER, Data: u32(uint32(br.Index))},
	})...)
	return c.request(syscall.RTM_NEWLINK, 0, body)
}

// AddAddr assigns an IPv4 address with prefix length to the named interface.
func (c *Conn) AddAddr(name string, p netip.Prefix) error {
	if !p.Addr().Is4() {
		return fmt.Errorf("netlink: %v is not IPv4", p)
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	b := make([]byte, syscall.SizeofIfAddrmsg)
	b[0] = syscall.AF_INET
	b[1] = byte(p.Bits())
	native.PutUint32(b[4:], uint32(ifi.Index))
	ip := p.Addr().AsSlice()
	body := append(b, EncodeAttrs([]Attr{
		{Type: syscall.IFA_LOCAL, Data: ip},
		{Type: syscall.IFA_ADDRESS, Data: ip},
	})...)
	return c.request(syscall.RTM_NEWADDR, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, body)
}

// AddDefaultRoute adds an IPv4 default route via gw out of the named
// interface.
func (c *Conn) AddDefaultRoute(name string, gw netip.Addr) error {
	if !gw.Is4() {
		return fmt.Errorf("netlink: %v is not IPv4", gw)
	}
	ifi, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	b := make([]byte, syscall.SizeofRtMsg)
	b[0] = syscall.AF_INET
	b[4] = syscall.RT_TABLE_MAIN
	b[5] = syscall.RTPROT_BOOT
	b[6] = syscall.RT_SCOPE_UNIVERSE
	b[7] = syscall.RTN_UNICAST
	body := append(b, EncodeAttrs([]Attr{
		{Type: syscall.RTA_GATEWAY, Data: gw.AsSlice()},
		{Type: syscall.RTA_OIF, Data: u32(uint32(ifi.Index))},
	})...)
	return c.request(syscall.RTM_NEWROUTE, syscall.NLM_F_CREATE|syscall.NLM_F_EXCL, body)
}
