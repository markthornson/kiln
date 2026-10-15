// Package network connects containers to the host: each container gets its
// own network namespace with a veth pair, whose host end is attached to the
// kiln0 bridge and whose container end is eth0 with an address from the
// bridge's subnet.
//
//	host                         container netns
//	kiln0 10.88.0.1/24 ── kv<id> ═══ eth0 10.88.0.N/24 (default via 10.88.0.1)
package network

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"
	"syscall"

	"github.com/markthornson/kiln/internal/netlink"
)

const (
	Bridge        = "kiln0"
	ContainerLink = "eth0"
	maxLinkName   = 15 // IFNAMSIZ - 1
)

// Subnet and LeaseDir are variables so tests and future config can change them.
var (
	Subnet   = netip.MustParsePrefix("10.88.0.0/24")
	LeaseDir = "/run/kiln/ipam"
)

// EnsureBridge creates the bridge with the gateway address, if missing, and
// brings it up. It is safe to call concurrently and repeatedly.
func EnsureBridge() error {
	c, err := netlink.Dial()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.CreateBridge(Bridge); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("create bridge %s: %w", Bridge, err)
	}
	gw := netip.PrefixFrom(Gateway(Subnet), Subnet.Bits())
	if err := c.AddAddr(Bridge, gw); err != nil && !errors.Is(err, syscall.EEXIST) {
		return fmt.Errorf("address bridge %s: %w", Bridge, err)
	}
	if err := c.SetUp(Bridge); err != nil {
		return fmt.Errorf("bring up %s: %w", Bridge, err)
	}
	return nil
}

// Attachment is the host-side network state of one container.
type Attachment struct {
	HostLink string
	Spec     Spec
}

// Attach leases an address and creates a veth pair whose eth0 end lives in
// the network namespace of process pid. Call EnsureBridge first.
func Attach(id string, pid int) (*Attachment, error) {
	leases := Leases{Dir: LeaseDir, Subnet: Subnet}
	addr, err := leases.Allocate()
	if err != nil {
		return nil, err
	}
	a := &Attachment{
		HostLink: hostLinkName(id),
		Spec:     Spec{Addr: netip.PrefixFrom(addr, Subnet.Bits()), Gateway: Gateway(Subnet)},
	}
	if err := a.create(pid); err != nil {
		a.Detach()
		return nil, err
	}
	return a, nil
}

func (a *Attachment) create(pid int) error {
	c, err := netlink.Dial()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.CreateVeth(a.HostLink, ContainerLink, pid); err != nil {
		return fmt.Errorf("create veth %s: %w", a.HostLink, err)
	}
	if err := c.SetMaster(a.HostLink, Bridge); err != nil {
		return fmt.Errorf("attach %s to %s: %w", a.HostLink, Bridge, err)
	}
	if err := c.SetUp(a.HostLink); err != nil {
		return fmt.Errorf("bring up %s: %w", a.HostLink, err)
	}
	return nil
}

// Detach deletes the host end of the veth pair (the kernel also removes it
// when the container's namespace dies) and releases the address.
func (a *Attachment) Detach() error {
	var first error
	if c, err := netlink.Dial(); err != nil {
		first = err
	} else {
		if err := c.DeleteLink(a.HostLink); err != nil && !errors.Is(err, syscall.ENODEV) {
			first = fmt.Errorf("delete %s: %w", a.HostLink, err)
		}
		c.Close()
	}
	leases := Leases{Dir: LeaseDir, Subnet: Subnet}
	if err := leases.Release(a.Spec.Addr.Addr()); err != nil && first == nil {
		first = err
	}
	return first
}

func hostLinkName(id string) string {
	name := "kv" + id
	if len(name) > maxLinkName {
		name = name[:maxLinkName]
	}
	return name
}

// Spec is what the container needs to configure its side: its address and
// gateway. The zero Spec means no network beyond loopback.
type Spec struct {
	Addr    netip.Prefix
	Gateway netip.Addr
}

// String encodes s for the parent-to-init pipe, e.g. "10.88.0.2/24 10.88.0.1"
// or "none".
func (s Spec) String() string {
	if !s.Addr.IsValid() {
		return "none"
	}
	return s.Addr.String() + " " + s.Gateway.String()
}

// ParseSpec decodes the output of Spec.String.
func ParseSpec(line string) (Spec, error) {
	if line == "none" {
		return Spec{}, nil
	}
	addr, gw, ok := strings.Cut(line, " ")
	if !ok {
		return Spec{}, fmt.Errorf("network: bad spec %q", line)
	}
	p, err := netip.ParsePrefix(addr)
	if err != nil {
		return Spec{}, fmt.Errorf("network: bad spec %q: %w", line, err)
	}
	g, err := netip.ParseAddr(gw)
	if err != nil {
		return Spec{}, fmt.Errorf("network: bad spec %q: %w", line, err)
	}
	if !p.Addr().Is4() || !g.Is4() || !p.Contains(g) || p.Addr() == g {
		return Spec{}, fmt.Errorf("network: bad spec %q: need distinct IPv4 address and gateway in one subnet", line)
	}
	return Spec{Addr: p, Gateway: g}, nil
}

// ReadSpec reads one Spec line from r.
func ReadSpec(r io.Reader) (Spec, error) {
	line, err := bufio.NewReader(r).ReadString('\n')
	if err != nil {
		return Spec{}, fmt.Errorf("network: read spec: %w", err)
	}
	return ParseSpec(strings.TrimSuffix(line, "\n"))
}

// ConfigureContainer runs inside the container's network namespace. It brings
// up loopback and, if s has an address, configures eth0 and the default route.
func ConfigureContainer(s Spec) error {
	c, err := netlink.Dial()
	if err != nil {
		return err
	}
	defer c.Close()
	if err := c.SetUp("lo"); err != nil {
		return fmt.Errorf("bring up lo: %w", err)
	}
	if !s.Addr.IsValid() {
		return nil
	}
	if err := c.AddAddr(ContainerLink, s.Addr); err != nil {
		return fmt.Errorf("address %s: %w", ContainerLink, err)
	}
	if err := c.SetUp(ContainerLink); err != nil {
		return fmt.Errorf("bring up %s: %w", ContainerLink, err)
	}
	if err := c.AddDefaultRoute(ContainerLink, s.Gateway); err != nil {
		return fmt.Errorf("default route: %w", err)
	}
	return nil
}
