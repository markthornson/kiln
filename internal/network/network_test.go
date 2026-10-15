package network

import (
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestPick(t *testing.T) {
	subnet := netip.MustParsePrefix("10.88.0.0/30") // .0 net, .1 gw, .2 host, .3 broadcast
	a, ok := pick(subnet, func(netip.Addr) bool { return false })
	if !ok || a != netip.MustParseAddr("10.88.0.2") {
		t.Fatalf("pick = %v, %v; want 10.88.0.2", a, ok)
	}
	if _, ok := pick(subnet, func(netip.Addr) bool { return true }); ok {
		t.Fatal("pick succeeded on a full subnet")
	}
}

// FuzzPick: for any subnet size and set of used addresses, the result is a
// usable host address that is not in use, and pick fails only when every
// usable address is taken.
func FuzzPick(f *testing.F) {
	f.Add(uint8(24), []byte{2, 3, 4})
	f.Add(uint8(30), []byte{})
	f.Add(uint8(29), []byte{2, 3, 4, 5, 6})
	f.Fuzz(func(t *testing.T, bits uint8, used []byte) {
		bits = 24 + bits%7 // /24 .. /30
		subnet := netip.PrefixFrom(netip.MustParseAddr("10.88.0.0"), int(bits))
		inUse := map[netip.Addr]bool{}
		for _, b := range used {
			inUse[netip.AddrFrom4([4]byte{10, 88, 0, b})] = true
		}
		a, ok := pick(subnet, func(a netip.Addr) bool { return inUse[a] })

		size := 1 << (32 - int(bits))
		var free int
		for i := 2; i < size-1; i++ {
			if !inUse[netip.AddrFrom4([4]byte{10, 88, 0, byte(i)})] {
				free++
			}
		}
		if !ok {
			if free > 0 {
				t.Fatalf("pick failed with %d free addresses in %v", free, subnet)
			}
			return
		}
		last := a.As4()[3]
		if !subnet.Contains(a) || last == 0 || last == 1 || int(last) == size-1 || inUse[a] {
			t.Fatalf("pick(%v) = %v: network, gateway, broadcast, outside or in use", subnet, a)
		}
	})
}

// FuzzLeases runs a random sequence of allocations and releases against a
// lease directory and checks it against a simple model: live leases are
// unique and allocation fails only when the subnet is full.
func FuzzLeases(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0})
	f.Add([]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, ops []byte) {
		l := Leases{Dir: t.TempDir(), Subnet: netip.MustParsePrefix("10.88.0.0/28")} // 13 usable
		const capacity = 13
		live := map[netip.Addr]bool{}
		var order []netip.Addr
		for _, op := range ops {
			if op%2 == 0 || len(order) == 0 {
				a, err := l.Allocate()
				if errors.Is(err, ErrExhausted) {
					if len(live) < capacity {
						t.Fatalf("exhausted with %d/%d leased", len(live), capacity)
					}
					continue
				}
				if err != nil {
					t.Fatal(err)
				}
				if live[a] {
					t.Fatalf("%v leased twice", a)
				}
				live[a] = true
				order = append(order, a)
				continue
			}
			i := int(op/2) % len(order)
			if err := l.Release(order[i]); err != nil {
				t.Fatal(err)
			}
			delete(live, order[i])
			order = append(order[:i], order[i+1:]...)
		}
	})
}

func TestLeasesConcurrent(t *testing.T) {
	l := Leases{Dir: t.TempDir(), Subnet: netip.MustParsePrefix("10.88.0.0/24")}
	const n = 50
	addrs := make([]netip.Addr, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := l.Allocate()
			if err != nil {
				t.Error(err)
			}
			addrs[i] = a
		}()
	}
	wg.Wait()
	seen := map[netip.Addr]bool{}
	for _, a := range addrs {
		if seen[a] {
			t.Fatalf("%v allocated twice", a)
		}
		seen[a] = true
	}
}

func TestLeasesReclaimDeadOwner(t *testing.T) {
	l := Leases{Dir: t.TempDir(), Subnet: netip.MustParsePrefix("10.88.0.0/30")} // one usable address
	// A lease held by a process that has exited, as after kill -9.
	cmd := exec.Command("true")
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	stale := netip.MustParseAddr("10.88.0.2")
	if err := os.WriteFile(filepath.Join(l.Dir, stale.String()), []byte(strconv.Itoa(cmd.Process.Pid)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := l.Allocate()
	if err != nil || a != stale {
		t.Fatalf("Allocate = %v, %v; want stale lease %v reclaimed", a, err, stale)
	}
	// Now held by us (alive): must not be reclaimed.
	if _, err := l.Allocate(); !errors.Is(err, ErrExhausted) {
		t.Fatalf("second Allocate err = %v, want ErrExhausted", err)
	}
}

func TestSpecRoundTrip(t *testing.T) {
	for _, s := range []Spec{
		{},
		{Addr: netip.MustParsePrefix("10.88.0.2/24"), Gateway: netip.MustParseAddr("10.88.0.1")},
	} {
		got, err := ParseSpec(s.String())
		if err != nil || got != s {
			t.Errorf("ParseSpec(%q) = %+v, %v", s.String(), got, err)
		}
	}
	for _, bad := range []string{"", "10.88.0.2/24", "10.88.0.2/24 10.99.0.1", "10.88.0.1/24 10.88.0.1", "::2/64 ::1", "x y"} {
		if _, err := ParseSpec(bad); err == nil {
			t.Errorf("ParseSpec(%q) succeeded", bad)
		}
	}
}

func FuzzParseSpec(f *testing.F) {
	f.Add("10.88.0.2/24 10.88.0.1")
	f.Add("none")
	f.Fuzz(func(t *testing.T, line string) {
		s, err := ParseSpec(line)
		if err != nil {
			return
		}
		again, err := ParseSpec(s.String())
		if err != nil || again != s {
			t.Fatalf("ParseSpec(%q) -> %+v -> %q -> %+v, %v", line, s, s.String(), again, err)
		}
	})
}

func TestHostLinkName(t *testing.T) {
	// IDs that differ only past the 15-byte interface name limit.
	a, b := HostLinkName("test-shared-prefix-aaaa"), HostLinkName("test-shared-prefix-bbbb")
	if a == b {
		t.Errorf("IDs sharing a prefix collide: %q", a)
	}
	if HostLinkName("x") != HostLinkName("x") {
		t.Error("HostLinkName is not deterministic")
	}
}

// FuzzHostLinkName: any container ID yields a valid interface name.
func FuzzHostLinkName(f *testing.F) {
	f.Add("a1b2c3d4e5f6")
	f.Add("with/slash:colon and space")
	f.Add("")
	f.Fuzz(func(t *testing.T, id string) {
		name := HostLinkName(id)
		if len(name) == 0 || len(name) > maxLinkName {
			t.Fatalf("HostLinkName(%q) = %q: length %d", id, name, len(name))
		}
		if strings.ContainsAny(name, "/: \t\n\x00") || name == "." || name == ".." {
			t.Fatalf("HostLinkName(%q) = %q: invalid interface name", id, name)
		}
	})
}
