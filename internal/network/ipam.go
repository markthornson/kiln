package network

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// ErrExhausted means every host address in the subnet is leased.
var ErrExhausted = errors.New("network: no free addresses in subnet")

// Gateway is the subnet's first host address, assigned to the bridge.
func Gateway(subnet netip.Prefix) netip.Addr { return subnet.Masked().Addr().Next() }

// pick returns the lowest address in subnet that is not the network address,
// the gateway, the broadcast address, or in use.
func pick(subnet netip.Prefix, inUse func(netip.Addr) bool) (netip.Addr, bool) {
	subnet = subnet.Masked()
	for a := Gateway(subnet).Next(); subnet.Contains(a); a = a.Next() {
		if !subnet.Contains(a.Next()) {
			break // a is the broadcast address
		}
		if !inUse(a) {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// Leases hands out addresses from a subnet, recording each lease as a file in
// Dir so concurrent kiln processes never share an address. A lease file holds
// the PID of the kiln process that owns it; leases whose owner has died (for
// example after kill -9) are reclaimed.
type Leases struct {
	Dir    string
	Subnet netip.Prefix
}

// Allocate leases a free address to the calling process.
func (l Leases) Allocate() (netip.Addr, error) {
	if err := os.MkdirAll(l.Dir, 0o755); err != nil {
		return netip.Addr{}, err
	}
	// One allocation at a time across processes. flock locks belong to the
	// open file, so this also serializes goroutines that each open the lock.
	lock, err := os.OpenFile(filepath.Join(l.Dir, "lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return netip.Addr{}, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return netip.Addr{}, fmt.Errorf("lock leases: %w", err)
	}

	addr, ok := pick(l.Subnet, func(a netip.Addr) bool {
		data, err := os.ReadFile(l.path(a))
		if errors.Is(err, os.ErrNotExist) {
			return false
		}
		if err == nil && ownerDead(string(data)) {
			os.Remove(l.path(a))
			return false
		}
		return true // live owner, or unreadable: don't risk sharing it
	})
	if !ok {
		return netip.Addr{}, ErrExhausted
	}
	if err := os.WriteFile(l.path(addr), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644); err != nil {
		return netip.Addr{}, err
	}
	return addr, nil
}

// Release returns an address to the pool.
func (l Leases) Release(a netip.Addr) error {
	if err := os.Remove(l.path(a)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (l Leases) path(a netip.Addr) string { return filepath.Join(l.Dir, a.String()) }

// ownerDead reports whether the PID recorded in a lease file has exited.
func ownerDead(content string) bool {
	pid, err := strconv.Atoi(strings.TrimSpace(content))
	if err != nil || pid <= 0 {
		return false
	}
	return errors.Is(syscall.Kill(pid, 0), syscall.ESRCH)
}
