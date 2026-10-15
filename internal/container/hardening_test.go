//go:build integration

package container

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
	"testing"
)

// checkHardened runs inside the container and verifies its privilege state
// from /proc/self/status: no capabilities in any set, no_new_privs on, and a
// seccomp filter installed (Seccomp: 2 == SECCOMP_MODE_FILTER).
func checkHardened() int {
	want := map[string]string{
		"CapInh":     "0000000000000000",
		"CapPrm":     "0000000000000000",
		"CapEff":     "0000000000000000",
		"CapBnd":     "0000000000000000",
		"NoNewPrivs": "1",
		"Seccomp":    "2",
	}
	f, err := os.Open("/proc/self/status")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return failed
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		key, val, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		if wantVal, checked := want[key]; checked {
			if got := strings.TrimSpace(val); got != wantVal {
				fmt.Fprintf(os.Stderr, "%s = %q, want %q\n", key, got, wantVal)
				return escaped
			}
			delete(want, key)
		}
	}
	if len(want) != 0 {
		fmt.Fprintf(os.Stderr, "status fields missing: %v\n", want)
		return failed
	}
	return contained
}

// checkBlockedSyscalls runs inside the container and verifies that privileged
// syscalls fail. mount and mknod are stopped by the seccomp filter; sethostname
// is not in the filter, so it tests the capability drop (it needs
// CAP_SYS_ADMIN, which the container no longer has). All must return EPERM.
func checkBlockedSyscalls() int {
	type attempt struct {
		name string
		err  error
	}
	attempts := []attempt{
		{"mount", syscall.Mount("none", "/tmp", "tmpfs", 0, "")},
		{"mknod device node", syscall.Mknod("/tmp/disk", syscall.S_IFBLK|0o600, 0x0800)},
		{"sethostname", syscall.Sethostname([]byte("escaped"))},
	}
	for _, a := range attempts {
		if !errors.Is(a.err, syscall.EPERM) {
			fmt.Fprintf(os.Stderr, "%s: err = %v, want EPERM\n", a.name, a.err)
			return escaped
		}
	}
	return contained
}

func TestContainerIsHardened(t *testing.T) {
	requireRoot(t)
	if code := runIn(t, newRootfs(t), "/bin/kilntest", "hardened"); code != contained {
		t.Fatalf("hardening checks failed: exit %d", code)
	}
}

func TestPrivilegedSyscallsBlocked(t *testing.T) {
	requireRoot(t)
	if code := runIn(t, newRootfs(t), "/bin/kilntest", "blocked-syscalls"); code != contained {
		t.Fatalf("a privileged syscall was not blocked: exit %d", code)
	}
}

// TestHardeningDoesNotBreakWorkload is a guard against an over-strict filter:
// a container doing ordinary work (files, a subprocess, networking) must still
// run cleanly once hardened.
func TestHardeningDoesNotBreakWorkload(t *testing.T) {
	requireRoot(t)
	base := newShellRootfs(t)
	// A real shell doing file I/O and spawning a child, all under the filter.
	script := `echo hi > /tmp/f && cat /tmp/f >/dev/null && (echo sub | cat >/dev/null) && hostname >/dev/null`
	code, err := Run(Config{ID: "test-workload", Rootfs: base, Hostname: "kilntest",
		Args: []string{"sh", "-c", script}, Network: NetworkNone})
	if err != nil || code != 0 {
		t.Fatalf("hardened workload: exit %d, %v", code, err)
	}
}
