package container

// Unit tests that need no privileges. Tests that run real containers are in
// integration_test.go (go test -tags integration, as root).

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/markthornson/kiln/internal/cgroups"
)

func TestUnknownNetworkMode(t *testing.T) {
	if _, err := Run(Config{ID: "x", Rootfs: "/", Args: []string{"true"}, Network: "host"}); err == nil || !strings.Contains(err.Error(), "network mode") {
		t.Fatalf("Run with -net host: %v", err)
	}
}

// useTempStateDir points StateDir and the cgroup root at temp directories,
// so pruning in tests can never touch real containers.
func useTempStateDir(t *testing.T) {
	t.Helper()
	oldState, oldRoot := StateDir, cgroups.Root
	StateDir, cgroups.Root = t.TempDir(), t.TempDir()
	t.Cleanup(func() { StateDir, cgroups.Root = oldState, oldRoot })
}

func TestNewState(t *testing.T) {
	useTempStateDir(t)
	dir, err := newState("abc123")
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"upper", "work", "merged"} {
		if fi, err := os.Stat(filepath.Join(dir, d)); err != nil || !fi.IsDir() {
			t.Errorf("%s: %v", d, err)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "owner")); strings.TrimSpace(string(b)) != fmt.Sprint(os.Getpid()) {
		t.Errorf("owner = %q", b)
	}
	if _, err := newState("abc123"); err == nil {
		t.Error("second container with the same ID accepted")
	}
}

func TestNewStateRejectsBadIDs(t *testing.T) {
	useTempStateDir(t)
	for _, id := range []string{"", ".", "..", "a/b", "../escape"} {
		if _, err := newState(id); err == nil {
			t.Errorf("ID %q accepted", id)
		}
	}
	if entries, _ := os.ReadDir(StateDir); len(entries) != 0 {
		t.Errorf("rejected IDs left %d entries in StateDir", len(entries))
	}
}

func TestPruneStale(t *testing.T) {
	useTempStateDir(t)
	dead := exec.Command("true")
	if err := dead.Run(); err != nil {
		t.Fatal(err)
	}
	owners := map[string]string{
		"dead":    fmt.Sprint(dead.Process.Pid),
		"live":    fmt.Sprint(os.Getpid()),
		"garbage": "not a pid",
	}
	for name, owner := range owners {
		if err := os.MkdirAll(filepath.Join(StateDir, name, "upper"), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(StateDir, name, "owner"), []byte(owner), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// No owner file yet: a container being created right now.
	if err := os.Mkdir(filepath.Join(StateDir, "creating"), 0o700); err != nil {
		t.Fatal(err)
	}
	pruneStale()
	for name, wantKept := range map[string]bool{"dead": false, "live": true, "garbage": true, "creating": true} {
		_, err := os.Stat(filepath.Join(StateDir, name))
		if kept := err == nil; kept != wantKept {
			t.Errorf("%s: kept=%v, want %v", name, kept, wantKept)
		}
	}
}

func TestPruneStaleCgroups(t *testing.T) {
	useTempStateDir(t)
	mk := func(p string) {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, ctrl := range []string{"memory", "pids"} {
		mk(filepath.Join(cgroups.Root, ctrl, "kiln", "orphan")) // kiln was killed: no state
		mk(filepath.Join(cgroups.Root, ctrl, "kiln", "running"))
	}
	mk(filepath.Join(StateDir, "running"))
	if err := os.WriteFile(filepath.Join(StateDir, "running", "owner"), []byte(fmt.Sprint(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}
	pruneStale()
	if got := fmt.Sprint(cgroups.IDs()); got != "[running]" {
		t.Errorf("cgroups after prune = %s, want [running]", got)
	}
}
