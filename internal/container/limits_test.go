//go:build integration

package container

import (
	"fmt"
	"math/rand/v2"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/markthornson/kiln/internal/cgroups"
	"github.com/markthornson/kiln/internal/netlink"
	"github.com/markthornson/kiln/internal/network"
	"github.com/markthornson/kiln/internal/rootfs"
)

// newShellRootfs builds a base with a shell and a few tools. Limit tests use
// sh rather than the Go test binary as the workload: pids.max counts threads,
// and the Go runtime's thread count would blur the exact boundaries.
func newShellRootfs(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := rootfs.Build(dir, []string{"sh", "sleep", "cat", "hostname"}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func runSh(t *testing.T, id, base string, limits cgroups.Limits, script string) int {
	t.Helper()
	code, err := Run(Config{ID: id, Rootfs: base, Hostname: "kilntest", Args: []string{"sh", "-c", script}, Limits: limits})
	if err != nil {
		t.Fatalf("Run(%s): %v", id, err)
	}
	return code
}

// TestPidsLimitBoundary is a property test against the real kernel: with
// pids.max = N the container (sh, one process) can start exactly N-1 more.
func TestPidsLimitBoundary(t *testing.T) {
	requireRoot(t)
	base := newShellRootfs(t)
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 0))
	for trial := range 12 {
		n := 2 + rng.IntN(7) // pids.max in 2..8
		// Bias towards the boundary, where off-by-ones live.
		k := n - 2 + rng.IntN(3) // N-2, N-1 or N children
		if trial%4 == 0 {
			k = rng.IntN(n + 2)
		}
		script := fmt.Sprintf(`i=0; while [ $i -lt %d ]; do sleep 5 & i=$((i+1)); done`, k)
		code := runSh(t, fmt.Sprintf("test-pids-%d", trial), base, cgroups.Limits{MaxPids: int64(n)}, script)
		if ok := k <= n-1; ok != (code == 0) {
			t.Errorf("pids.max=%d, %d children: exit %d, want success=%v", n, k, code, ok)
		}
	}
}

func TestMemoryLimit(t *testing.T) {
	requireRoot(t)
	base := newShellRootfs(t)
	limits := cgroups.Limits{MemoryBytes: 32 << 20}
	// Doubling a string forever must be OOM-killed: SIGKILL, so 128+9.
	if code := runSh(t, "test-mem-oom", base, limits, `x=a; while :; do x=$x$x; done`); code != 137 {
		t.Errorf("unbounded allocation under 32MiB limit: exit %d, want 137", code)
	}
	// About 1MiB fits comfortably.
	if code := runSh(t, "test-mem-ok", base, limits, `x=a; i=0; while [ $i -lt 20 ]; do x=$x$x; i=$((i+1)); done`); code != 0 {
		t.Errorf("1MiB under 32MiB limit: exit %d, want 0", code)
	}
}

// TestLimitsWrittenToCgroup reads the limit files from the host while the
// container is running, and checks the group is gone afterwards.
func TestLimitsWrittenToCgroup(t *testing.T) {
	requireRoot(t)
	base := newShellRootfs(t)
	id := "test-cgfiles"
	limits := cgroups.Limits{MemoryBytes: 48 << 20, MaxPids: 7}
	done := make(chan int)
	go func() {
		code, err := Run(Config{ID: id, Rootfs: base, Hostname: "kilntest", Args: []string{"sleep", "2"}, Limits: limits})
		if err != nil {
			t.Error(err)
		}
		done <- code
	}()
	// Limit files differ by hierarchy: v1 has a tree per controller and names
	// the memory limit memory.limit_in_bytes; v2 is unified and uses memory.max.
	memPath := filepath.Join(cgroups.Root, "memory", "kiln", id, "memory.limit_in_bytes")
	pidsMax := filepath.Join(cgroups.Root, "pids", "kiln", id, "pids.max")
	current := filepath.Join(cgroups.Root, "pids", "kiln", id, "pids.current")
	if cgroups.Version() == 2 {
		leaf := filepath.Join(cgroups.Root, "kiln", id)
		memPath = filepath.Join(leaf, "memory.max")
		pidsMax = filepath.Join(leaf, "pids.max")
		current = filepath.Join(leaf, "pids.current")
	}
	files := map[string]string{
		memPath: strconv.FormatInt(limits.MemoryBytes, 10),
		pidsMax: strconv.FormatInt(limits.MaxPids, 10),
		current: "1", // just sleep: init's threads collapsed at exec
	}
	got := map[string]string{}
	read := func() bool {
		for f := range files {
			b, err := os.ReadFile(f)
			if err != nil {
				return false
			}
			got[f] = strings.TrimSpace(string(b))
		}
		return got[current] == "1"
	}
	if !waitFor(read) {
		t.Errorf("cgroup files never settled: %v", got)
	}
	for f, want := range files {
		if got[f] != want {
			t.Errorf("%s = %q, want %q", f, got[f], want)
		}
	}
	if code := <-done; code != 0 {
		t.Errorf("exit %d", code)
	}
	if slices.Contains(cgroups.IDs(), id) {
		t.Errorf("cgroup %s not removed after the container exited", id)
	}
}

func TestExitCodes(t *testing.T) {
	requireRoot(t)
	base := newShellRootfs(t)
	for script, want := range map[string]int{
		"exit 0":   0,
		"exit 7":   7,
		"exit 255": 255,
		"nosuch":   127, // sh: command not found
	} {
		if code := runSh(t, "test-exit", base, cgroups.Limits{}, script); code != want {
			t.Errorf("%q: exit %d, want %d", script, code, want)
		}
	}
	// A command that doesn't exist in the rootfs fails in init, before exec.
	code, err := Run(Config{ID: "test-exit", Rootfs: base, Hostname: "kilntest", Args: []string{"/no/such/binary"}})
	if err != nil || code != 1 {
		t.Errorf("missing binary: exit %d, %v; want 1", code, err)
	}
}

func TestPIDAndUTSNamespaces(t *testing.T) {
	requireRoot(t)
	hostName, _ := os.Hostname()
	base := newShellRootfs(t)
	// sh is PID 1, /proc lists no process but sh (the glob runs in sh itself,
	// without forking), and the hostname is the container's.
	script := `[ "$$" = 1 ] || exit 10
procs=""; for p in /proc/[0-9]*; do procs="$procs ${p#/proc/}"; done
[ "$procs" = " 1" ] || { echo "processes:$procs"; exit 11; }
[ "$(hostname)" = box ] || exit 12`
	code, err := Run(Config{ID: "test-ns", Rootfs: base, Hostname: "box", Args: []string{"sh", "-c", script}})
	if err != nil || code != 0 {
		t.Errorf("namespace checks: exit %d, %v (10: not PID 1, 11: foreign processes, 12: hostname)", code, err)
	}
	if after, _ := os.Hostname(); after != hostName {
		t.Errorf("host hostname changed: %q -> %q", hostName, after)
	}
}

// hostState captures everything a container run could leak on the host.
type hostState struct {
	cgroups, state, leases, links []string
	mounts                        int
}

func captureHost(t *testing.T) hostState {
	t.Helper()
	var s hostState
	list := func(dir string, keep func(os.DirEntry) bool) []string {
		entries, _ := os.ReadDir(dir)
		var names []string
		for _, e := range entries {
			if keep(e) {
				names = append(names, e.Name())
			}
		}
		return names
	}
	s.cgroups = cgroups.IDs()
	slices.Sort(s.cgroups)
	s.state = list(StateDir, func(os.DirEntry) bool { return true })
	// Leases of dead kiln processes are reclaimed on use, so only live ones count.
	s.leases = list(network.LeaseDir, func(e os.DirEntry) bool {
		b, err := os.ReadFile(filepath.Join(network.LeaseDir, e.Name()))
		pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
		return e.Name() != "lock" && err == nil && pid > 0 && syscall.Kill(pid, 0) == nil
	})
	ifaces, _ := net.Interfaces()
	for _, ifi := range ifaces {
		if strings.HasPrefix(ifi.Name, "kv") {
			s.links = append(s.links, ifi.Name)
		}
	}
	mi, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		t.Fatal(err)
	}
	s.mounts = strings.Count(string(mi), "\n")
	return s
}

// TestNoLeaks runs containers through every way they can end, several at a
// time, and checks the host is left exactly as it was.
func TestNoLeaks(t *testing.T) {
	requireRoot(t)
	if err := network.EnsureBridge(); err != nil {
		t.Fatal(err)
	}
	base := newShellRootfs(t)
	cases := []struct {
		name   string
		cfg    Config
		script string
	}{
		{"ok", Config{}, "true"},
		{"fail", Config{}, "exit 3"},
		{"oom", Config{Limits: cgroups.Limits{MemoryBytes: 16 << 20}}, `x=a; while :; do x=$x$x; done`},
		{"pids", Config{Limits: cgroups.Limits{MaxPids: 3}}, `sleep 5 & sleep 5 & sleep 5 & sleep 5`},
		{"orphans", Config{}, `sleep 100 & sleep 100 & exit 0`},
		{"bridge", Config{Network: NetworkBridge}, "true"},
		{"bridge-orphans", Config{Network: NetworkBridge}, `sleep 100 & exit 0`},
		{"bridge-missing-binary", Config{Network: NetworkBridge}, ""},
	}
	before := captureHost(t)
	for round := range 5 {
		var wg sync.WaitGroup
		for _, c := range cases {
			wg.Add(1)
			go func() {
				defer wg.Done()
				cfg := c.cfg
				cfg.ID = fmt.Sprintf("test-leak-%s-%d", c.name, round)
				cfg.Rootfs, cfg.Hostname = base, "kilntest"
				cfg.Args = []string{"sh", "-c", c.script}
				if c.script == "" {
					cfg.Args = []string{"/no/such/binary"}
				}
				if _, err := Run(cfg); err != nil {
					t.Errorf("%s: %v", cfg.ID, err)
				}
			}()
		}
		wg.Wait()
	}
	after := captureHost(t)
	if fmt.Sprint(before) != fmt.Sprint(after) {
		t.Errorf("host state changed:\nbefore %+v\nafter  %+v", before, after)
	}
}

// TestBridgeIDsWithSharedPrefix: host veth names are limited to 15 bytes, so
// they must stay unique for IDs that only differ after that.
func TestBridgeIDsWithSharedPrefix(t *testing.T) {
	requireRoot(t)
	base := newShellRootfs(t)
	ids := []string{"test-shared-prefix-aaaa", "test-shared-prefix-bbbb", "test-shared-prefix-cccc"}
	errs := make([]error, len(ids))
	codes := make([]int, len(ids))
	var wg sync.WaitGroup
	for i, id := range ids {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Overlap the containers' lifetimes so their links coexist.
			codes[i], errs[i] = Run(Config{ID: id, Rootfs: base, Hostname: "kilntest",
				Args: []string{"sleep", "1"}, Network: NetworkBridge})
		}()
	}
	wg.Wait()
	for i, id := range ids {
		if errs[i] != nil || codes[i] != 0 {
			t.Errorf("%s: exit %d, %v", id, codes[i], errs[i])
		}
	}
}

// TestFailedAttachKeepsOthersLink: if the host link name is taken, the run
// fails, and must not delete the link it failed to create.
func TestFailedAttachKeepsOthersLink(t *testing.T) {
	requireRoot(t)
	if err := network.EnsureBridge(); err != nil {
		t.Fatal(err)
	}
	id := "test-taken"
	name := network.HostLinkName(id)
	c, err := netlink.Dial()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	// Someone else's veth pair, with the name this container would use.
	if err := c.CreateVeth(name, "kvtest-peer", os.Getpid()); err != nil {
		t.Fatal(err)
	}
	defer c.DeleteLink(name)
	_, err = Run(Config{ID: id, Rootfs: newShellRootfs(t), Hostname: "kilntest", Args: []string{"true"}, Network: NetworkBridge})
	if err == nil {
		t.Fatal("Run succeeded despite the name clash")
	}
	if _, err := net.InterfaceByName(name); err != nil {
		t.Fatalf("the other link was deleted: %v", err)
	}
}
