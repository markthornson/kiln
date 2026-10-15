//go:build integration

// Integration tests: real containers, so they need root and cgroup v1.
// Run with: sudo go test -tags integration ./...
package container

import (
	"bufio"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/markthornson/kiln/internal/cgroups"
	"github.com/markthornson/kiln/internal/mountinfo"
	"github.com/markthornson/kiln/internal/network"
	"github.com/markthornson/kiln/internal/rootfs"
)

// The test binary doubles as the container's init (Run re-executes
// /proc/self/exe with "init") and as the program run inside the container.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "init":
			err := Init(os.Args[2], os.Args[3], os.Args[4], os.Args[5], os.Args[6:])
			fmt.Fprintln(os.Stderr, "init:", err)
			os.Exit(1)
		case "escape":
			os.Exit(tryEscape(os.Args[2]))
		case "mounts":
			os.Exit(checkMounts())
		case "net":
			os.Exit(checkNet(os.Args[2], os.Args[3]))
		case "write":
			os.Exit(writeLayer())
		case "pristine":
			os.Exit(checkPristine())
		case "own-writes":
			os.Exit(checkOwnWrites())
		case "hang":
			time.Sleep(time.Hour)
		case "run-hang": // act as a kiln process running a long container
			code, err := Run(Config{ID: os.Args[3], Rootfs: os.Args[2], Hostname: "kilntest",
				Args: []string{"/bin/kilntest", "hang"}, Network: NetworkBridge})
			fmt.Fprintln(os.Stderr, "run-hang returned:", code, err)
			os.Exit(1)
		}
	}
	os.Exit(m.Run())
}

// Exit codes used by the in-container helpers.
const (
	contained = 0
	escaped   = 10
	failed    = 11
)

// tryEscape is the classic chroot breakout: chroot into a subdirectory
// without moving the working directory, walk ".." past the root, and chroot
// there. It reports whether hostFile (outside the rootfs) became visible.
func tryEscape(hostFile string) int {
	if err := os.Mkdir("/breakout", 0o755); err != nil && !os.IsExist(err) {
		fmt.Fprintln(os.Stderr, err)
		return failed
	}
	if err := syscall.Chroot("/breakout"); err != nil {
		fmt.Fprintln(os.Stderr, "chroot:", err)
		return failed
	}
	for i := 0; i < 64; i++ {
		syscall.Chdir("..")
	}
	if err := syscall.Chroot("."); err != nil {
		fmt.Fprintln(os.Stderr, "chroot .:", err)
		return failed
	}
	if _, err := os.Stat(hostFile); err == nil {
		fmt.Fprintln(os.Stderr, "escaped: host file visible:", hostFile)
		return escaped
	}
	return contained
}

// checkMounts verifies the container sees exactly its own mounts: one root,
// /proc and /dev, and nothing left over from the host.
func checkMounts() int {
	mounts, err := mountinfo.Self()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return failed
	}
	seen := map[string]int{}
	for _, m := range mounts {
		seen[m.MountPoint]++
		if m.MountPoint == "/" && m.FSType != "overlay" {
			fmt.Fprintf(os.Stderr, "root is %s, want overlay\n", m.FSType)
			return failed
		}
	}
	want := map[string]int{"/": 1, "/proc": 1, "/dev": 1}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		fmt.Fprintf(os.Stderr, "mount points = %v, want %v\n", seen, want)
		return escaped
	}
	return contained
}

// writeLayer changes the container's filesystem in every way overlayfs has to
// handle: modify, create, delete, mkdir, chmod and rename.
func writeLayer() int {
	steps := []func() error{
		func() error { return os.WriteFile("/etc/hostname", []byte("changed\n"), 0o644) },
		func() error { return os.WriteFile("/tmp/new", []byte("new"), 0o644) },
		func() error { return os.Remove("/etc/data") },
		func() error { return os.Mkdir("/newdir", 0o755) },
		func() error { return os.Chmod("/bin/kilntest", 0o700) },
		func() error { return os.Rename("/etc/keep", "/etc/moved") },
		func() error { return os.RemoveAll("/lib") }, // whole tree of shared libraries
	}
	for i, step := range steps {
		if err := step(); err != nil {
			fmt.Fprintf(os.Stderr, "step %d: %v\n", i, err)
			return failed
		}
	}
	return contained
}

// checkPristine verifies a container sees none of writeLayer's changes.
func checkPristine() int {
	problems := 0
	report := func(format string, a ...any) { fmt.Fprintf(os.Stderr, format+"\n", a...); problems++ }
	if b, _ := os.ReadFile("/etc/hostname"); string(b) != "kiln\n" {
		report("/etc/hostname = %q", b)
	}
	for _, p := range []string{"/tmp/new", "/newdir", "/etc/moved"} {
		if _, err := os.Lstat(p); err == nil {
			report("%s exists", p)
		}
	}
	for _, p := range []string{"/etc/data", "/etc/keep"} {
		if _, err := os.Lstat(p); err != nil {
			report("%s: %v", p, err)
		}
	}
	if fi, err := os.Stat("/bin/kilntest"); err != nil || fi.Mode().Perm() != 0o755 {
		report("/bin/kilntest mode: %v %v", fi, err)
	}
	if problems > 0 {
		return failed
	}
	return contained
}

// checkOwnWrites writes a random token, waits so a concurrent container can
// write its own, and checks the token is still ours.
func checkOwnWrites() int {
	tok := make([]byte, 8)
	rand.Read(tok)
	if err := os.WriteFile("/etc/data", tok, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return failed
	}
	time.Sleep(500 * time.Millisecond)
	if got, _ := os.ReadFile("/etc/data"); string(got) != string(tok) {
		fmt.Fprintf(os.Stderr, "/etc/data = %x, wrote %x\n", got, tok)
		return escaped
	}
	return contained
}

// checkNet verifies the container's interfaces for the given network mode and
// that it can (bridge) or cannot (none) reach a TCP server on the host.
func checkNet(mode, hostAddr string) int {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return failed
	}
	var names []string
	for _, ifi := range ifaces {
		names = append(names, ifi.Name)
		if ifi.Flags&net.FlagUp == 0 {
			fmt.Fprintln(os.Stderr, ifi.Name, "is down")
			return failed
		}
	}
	slices.Sort(names)
	conn, dialErr := net.DialTimeout("tcp", hostAddr, 3*time.Second)
	if mode == "none" {
		if fmt.Sprint(names) != "[lo]" {
			fmt.Fprintln(os.Stderr, "interfaces:", names)
			return escaped
		}
		if dialErr == nil {
			fmt.Fprintln(os.Stderr, "reached host with -net none")
			return escaped
		}
		return contained
	}
	if fmt.Sprint(names) != "[eth0 lo]" {
		fmt.Fprintln(os.Stderr, "interfaces:", names)
		return failed
	}
	if dialErr != nil {
		fmt.Fprintln(os.Stderr, "dial host:", dialErr)
		return failed
	}
	defer conn.Close()
	// The address the host sees must be the one kiln told us about.
	if got := conn.LocalAddr().(*net.TCPAddr).IP.String(); got != os.Getenv("KILN_IP") {
		fmt.Fprintf(os.Stderr, "local address %s, KILN_IP %q\n", got, os.Getenv("KILN_IP"))
		return failed
	}
	conn.SetReadDeadline(time.Now().Add(20 * time.Second))
	reply, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil || reply != "ok\n" {
		fmt.Fprintf(os.Stderr, "reply %q, %v\n", reply, err)
		return failed
	}
	return contained
}

// requireRoot fails rather than skips: whoever passed -tags integration
// asked for these tests to run.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Fatal("integration tests need root: sudo go test -tags integration ./...")
	}
	for _, ctrl := range []string{"memory", "pids"} {
		if _, err := os.Stat("/sys/fs/cgroup/" + ctrl); err != nil {
			t.Fatalf("integration tests need the cgroup v1 %s controller: %v", ctrl, err)
		}
	}
}

// newRootfs builds a rootfs containing a copy of this test binary at
// /bin/kilntest, plus any shared libraries it needs.
func newRootfs(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := rootfs.Build(dir, nil); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	copy := func(src, dst string) {
		data, err := os.ReadFile(src)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dst, data, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	copy(self, filepath.Join(dir, "bin", "kilntest"))
	for name, content := range map[string]string{"etc/data": "orig", "etc/keep": "keep"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out, _ := exec.Command("ldd", self).CombinedOutput()
	for _, lib := range rootfs.ParseLdd(string(out)) {
		copy(lib, filepath.Join(dir, lib))
	}
	return dir
}

func runIn(t *testing.T, dir string, args ...string) int {
	t.Helper()
	return runNet(t, dir, NetworkNone, args...)
}

func runNet(t *testing.T, dir, mode string, args ...string) int {
	t.Helper()
	code, err := Run(Config{ID: "test-" + filepath.Base(dir), Rootfs: dir, Hostname: "kilntest", Args: args, Network: mode})
	if err != nil {
		t.Fatal(err)
	}
	return code
}

func TestChrootEscapeFails(t *testing.T) {
	requireRoot(t)
	hostFile := filepath.Join(t.TempDir(), "host-only")
	if err := os.WriteFile(hostFile, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	switch code := runIn(t, newRootfs(t), "/bin/kilntest", "escape", hostFile); code {
	case contained:
	case escaped:
		t.Fatal("process escaped the container root")
	default:
		t.Fatalf("escape helper failed: exit %d", code)
	}
}

func TestOnlyContainerMountsVisible(t *testing.T) {
	requireRoot(t)
	if code := runIn(t, newRootfs(t), "/bin/kilntest", "mounts"); code != contained {
		t.Fatalf("mounts check: exit %d", code)
	}
}

func TestBridgeNetwork(t *testing.T) {
	requireRoot(t)
	if err := network.EnsureBridge(); err != nil {
		t.Fatal(err)
	}
	// Dial a host address outside the bridge subnet so the container's
	// default route is exercised, not just the on-link subnet route.
	target := hostAddrOutside(t, network.Subnet)
	ln, err := net.Listen("tcp", net.JoinHostPort(target.String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	ln.(*net.TCPListener).SetDeadline(time.Now().Add(30 * time.Second))

	// Reply only once both containers are connected, so they must be running
	// at the same time, each with its own address.
	peers := make(chan []string, 1)
	go func() {
		var conns []net.Conn
		var ips []string
		for len(conns) < 2 {
			c, err := ln.Accept()
			if err != nil {
				break
			}
			conns = append(conns, c)
			ips = append(ips, c.RemoteAddr().(*net.TCPAddr).IP.String())
		}
		for _, c := range conns {
			fmt.Fprintln(c, "ok")
			c.Close()
		}
		peers <- ips
	}()

	dirs := []string{newRootfs(t), newRootfs(t)}
	codes := make([]int, len(dirs))
	var wg sync.WaitGroup
	for i, dir := range dirs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Not runNet: t.Fatal must not be called off the test goroutine.
			code, err := Run(Config{ID: "test-" + filepath.Base(dir), Rootfs: dir, Hostname: "kilntest",
				Args: []string{"/bin/kilntest", "net", "bridge", ln.Addr().String()}, Network: NetworkBridge})
			if err != nil {
				t.Error(err)
			}
			codes[i] = code
		}()
	}
	wg.Wait()
	ips := <-peers
	for i, code := range codes {
		if code != contained {
			t.Errorf("container %d: exit %d", i, code)
		}
	}
	if len(ips) != 2 || ips[0] == ips[1] {
		t.Fatalf("container addresses = %v, want two distinct", ips)
	}
	for _, ip := range ips {
		if !network.Subnet.Contains(netip.MustParseAddr(ip)) {
			t.Errorf("container address %s outside %v", ip, network.Subnet)
		}
		if _, err := os.Stat(filepath.Join(network.LeaseDir, ip)); !os.IsNotExist(err) {
			t.Errorf("lease for %s not released: %v", ip, err)
		}
	}
	// Host ends of the veth pairs must be gone.
	ifaces, _ := net.Interfaces()
	for _, ifi := range ifaces {
		for _, dir := range dirs {
			if ifi.Name == network.HostLinkName("test-"+filepath.Base(dir)) {
				t.Errorf("leftover host link %s", ifi.Name)
			}
		}
	}
}

// hostAddrOutside returns a non-loopback IPv4 address of the host that is not
// in subnet, falling back to the bridge gateway if there is none.
func hostAddrOutside(t *testing.T, subnet netip.Prefix) netip.Addr {
	t.Helper()
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range addrs {
		p, err := netip.ParsePrefix(a.String())
		if err != nil {
			continue
		}
		if ip := p.Addr(); ip.Is4() && !ip.IsLoopback() && !subnet.Contains(ip) {
			return ip
		}
	}
	t.Log("no host address outside the bridge subnet; default route not exercised")
	return network.Gateway(subnet)
}

func TestNoNetwork(t *testing.T) {
	requireRoot(t)
	if err := network.EnsureBridge(); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(network.Gateway(network.Subnet).String(), "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if code := runNet(t, newRootfs(t), NetworkNone, "/bin/kilntest", "net", "none", ln.Addr().String()); code != contained {
		t.Fatalf("exit %d", code)
	}
}

// TestContainerDiesWithKiln kills a kiln process with SIGKILL, so it cannot
// clean up, and checks its container dies too. A surviving container would
// keep an IP whose lease looks stale and gets reassigned.
func TestContainerDiesWithKiln(t *testing.T) {
	requireRoot(t)
	dir := newRootfs(t)
	id := "test-orphan"
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "run-hang", dir, id)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// The host end of the veth lives exactly as long as the container's
	// network namespace, i.e. as long as the container.
	link := network.HostLinkName(id)
	if !waitFor(func() bool { _, err := net.InterfaceByName(link); return err == nil }) {
		cmd.Process.Kill()
		t.Fatalf("container never came up (no %s)", link)
	}
	cmd.Process.Kill()
	cmd.Wait()
	if !waitFor(func() bool { _, err := net.InterfaceByName(link); return err != nil }) {
		exec.Command("pkill", "-9", "-x", "kilntest").Run() // don't leak the orphan
		t.Fatal("container survived its kiln process")
	}

	// The killed kiln couldn't clean up; the next run must.
	if code := runIn(t, dir, "/bin/kilntest", "mounts"); code != contained {
		t.Fatalf("next run: exit %d", code)
	}
	for _, p := range []string{
		filepath.Join(StateDir, id),
		filepath.Join(cgroups.Root, "memory", "kiln", id),
		filepath.Join(cgroups.Root, "pids", "kiln", id),
	} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("left behind by killed kiln: %s (%v)", p, err)
		}
	}
}

func waitFor(cond func() bool) bool {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return false
}

// snapshot records every path in a tree with its type, mode and content hash.
func snapshot(t *testing.T, root string) map[string]string {
	t.Helper()
	snap := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		entry := info.Mode().String()
		switch {
		case info.Mode().IsRegular():
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			sum := sha256.Sum256(data)
			entry += " " + hex.EncodeToString(sum[:])
		case info.Mode()&fs.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			entry += " -> " + target
		}
		rel, _ := filepath.Rel(root, path)
		snap[rel] = entry
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return snap
}

func TestBaseImageUnchanged(t *testing.T) {
	requireRoot(t)
	base := newRootfs(t)
	before := snapshot(t, base)
	if code := runIn(t, base, "/bin/kilntest", "write"); code != contained {
		t.Fatalf("write: exit %d", code)
	}
	after := snapshot(t, base)
	for p, v := range before {
		if after[p] != v {
			t.Errorf("base %s changed: %q -> %q", p, v, after[p])
		}
	}
	for p := range after {
		if _, ok := before[p]; !ok {
			t.Errorf("base gained %s", p)
		}
	}
	// A new container starts from the base again, not from the last layer.
	if code := runIn(t, base, "/bin/kilntest", "pristine"); code != contained {
		t.Fatalf("second container saw the first one's writes: exit %d", code)
	}
}

func TestConcurrentLayersIsolated(t *testing.T) {
	requireRoot(t)
	base := newRootfs(t)
	codes := make([]int, 3)
	var wg sync.WaitGroup
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, err := Run(Config{ID: fmt.Sprintf("test-iso-%d", i), Rootfs: base, Hostname: "kilntest",
				Args: []string{"/bin/kilntest", "own-writes"}})
			if err != nil {
				t.Error(err)
			}
			codes[i] = code
		}()
	}
	wg.Wait()
	for i, code := range codes {
		if code != contained {
			t.Errorf("container %d: exit %d", i, code)
		}
	}
}

func TestStateCleanup(t *testing.T) {
	requireRoot(t)
	// Left behind by a kiln process that was killed: its owner PID is dead.
	dead := exec.Command("true")
	if err := dead.Run(); err != nil {
		t.Fatal(err)
	}
	stale := filepath.Join(StateDir, "test-stale")
	if err := os.MkdirAll(filepath.Join(stale, "upper"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(stale, "owner"), []byte(fmt.Sprint(dead.Process.Pid)), 0o600); err != nil {
		t.Fatal(err)
	}
	// One held by a live process (us) must survive.
	live := filepath.Join(StateDir, "test-live")
	if err := os.MkdirAll(live, 0o700); err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(live)
	if err := os.WriteFile(filepath.Join(live, "owner"), []byte(fmt.Sprint(os.Getpid())), 0o600); err != nil {
		t.Fatal(err)
	}

	dir := newRootfs(t)
	if code := runIn(t, dir, "/bin/kilntest", "write"); code != contained {
		t.Fatalf("exit %d", code)
	}
	for _, d := range []string{stale, filepath.Join(StateDir, "test-"+filepath.Base(dir))} {
		if _, err := os.Stat(d); !os.IsNotExist(err) {
			t.Errorf("%s not removed: %v", d, err)
		}
	}
	if _, err := os.Stat(live); err != nil {
		t.Errorf("live state removed: %v", err)
	}
}

func TestBaseWithAwkwardPath(t *testing.T) {
	requireRoot(t)
	odd := filepath.Join(t.TempDir(), `base,with:odd\chars`)
	if err := os.Rename(newRootfs(t), odd); err != nil {
		t.Fatal(err)
	}
	code, err := Run(Config{ID: "test-odd", Rootfs: odd, Hostname: "kilntest", Args: []string{"/bin/kilntest", "pristine"}})
	if err != nil || code != contained {
		t.Fatalf("Run = %d, %v", code, err)
	}
}

func TestInvalidRootfsAndID(t *testing.T) {
	requireRoot(t)
	if _, err := Run(Config{ID: "x", Rootfs: "/nonexistent", Args: []string{"sh"}}); err == nil {
		t.Error("missing rootfs accepted")
	}
	for _, id := range []string{"", "..", "a/b"} {
		if _, err := Run(Config{ID: id, Rootfs: "/", Args: []string{"sh"}}); err == nil {
			t.Errorf("container ID %q accepted", id)
		}
	}
}
