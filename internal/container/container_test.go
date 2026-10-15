package container

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

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
			err := Init(os.Args[2], os.Args[3], os.Args[4], os.Args[5:])
			fmt.Fprintln(os.Stderr, "init:", err)
			os.Exit(1)
		case "escape":
			os.Exit(tryEscape(os.Args[2]))
		case "mounts":
			os.Exit(checkMounts())
		case "net":
			os.Exit(checkNet(os.Args[2], os.Args[3]))
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
	}
	want := map[string]int{"/": 1, "/proc": 1, "/dev": 1}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		fmt.Fprintf(os.Stderr, "mount points = %v, want %v\n", seen, want)
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

func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat("/sys/fs/cgroup/pids"); err != nil {
		t.Skip("needs cgroup v1 pids controller")
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
			if ifi.Name == "kvtest-"+filepath.Base(dir) {
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

func TestUnknownNetworkMode(t *testing.T) {
	if _, err := Run(Config{ID: "x", Rootfs: "/", Args: []string{"true"}, Network: "host"}); err == nil || !strings.Contains(err.Error(), "network mode") {
		t.Fatalf("Run with -net host: %v", err)
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
	link := "kv" + id
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
}

func waitFor(cond func() bool) bool {
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		if cond() {
			return true
		}
	}
	return false
}
