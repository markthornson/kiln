package container

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/markthornson/kiln/internal/mountinfo"
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
	code, err := Run(Config{ID: "test-" + filepath.Base(dir), Rootfs: dir, Hostname: "kilntest", Args: args})
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
