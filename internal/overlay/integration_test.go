//go:build integration

package overlay

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestKernelAgrees mounts real overlays whose paths contain random awkward
// characters and checks that the kernel reads Options the way ParseOptions
// does: the mount works and shows the lower layer's content.
func TestKernelAgrees(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("integration tests need root: sudo go test -tags integration ./...")
	}
	const charset = `abc,:\ =x'"` + "\t"
	rng := rand.New(rand.NewPCG(1, 2))
	for i := range 40 {
		var name strings.Builder
		for range 1 + rng.IntN(10) {
			name.WriteByte(charset[rng.IntN(len(charset))])
		}
		root := filepath.Join(t.TempDir(), name.String())
		lower, upper, work, mnt := root+"/lower", root+"/upper", root+"/work", root+"/mnt"
		for _, d := range []string{lower, upper, work, mnt} {
			if err := os.MkdirAll(d, 0o755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(lower+"/marker", []byte(name.String()), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mount("overlay", mnt, "overlay", 0, Options(lower, upper, work)); err != nil {
			t.Fatalf("case %d: mount with dir %q: %v", i, name.String(), err)
		}
		got, err := os.ReadFile(mnt + "/marker")
		syscall.Unmount(mnt, 0)
		if err != nil || string(got) != name.String() {
			t.Fatalf("case %d: dir %q: marker = %q, %v", i, name.String(), got, err)
		}
	}
}
