package overlay

import (
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func TestOptions(t *testing.T) {
	got := Options("/base,v1", `/c/up\per`, "/c/work:x")
	want := `lowerdir=/base\,v1,upperdir=/c/up\\per,workdir=/c/work\:x`
	if got != want {
		t.Errorf("Options = %q, want %q", got, want)
	}
}

func TestParseOptions(t *testing.T) {
	p, err := ParseOptions(`lowerdir=/a\:b:/c,upperdir=/u,workdir=/w\,1,xino=off`)
	if err != nil {
		t.Fatal(err)
	}
	want := Parsed{Lower: []string{"/a:b", "/c"}, Upper: "/u", Work: "/w,1", OtherOptions: []string{"xino=off"}}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("ParseOptions = %+v, want %+v", p, want)
	}
}

// FuzzOptionsRoundTrip: whatever the paths contain, the options string must
// parse back to exactly one lower layer and the same three paths, and must not
// smuggle in extra options.
func FuzzOptionsRoundTrip(f *testing.F) {
	f.Add("/base", "/c/upper", "/c/work")
	f.Add("/a:/b", "/u,workdir=/evil", `/w\`)
	f.Add(`\`, `\\,`, `:\:`)
	f.Fuzz(func(t *testing.T, lower, upper, work string) {
		p, err := ParseOptions(Options(lower, upper, work))
		if err != nil {
			t.Fatal(err)
		}
		want := Parsed{Lower: []string{lower}, Upper: upper, Work: work}
		if !reflect.DeepEqual(p, want) {
			t.Fatalf("Options(%q, %q, %q) parsed as %+v", lower, upper, work, p)
		}
	})
}

// TestKernelAgrees mounts real overlays whose paths contain random awkward
// characters and checks that the kernel reads Options the way ParseOptions
// does: the mount works and shows the lower layer's content.
func TestKernelAgrees(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
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
