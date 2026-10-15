package rootfs

import (
	"reflect"
	"strings"
	"testing"
)

func TestParseLdd(t *testing.T) {
	out := `	linux-vdso.so.1 (0x00007ffc8a9e1000)
	libtinfo.so.6 => /lib/x86_64-linux-gnu/libtinfo.so.6 (0x00007f1e2c000000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f1e2bc00000)
	libmissing.so => not found
	/lib64/ld-linux-x86-64.so.2 (0x00007f1e2c1a0000)
	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f1e2bc00000)
`
	want := []string{
		"/lib/x86_64-linux-gnu/libtinfo.so.6",
		"/lib/x86_64-linux-gnu/libc.so.6",
		"/lib64/ld-linux-x86-64.so.2",
	}
	if got := ParseLdd(out); !reflect.DeepEqual(got, want) {
		t.Errorf("ParseLdd() = %q, want %q", got, want)
	}
}

func TestParseLddStatic(t *testing.T) {
	if got := ParseLdd("\tnot a dynamic executable\n"); len(got) != 0 {
		t.Errorf("static binary should yield no libs, got %q", got)
	}
}

// FuzzParseLdd checks invariants that must hold for any input:
// every result is absolute, contains no whitespace, and is unique.
func FuzzParseLdd(f *testing.F) {
	f.Add("libc.so.6 => /lib/libc.so.6 (0x1)\n/lib64/ld.so (0x2)")
	f.Add("x => not found")
	f.Add("")
	f.Fuzz(func(t *testing.T, in string) {
		seen := map[string]bool{}
		for _, p := range ParseLdd(in) {
			if !strings.HasPrefix(p, "/") {
				t.Fatalf("non-absolute path %q", p)
			}
			if strings.ContainsAny(p, " \t\n") {
				t.Fatalf("path contains whitespace %q", p)
			}
			if seen[p] {
				t.Fatalf("duplicate path %q", p)
			}
			seen[p] = true
		}
	})
}
