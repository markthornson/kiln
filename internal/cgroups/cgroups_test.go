package cgroups

import (
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

// v1Root makes Root a temp directory laid out like a cgroup v1 mount: a
// subdirectory per controller, no cgroup.controllers file.
func v1Root(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	for _, ctrl := range []string{"memory", "pids"} {
		if err := os.MkdirAll(filepath.Join(dir, ctrl), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	setRoot(t, dir)
}

// v2Root makes Root a temp directory laid out like a cgroup v2 mount: a
// cgroup.controllers file at the root marks it unified.
func v2Root(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.controllers"), []byte("memory pids\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	setRoot(t, dir)
}

func setRoot(t *testing.T, dir string) {
	t.Helper()
	old := Root
	Root = dir
	t.Cleanup(func() { Root = old })
}

func TestVersionDetection(t *testing.T) {
	v1Root(t)
	if Version() != 1 {
		t.Errorf("v1 layout detected as v%d", Version())
	}
	v2Root(t)
	if Version() != 2 {
		t.Errorf("v2 layout detected as v%d", Version())
	}
}

// limitFile returns where the given limit is stored for container id under the
// current hierarchy, and whether the file should exist for value v.
func limitFile(id, which string) string {
	if Version() == 2 {
		name := map[string]string{"memory": "memory.max", "pids": "pids.max"}[which]
		return filepath.Join(Root, kilnDir, id, name)
	}
	ctrl := map[string]string{"memory": "memory", "pids": "pids"}[which]
	name := map[string]string{"memory": "memory.limit_in_bytes", "pids": "pids.max"}[which]
	return filepath.Join(Root, ctrl, kilnDir, id, name)
}

// emptyLeaves removes the files inside a group's directories. On a real cgroup
// filesystem rmdir removes a cgroup directory along with its control files;
// a temp-dir fixture has those as ordinary files, so the test clears them to
// let Destroy's rmdir succeed the way it does against the kernel.
func emptyLeaves(t *testing.T, id string) {
	t.Helper()
	for _, p := range procsFiles(id) {
		dir := filepath.Dir(p)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if !e.IsDir() {
				os.Remove(filepath.Join(dir, e.Name()))
			}
		}
	}
}

func readLimit(t *testing.T, id, which string) (string, bool) {
	t.Helper()
	b, err := os.ReadFile(limitFile(id, which))
	if os.IsNotExist(err) {
		return "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	return string(b), true
}

func checkCreateReadDestroy(t *testing.T, l Limits) {
	t.Helper()
	g, err := New("c1", l)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, which := range []string{"memory", "pids"} {
		want := map[string]int64{"memory": l.MemoryBytes, "pids": l.MaxPids}[which]
		got, exists := readLimit(t, "c1", which)
		if want > 0 {
			if !exists || got != strconv.FormatInt(want, 10) {
				t.Errorf("%s limit = %q (exists=%v), want %d", which, got, exists, want)
			}
		} else if exists {
			t.Errorf("%s limit file written for non-positive limit %d: %q", which, want, got)
		}
	}
	if ids := IDs(); !slices.Equal(ids, []string{"c1"}) {
		t.Errorf("IDs = %v, want [c1]", ids)
	}
	// A Joiner can be opened once the group exists (cgroup.procs is created by
	// the kernel; here the test makes it so the open succeeds).
	for _, p := range procsFiles("c1") {
		if err := os.WriteFile(p, nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	j, err := OpenJoiner("c1")
	if err != nil {
		t.Fatalf("OpenJoiner: %v", err)
	}
	if len(j) != len(procsFiles("c1")) {
		t.Errorf("Joiner has %d handles, want %d", len(j), len(procsFiles("c1")))
	}
	j.Close()

	emptyLeaves(t, "c1")
	if err := g.Destroy(); err != nil {
		t.Errorf("Destroy: %v", err)
	}
	if ids := IDs(); len(ids) != 0 {
		t.Errorf("IDs after Destroy = %v, want none", ids)
	}
}

func TestCreateReadDestroyV1(t *testing.T) {
	v1Root(t)
	checkCreateReadDestroy(t, Limits{MemoryBytes: 64 << 20, MaxPids: 10})
}

func TestCreateReadDestroyV2(t *testing.T) {
	v2Root(t)
	checkCreateReadDestroy(t, Limits{MemoryBytes: 64 << 20, MaxPids: 10})
}

func TestV2EnablesControllers(t *testing.T) {
	v2Root(t)
	if _, err := New("c1", Limits{MaxPids: 5}); err != nil {
		t.Fatal(err)
	}
	// Both the root and the kiln directory must opt their subtrees into the
	// controllers, or kiln/<id> would have no memory.max or pids.max.
	for _, dir := range []string{Root, filepath.Join(Root, kilnDir)} {
		b, err := os.ReadFile(filepath.Join(dir, "cgroup.subtree_control"))
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		if string(b) != "+memory +pids" {
			t.Errorf("%s/cgroup.subtree_control = %q", dir, b)
		}
	}
}

func TestRemoveMissingIsNoError(t *testing.T) {
	for _, setup := range []func(*testing.T){v1Root, v2Root} {
		setup(t)
		if err := Remove("never-created"); err != nil {
			t.Errorf("Remove of a missing group: %v", err)
		}
	}
}

// FuzzLimitsRoundTrip: for either hierarchy and any limit values, New writes
// exactly the positive limits (and nothing for non-positive ones), IDs lists
// the group, and Destroy removes it. A model of the policy, checked against
// the files actually written.
func FuzzLimitsRoundTrip(f *testing.F) {
	f.Add(int64(64<<20), int64(10), false)
	f.Add(int64(0), int64(0), true)
	f.Add(int64(-1), int64(5), true)
	f.Fuzz(func(t *testing.T, mem, pids int64, v2 bool) {
		dir := t.TempDir()
		if v2 {
			if err := os.WriteFile(filepath.Join(dir, "cgroup.controllers"), []byte("memory pids\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		} else {
			for _, ctrl := range []string{"memory", "pids"} {
				if err := os.MkdirAll(filepath.Join(dir, ctrl), 0o755); err != nil {
					t.Fatal(err)
				}
			}
		}
		setRoot(t, dir)

		l := Limits{MemoryBytes: mem, MaxPids: pids}
		g, err := New("c1", l)
		if err != nil {
			t.Fatalf("New(%+v, v2=%v): %v", l, v2, err)
		}
		for _, tc := range []struct {
			which string
			v     int64
		}{{"memory", mem}, {"pids", pids}} {
			got, exists := readLimit(t, "c1", tc.which)
			switch {
			case tc.v > 0 && (!exists || got != strconv.FormatInt(tc.v, 10)):
				t.Fatalf("%s = %q (exists=%v), want %d", tc.which, got, exists, tc.v)
			case tc.v <= 0 && exists:
				t.Fatalf("%s written for non-positive %d", tc.which, tc.v)
			}
		}
		if ids := IDs(); !slices.Equal(ids, []string{"c1"}) {
			t.Fatalf("IDs = %v, want [c1]", ids)
		}
		emptyLeaves(t, "c1")
		if err := g.Destroy(); err != nil {
			t.Fatalf("Destroy: %v", err)
		}
		if ids := IDs(); len(ids) != 0 {
			t.Fatalf("IDs after Destroy = %v", ids)
		}
	})
}
