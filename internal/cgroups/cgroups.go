// Package cgroups applies resource limits using cgroup v1 controllers.
package cgroups

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Root is the cgroup v1 mount point. Overridable for tests.
var Root = "/sys/fs/cgroup"

// Limits describes the resources a container may use. Zero means unlimited.
type Limits struct {
	MemoryBytes int64
	MaxPids     int64
}

// Group is a per-container cgroup across the memory and pids controllers.
type Group struct {
	name string
}

// New creates cgroup directories named kiln/<id> and writes the limits.
func New(id string, l Limits) (*Group, error) {
	g := &Group{name: filepath.Join("kiln", id)}
	writes := map[string]map[string]int64{
		"memory": {"memory.limit_in_bytes": l.MemoryBytes},
		"pids":   {"pids.max": l.MaxPids},
	}
	for ctrl, files := range writes {
		dir := g.dir(ctrl)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("create %s cgroup: %w", ctrl, err)
		}
		for file, v := range files {
			if v <= 0 {
				continue
			}
			if err := os.WriteFile(filepath.Join(dir, file), []byte(strconv.FormatInt(v, 10)), 0o644); err != nil {
				return nil, fmt.Errorf("write %s: %w", file, err)
			}
		}
	}
	return g, nil
}

// Joiner holds open handles to a group's cgroup.procs files so a process can
// join after it has chrooted away from /sys/fs/cgroup.
type Joiner []*os.File

// OpenJoiner opens the cgroup.procs files of the group named by id (as
// created by New).
func OpenJoiner(id string) (Joiner, error) {
	g := &Group{name: filepath.Join("kiln", id)}
	var j Joiner
	for _, ctrl := range []string{"memory", "pids"} {
		f, err := os.OpenFile(filepath.Join(g.dir(ctrl), "cgroup.procs"), os.O_WRONLY, 0)
		if err != nil {
			j.Close()
			return nil, fmt.Errorf("open %s cgroup: %w", ctrl, err)
		}
		j = append(j, f)
	}
	return j, nil
}

// JoinSelf moves the calling process (all threads) into the group.
//
// The pids controller only enforces pids.max on fork, not on migration, so a
// multi-threaded Go process can join a group whose limit is below its thread
// count, as long as it execs (collapsing to one thread) immediately after.
func (j Joiner) JoinSelf() error {
	for _, f := range j {
		if _, err := f.Write([]byte("0")); err != nil {
			return fmt.Errorf("join cgroup: %w", err)
		}
	}
	return nil
}

// Close releases the handles.
func (j Joiner) Close() {
	for _, f := range j {
		f.Close()
	}
}

// Destroy removes the group. All its processes must have exited.
func (g *Group) Destroy() error {
	var first error
	for _, ctrl := range []string{"memory", "pids"} {
		if err := os.Remove(g.dir(ctrl)); err != nil && !os.IsNotExist(err) && first == nil {
			first = err
		}
	}
	return first
}

func (g *Group) dir(ctrl string) string { return filepath.Join(Root, ctrl, g.name) }
