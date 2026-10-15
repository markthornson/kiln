// Package cgroups applies per-container resource limits (memory and process
// count) using cgroups. It supports both hierarchies and picks one at runtime:
//
//   - cgroup v1: a separate tree per controller, e.g. /sys/fs/cgroup/memory
//     and /sys/fs/cgroup/pids, each with its own kiln/<id> directory.
//   - cgroup v2: a single unified tree at /sys/fs/cgroup, where each
//     kiln/<id> directory carries every controller, and a parent must list a
//     controller in cgroup.subtree_control before its children can use it.
//
// The rest of kiln is unaffected by which is in use: New, OpenJoiner, Destroy,
// IDs and Remove behave the same either way.
package cgroups

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
)

// Root is the cgroup mount point. Overridable for tests.
var Root = "/sys/fs/cgroup"

// Limits describes the resources a container may use. Zero means unlimited.
type Limits struct {
	MemoryBytes int64
	MaxPids     int64
}

// kilnDir is the parent of every per-container group, relative to a hierarchy
// root.
const kilnDir = "kiln"

// Version reports the cgroup hierarchy in use at Root: 2 for the unified v2
// hierarchy, 1 otherwise. v2 is identified by the cgroup.controllers file the
// kernel places at the root of a cgroup2 mount, which v1 never has.
func Version() int {
	if _, err := os.Stat(filepath.Join(Root, "cgroup.controllers")); err == nil {
		return 2
	}
	return 1
}

// Group is a per-container cgroup.
type Group struct {
	id string
	v2 bool
}

// New creates the cgroup for container id and writes its limits.
func New(id string, l Limits) (*Group, error) {
	g := &Group{id: id, v2: Version() == 2}
	if g.v2 {
		return g, g.createV2(l)
	}
	return g, g.createV1(l)
}

// v1 controllers kiln uses, with the file that holds each limit. A zero limit
// is left unwritten, keeping the controller's default (unlimited).
func v1Files(l Limits) map[string]map[string]int64 {
	return map[string]map[string]int64{
		"memory": {"memory.limit_in_bytes": l.MemoryBytes},
		"pids":   {"pids.max": l.MaxPids},
	}
}

func (g *Group) createV1(l Limits) error {
	for ctrl, files := range v1Files(l) {
		dir := filepath.Join(Root, ctrl, kilnDir, g.id)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("create %s cgroup: %w", ctrl, err)
		}
		for file, v := range files {
			if err := writeLimit(filepath.Join(dir, file), v); err != nil {
				return err
			}
		}
	}
	return nil
}

func (g *Group) createV2(l Limits) error {
	// A controller is only usable in kiln/<id> once its ancestors enable it
	// for their subtrees: first the root (so the kiln directory has it
	// available), then the kiln directory (so each container has it).
	kiln := filepath.Join(Root, kilnDir)
	if err := os.MkdirAll(kiln, 0o755); err != nil {
		return fmt.Errorf("create kiln cgroup: %w", err)
	}
	for _, dir := range []string{Root, kiln} {
		if err := os.WriteFile(filepath.Join(dir, "cgroup.subtree_control"), []byte("+memory +pids"), 0o644); err != nil {
			return fmt.Errorf("enable controllers in %s: %w", dir, err)
		}
	}
	dir := filepath.Join(kiln, g.id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create cgroup: %w", err)
	}
	// Same limits, different file names; v2 spells "unlimited" as "max", which
	// is the default, so an unset limit is still just left unwritten.
	for file, v := range map[string]int64{"memory.max": l.MemoryBytes, "pids.max": l.MaxPids} {
		if err := writeLimit(filepath.Join(dir, file), v); err != nil {
			return err
		}
	}
	return nil
}

// writeLimit writes a positive limit; a zero or negative limit is skipped,
// leaving the controller's default.
func writeLimit(path string, v int64) error {
	if v <= 0 {
		return nil
	}
	if err := os.WriteFile(path, []byte(strconv.FormatInt(v, 10)), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", filepath.Base(path), err)
	}
	return nil
}

// procsFiles returns the cgroup.procs paths a process writes to join the group
// of container id: one per controller under v1, a single unified file under v2.
func procsFiles(id string) []string {
	if Version() == 2 {
		return []string{filepath.Join(Root, kilnDir, id, "cgroup.procs")}
	}
	return []string{
		filepath.Join(Root, "memory", kilnDir, id, "cgroup.procs"),
		filepath.Join(Root, "pids", kilnDir, id, "cgroup.procs"),
	}
}

// Joiner holds open handles to a group's cgroup.procs files so a process can
// join after it has pivoted away from /sys/fs/cgroup.
type Joiner []*os.File

// OpenJoiner opens the cgroup.procs files of the group named by id (as created
// by New).
func OpenJoiner(id string) (Joiner, error) {
	var j Joiner
	for _, path := range procsFiles(id) {
		f, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			j.Close()
			return nil, fmt.Errorf("open cgroup.procs: %w", err)
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
// This holds for both v1 and v2.
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
	return removeGroup(g.id, g.v2)
}

// Remove deletes the group of container id. It fails, harmlessly, while the
// group still has processes.
func Remove(id string) error {
	return removeGroup(id, Version() == 2)
}

func removeGroup(id string, v2 bool) error {
	if v2 {
		return ignoreNotExist(os.Remove(filepath.Join(Root, kilnDir, id)))
	}
	var first error
	for _, ctrl := range []string{"memory", "pids"} {
		if err := ignoreNotExist(os.Remove(filepath.Join(Root, ctrl, kilnDir, id))); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func ignoreNotExist(err error) error {
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// IDs lists the container IDs that have a kiln group.
func IDs() []string {
	dirs := []string{filepath.Join(Root, kilnDir)}
	if Version() != 2 {
		dirs = []string{filepath.Join(Root, "memory", kilnDir), filepath.Join(Root, "pids", kilnDir)}
	}
	seen := map[string]bool{}
	var ids []string
	for _, dir := range dirs {
		entries, _ := os.ReadDir(dir)
		for _, e := range entries {
			if e.IsDir() && !seen[e.Name()] {
				seen[e.Name()] = true
				ids = append(ids, e.Name())
			}
		}
	}
	return ids
}
