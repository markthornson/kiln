package container

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// StateDir holds one directory per running container:
//
//	<StateDir>/<id>/owner   PID of the kiln process running the container
//	<StateDir>/<id>/upper   the container's writable overlay layer
//	<StateDir>/<id>/work    overlayfs scratch space (same filesystem as upper)
//	<StateDir>/<id>/merged  where the overlay is mounted, inside the container's
//	                        mount namespace only
var StateDir = "/var/lib/kiln/containers"

// newState creates the state directory for container id, after removing any
// left behind by kiln processes that died without cleaning up.
func newState(id string) (string, error) {
	if id == "" || id == "." || id == ".." || strings.ContainsRune(id, '/') {
		return "", fmt.Errorf("invalid container ID %q", id)
	}
	pruneStale()
	dir := filepath.Join(StateDir, id)
	if err := os.MkdirAll(StateDir, 0o700); err != nil {
		return "", err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", fmt.Errorf("container %s: %w", id, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "owner"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600); err != nil {
		os.RemoveAll(dir)
		return "", err
	}
	for _, d := range []string{"upper", "work", "merged"} {
		if err := os.Mkdir(filepath.Join(dir, d), 0o755); err != nil {
			os.RemoveAll(dir)
			return "", err
		}
	}
	return dir, nil
}

// pruneStale removes state directories whose owning kiln process has exited.
// Their containers are gone too: Run sets Pdeathsig, so a container dies with
// its kiln process, and the overlay was only mounted in its namespace.
func pruneStale() {
	entries, err := os.ReadDir(StateDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		dir := filepath.Join(StateDir, e.Name())
		data, err := os.ReadFile(filepath.Join(dir, "owner"))
		if err != nil {
			continue // being created right now, or not ours
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || pid <= 0 {
			continue
		}
		if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
			os.RemoveAll(dir)
		}
	}
}
