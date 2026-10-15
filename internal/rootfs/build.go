package rootfs

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
)

// DefaultBinaries is a small toolbox that makes a rootfs usable interactively.
var DefaultBinaries = []string{"sh", "ls", "cat", "echo", "ps", "hostname", "mount", "id", "sleep", "head"}

// Build creates a rootfs at dir containing the named host binaries (resolved
// via $PATH) plus every shared library they need.
func Build(dir string, binaries []string) error {
	for _, d := range []string{"bin", "dev", "proc", "tmp", "etc"} {
		if err := os.MkdirAll(filepath.Join(dir, d), 0o755); err != nil {
			return err
		}
	}
	for _, name := range binaries {
		src, err := exec.LookPath(name)
		if err != nil {
			return fmt.Errorf("find %s: %w", name, err)
		}
		if err := copyFile(src, filepath.Join(dir, "bin", name)); err != nil {
			return err
		}
		out, err := exec.Command("ldd", src).CombinedOutput()
		if err != nil && len(out) == 0 {
			return fmt.Errorf("ldd %s: %w", src, err)
		}
		for _, lib := range ParseLdd(string(out)) {
			if err := copyFile(lib, filepath.Join(dir, lib)); err != nil {
				return err
			}
		}
	}
	return os.WriteFile(filepath.Join(dir, "etc", "hostname"), []byte("kiln\n"), 0o644)
}

func copyFile(src, dst string) error {
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	return out.Close()
}
