// Package rootfs builds minimal root filesystems by copying host binaries
// and the shared libraries they depend on.
package rootfs

import (
	"bufio"
	"strings"
)

// ParseLdd extracts the absolute library paths from `ldd` output.
//
// ldd prints lines in a few shapes:
//
//	linux-vdso.so.1 (0x00007ffd...)                     -> no file, skipped
//	libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x...) -> path after "=>"
//	/lib64/ld-linux-x86-64.so.2 (0x...)                 -> bare absolute path
//	libfoo.so => not found                               -> skipped
//
// Duplicates are removed; order of first appearance is preserved.
func ParseLdd(out string) []string {
	var libs []string
	seen := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if _, rhs, ok := strings.Cut(line, "=>"); ok {
			line = strings.TrimSpace(rhs)
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		path := fields[0]
		if !strings.HasPrefix(path, "/") || seen[path] {
			continue
		}
		seen[path] = true
		libs = append(libs, path)
	}
	return libs
}
