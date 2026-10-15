// Package mountinfo parses /proc/<pid>/mountinfo.
//
// Each line looks like (see proc(5)):
//
//	36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue
//	ID PARENT MAJ:MIN ROOT MOUNTPOINT OPTIONS [OPTIONAL...] - FSTYPE SOURCE SUPEROPTIONS
//
// Fields are separated by single spaces. The kernel escapes space, tab,
// newline and backslash inside fields as \040, \011, \012 and \134.
package mountinfo

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// Mount is one mount as seen from the reading process's mount namespace.
type Mount struct {
	ID, Parent int
	Root       string // path within the filesystem that forms this mount's root
	MountPoint string
	FSType     string
	Source     string
}

// Self parses /proc/self/mountinfo.
func Self() ([]Mount, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f)
}

// Parse reads every mountinfo line from r.
func Parse(r io.Reader) ([]Mount, error) {
	var mounts []Mount
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		if sc.Text() == "" {
			continue
		}
		m, err := ParseLine(sc.Text())
		if err != nil {
			return nil, err
		}
		mounts = append(mounts, m)
	}
	return mounts, sc.Err()
}

// ParseLine parses a single mountinfo line.
func ParseLine(line string) (Mount, error) {
	// Split on single spaces, not strings.Fields: Fields also splits on \r,
	// \v, U+00A0 and so on, which the kernel does not escape.
	f := strings.Split(line, " ")
	sep := -1
	for i := 6; i < len(f); i++ {
		if f[i] == "-" {
			sep = i
			break
		}
	}
	if sep < 0 || len(f) < sep+4 {
		return Mount{}, fmt.Errorf("mountinfo: malformed line %q", line)
	}
	id, err := strconv.Atoi(f[0])
	if err != nil {
		return Mount{}, fmt.Errorf("mountinfo: bad mount ID in %q", line)
	}
	parent, err := strconv.Atoi(f[1])
	if err != nil {
		return Mount{}, fmt.Errorf("mountinfo: bad parent ID in %q", line)
	}
	return Mount{
		ID:         id,
		Parent:     parent,
		Root:       Unescape(f[3]),
		MountPoint: Unescape(f[4]),
		FSType:     Unescape(f[sep+1]),
		Source:     Unescape(f[sep+2]),
	}, nil
}

// Format renders m as a mountinfo line, with placeholder device and options.
func Format(m Mount) string {
	return fmt.Sprintf("%d %d 0:0 %s %s rw - %s %s rw",
		m.ID, m.Parent, Escape(m.Root), Escape(m.MountPoint), Escape(m.FSType), Escape(m.Source))
}

// escaped lists the bytes the kernel escapes (seq_file's mangle set).
const escaped = " \t\n\\"

// Escape encodes s the way the kernel does in mountinfo fields.
func Escape(s string) string {
	if !strings.ContainsAny(s, escaped) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(escaped, s[i]) >= 0 {
			fmt.Fprintf(&b, "\\%03o", s[i])
		} else {
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// Unescape decodes \NNN octal escapes. Anything else is kept as is.
func Unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		// \NNN with a first digit above 3 would not fit in a byte.
		if s[i] == '\\' && i+3 < len(s) && s[i+1] >= '0' && s[i+1] <= '3' && isOctal(s[i+2]) && isOctal(s[i+3]) {
			b.WriteByte((s[i+1]-'0')<<6 | (s[i+2]-'0')<<3 | (s[i+3] - '0'))
			i += 3
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func isOctal(c byte) bool { return c >= '0' && c <= '7' }
