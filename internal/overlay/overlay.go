// Package overlay builds overlayfs mount options.
//
// An overlay mount stacks a writable upper directory over a read-only lower
// one: reads fall through to lower, writes go to upper (copying files up on
// first modification), and deletions are recorded in upper as whiteouts. The
// lower directory is never modified, so one base image can back many
// containers.
//
// Paths are passed in a single options string,
//
//	lowerdir=/base,upperdir=/c/upper,workdir=/c/work
//
// in which the kernel splits options on ',' and multiple lower directories
// on ':'. A path containing either character must be escaped with '\', or the
// mount fails or, worse, silently stacks the wrong directories ("/a:/b" is two
// lower layers).
package overlay

import (
	"errors"
	"strings"
)

var escaper = strings.NewReplacer(`\`, `\\`, `,`, `\,`, `:`, `\:`)

// Escape escapes a path for use as an overlay option value.
func Escape(path string) string { return escaper.Replace(path) }

// Options returns the mount data for an overlay of upper (with its required
// work directory) over a single read-only lower directory. upper and work must
// be on the same filesystem.
func Options(lower, upper, work string) string {
	return "lowerdir=" + Escape(lower) + ",upperdir=" + Escape(upper) + ",workdir=" + Escape(work)
}

// Parsed is the result of ParseOptions.
type Parsed struct {
	Lower        []string
	Upper, Work  string
	OtherOptions []string
}

// ParseOptions parses mount data the way overlayfs does: options split on
// unescaped ',', lowerdir split on unescaped ':', then '\' escapes removed.
// It is a model of the kernel used to check Options, not used at runtime.
func ParseOptions(data string) (Parsed, error) {
	var p Parsed
	for _, opt := range splitUnescaped(data, ',') {
		key, val, _ := strings.Cut(opt, "=")
		switch key {
		case "lowerdir":
			for _, l := range splitUnescaped(val, ':') {
				p.Lower = append(p.Lower, unescape(l))
			}
		case "upperdir":
			p.Upper = unescape(val)
		case "workdir":
			p.Work = unescape(val)
		default:
			p.OtherOptions = append(p.OtherOptions, opt)
		}
	}
	if len(p.Lower) == 0 {
		return p, errors.New("overlay: no lowerdir")
	}
	return p, nil
}

// splitUnescaped splits s on sep, except where sep is preceded by an odd
// number of backslashes. Escapes are kept for the caller to remove.
func splitUnescaped(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++ // skip the escaped byte
		case sep:
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
		}
		b.WriteByte(s[i])
	}
	return b.String()
}
