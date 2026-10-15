package mountinfo

import (
	"reflect"
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	in := `23 28 0:22 / /proc rw,relatime - proc proc rw
36 35 98:0 /mnt1 /mnt\0402 rw,noatime master:1 shared:2 - ext3 /dev/root rw,errors=continue
40 28 0:4 net:[4026531840] /run/netns/a rw shared:3 - nsfs nsfs rw
`
	got, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	want := []Mount{
		{ID: 23, Parent: 28, Root: "/", MountPoint: "/proc", FSType: "proc", Source: "proc"},
		{ID: 36, Parent: 35, Root: "/mnt1", MountPoint: "/mnt 2", FSType: "ext3", Source: "/dev/root"},
		{ID: 40, Parent: 28, Root: "net:[4026531840]", MountPoint: "/run/netns/a", FSType: "nsfs", Source: "nsfs"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Parse() =\n%+v\nwant\n%+v", got, want)
	}
}

func TestParseLineErrors(t *testing.T) {
	for _, line := range []string{
		"",
		"23 28 0:22 / /proc rw,relatime proc proc rw", // no separator
		"23 28 0:22 / /proc rw - proc",                // too few fields after "-"
		"x 28 0:22 / /proc rw - proc proc rw",
		"23 y 0:22 / /proc rw - proc proc rw",
	} {
		if _, err := ParseLine(line); err == nil {
			t.Errorf("ParseLine(%q) succeeded, want error", line)
		}
	}
}

func TestUnescape(t *testing.T) {
	for in, want := range map[string]string{
		`a\040b`:   "a b",
		`\134`:     `\`,
		`\011\012`: "\t\n",
		`\400`:     `\400`, // does not fit in a byte
		`\04`:      `\04`,  // too short
		`\08`:      `\08`,  // not octal
		`tail\`:    `tail\`,
	} {
		if got := Unescape(in); got != want {
			t.Errorf("Unescape(%q) = %q, want %q", in, got, want)
		}
	}
}

// FuzzEscapeRoundTrip: Unescape must invert Escape for every string, and
// escaped output must contain none of the bytes that separate fields.
func FuzzEscapeRoundTrip(f *testing.F) {
	f.Add("/mnt/with space")
	f.Add(`back\slash\040`)
	f.Add("\t\n\r\v ")
	f.Fuzz(func(t *testing.T, s string) {
		e := Escape(s)
		if strings.ContainsAny(e, " \t\n") {
			t.Fatalf("Escape(%q) = %q contains a separator", s, e)
		}
		if got := Unescape(e); got != s {
			t.Fatalf("Unescape(Escape(%q)) = %q", s, got)
		}
	})
}

// FuzzParseLine: whatever ParseLine accepts must survive Format and a second
// parse unchanged. This catches field-splitting and escaping disagreements.
func FuzzParseLine(f *testing.F) {
	f.Add("23 28 0:22 / /proc rw,relatime - proc proc rw")
	f.Add(`36 35 98:0 /mnt1 /mnt\0402 rw,noatime master:1 - ext3 /dev/root rw`)
	f.Add("1 0 0:1 / x /a\rb rw - tmpfs tmp\vfs rw")
	f.Fuzz(func(t *testing.T, line string) {
		m, err := ParseLine(line)
		if err != nil {
			return
		}
		again, err := ParseLine(Format(m))
		if err != nil {
			t.Fatalf("ParseLine(Format(%+v)): %v", m, err)
		}
		if again != m {
			t.Fatalf("round trip changed mount:\n got %+v\nwant %+v", again, m)
		}
	})
}
