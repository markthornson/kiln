package overlay

import (
	"reflect"
	"testing"
)

func TestOptions(t *testing.T) {
	got := Options("/base,v1", `/c/up\per`, "/c/work:x")
	want := `lowerdir=/base\,v1,upperdir=/c/up\\per,workdir=/c/work\:x`
	if got != want {
		t.Errorf("Options = %q, want %q", got, want)
	}
}

func TestParseOptions(t *testing.T) {
	p, err := ParseOptions(`lowerdir=/a\:b:/c,upperdir=/u,workdir=/w\,1,xino=off`)
	if err != nil {
		t.Fatal(err)
	}
	want := Parsed{Lower: []string{"/a:b", "/c"}, Upper: "/u", Work: "/w,1", OtherOptions: []string{"xino=off"}}
	if !reflect.DeepEqual(p, want) {
		t.Errorf("ParseOptions = %+v, want %+v", p, want)
	}
}

// FuzzOptionsRoundTrip: whatever the paths contain, the options string must
// parse back to exactly one lower layer and the same three paths, and must not
// smuggle in extra options.
func FuzzOptionsRoundTrip(f *testing.F) {
	f.Add("/base", "/c/upper", "/c/work")
	f.Add("/a:/b", "/u,workdir=/evil", `/w\`)
	f.Add(`\`, `\\,`, `:\:`)
	f.Fuzz(func(t *testing.T, lower, upper, work string) {
		p, err := ParseOptions(Options(lower, upper, work))
		if err != nil {
			t.Fatal(err)
		}
		want := Parsed{Lower: []string{lower}, Upper: upper, Work: work}
		if !reflect.DeepEqual(p, want) {
			t.Fatalf("Options(%q, %q, %q) parsed as %+v", lower, upper, work, p)
		}
	})
}
