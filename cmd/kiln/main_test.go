package main

import (
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestParseRun(t *testing.T) {
	cfg, err := parseRun([]string{"-pids", "5", "-memory", "20000000", "/tmp/rfs", "sh", "-c", "echo hi"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Rootfs != "/tmp/rfs" || cfg.Hostname != "kiln" {
		t.Errorf("rootfs/hostname = %q/%q", cfg.Rootfs, cfg.Hostname)
	}
	// Flags after ROOTFS belong to the command, not to kiln.
	if want := []string{"sh", "-c", "echo hi"}; !reflect.DeepEqual(cfg.Args, want) {
		t.Errorf("Args = %q, want %q", cfg.Args, want)
	}
	if cfg.Limits.MaxPids != 5 || cfg.Limits.MemoryBytes != 20000000 {
		t.Errorf("Limits = %+v", cfg.Limits)
	}
	if cfg.Network != "bridge" {
		t.Errorf("Network = %q, want bridge by default", cfg.Network)
	}
	if len(cfg.ID) != 12 {
		t.Errorf("ID = %q, want 12 hex chars", cfg.ID)
	}
}

func TestParseRunErrors(t *testing.T) {
	for _, args := range [][]string{
		{},
		{"/tmp/rfs"},
		{"-pids", "-1", "/tmp/rfs", "sh"},
		{"-memory", "-5", "/tmp/rfs", "sh"},
		{"-pids", "lots", "/tmp/rfs", "sh"},
		{"-hostname", "", "/tmp/rfs", "sh"},
		{"-hostname", strings.Repeat("h", 65), "/tmp/rfs", "sh"},
		{"", "sh"},
		{"/tmp/rfs", ""},
		{"-bogus", "/tmp/rfs", "sh"},
		{"-net", "host", "/tmp/rfs", "sh"},
	} {
		if _, err := parseRun(args, io.Discard); err == nil {
			t.Errorf("parseRun(%q) succeeded, want error", args)
		}
	}
}

func TestDispatchUsage(t *testing.T) {
	for _, tc := range []struct {
		args []string
		code int
	}{
		{nil, 2},
		{[]string{"nope"}, 2},
		{[]string{"rootfs"}, 2},
		{[]string{"run"}, 2},
		{[]string{"run", "-pids", "x", "/r", "sh"}, 2},
		{[]string{"init", "id"}, 2},
		{[]string{"help"}, 0},
	} {
		var out strings.Builder
		if got := dispatch(tc.args, &out); got != tc.code {
			t.Errorf("dispatch(%q) = %d, want %d", tc.args, got, tc.code)
		}
		if !strings.Contains(out.String(), "usage") && !strings.Contains(out.String(), "internal") {
			t.Errorf("dispatch(%q) printed no usage: %q", tc.args, out.String())
		}
	}
}

// FuzzParseRun checks that any accepted command line yields a config the
// runtime can use: non-empty rootfs and command, non-negative limits, a valid
// hostname, and the command taken verbatim from the tail of the arguments.
func FuzzParseRun(f *testing.F) {
	f.Add("-pids\x005\x00/tmp/rfs\x00sh")
	f.Add("-memory=1\x00-hostname\x00box\x00/r\x00sh\x00-c\x00ls")
	f.Add("--\x00-weird-rootfs\x00cmd")
	f.Add("-net\x00none\x00/r\x00sh")
	f.Add("")
	f.Fuzz(func(t *testing.T, joined string) {
		args := strings.Split(joined, "\x00")
		cfg, err := parseRun(args, io.Discard)
		if err != nil {
			return
		}
		if cfg.Rootfs == "" || len(cfg.Args) == 0 || cfg.Args[0] == "" {
			t.Fatalf("empty rootfs or command from %q: %+v", args, cfg)
		}
		if cfg.Limits.MemoryBytes < 0 || cfg.Limits.MaxPids < 0 {
			t.Fatalf("negative limits from %q: %+v", args, cfg.Limits)
		}
		if cfg.Network != "bridge" && cfg.Network != "none" {
			t.Fatalf("bad network mode %q from %q", cfg.Network, args)
		}
		if cfg.Hostname == "" || len(cfg.Hostname) > maxHostname {
			t.Fatalf("bad hostname %q from %q", cfg.Hostname, args)
		}
		tail := args[len(args)-len(cfg.Args):]
		if !reflect.DeepEqual(tail, cfg.Args) {
			t.Fatalf("command %q is not the tail of %q", cfg.Args, args)
		}
	})
}
