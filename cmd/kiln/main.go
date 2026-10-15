// Command kiln is a minimal container runtime.
//
//	kiln rootfs DIR [BINARY...]
//	kiln run [-memory BYTES] [-pids N] [-hostname NAME] [-net bridge|none] ROOTFS CMD [ARG...]
//
// "init" is a hidden subcommand: container.Run re-executes kiln with it inside
// the new namespaces.
package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/markthornson/kiln/internal/cgroups"
	"github.com/markthornson/kiln/internal/container"
	"github.com/markthornson/kiln/internal/rootfs"
)

const usage = `usage:
  kiln rootfs DIR [BINARY...]
  kiln run [-memory BYTES] [-pids N] [-hostname NAME] [-net bridge|none] ROOTFS CMD [ARG...]
`

// maxHostname is the kernel's limit for sethostname (HOST_NAME_MAX).
const maxHostname = 64

func main() {
	os.Exit(dispatch(os.Args[1:], os.Stderr))
}

// dispatch runs a subcommand and returns the process exit code.
func dispatch(args []string, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "rootfs":
		if len(args) < 2 {
			fmt.Fprint(stderr, usage)
			return 2
		}
		bins := args[2:]
		if len(bins) == 0 {
			bins = rootfs.DefaultBinaries
		}
		if err := rootfs.Build(args[1], bins); err != nil {
			fmt.Fprintf(stderr, "kiln: rootfs: %v\n", err)
			return 1
		}
		return 0
	case "run":
		cfg, err := parseRun(args[1:], stderr)
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		if err != nil {
			fmt.Fprintf(stderr, "kiln: run: %v\n%s", err, usage)
			return 2
		}
		code, err := container.Run(cfg)
		if err != nil {
			fmt.Fprintf(stderr, "kiln: run: %v\n", err)
			return 1
		}
		return code
	case "init":
		if len(args) < 4 {
			fmt.Fprintln(stderr, "kiln: init is internal; use kiln run")
			return 2
		}
		err := container.Init(args[1], args[2], args[3], args[4:])
		// Init only returns on failure.
		fmt.Fprintf(stderr, "kiln: init: %v\n", err)
		return 1
	case "-h", "-help", "--help", "help":
		fmt.Fprint(stderr, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "kiln: unknown command %q\n%s", args[0], usage)
		return 2
	}
}

// parseRun turns the arguments of "kiln run" into a container config.
// Flags must come before ROOTFS; everything after it is the command.
func parseRun(args []string, stderr io.Writer) (container.Config, error) {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	fs.SetOutput(stderr)
	memory := fs.Int64("memory", 0, "memory limit in bytes (0 = unlimited)")
	pids := fs.Int64("pids", 0, "max processes/threads (0 = unlimited)")
	hostname := fs.String("hostname", "kiln", "container hostname")
	netMode := fs.String("net", container.NetworkBridge, "network: bridge (eth0 on kiln0) or none (loopback only)")
	if err := fs.Parse(args); err != nil {
		return container.Config{}, err
	}
	if *memory < 0 || *pids < 0 {
		return container.Config{}, fmt.Errorf("limits must not be negative")
	}
	if *hostname == "" || len(*hostname) > maxHostname {
		return container.Config{}, fmt.Errorf("hostname must be 1-%d bytes", maxHostname)
	}
	if *netMode != container.NetworkBridge && *netMode != container.NetworkNone {
		return container.Config{}, fmt.Errorf("-net must be %q or %q", container.NetworkBridge, container.NetworkNone)
	}
	if fs.NArg() < 2 {
		return container.Config{}, fmt.Errorf("need ROOTFS and CMD")
	}
	if fs.Arg(0) == "" || fs.Arg(1) == "" {
		return container.Config{}, fmt.Errorf("ROOTFS and CMD must not be empty")
	}
	return container.Config{
		ID:       newID(),
		Rootfs:   fs.Arg(0),
		Hostname: *hostname,
		Args:     fs.Args()[1:],
		Limits:   cgroups.Limits{MemoryBytes: *memory, MaxPids: *pids},
		Network:  *netMode,
	}, nil
}

// newID returns a random container ID, used as the cgroup name.
func newID() string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic(err) // crypto/rand does not fail on Linux
	}
	return hex.EncodeToString(b)
}
