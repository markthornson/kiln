// Package container runs a command in isolated Linux namespaces.
//
// The parent creates a cgroup, then re-executes /proc/self/exe with the hidden
// "init" subcommand inside fresh UTS, PID, mount and network namespaces. The
// parent connects the child's network namespace to the host bridge and sends
// the child its address over a pipe (fd 3). The child configures its network,
// sets the hostname, mounts an overlay of a fresh writable layer over the
// read-only base rootfs, pivots into it, mounts /proc and /dev, joins the
// cgroup, drops all capabilities and installs a seccomp filter, and execs the
// command.
package container

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"

	"github.com/markthornson/kiln/internal/cgroups"
	"github.com/markthornson/kiln/internal/network"
	"github.com/markthornson/kiln/internal/overlay"
	"github.com/markthornson/kiln/internal/seccomp"
)

// Network modes.
const (
	NetworkNone   = "none"   // own namespace with loopback only
	NetworkBridge = "bridge" // plus eth0 on the kiln0 bridge
)

// Config describes one container run.
type Config struct {
	ID       string
	Rootfs   string // read-only base image; the container writes to its own layer
	Hostname string
	Args     []string
	Limits   cgroups.Limits
	Network  string // NetworkNone (also the zero value) or NetworkBridge
}

// Run starts the container, waits for it and returns its exit code.
func Run(c Config) (int, error) {
	switch c.Network {
	case "", NetworkNone, NetworkBridge:
	default:
		return -1, fmt.Errorf("unknown network mode %q", c.Network)
	}
	base, err := filepath.Abs(c.Rootfs)
	if err != nil {
		return -1, err
	}
	if fi, err := os.Stat(base); err != nil || !fi.IsDir() {
		return -1, fmt.Errorf("rootfs %s is not a directory", c.Rootfs)
	}
	state, err := newState(c.ID)
	if err != nil {
		return -1, err
	}
	defer os.RemoveAll(state)

	cmd := exec.Command("/proc/self/exe", append([]string{"init", c.ID, base, state, c.Hostname}, c.Args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET,
		// If kiln dies (even by SIGKILL), take the container with it. Otherwise
		// it would keep running with an IP whose lease, owned by kiln's PID,
		// looks stale and gets handed to the next container.
		Pdeathsig: syscall.SIGKILL,
	}
	if c.Network == NetworkBridge {
		if err := network.EnsureBridge(); err != nil {
			return -1, err
		}
	}

	group, err := cgroups.New(c.ID, c.Limits)
	if err != nil {
		return -1, err
	}
	defer group.Destroy()

	// The child blocks reading this pipe until its network is attached.
	syncR, syncW, err := os.Pipe()
	if err != nil {
		return -1, err
	}
	defer syncW.Close()
	cmd.ExtraFiles = []*os.File{syncR} // fd 3 in the child
	err = cmd.Start()
	syncR.Close()
	if err != nil {
		return -1, fmt.Errorf("start: %w", err)
	}

	var spec network.Spec
	if c.Network == NetworkBridge {
		att, err := network.Attach(c.ID, cmd.Process.Pid)
		if err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			return -1, err
		}
		defer att.Detach()
		spec = att.Spec
	}
	if _, err := fmt.Fprintln(syncW, spec); err != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return -1, fmt.Errorf("signal container: %w", err)
	}
	syncW.Close()

	err = cmd.Wait()
	if exitErr, ok := err.(*exec.ExitError); ok {
		// Like a shell, report death-by-signal as 128+signal.
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			fmt.Fprintf(os.Stderr, "kiln: container killed by signal %d (%v)\n", int(ws.Signal()), ws.Signal())
			return 128 + int(ws.Signal()), nil
		}
		return exitErr.ExitCode(), nil
	}
	if err != nil {
		return -1, err
	}
	return 0, nil
}

// Init runs inside the new namespaces as PID 1. It never returns on success.
// base is the read-only image and state the directory made by newState.
func Init(id, base, state, hostname string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command given")
	}
	// Keep this goroutine on one thread so nothing migrates mid-setup.
	runtime.LockOSThread()
	// Wait for the parent to attach our network namespace (see Run).
	sync := os.NewFile(3, "sync")
	spec, err := network.ReadSpec(sync)
	sync.Close()
	if err != nil {
		return err
	}
	if err := network.ConfigureContainer(spec); err != nil {
		return err
	}
	// Opened before pivot_root, used just before exec; see Joiner.JoinSelf.
	cg, err := cgroups.OpenJoiner(id)
	if err != nil {
		return err
	}
	if err := syscall.Sethostname([]byte(hostname)); err != nil {
		return fmt.Errorf("sethostname: %w", err)
	}
	// Stop our mounts from propagating back to the host.
	if err := syscall.Mount("", "/", "", syscall.MS_PRIVATE|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("make / private: %w", err)
	}
	// Mounted in our own namespace only: the host never sees it, and it goes
	// away with the container.
	merged := filepath.Join(state, "merged")
	opts := overlay.Options(base, filepath.Join(state, "upper"), filepath.Join(state, "work"))
	if err := syscall.Mount("overlay", merged, "overlay", 0, opts); err != nil {
		return fmt.Errorf("mount overlay: %w", err)
	}
	if err := enterRootfs(merged); err != nil {
		return err
	}
	if err := syscall.Mount("proc", "/proc", "proc", 0, ""); err != nil {
		return fmt.Errorf("mount /proc: %w", err)
	}
	if err := syscall.Mount("tmpfs", "/dev", "tmpfs", 0, "mode=755"); err != nil {
		return fmt.Errorf("mount /dev: %w", err)
	}
	if err := syscall.Mknod("/dev/null", syscall.S_IFCHR|0o666, 1<<8|3); err != nil {
		return fmt.Errorf("mknod /dev/null: %w", err)
	}
	path, err := exec.LookPath(args[0])
	if err != nil {
		return err
	}
	if err := cg.JoinSelf(); err != nil {
		return err
	}
	// Last, after every privileged step above: drop all capabilities and
	// install the seccomp filter. From here the process (and the command it
	// is about to exec) can do no more than an unprivileged user, and cannot
	// regain privilege. execve collapses to this one thread, carrying its
	// hardened state to the new program; see the Joiner note above.
	if err := seccomp.DropPrivileges(); err != nil {
		return err
	}
	env := []string{"PATH=/bin", "HOME=/", "PS1=kiln# "}
	if spec.Addr.IsValid() {
		env = append(env, "KILN_IP="+spec.Addr.Addr().String())
	}
	return syscall.Exec(path, args, env)
}

// enterRootfs makes rootfs, which must be a mount point, the root mount of
// this mount namespace and detaches the old root. Unlike chroot, which only
// changes the path lookup start, this leaves no mount of the host filesystem
// for the process to climb back to.
func enterRootfs(rootfs string) error {
	if err := os.Chdir(rootfs); err != nil {
		return err
	}
	// pivot_root(".", ".") stacks the old root on top of the new one, so the
	// rootfs needs no directory to hold it; unmounting "." then removes it.
	if err := syscall.PivotRoot(".", "."); err != nil {
		return fmt.Errorf("pivot_root: %w", err)
	}
	if err := syscall.Unmount(".", syscall.MNT_DETACH); err != nil {
		return fmt.Errorf("detach old root: %w", err)
	}
	return os.Chdir("/")
}
