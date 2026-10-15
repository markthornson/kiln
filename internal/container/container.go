// Package container runs a command in isolated Linux namespaces.
//
// The parent creates a cgroup, then re-executes /proc/self/exe with the hidden
// "init" subcommand inside fresh UTS, PID and mount namespaces. That child
// sets the hostname, pivots into the rootfs, mounts /proc and /dev, joins the
// cgroup and execs the command.
package container

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"

	"github.com/markthornson/kiln/internal/cgroups"
)

// Config describes one container run.
type Config struct {
	ID       string
	Rootfs   string
	Hostname string
	Args     []string
	Limits   cgroups.Limits
}

// Run starts the container, waits for it and returns its exit code.
func Run(c Config) (int, error) {
	cmd := exec.Command("/proc/self/exe", append([]string{"init", c.ID, c.Rootfs, c.Hostname}, c.Args...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUTS | syscall.CLONE_NEWPID | syscall.CLONE_NEWNS,
	}

	group, err := cgroups.New(c.ID, c.Limits)
	if err != nil {
		return -1, err
	}
	defer group.Destroy()

	if err := cmd.Start(); err != nil {
		return -1, fmt.Errorf("start: %w", err)
	}
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
func Init(id, rootfs, hostname string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("no command given")
	}
	// Keep this goroutine on one thread so nothing migrates mid-setup.
	runtime.LockOSThread()
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
	if err := enterRootfs(rootfs); err != nil {
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
	return syscall.Exec(path, args, []string{"PATH=/bin", "HOME=/", "PS1=kiln# "})
}

// enterRootfs makes rootfs the root mount of this mount namespace and detaches
// the old root. Unlike chroot, which only changes the path lookup start, this
// leaves no mount of the host filesystem for the process to climb back to.
func enterRootfs(rootfs string) error {
	// pivot_root requires the new root to be a mount point.
	if err := syscall.Mount(rootfs, rootfs, "", syscall.MS_BIND|syscall.MS_REC, ""); err != nil {
		return fmt.Errorf("bind mount rootfs: %w", err)
	}
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
