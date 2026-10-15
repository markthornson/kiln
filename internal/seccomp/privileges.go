package seccomp

import (
	"fmt"
	"syscall"
	"unsafe"
)

// _LINUX_CAPABILITY_VERSION_3, the 64-bit capability ABI (linux/capability.h).
const capVersion3 = 0x20080522

// capHeader and capData mirror the kernel's cap_user_header_t and
// cap_user_data_t. With the v3 ABI the data is two 32-bit words per set.
type capHeader struct {
	version uint32
	pid     int32
}

type capData struct {
	effective   uint32
	permitted   uint32
	inheritable uint32
}

// DropPrivileges strips every capability from the process, stops it from
// regaining any through a later execve, and then installs the seccomp filter.
// It runs just before the container execs its command, after all privileged
// setup (mounts, mknod, cgroup join) is done.
//
// The order is required: no_new_privs must be set before a process without
// CAP_SYS_ADMIN may install a seccomp filter, and clearing the capability
// sets must come after no_new_privs so the filter install itself is allowed.
func DropPrivileges() error {
	if err := clearBoundingSet(); err != nil {
		return err
	}
	if err := clearCapabilities(); err != nil {
		return err
	}
	// PR_SET_NO_NEW_PRIVS: no execve can ever grant this process (or its
	// children) more privilege, e.g. via a setuid binary or file capabilities.
	if _, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0, 0, 0, 0); errno != 0 {
		return fmt.Errorf("seccomp: set no_new_privs: %w", errno)
	}
	return Apply()
}

// clearBoundingSet removes every capability from the bounding set, so they
// cannot be picked up again from a file-capability binary. Unknown capability
// numbers return EINVAL, which marks the end of the range.
func clearBoundingSet() error {
	for cap := uintptr(0); ; cap++ {
		_, _, errno := syscall.Syscall6(syscall.SYS_PRCTL, syscall.PR_CAPBSET_DROP, cap, 0, 0, 0, 0)
		if errno == syscall.EINVAL {
			return nil
		}
		if errno != 0 {
			return fmt.Errorf("seccomp: drop bounding capability %d: %w", cap, errno)
		}
	}
}

// clearCapabilities zeroes the effective, permitted and inheritable sets, so
// the process holds no capability at all.
func clearCapabilities() error {
	hdr := capHeader{version: capVersion3, pid: 0} // 0 == this thread
	var data [2]capData                            // all zero: drop everything
	if _, _, errno := syscall.Syscall(syscall.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0); errno != 0 {
		return fmt.Errorf("seccomp: clear capabilities: %w", errno)
	}
	return nil
}
