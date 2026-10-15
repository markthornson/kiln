// Package seccomp builds and installs a seccomp-BPF filter that blocks
// syscalls a container has no business making, and drops all capabilities.
//
// A seccomp filter is a classic-BPF program the kernel runs on every syscall.
// The program reads fields of a `struct seccomp_data` (the syscall number,
// the architecture, the arguments) and returns an action: allow the call,
// fail it with an errno, or kill the process. The program here is a blocklist:
// a handful of dangerous syscalls return EPERM, and everything else is
// allowed, so ordinary workloads keep working.
//
// Blocking is defence in depth. The container already runs with no
// capabilities (see DropPrivileges) and in its own namespaces, which stops
// most of these calls on their own. The filter stops them a second way, keeps
// them blocked no matter what the process does later, and shrinks the kernel
// surface the container can reach.
package seccomp

import (
	"fmt"
	"syscall"
	"unsafe"
)

// seccomp_data field offsets (linux/seccomp.h).
const (
	offNr   = 0 // int      nr    — the syscall number
	offArch = 4 // __u32    arch  — AUDIT_ARCH_* of the calling convention
)

// Kernel constants missing from package syscall.
const (
	auditArchX86_64 = 0xC000003E // AUDIT_ARCH_X86_64

	// amd64 syscall numbers and a prctl option the frozen syscall package never
	// added (see golang.org/x/sys/unix). Named here so the package stays
	// dependency-free.
	sysSeccomp     = 317
	sysSetns       = 308
	sysFinitModule = 313
	sysBPF         = 321

	prSetNoNewPrivs = 38 // PR_SET_NO_NEW_PRIVS

	seccompSetModeFilter = 1 // SECCOMP_SET_MODE_FILTER

	retAllow       = 0x7fff0000 // SECCOMP_RET_ALLOW
	retErrno       = 0x00050000 // SECCOMP_RET_ERRNO, or'd with the errno
	retKillProcess = 0x80000000 // SECCOMP_RET_KILL_PROCESS
	retErrnoEPERM  = retErrno | uint32(syscall.EPERM)
)

// Blocked is the set of syscalls the filter denies with EPERM. Each would let
// a process inside the container damage or escape the host if it somehow held
// the capability for it: remount or detach filesystems, create device nodes,
// load kernel code, reboot, swap, or join another namespace.
var Blocked = []uintptr{
	syscall.SYS_MOUNT,
	syscall.SYS_UMOUNT2,
	syscall.SYS_PIVOT_ROOT,
	syscall.SYS_CHROOT,
	syscall.SYS_MKNOD,
	syscall.SYS_MKNODAT,
	syscall.SYS_REBOOT,
	syscall.SYS_KEXEC_LOAD,
	syscall.SYS_INIT_MODULE,
	sysFinitModule,
	syscall.SYS_DELETE_MODULE,
	syscall.SYS_SWAPON,
	syscall.SYS_SWAPOFF,
	sysSetns,
	syscall.SYS_UNSHARE,
	syscall.SYS_PTRACE,
	sysBPF,
	syscall.SYS_PERF_EVENT_OPEN,
}

// classic-BPF instruction classes and fields (linux/bpf_common.h), named here
// because package syscall's copies are awkward to combine.
const (
	bpfLD  = 0x00
	bpfW   = 0x00
	bpfABS = 0x20
	bpfJMP = 0x05
	bpfJEQ = 0x10
	bpfRET = 0x06
	bpfK   = 0x00
)

func stmt(code uint16, k uint32) syscall.SockFilter {
	return syscall.SockFilter{Code: code, K: k}
}

// jeq jumps jt instructions forward when the accumulator equals k, else jf.
func jeq(k uint32, jt, jf uint8) syscall.SockFilter {
	return syscall.SockFilter{Code: bpfJMP | bpfJEQ | bpfK, Jt: jt, Jf: jf, K: k}
}

// Program returns the BPF filter for the given blocked syscalls. Layout:
//
//	load arch; if != x86_64 -> KILL_PROCESS
//	load nr
//	for each blocked nr: if == nr, fall through to the next RET ERRNO, else skip it
//	ALLOW
//
// Each blocked syscall is its own two-instruction compare-and-return, so every
// jump offset is 0 or 1 — no shared target whose distance could overflow the
// 8-bit jump field, and duplicates in the list stay harmless. Jumps are always
// forward, so the kernel's verifier accepts the program. A different
// architecture is killed, not failed, because its syscall numbers would not
// match this table.
func Program(blocked []uintptr) []syscall.SockFilter {
	prog := []syscall.SockFilter{
		stmt(bpfLD|bpfW|bpfABS, offArch),
		jeq(auditArchX86_64, 1, 0), // match -> skip the kill
		stmt(bpfRET|bpfK, retKillProcess),
		stmt(bpfLD|bpfW|bpfABS, offNr),
	}
	for _, nr := range blocked {
		prog = append(prog,
			jeq(uint32(nr), 0, 1), // match -> next insn; else skip it
			stmt(bpfRET|bpfK, retErrnoEPERM),
		)
	}
	return append(prog, stmt(bpfRET|bpfK, retAllow))
}

// Apply installs the filter for Blocked on the calling thread (and, after a
// following execve, its children). The caller must already hold
// no_new_privs, which DropPrivileges sets.
func Apply() error {
	filter := Program(Blocked)
	prog := syscall.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}
	if _, _, errno := syscall.Syscall(sysSeccomp, seccompSetModeFilter, 0,
		uintptr(unsafe.Pointer(&prog))); errno != 0 {
		return fmt.Errorf("seccomp: install filter: %w", errno)
	}
	return nil
}
