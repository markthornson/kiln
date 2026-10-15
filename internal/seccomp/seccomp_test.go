package seccomp

import (
	"encoding/binary"
	"slices"
	"syscall"
	"testing"
)

// run is a tiny interpreter for the classic-BPF subset Program emits: load a
// 32-bit word from seccomp_data at an absolute offset, compare-and-jump, and
// return. It mirrors what the kernel does, so the test can check the filter's
// decisions without installing it.
func run(prog []syscall.SockFilter, nr uintptr, arch uint32) uint32 {
	var data [64]byte
	binary.LittleEndian.PutUint32(data[offNr:], uint32(nr))
	binary.LittleEndian.PutUint32(data[offArch:], arch)

	var a uint32
	for pc := 0; pc < len(prog); pc++ {
		ins := prog[pc]
		switch ins.Code {
		case bpfLD | bpfW | bpfABS:
			a = binary.LittleEndian.Uint32(data[ins.K:])
		case bpfJMP | bpfJEQ | bpfK:
			if a == ins.K {
				pc += int(ins.Jt)
			} else {
				pc += int(ins.Jf)
			}
		case bpfRET | bpfK:
			return ins.K
		default:
			panic("seccomp test: unexpected BPF instruction")
		}
	}
	panic("seccomp test: program fell through without returning")
}

func TestProgramDecisions(t *testing.T) {
	prog := Program(Blocked)
	for _, nr := range Blocked {
		if got := run(prog, nr, auditArchX86_64); got != retErrnoEPERM {
			t.Errorf("blocked syscall %d: action %#x, want ERRNO(EPERM) %#x", nr, got, retErrnoEPERM)
		}
	}
	// A representative sample of syscalls the workload needs.
	for _, nr := range []uintptr{syscall.SYS_READ, syscall.SYS_WRITE, syscall.SYS_OPENAT, syscall.SYS_EXECVE, syscall.SYS_CLONE, syscall.SYS_EXIT_GROUP} {
		if got := run(prog, nr, auditArchX86_64); got != retAllow {
			t.Errorf("allowed syscall %d: action %#x, want ALLOW %#x", nr, got, retAllow)
		}
	}
	// The right syscall number on the wrong architecture is killed, not
	// allowed: the number would mean something else there.
	if got := run(prog, syscall.SYS_READ, 0x40000003 /* AUDIT_ARCH_ARM */); got != retKillProcess {
		t.Errorf("wrong arch: action %#x, want KILL_PROCESS %#x", got, retKillProcess)
	}
}

// FuzzProgram: for any blocklist and any (nr, arch), the generated filter
// blocks exactly the listed syscalls on the native arch, kills everything on
// other arches, and allows the rest — matching a direct model of the policy.
func FuzzProgram(f *testing.F) {
	f.Add([]byte{40, 0, 166}, uint32(40), uint32(auditArchX86_64)) // nr in the list
	f.Add([]byte{40}, uint32(1), uint32(auditArchX86_64))          // nr not in the list
	f.Add([]byte{}, uint32(0), uint32(0))                          // empty blocklist, wrong arch
	f.Fuzz(func(t *testing.T, raw []byte, nr uint32, arch uint32) {
		blocked := make([]uintptr, len(raw))
		for i, b := range raw {
			blocked[i] = uintptr(b)
		}
		got := run(Program(blocked), uintptr(nr), arch)

		var want uint32
		switch {
		case arch != auditArchX86_64:
			want = retKillProcess
		case slices.Contains(blocked, uintptr(nr)):
			want = retErrnoEPERM
		default:
			want = retAllow
		}
		if got != want {
			t.Fatalf("nr=%d arch=%#x blocked=%v: action %#x, want %#x", nr, arch, blocked, got, want)
		}
	})
}

func TestProgramWithinKernelLimit(t *testing.T) {
	// The kernel caps a filter at BPF_MAXINSNS (4096) instructions.
	if n := len(Program(Blocked)); n > 4096 {
		t.Errorf("program has %d instructions, over the 4096 limit", n)
	}
}

// TestBlockedSyscallsDistinct guards against a copy-paste duplicate in the
// list, which would make a redundant comparison and a misleading jump offset.
func TestBlockedSyscallsDistinct(t *testing.T) {
	seen := map[uintptr]bool{}
	for _, nr := range Blocked {
		if seen[nr] {
			t.Errorf("duplicate syscall %d in Blocked", nr)
		}
		seen[nr] = true
	}
}
