# kiln: notes for Claude sessions

Long-term learning project: a homelab platform (container runtime → scheduler
→ mini CI) whose workload is testing its own code. See README.md and ROADMAP.md.

## Working on it

- Pick the next unchecked milestone in ROADMAP.md unless the user asks otherwise.
- Every change ships with tests. Prefer adding a `Fuzz*` or property test to
  anything that parses input or maintains invariants.
- When a fuzzer or test finds a real bug, add a row to the README "Bugs found"
  table and keep the crashing input under `testdata/fuzz/`.
- Check off milestones in ROADMAP.md when they're done.

## Commands

    go vet ./... && go vet -tags integration ./... && go test ./...
    go test -tags integration ./...      # real containers; needs root
    go test ./internal/rootfs -run='^$' -fuzz=FuzzParseLdd -fuzztime=30s
    go test ./internal/mountinfo -run='^$' -fuzz=FuzzParseLine -fuzztime=30s
    go test ./internal/network -run='^$' -fuzz=FuzzLeases -fuzztime=30s
    go test ./internal/overlay -run='^$' -fuzz=FuzzOptionsRoundTrip -fuzztime=30s
    go build -o kiln ./cmd/kiln && ./kiln rootfs /tmp/rfs && ./kiln run /tmp/rfs sh

## Environment notes (cloud sandbox)

- Runs as root; namespaces work; cgroups are **v1** at /sys/fs/cgroup/{memory,pids,...}.
- No Docker daemon and no /dev/kvm. Image CDNs (e.g. Alpine) are blocked, so
  build rootfs from host binaries with `kiln rootfs`.
- Go processes are multi-threaded: anything joining a pids-limited cgroup must
  do so right before exec (see cgroups.Joiner).
- Tests that need root or touch the host (real containers, real mounts) go in
  `*integration_test.go` files with `//go:build integration`, and fail (not
  skip) without root. Everything else must pass as an ordinary user.
- internal/container integration tests run real containers: the test binary is
  re-executed as the container's init (see TestMain) and copied into the rootfs
  as /bin/kilntest to act as the workload. Limit tests use /bin/sh instead,
  because pids.max counts the Go runtime's threads.
- When adding a safeguard, check its test fails with the safeguard removed
  (and that the mutant still compiles).
- iproute2 (`ip`) is not installed; use internal/netlink, or read /sys/class/net
  and /proc/net/*. Network tests create the host's kiln0 bridge and use leases
  in /run/kiln/ipam.
- A container's rootfs is an overlay over the read-only base; per-container
  layers live in /var/lib/kiln/containers/<id> and are removed on exit. Writes
  inside a container never reach the base directory.
- Containers are hardened just before exec (internal/seccomp): all capabilities
  dropped, no_new_privs set, seccomp-BPF filter installed. chroot/mount/mknod
  etc. are blocked, so tests or workloads that need them must run on the host,
  not in a container. The seccomp filter is pure data: unit-test/fuzz it with
  the BPF interpreter in seccomp_test.go, no root needed.
- `pkill -f PATTERN` matches your own shell's command line; use `pkill -x NAME`.
  A container's PID 1 ignores SIGTERM, so clean up stray ones with `-9`.
