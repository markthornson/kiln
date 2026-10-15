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

    go vet ./... && go test ./...
    go test ./internal/rootfs -run='^$' -fuzz=FuzzParseLdd -fuzztime=30s
    go test ./internal/mountinfo -run='^$' -fuzz=FuzzParseLine -fuzztime=30s
    go build -o kiln ./cmd/kiln && ./kiln rootfs /tmp/rfs && ./kiln run /tmp/rfs sh

## Environment notes (cloud sandbox)

- Runs as root; namespaces work; cgroups are **v1** at /sys/fs/cgroup/{memory,pids,...}.
- No Docker daemon and no /dev/kvm. Image CDNs (e.g. Alpine) are blocked, so
  build rootfs from host binaries with `kiln rootfs`.
- Go processes are multi-threaded: anything joining a pids-limited cgroup must
  do so right before exec (see cgroups.Joiner).
- internal/container tests run real containers: the test binary is re-executed
  as the container's init (see TestMain) and copied into the rootfs as
  /bin/kilntest to act as the workload. They skip when not root.
