# kiln

A homelab platform built from scratch, to learn how Docker, Kubernetes and
CI systems actually work. It is built in layers:

1. **Container runtime**: namespaces, cgroups, chroot (← we are here)
2. **Job scheduler**: queue jobs and run them in containers with limits
3. **Mini CI**: watch a repo, run its tests in containers, keep history
4. **Testing lab**: the platform's real workload is fuzzing, property-testing
   and mutation-testing *its own code*, continuously

See [ROADMAP.md](ROADMAP.md) for milestones.

## Try it

Needs Linux and root (or equivalent capabilities).

```sh
go build -o kiln ./cmd/kiln
sudo ./kiln rootfs /tmp/rfs              # minimal rootfs from host binaries
sudo ./kiln run /tmp/rfs sh               # interactive shell, PID 1, own hostname
sudo ./kiln run -pids 5 /tmp/rfs sh -c 'for i in $(seq 8); do sleep 1 & done'   # "Cannot fork"
sudo ./kiln run -memory 20000000 /tmp/rfs sh -c 'x=a; while :; do x=$x$x; done' # OOM-killed
```

## Test

```sh
go test ./...
go test ./internal/rootfs -run='^$' -fuzz=FuzzParseLdd -fuzztime=30s
```

## Bugs found so far

| # | Found by | Bug |
|---|----------|-----|
| 1 | `FuzzParseLdd`, in under 1s | ldd parser split paths only on spaces, so `"/lib\t..."` produced a path containing a tab. Regression input kept in `testdata/fuzz/`. |
| 2 | Manual limit test | The pids limit killed kiln's *own* Go runtime: Go processes are multi-threaded and pids.max counts threads. Fixed by joining the cgroup immediately before `exec` (migration isn't limit-checked, only fork is). |
