# Roadmap

Each milestone should end with: tests passing, at least one new fuzz or
property test, and the README updated (including the "Bugs found" table).

## Phase 1: Container runtime

- [x] M1.1 `kiln run`: UTS/PID/mount namespaces, chroot, /proc, /dev/null
- [x] M1.2 cgroup v1 memory + pids limits; exit codes and signal deaths reported
- [x] M1.3 `kiln rootfs`: build rootfs from host binaries via ldd (fuzzed)
- [x] M1.4 `pivot_root` instead of chroot (chroot is escapable)
- [x] M1.5 Network namespace + veth pair + bridge, so containers get an IP
- [x] M1.6 Overlay filesystem: read-only base image + per-container writable layer
- [ ] M1.7 Integration test suite (`go test -tags integration`, needs root): isolation, limits, cleanup
- [ ] M1.8 cgroup v2 support, detected at runtime
- [ ] M1.9 Drop capabilities + seccomp filter; test that escape attempts fail

## Phase 2: Job scheduler

- [ ] M2.1 Job spec (YAML/JSON): image, command, limits, timeout. **Fuzz the spec parser.**
- [ ] M2.2 `kilnd` daemon with HTTP API: submit, list, logs, cancel
- [ ] M2.3 Worker pool with a global CPU/memory budget; queueing and fairness
- [ ] M2.4 Persist job state (SQLite or an append-only log) and survive restarts
- [ ] M2.5 Property tests: the scheduler never exceeds its budget and every job reaches a final state

## Phase 3: Mini CI

- [ ] M3.1 Pipeline file in a repo (`.kiln.yml`): steps run as jobs
- [ ] M3.2 Clone repo at a commit, cache Go modules between runs
- [ ] M3.3 Web dashboard: run history, logs, pass/fail trend
- [ ] M3.4 kiln runs its own CI

## Phase 4: Testing lab (kiln tests kiln)

- [ ] M4.1 Long-running fuzz jobs: every `Fuzz*` target runs continuously as a scheduled job; crashes are saved as regression tests
- [ ] M4.2 Mutation testing (e.g. go-mutesting); track mutation score over time
- [ ] M4.3 Chaos tests: kill workers mid-job and fill the disk; the scheduler must recover
- [ ] M4.4 Dashboard: coverage, mutation score, fuzz exec/s, and bugs found per week

## Known limitations / ideas

- The runtime needs root; rootless via user namespaces would be a nice stretch goal.
- Until M1.9, the container process keeps every capability: `pivot_root` stops the
  chroot breakout, but a root process could still e.g. `mknod` the host disk and mount it.
- Networking is IPv4-only on one fixed subnet (10.88.0.0/24), with no NAT/masquerade to
  the outside, no port publishing and no DNS. Containers reach the host and each other only.
- Images are a single directory (one lower layer). There is no layered image format, and a
  container's writable layer is discarded on exit (no `commit` or `diff`).
- Only cgroup v1 is supported so far (the dev sandbox uses v1).
