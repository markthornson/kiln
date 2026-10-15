# kiln

A homelab platform built from scratch, to learn how Docker, Kubernetes and
CI systems actually work. It is built in layers:

1. **Container runtime**: namespaces, cgroups, pivot_root, bridged networking, overlay filesystems (← we are here)
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
sudo ./kiln run /tmp/rfs sh -c 'echo $KILN_IP; cat /proc/net/route'   # eth0 on the kiln0 bridge
sudo ./kiln run -net none /tmp/rfs cat /proc/net/dev                    # loopback only
sudo ./kiln run /tmp/rfs sh -c 'rm /bin/ls; echo hi > /etc/hostname'    # ...then /tmp/rfs is untouched
```

### Filesystem

`ROOTFS` is a read-only base image. Each container gets an overlay of a fresh
writable layer on top of it, so containers can change, create and delete
anything without affecting the base or each other:

```
/var/lib/kiln/containers/<id>/upper    the container's writes (and deletion "whiteouts")
/var/lib/kiln/containers/<id>/work     overlayfs scratch space
/var/lib/kiln/containers/<id>/merged   overlay mount point, mounted only in the container's namespace
```

The layer is deleted when the container exits; layers left by a killed kiln
process are pruned on the next run. Paths are escaped for the overlay options
string (`,` `:` `\`), so a base path like `/images/a,b` works and `/a:/b` can't
be misread as two layers.

### Networking

Every container gets its own network namespace. With `-net bridge` (the
default) kiln creates a `kiln0` bridge at 10.88.0.1/24 on first use, leases
the container an address, and connects it with a veth pair:

```
host                          container netns
kiln0 10.88.0.1/24 ── kv<id> ═══ eth0 10.88.0.N/24, default via 10.88.0.1
```

Links, addresses and routes are configured over rtnetlink directly
(`internal/netlink`), so no `ip` binary is needed. Leases are files in
`/run/kiln/ipam`, allocated under a `flock`; a lease whose kiln process has
died is reclaimed. Containers can reach the host and each other, but there is
no NAT to the outside world yet.

## Test

```sh
go test ./...        # container tests need root + cgroup v1, and skip otherwise
go test ./internal/rootfs -run='^$' -fuzz=FuzzParseLdd -fuzztime=30s
go test ./internal/mountinfo -run='^$' -fuzz=FuzzParseLine -fuzztime=30s
go test ./cmd/kiln -run='^$' -fuzz=FuzzParseRun -fuzztime=30s
go test ./internal/netlink -run='^$' -fuzz=FuzzAttrsRoundTrip -fuzztime=30s
go test ./internal/network -run='^$' -fuzz=FuzzLeases -fuzztime=30s
go test ./internal/overlay -run='^$' -fuzz=FuzzOptionsRoundTrip -fuzztime=30s
```

Fuzz targets: `FuzzParseLdd`, `FuzzParseLine`, `FuzzEscapeRoundTrip`,
`FuzzParseRun`, `FuzzAttrsRoundTrip`, `FuzzMessagesRoundTrip`, `FuzzPick`,
`FuzzLeases`, `FuzzParseSpec`, `FuzzOptionsRoundTrip`.

## Bugs found so far

| # | Found by | Bug |
|---|----------|-----|
| 1 | `FuzzParseLdd`, in under 1s | ldd parser split paths only on spaces, so `"/lib\t..."` produced a path containing a tab. Regression input kept in `testdata/fuzz/`. |
| 2 | Manual limit test | The pids limit killed kiln's *own* Go runtime: Go processes are multi-threaded and pids.max counts threads. Fixed by joining the cgroup immediately before `exec` (migration isn't limit-checked, only fork is). |
| 3 | `TestChrootEscapeFails` | The container root was a plain `chroot`, so a root process could break out (chroot into a subdirectory, walk `..` past the root, chroot again) and read the host filesystem. Fixed in M1.4 by bind-mounting the rootfs, `pivot_root`-ing into it and detaching the old root. |
| 4 | Manual `kill -9` test, now `TestContainerDiesWithKiln` | Killing the `kiln` process left its container running, still using its IP. The lease (owned by kiln's now-dead PID) then looked stale and was handed to the next container: two containers, one address. Fixed by setting `Pdeathsig: SIGKILL` so the kernel kills the container when kiln dies. |
