# Spike M4 — google/nftables in a network namespace (Linux)

**Status:** authored + compile/vet/gofmt clean; **SKIPS on the reference host**
(no effective CAP_NET_ADMIN in an unprivileged userns — see below). The
enforcement path is **CI-verified, not host-verified**: it runs for real only
where unprivileged user+net namespaces grant a usable CAP_NET_ADMIN (a
privileged / userns-permitting CI container).
**Validates:** Task 13c (rung-1 nftables **address** filtering).

- **File:** `spikes/nftables/nftables_netns_linux_test.go` (`//go:build linux`,
  package `nftablesspike`, capability-gated).
- **Run:** `go test -race ./spikes/nftables/ -run TestNftablesNetnsEgressFilter -v`
- **Deps:** `github.com/google/nftables v0.3.0` (pure-Go netlink, **no cgo**),
  `golang.org/x/sys/unix`.

## What it proves (in CI)

Inside a fresh network namespace, an `inet filter` table whose `output` chain has
**policy DROP** plus a small ACCEPT allowlist enforces egress at the packet level:
a loopback listener stays reachable while the cloud metadata IP
`169.254.169.254` is dropped — and the drop is provably caused by the **nftables
rule**, not by an empty/blackhole namespace.

## How the netns + CAP_NET_ADMIN is obtained

Applying nftables needs **CAP_NET_ADMIN in the target netns**. The self-contained,
backend-shaped way to get that unprivileged is to **re-exec the test binary** into
a child created with `SysProcAttr.Cloneflags = CLONE_NEWUSER|CLONE_NEWNET` and a
uid/gid map making the child root inside the new user namespace — exactly what the
real backend (Task 13a/c) does to its stage-2 child via `SysProcAttr`. Because the
**whole child process (every thread)** lives in the new netns, the default
`nftables.New()` netlink socket, the `lo` ioctls, and the probe dials all target
that netns with no per-thread `setns` juggling.

> Note: `unshare(CLONE_NEWUSER)` inline in the test would fail `EINVAL` — a
> **multithreaded** process (the Go runtime) cannot unshare a user namespace. The
> `clone` at `fork/exec` time is the correct primitive, and it mirrors production.

Loopback in a fresh netns starts **DOWN and unaddressed**, so the child:
1. brings `lo` **UP** (`SIOCGIFFLAGS`/`SIOCSIFFLAGS`) — the **first CAP_NET_ADMIN
   op**, hence the capability probe;
2. assigns `127.0.0.1/8` to `lo` and `169.254.169.254/32` to the `lo:1` alias (both
   via `SIOCSIFADDR`/`SIOCSIFNETMASK`). Making the metadata IP a **local** address
   is what lets a dial to it traverse the `output` hook (so nftables can act on
   it) instead of failing at routing.

## The exact ruleset built

`table inet filter` → `chain output { type filter hook output priority filter; policy drop; }`,
rules in order (first match wins; the chain **policy DROP** catches the rest):

| # | Rule (nft syntax)              | Expression sequence (google/nftables)                                                                                                                                          |
|---|--------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 1 | `ct state established,related accept` | `Ct{STATE}` → `Bitwise{mask=ESTABLISHED\|RELATED, xor=0, len=4}` → `Cmp{neq, 0}` → `Verdict{accept}`                                                                    |
| 2 | `oif lo ip daddr 127.0.0.0/8 accept`  | `Meta{OIFNAME}`→`Cmp{eq,"lo"\0…}` ; `Meta{NFPROTO}`→`Cmp{eq,NFPROTO_IPV4}` ; `Payload{network,off16,len4}`→`Bitwise{mask=255.0.0.0}`→`Cmp{eq,127.0.0.0}` → `accept` |
| 3 | `tcp dport 443 accept`         | `Meta{L4PROTO}`→`Cmp{eq,IPPROTO_TCP}` ; `Payload{transport,off2,len2}`→`Cmp{eq,0x01bb}` → `accept`                                                                              |
| 4 | `udp dport 53 accept`          | `Meta{L4PROTO}`→`Cmp{eq,IPPROTO_UDP}` ; `Payload{transport,off2,len2}`→`Cmp{eq,0x0035}` → `accept`                                                                              |
| 5 | `tcp dport 53 accept`          | `Meta{L4PROTO}`→`Cmp{eq,IPPROTO_TCP}` ; `Payload{transport,off2,len2}`→`Cmp{eq,0x0035}` → `accept`                                                                              |

Every register load/compare uses register 1 (register 0 is the verdict register).
Ports are matched in **network byte order** (raw transport-header bytes:
443 = `01 bb`, 53 = `00 35`). All expression shapes were cross-checked against
google/nftables' own `nftables_test.go` / `integration/nft_test.go` (the nft(8)
strace-derived golden byte sequences for `tcp dport`, `ct state`, `oifname`, and
`ip daddr` network-header payload matches).

### Why the loopback ACCEPT is ADDRESS-scoped (the crux of Task 13c)

The metadata IP is also a **local** address, so it egresses `oif lo` too. A blanket
`oif lo accept` would therefore wrongly permit the metadata IP. Scoping rule #2 to
`oif lo AND ip daddr 127.0.0.0/8` is precisely the rung-1 **address filtering**
property under test: loopback is allowed by **address**, and `169.254.169.254`
falls through to `policy drop`.

## Anti-fail-open: assertions that run in CI

A test that only checked "metadata unreachable" would **fail open** — a sealed
netns with no routing makes *everything* unreachable, so that alone proves
nothing. The spike therefore asserts a **paired positive + negative around the
same IP:port**, plus a pre-ruleset control:

| Marker        | When            | Asserted value | Proves                                                                                    |
|---------------|-----------------|----------------|-------------------------------------------------------------------------------------------|
| `LO`          | after setup     | `UP`           | loopback up + both addresses assigned (CAP_NET_ADMIN worked)                               |
| `METACONTROL` | **before** nft  | `REFUSED`      | metadata IP is local/routable (RST from closed port) — **not a blackhole**                |
| `APPLY`       | —               | `OK`           | ruleset flushed into the netns                                                             |
| `LOOPBACK`    | **after** nft   | `CONNECTED`    | **positive** — the DROP policy is **scoped**, not a blanket deny                           |
| `METADATA`    | **after** nft   | `TIMEOUT`      | **negative** — SYN silently dropped at `output`                                            |

The load-bearing pair is `METACONTROL=REFUSED` → `METADATA=TIMEOUT`: the **same**
`169.254.169.254:80` flips from *reached-the-stack* (RST) to *dropped* (timeout)
with **nothing changed but the applied ruleset** — so nftables, not the namespace,
is provably the cause. `LOOPBACK=CONNECTED` proves the ruleset is not a blanket
blackhole. (`ct state` matching assumes `nf_conntrack` is available in the CI
netns; referencing `ct` auto-creates the dependency on a modern kernel.)

## Why it SKIPS on the reference host (a skip is never a pass)

The host has `apparmor_restrict_unprivileged_userns=1` (Ubuntu 24.04+ default).
The child user+net namespace **is** created — the child even observes uid 0 —
but the apparmor-restricted userns grants **no effective CAP_NET_ADMIN**, so the
first privileged op (`lo` UP) returns `EPERM`. The child reports this and the
parent records a **specific** skip. Two gates cover the two environment failure
modes:

- **Gate 1** — namespace creation itself refused (no `CHILD=STARTED` marker; e.g.
  userns disabled or `uid_map` write denied) → skip.
- **Gate 2** — namespace created but no usable CAP_NET_ADMIN (`CAP=DENIED:…`
  marker) → skip. **This is the mode observed here.**

Exact skip emitted on this host:

```
nftables netns spike requires unprivileged userns + netns creation (CAP_NET_ADMIN
in a new netns): the user+net namespace was created but grants no effective
CAP_NET_ADMIN inside the new netns (apparmor_restrict_unprivileged_userns=1
restricts capabilities in unprivileged user namespaces): DENIED:loopback up:
SIOCSIFFLAGS: operation not permitted
```

Verified on this host: **compiles**, `go vet ./spikes/nftables/...` **clean**,
`gofmt -l` **clean**, `CGO_ENABLED=0 go build ./...` **unaffected**, and
`go test -race` **SKIPS cleanly** (no error, no hang) with the reason above.

---

## Load-bearing net-soundness finding: Landlock TCP port rules ≠ MPTCP (for Task 12c)

This finding is **why rung-1 uses nftables** and it constrains rung-2 (Task 12b):

- **go-landlock's `ConnectTCP`/`BindTCP` port rules (Landlock ABI v4+) restrict
  only *classic* TCP sockets — NOT Multipath TCP.** Landlock's network hooks key
  on the classic-TCP socket path; an `IPPROTO_MPTCP` socket is not covered.
- **Since Go 1.24, `net.Listen`/`net.Dial` default to MPTCP on Linux.** A confined
  child using ordinary Go net calls therefore opens MPTCP sockets that **bypass a
  Landlock TCP port allowlist** — the port rule is silently not enforced.

**Consequences to design around:**

1. **Rung-2 TCP-port enforcement via Landlock is NOT sound on its own.** For
   `GuaranteeNetworkBoundary` to be honestly claimable, the **seccomp filter
   (Task 12b)** must also block `socket(…, IPPROTO_MPTCP)` (protocol **262**) —
   otherwise the allowlist is trivially bypassed by the Go 1.24+ default.
2. **Any Landlock-TCP test must disable MPTCP** to measure the classic path:
   `net.Dialer{}.SetMultipathTCP(false)` (and `Listener` equivalent) or
   `GODEBUG=multipathtcp=0`. A Landlock port test left on the Go default would
   pass or fail for the wrong reason.

**Why nftables (rung-1) does not have this hole.** nftables filters **packets** at
the netfilter hooks by address/port/protocol, **regardless of the socket protocol
that generated them**. An MPTCP subflow SYN is still a TCP/IP packet: it carries
the same IPv4 `daddr` and TCP `dport`, so rules #2–#5 above match it exactly as
they match classic TCP. There is no classic-vs-MPTCP distinction at the packet
layer, so an nftables address/port boundary is **MPTCP-agnostic** and cannot be
bypassed by the socket-protocol trick — which is exactly why rung-1 real network
boundaries are enforced with nftables, not Landlock port rules.

## CI requirements & carry-forward for Task 13c (from adversarial review — verdict SOUND)

The nftables ruleset was verified byte-for-byte against google/nftables' own
golden (nft(8) strace-derived) tests; no blockers. Notes for the shipped rung-1
backend and the CI that runs this spike's enforcement path:

1. **CI must load `nf_conntrack`.** The `ct state established,related accept`
   rule requires the conntrack module; on a minimal netns without it,
   `conn.Flush()` returns `EOPNOTSUPP` and the test hard-fails (a CI
   environment error, never a false pass). The spike keeps the ct rule on
   purpose — it de-risks Task 13c's real ruleset, which needs conntrack for
   return traffic — so the **Task 26 CI image must ensure `nf_conntrack` is
   available** in the netns the spike/backend runs in.
2. **Gate hardening applied.** Gate 2 now skips *only* on an explicit
   `CAP=DENIED:` marker; a child that starts but dies before resolving the
   capability probe (socket failure, non-EPERM ioctl bug, panic) now
   `t.Fatalf`s instead of masquerading as a green environment skip — a skip is
   never a pass.
3. **Don't depend on link-local aliasing in shipped code.** The spike assigns
   `169.254.169.254/32` to a `lo` alias so a dial to it is locally routed and
   traverses the OUTPUT hook (making the drop observable). This is a test
   contrivance; the real backend blocks the metadata IP for *egress to the real
   metadata endpoint*, not a local alias.
4. **MPTCP:** as above — rung-1 nftables is packet-level and MPTCP-agnostic;
   the rung-2 seccomp filter (Task 12b) is what must block `IPPROTO_MPTCP` so the
   rung-2 Landlock port allowlist is sound.
