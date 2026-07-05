# SPIKE: macOS Seatbelt network expressiveness (Task M1 / SPEC §13 Q6)

Throwaway investigation to determine what `sandbox-exec` + SBPL can express for
network filtering, so Task 8 (Seatbelt backend) knows which `NetPolicy` fields
map to real SBPL rules and which must compile to **blocked** under the
soundness rule (SPEC §7.5: never wider than policy). Findings are empirical;
SBPL is undocumented and deprecated.

## Environment

| | |
|---|---|
| macOS | 26.5.1 (build 25F80), arm64 |
| sandbox-exec | `/usr/bin/sandbox-exec` present, runnable (not blocked in this env) |
| Probe tools | `/usr/bin/curl`, `/usr/bin/nc`, Go 1.26.4 (built two tiny probe binaries: a loopback `listen`er and a `dial`er) |
| Network | **External egress works here** (8.8.8.8:443 and https://example.com reachable), so enforcement was observable end-to-end — not just from syntax acceptance |

Method: for **acceptance** (does it compile) run `sandbox-exec -p '<profile>'
/usr/bin/true` — exit 0 = profile compiled; nonzero with an SBPL error on
stderr = rejected (captured verbatim). For **enforcement** run a connect probe
under the profile against a listener I control and read the failure mode:
`operation not permitted` = sandbox-blocked; `connection refused` / timeout =
sandbox-allowed (just no listener / unreachable). That error-type discriminator
is what separates a real network denial from an unrelated failure.

Base profile used for enforcement tests (lets a Go/curl binary start while
network stays denied by default):

```
(version 1)(deny default)
(allow process-exec)(allow file-read*)(allow process-fork)
(allow sysctl-read)(allow mach-lookup)
```

Note: `(deny default)` blocks even `execvp` — a bare `(deny default)` profile
fails to run `/usr/bin/true` with `Operation not permitted` (exit 71). A Go
binary additionally needs `sysctl-read` (to read the system page size) or it
panics before `main`. These are FS/process concerns owned by the FS half of the
backend; they are not network rules but the net profile must coexist with them.

## Results

| Construct | Compiles? | Enforced? | Exact working syntax / rejection error |
|---|---|---|---|
| **1. Default-deny base** | yes | **yes** | `(version 1)(deny default)` + selective allows. With no network allow, `connect()` fails `operation not permitted`; even `execvp` is denied. |
| **2. Outbound TCP port scope** | yes | **yes** | `(allow network-outbound (remote tcp "*:443"))`. Observed: `:19443` connects, `:19080` → `operation not permitted`. Port may be a number or `*`. |
| **3. Loopback allow** | yes | **yes (with caveat)** | `(allow network-outbound (remote ip "localhost:*"))`. Reaches `127.0.0.1`. See "localhost semantics" below. |
| **4a. Literal IPv4 host** | **no** | — | `(remote ip "10.0.0.0:*")` → `sandbox-exec: host must be * or localhost in network address` |
| **4b. CIDR / subnet** | **no** | — | `(remote ip "10.0.0.0/8:*")` → same `host must be * or localhost` error. `(remote ip (subnet "10.0.0.0/8"))` → `unbound variable: subnet`. |
| **4c. IPv6 literal** | **no** | — | `(remote ip "[::1]:*")` → `host must be * or localhost in network address` |
| **4d. host without port** | **no** | — | `(remote ip "10.0.0.1")` → `port missing in network address: 10.0.0.1` |
| **5. Metadata IP deny** | **no** | vacuous only | `(deny network-outbound (remote tcp "169.254.169.254:80"))` → `host must be * or localhost`. `(require-not (remote ip "169.254.169.254:80"))` → same. Cannot carve out an IP. |
| Rule precedence | — | **last-match-wins** | `(allow ... "*:*")(deny ... "*:19080")` → `:19080` blocked, other ports allowed. deny can override a prior broad allow, **but only by port/host wildcard**, never by IP. |
| **DNS (name resolution)** | yes | **yes** | `(allow network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))` — see "DNS" below. Both `(remote unix-socket (path-literal …))` and bare `(literal "…")` compile and work. |
| mDNSResponder mach-lookup (tighter) | yes | — | `(allow mach-lookup (global-name "com.apple.mDNSResponder"))` compiles. |

### The crux: SBPL network address host is `*` or `localhost` only

Every attempt to name a host by IP address — literal v4, literal v6, CIDR,
subnet — is rejected at **compile** time with:

```
sandbox-exec: host must be * or localhost in network address
```

The SBPL network-address grammar is effectively
`(remote|local  ip|tcp|udp  "<*|localhost>:<port|*>")`. The host field admits
**only** the tokens `*` and `localhost`. There is no address-matching primitive
of any kind (no `subnet`, no `host`, no numeric literal). This is a hard parser
limit, not a runtime behavior — so it cannot be worked around with precedence,
`require-not`, or any rule ordering.

### localhost semantics (important, and slightly surprising)

`(remote ip "localhost:*")` does **not** mean "127.0.0.0/8 only". Observed:

- `127.0.0.1:19553` → allowed (as expected).
- `192.168.1.124:19553` (this host's **own LAN interface IP**) → **also allowed**.
- `8.8.8.8:443` (a genuinely remote host) → **blocked** (`operation not
  permitted`), while the same dial under `(remote tcp "*:443")` succeeds.

So `localhost` = "any address belonging to this host" (loopback **plus** the
host's own interface addresses), and it does **not** reach remote hosts. It is
therefore **wider than strict loopback** (it includes the box's own LAN-facing
services) but **does not leak to the network**. There is no primitive that
expresses 127.0.0.0/8-only.

### DNS: the SPEC's "mDNSResponder mach-lookup + outbound 53" is incomplete

A profile with `(allow mach-lookup)` + `(remote udp "*:53")` + `(remote tcp
"*:53")` still fails to resolve — `curl https://example.com` exits 6 ("Could not
resolve host"). The sandbox log shows the real blocker:

```
Sandbox: curl(…) deny(1) network-outbound /private/var/run/mDNSResponder
```

macOS `getaddrinfo` does not send DNS packets from the calling process; it hands
the query to the **mDNSResponder** system daemon over a **unix-domain socket**
at `/private/var/run/mDNSResponder`, and mDNSResponder (unsandboxed) does the
actual :53 traffic. So the client needs the unix socket, **not** outbound 53.
Adding

```
(allow network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))
```

makes `curl https://example.com` return **HTTP 200**. Verified minimal: DNS
works with the mDNSResponder unix socket alone — dropping outbound udp/tcp 53
and `ipc-posix-shm*` did not break resolution (the `ipc-posix-shm` denials in
the log are non-fatal noise). Keep an outbound-53 allowance only for tools that
resolve directly (Go's pure-`netgo` resolver, `dig`), and record that as a
belt-and-suspenders extra, not the primary channel.

## Verdict — SPEC §13 Q6

**macOS `trusted` CANNOT get real address-scoped (`Private` / metadata) rules.
They MUST compile to `blocked`.** Seatbelt's SBPL network filter has no
IP/CIDR/subnet matching whatsoever — the host token is restricted to `*` or
`localhost` at parse time. Concretely:

- **`Private` (RFC1918 + ULA)** is **not expressible** → compile to **blocked**,
  with a `CompileReport` `unenforced` entry. Same outcome as Linux Landlock
  rung 2 (SPEC §5.2/§7.5) — for the same underlying reason (no sockaddr-level
  address matching), reached independently.
- **Metadata hard-deny (§5.4)** — `169.254.169.254` / `fd00:ec2::254` — is **not
  expressible as a positive deny**. It holds **only vacuously**: metadata is
  reached over `:80` to a remote IP, and if `:80` (or `*`) is not in the allowed
  port set it is blocked by the port rules; if the policy allows `:80` or `*`,
  metadata becomes reachable and **cannot be carved out**. Under the `trusted`
  default `Ports {443}` (SPEC §13 note 3), the deny holds vacuously — identical
  to the rung-2 story in §5.4.

**Confirmed working (needed for the basic net policy):** default-deny base ✅,
outbound TCP **port scoping** ✅, **loopback** ✅ (via `localhost`, caveat above),
and **DNS** ✅ (via the mDNSResponder unix socket). All enforced, not just
accepted.

## Recommendation for Task 8 (`NetPolicy` field → backend action)

| `NetPolicy` field | macOS Seatbelt compilation |
|---|---|
| `Open` | unconfined — no profile (or `(allow default)`). |
| `Ports []uint16` | one `(allow network-outbound (remote tcp "*:<p>"))` per port. **Enforced.** |
| `Loopback` | `(allow network-outbound (remote ip "localhost:*"))`. **Enforced**, but emit a `CompileReport` note: `localhost` also matches this host's own non-loopback interface IPs (wider than 127.0.0.0/8); it does **not** reach remote hosts. If strict 127.0.0.0/8-only is ever required, it is **not expressible** → that stricter reading would compile to blocked. Recommend accepting `localhost` (the loopback use-case otherwise breaks) and recording the exact semantics. |
| `DNS` | `(allow network-outbound (remote unix-socket (path-literal "/private/var/run/mDNSResponder")))` **plus** the existing broad `mach-lookup` (or tighten to `(global-name "com.apple.mDNSResponder")`). Optionally add `(remote udp "*:53")(remote tcp "*:53")` for direct resolvers, noted as an extra. **Enforced.** Update the SPEC §5.2 DNS text — "outbound 53" alone does **not** work; the unix socket is the load-bearing rule. |
| `Private` | **Not expressible → compile to `blocked`.** No SBPL rule emitted. `CompileReport{Feature:"address-network", Status:"unenforced", Detail:"macOS SBPL network host is * or localhost only; RFC1918/ULA CIDR not expressible"}`. |
| Metadata deny (§5.4) | **Not expressible as a positive deny.** Do not emit an IP deny. Rely on the port set: it holds only when the metadata port (`:80`) is not allowed. `CompileReport{Feature:"metadata-deny", Status:"unenforced" (or "vacuous"), Detail:"holds only because :80 not in allowed ports; reachable if policy allows :80/*"}`. |

**Level / guarantees (SPEC §6, §10.3):** on macOS the `AddressNetwork`
guarantee bit is **false** — always. A policy that requests `Private` or
promises metadata semantics therefore tops out at **`Degraded`**, never `Full`.
This resolves the SPEC line ~778 caveat ("Full once CIDR rules verified"): CIDR
rules are now **verified as unsupported**, so a policy needing address scoping
stays `Degraded`. A policy needing only loopback + ports + DNS (no `Private`, no
positive metadata deny) can still reach `Full`, since every field it uses is
enforced.

**Structural fit:** matches the existing `ReportEntry{Feature,Status,Detail}` /
`CompileReport` shape (policy.go:132–147) and the fail-closed
`AddressNetwork` guarantee (backend/policy). The macOS backend can reuse the
exact same "compile-to-blocked + report" path that rung 2 uses for `Private`.

## Honest limitations

- Enforcement was fully observable because external egress happened to work in
  this environment; in a locked-down env the loopback/remote discrimination
  would have to lean on the `operation not permitted` vs `refused`/timeout error
  type alone (still reliable, just less satisfying).
- "localhost excludes remote hosts" is proven for one remote (8.8.8.8); the
  parser limit (`host must be * or localhost`) makes broader remote testing moot
  — you cannot name a remote host to allow it individually anyway.
- SBPL is undocumented/deprecated; a future macOS could change the grammar.
  These findings should be re-probed if the minimum macOS target moves.

## Scratch

Probe programs and profiles used are in `docs/spikes/scratch/` (`listen.go`,
`dial.go`, built binaries) — throwaway, not module code, safe to delete.
