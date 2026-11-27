# Mission scope for capability MCP servers

Status: implemented 2026-11-27, issue #14. Package `scope/`, CLI
`cmd/artex-scope`, ADR-0009.

This document is for operators who sign a mission and for anyone writing a
capability MCP server (#15+). It is not a description of ARTEX's platform-wide
target gate; see `docs/ARCHITECTURE.md` and `guard/` for that.

## What the guarantee is

A server that calls `scope.Guard` refuses an operation **before its side
effect** when the target, operation, time window or budget is outside the signed
mission. The refusal reaches the model as:

```
[ARTEX platform control, not target defense] SCOPE_DENIED: 10.1.2.7 is excluded by cidr 10.1.2.0/24
```

It is **not** an egress firewall. Native `Bash`, `shell_open`, `shell_send`,
custom tools, and any server that does not call the guard can still open a
socket. Those paths rely on the existing hook/target gate or network isolation.

## 1. Create a signing key (once per installation)

```sh
go run ./cmd/artex-scope keygen -dir keys
# key_id <id>
# wrote keys/mission.key (0600) and keys/mission.pub
```

`keys/` is gitignored. Back up the private key; every manifest signed with it is
only verifiable while its public key is pinned. Rotate by adding the new public
key to the server's key file, then removing the old one.

## 2. Write the mission manifest

```json
{
  "version": "artex.mission/v1",
  "mission_id": "acme-week-47",
  "server": "nmap",
  "issued_at": "2026-11-27T09:00:00Z",
  "not_before": "2026-11-27T09:00:00Z",
  "not_after": "2026-11-27T21:00:00Z",
  "allowed": [
    {"kind": "cidr", "value": "10.20.0.0/16", "ports": [22, 80, 443, 445]},
    {"kind": "domain", "value": "lab.example.test"}
  ],
  "excluded": [
    {"kind": "cidr", "value": "10.20.30.0/24", "note": "out-of-scope finance subnet"}
  ],
  "operations": {
    "discover": {"allowed": true, "max_per_run": 10},
    "service_scan": {"allowed": true}
  },
  "budgets": {
    "total_ops": 200,
    "per_server": {"nmap": 120, "netexec": 80}
  },
  "approval": "operator",
  "cleanup": ["remove uploaded files"]
}
```

Rules:

- `version` must be `artex.mission/v1`.
- `server` is the audience. A manifest for `nmap` is refused by any other server.
- `domain` covers the name and its subdomains. Wildcards are refused; write the
  registrable domain.
- `ports` is optional. When present, the caller must declare a port and it must
  match. A rule without `ports` covers every port.
- `excluded` wins over every `allowed` entry, even a broader one. A target
  subnet overlapping an exclusion is refused as a whole.
- `total_ops` and `per_server` are fixed here. The split may not exceed the
  total; a server may never borrow another's share.
- `operations` is an allow-list. An unknown operation is denied. `max_per_run`
  is an additional cap for a long-lived process.
- `requires_approval: true` denies with `SCOPE_APPROVAL_REQUIRED`; the approval
  itself is a platform concern, not something the server can invent.
- `not_before`/`not_after` are enforced at load and on every check.

## 3. Sign and verify

```sh
go run ./cmd/artex-scope sign -key keys/mission.key \
  -in mission.json -out mission.signed.json
go run ./cmd/artex-scope verify -key keys/mission.pub \
  -in mission.signed.json
# valid: mission=acme-week-47 server=nmap window=... operations=2 ...
```

`sign` normalises rule values before signing; `verify` checks the signature,
schema, budget coherence and window.

## 4. Deliver it to a server

Both variables are required; without them the server fails closed.

```sh
export ARTEX_SCOPE_MANIFEST=/run/secrets/mission.signed.json
export ARTEX_SCOPE_PUBKEY=/run/secrets/mission.pub
```

- **stdio:** the server reads them at startup and may re-stat the manifest
  before a new mission.
- **HTTP/SSE:** the same variables plus the envelope on inbound requests, e.g.
  `X-ARTEX-Mission-Manifest: <base64url envelope>`; re-verify per request because
  a session may be shared.
- **Development only:** `ARTEX_SCOPE_ALLOW_UNSCOPED=1` starts an explicitly
  unguarded mode that logs a warning and denies every operation. It is never a
  silent allow.

## 5. Enforce it in a tool handler

```go
g, err := scope.FromEnv()
if err != nil {
    return err // fail closed at startup
}

func (s *Server) discover(ctx context.Context, host string, port int) (Result, error) {
    target, ok := scope.Normalize(host)
    if !ok {
        return Result{}, scope.ToolError(scope.Deny(scope.CodeScopeDenied, "invalid target"))
    }
    target.Port = port
    req := scope.Request{Operation: "discover", Target: target}

    d := g.Check(ctx, req)              // no side effect
    if !d.Allow {
        return Result{}, scope.ToolError(d)
    }
    d, err := g.Charge(ctx, req, d)     // reserve one operation
    if err != nil || !d.Allow {
        return Result{}, scope.ToolError(d)
    }
    res, err := s.do(ctx, target)       // the only place with a side effect
    if err != nil {
        _ = g.Ledger.Release(g.Manifest.MissionID, g.Manifest.Server, 1)
    }
    return res, err
}
```

For a name target, the caller must pass the addresses it will actually dial and
must dial those same addresses:

```go
ips, err := scope.ResolveTargets(ctx, net.DefaultResolver.LookupNetIP, target)
req := scope.Request{Operation: "discover", Target: target, DNS: ips}
```

Dial `ips`, not the name again: a second lookup can return a different address,
which the guard will refuse (`SCOPE_DNS_CHANGED`) — and refusing is the point.

For redirects:

```go
if d := g.CheckRedirect(ctx, from, to, "discover"); !d.Allow {
    return scope.ToolError(d)
}
```

A cross-host hop must be explicitly allowed by name; resolving into an allowed
IP range is not enough.

## 6. Semantics at a glance

| Situation | Result |
|---|---|
| Target outside every allow rule | `SCOPE_DENIED` |
| Target in an excluded CIDR under an allowed parent | `SCOPE_DENIED`, `Excluded=true` |
| Target subnet overlapping an exclusion | `SCOPE_DENIED` |
| IPv6 literal/prefix not allowed | `SCOPE_DENIED` |
| `::ffff:10.0.0.1` | evaluated as `10.0.0.1` |
| Domain answer changes between checks | `SCOPE_DNS_CHANGED` |
| No resolver and no addresses | `SCOPE_DNS_FAILED` |
| Redirect to an unlisted name | `SCOPE_DENIED` |
| Operation absent or `allowed:false` | `SCOPE_OPERATION_DENIED` |
| Manifest audience is another server | `SCOPE_SERVER_NOT_AUDIENCE` |
| Now outside the window | `SCOPE_MANIFEST_EXPIRED` |
| Per-server split exhausted | `SCOPE_BUDGET_EXHAUSTED` |
| Signature/key/alg failure | `SCOPE_MANIFEST_INVALID` / `SCOPE_MANIFEST_UNSIGNED` |

## 7. Tests

```sh
go test ./scope -race -v
```

`scope/scope_test.go` maps the #14 acceptance criteria: out-of-scope before any
effect, exclusion under an allowed parent, IPv6, DNS change, redirect, operation
allow-list, time window, audience, tamper, budget split and concurrent charges.

## 8. Limits (do not overclaim)

- Only servers that call the guard are constrained.
- The budget is enforced per signed allocation inside each server; the
  cross-server total is a signing-time invariant and a future PostgreSQL audit,
  not live global enforcement.
- DNS pinning protects callers that pass the addresses they dial and re-check on
  redirect; a caller that resolves again after the check is outside the
  guarantee.
- The platform target gate remains the backstop for native tools; this package
  does not replace it.
