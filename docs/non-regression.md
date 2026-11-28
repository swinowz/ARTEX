# Non-regression baseline

Issue #29 tracks proving that extensions (MCP capability servers, scope-guard,
skills) do not alter ARTEX's core behaviour and that existing settings remain
unchanged.

## Local & CI runner

`scripts/verify.sh` is the single reproducible entry point (mirroring
`.github/workflows/ci.yml`):

```sh
# Fast baseline (no PostgreSQL required; DB-backed tests skip cleanly)
./scripts/verify.sh

# Go-only (gofmt, go build ./..., go vet ./..., go test -p 1 ./...)
./scripts/verify.sh --go-only

# Full suite with race detector and static web build (set ARTEX_PG_DSN for DB tests)
ARTEX_PG_DSN='postgres://...' ./scripts/verify.sh --full
```

## What is verified

1. **Formatting, build & static analysis**: `gofmt -l`, `go build ./...`,
   `go vet ./...`.
2. **Core non-regression**: `go test -p 1 ./...` and `-race` across all core
   packages plus `./scope` and `./mcps/nmap`.
3. **MCP contract & dynamic activation (#13)**: `TestMCPContractEndToEnd`
   (Streamable HTTP + stdio, deferred `SearchExtraTools`/`ExecuteExtraTool`,
   native `record_fact`/`report_finding`) and `TestMCPHealthStateTransitions`
   in `server/mcp_contract_test.go`.
4. **Signed mission scope (#14)**: `go test ./scope -race -count=1` and
   `cmd/artex-scope` CLI (`keygen`/`sign`/`verify`).
5. **Bounded `mcp-nmap` (#15)**: `go test ./mcps/nmap -race -count=1` and
   `TestMCPNmapEndToEnd` in `server/mcp_nmap_integration_test.go`.
6. **AD inventory (#17)**: `go test ./mcps/adcore ./mcps/netexec ./mcps/enum4linux -race -count=1`
   and `go test ./server -run TestWithTaskCredentials -race`. Fixtures cover
   SMB and LDAP success, logon failure, account lockout, access denied and an
   unsupported check, and assert that no credential value appears in a tool
   result, in an artifact or in the child environment.
7. **Live worker scaling & `workers` setting (#6, #32)**:
   `TestScaleWorkers*` and `TestWorkersSettingAndScaleTask` in
   `server/engine_scale_test.go`.
