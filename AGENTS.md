# AGENTS.md — ARTEX (fork swinowz/ARTEX)

Guide for any AI agent or contributor working on this repository.

## What this project is

ARTEX is an LLM-driven penetration-testing platform (Go backend, Next.js console,
PostgreSQL). This fork is the working base for a general pentest solution: web first,
then network, Wi-Fi, Active Directory, Entra ID, pivoting, C2, reverse engineering.
Target use: **authorized** engagements and labs only.

Extensions must go through ARTEX's native extension points (MCP servers, skills,
agent profiles). Changes to the core (engine, planner, worker loops, graphs, Reporter,
persistence, console) are exceptional and must be justified in an ADR first.

## Where work is tracked

- **Issues are the backlog.** Every idea, feature, bug and research item is an issue.
  Labels describe type, area and status (see below). Do not work from memory or chat only.
- **Progress goes in issue comments.** When you advance an issue, add a comment with:
  what changed, commit SHA or branch, what was verified and how, what remains.
  A new agent must be able to resume the issue from its body and comments alone.
- **Decisions go in `docs/adr/`** (numbered, short, one decision per file).
- **Local AI notes live in `cdocs/`** (gitignored). It holds infra access, dev setup,
  and state notes. Read `cdocs/README.md` first if it exists. If it does not exist on
  this machine, ask the user where it is; do not invent infrastructure details.

## Repository rules

- Remote `origin` is `swinowz/ARTEX`. There is **no** upstream remote: do not add
  `BaaRai/ARTEX` or any other remote to push to, and do not push to any repo the user
  did not name.
- Work on a branch per issue (`issue-<n>-<slug>`). Commit and push only when asked.
- One focused change per PR; reference the issue (`Closes #n` or `Refs #n`).
- **No secrets in git, issues, PRs or comments**: no passwords, tokens, private keys,
  API keys, real IPs of non-lab hosts, or credential dumps. Refer to where a secret is
  stored (path, env var name), never its value.
- The lab (GOAD) is intentionally vulnerable and uses fake domains. Its data is still
  treated as sensitive in tooling and logs.

## Labels

- `type:feature`, `type:bug`, `type:research`, `type:docs`, `type:security`, `type:infra`
- `area:core`, `area:mcp`, `area:skill`, `area:web`, `area:report`, `area:scope`, `area:dev`
- `status:ready`, `status:in-progress`, `status:blocked`, `status:review`
- `phase:P0` … `phase:P5` (roadmap phases from the framing document)

## Build and test

```sh
go build ./cmd/artex          # backend
go test ./...                 # Go tests (needs network for modules on first run)
cd web && npm ci && npm run build   # console (only if you touch web/)
```

Dev loop: see `scripts/dev-watch.sh` (backend hot reload) and `dev.sh` (frontend).

## Licence

LICENSE is AGPL-3.0. Before copying code from another project, check its licence
and record the decision in an ADR (see ADR-0003).
