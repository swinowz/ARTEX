# ADR-0002: Extend ARTEX through its native extension points, not its core

Status: accepted (2026-11-26)

## Context
The goal is a general pentest platform built on ARTEX. The core (engine, planner,
worker loops, graphs, Reporter, persistence, console) is shared upstream and must stay
mergeable.

## Decision
New capabilities are added as:
1. MCP servers (one per tool or suite), registered through the existing MCP management
   (`GET/POST/DELETE /api/mcp`, `POST /api/mcp/{id}/refresh`);
2. skills (`<SkillDir>/<name>/SKILL.md`, `SkillDir` = `ARTEX_SKILL_DIR` > config
   `skill_dir` > `skills/` next to the binary; `mcps:` in the frontmatter unlocks servers);
3. agent profiles only if the planner can actually dispatch to them (not yet proven).

Changes to the core require an ADR that names the exact files and why the extension
points are insufficient.

## Verified facts (2026-11-26, commit 3cb0638)
- `SkillDir()` precedence is as above (`config/config.go`).
- `mcps` in skill metadata is read by `server/server_mgmt.go`.
- The worker tool set is built with the literal key `"worker"` (`agent/toolcatalog.go`,
  `agent/worker.go`). A custom profile is not selected by the planner today.

## Consequences
- Each tool gets its own MCP server and its own issue.
- Dispatch to specialised workers (ad, wifi, ...) is a separate issue, not assumed.
