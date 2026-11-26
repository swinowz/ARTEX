# ADR-0002: Prefer native extension points, but changing the core is allowed

Status: accepted (2026-11-26), revised (2026-11-26)

## Context
The goal is a general pentest platform built on ARTEX. An earlier draft of this ADR
copied a "zero core change" rule from the GPT framing document. The operator never
asked for that rule and has explicitly rejected it: modifying ARTEX's core is allowed
and expected.

## Decision
Modifying the core (engine, planner, worker loops, graphs, Reporter, persistence,
console) is permitted. There is no rule that forbids it and no approval gate before it.

When a capability can be added cleanly as an MCP server or a skill, prefer that — it is
usually less work and keeps the change isolated. But when the native extension points
are insufficient or awkward, change the core. The general-pentest goal requires it:
finding verification is HTTP-only today (see #8), and specialised worker dispatch does
not exist (see #26); both need core changes.

Native extension points, when they fit:
1. MCP servers (one per tool or suite), registered through the existing MCP management
   (`GET/POST/DELETE /api/mcp`, `POST /api/mcp/{id}/refresh`);
2. skills (`<SkillDir>/<name>/SKILL.md`, `SkillDir` = `ARTEX_SKILL_DIR` > config
   `skill_dir` > `skills/` next to the binary; `mcps:` in the frontmatter unlocks servers);
3. agent profiles (today the planner dispatches only to the literal `"worker"` key; a
   real profile selector is a core change, tracked in #26).

## Discipline (traceability, not permission)
- Record a significant core change in an ADR: what changed, why the extension points did
  not fit, which files. This is for the next agent to understand the design, not a gate.
- Keep the change focused and tested so upstream merges from `BaaRai/ARTEX` stay feasible
  where we still want them. We may also diverge permanently where it serves the goal.

## Verified facts (2026-11-26, commit 3cb0638)
- `SkillDir()` precedence is as above (`config/config.go`).
- `mcps` in skill metadata is read by `server/server_mgmt.go`.
- The worker tool set is built with the literal key `"worker"` (`agent/toolcatalog.go`,
  `agent/worker.go`). A custom profile is not selected by the planner today.
- Finding verification requires a bound HTTP traffic body (`server/finding_verification.go`);
  non-HTTP findings cannot reach `verified` without a core change (see #8).

## Consequences
- Each tool can still get its own MCP server and its own issue when that is the clean path.
- Core changes (finding verification for non-HTTP evidence, worker dispatch, new schema)
  are first-class work items, not exceptions.
