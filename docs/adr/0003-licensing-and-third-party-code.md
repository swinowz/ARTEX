# ADR-0003: Licensing and reuse of third-party code

Status: proposed (2026-11-26), pending the research issue on existing projects

## Context
ARTEX is AGPL-3.0. Candidate sources have different licences and some are archived.
Reusing code without checking the licence can make the whole project non-distributable.

## Decision (proposed)
- Before copying any code: record the source repo, commit SHA, licence, and the reuse
  mode (copy, adapt, inspiration only) in the issue that needs it.
- Prefer MCP servers that wrap upstream tools over copying tool code.
- Respect per-tool licences (for example, the Nmap licence restricts some redistribution).
- Archived projects (CAI) are pinned to a revision with licence checked before reuse.

## Open questions
- Compatibility matrix AGPL-3.0 vs each candidate licence (to be filled by the research issue).
