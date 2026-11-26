# ADR-0001: GitHub issues are the backlog and the memory of the project

Status: accepted (2026-11-26)

## Context
Work is done by several agents and sessions. Chat history is not reliable as a memory.

## Decision
- Every feature, bug, research item and decision request is a GitHub issue.
- Progress is recorded as issue comments (what changed, verification, what remains).
- The issue body must be self-contained: an agent with no prior context can resume it.
- Labels (`type:*`, `area:*`, `status:*`, `phase:*`) are the only classification.

## Consequences
- Issues must be kept current; an issue stuck in `status:in-progress` without a comment
  for more than a session is a process bug.
