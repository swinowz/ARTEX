# ADR-0012: Separate worker and overseer LLM profiles

## Status

Accepted

## Context

The native Overseer has a separate agent role, but model profiles did not express
which role could use them. An unbound Overseer therefore followed the task or
global worker model, and a profile intended only for supervision could enter a
worker chain.

## Decision

LLM profiles have a persisted `role` capability: `worker`, `overseer`, or `both`.
The migration defaults existing profiles to `worker` to preserve their current
worker use. The worker pool, task profile validation, task runtime selection,
agent bindings, and global default reject or omit `overseer`-only profiles.
Overseer bindings accept only `overseer` or `both` profiles. Enabling the
Overseer requires an explicit eligible binding; it never follows a task/global
worker profile.

## Consequences

Existing deployments can continue using their profiles as workers. Operators
who enable the Overseer must assign an `overseer` or `both` profile. A `both`
profile can serve either role, while an `overseer` profile cannot be selected as
a worker failover or global default.
