# ADR-0004: Finding verification for non-HTTP evidence (tool output)

Status: accepted (2026-11-26) — implemented in increments, see #8

## Context
`server/finding_verification.go` only verifies a finding when a **proof/verification
HTTP traffic body** is bound (`assessFindingVerification`): POE ≥ L3, and every quote
found verbatim in a bound HTTP response body. A finding from a non-HTTP tool (nmap,
netexec, bloodhound, impacket, hashcat, ghidra, ...) has no HTTP body to bind, so it can
never reach `verified` — it stays `unverified` with note "no proof traffic bound"
(`agent/finding_workflow.go`). The market study (#3) found that hallucinated / unverified
findings are the single biggest complaint about AI pentest tools, so honest verification
of non-HTTP findings is the highest-value differentiator for a general pentest platform.

## Decision
Add a second evidence source — **command/tool output** — that a finding can bind and be
verified against, using the **same rules** as HTTP (POE ≥ L3, quote ≥ 8 runes, quote found
verbatim after whitespace normalization, read cap, fail-closed on unreadable/non-text).
HTTP verification is unchanged; the two sources are unioned.

## Plan (increments)
1. **Source-agnostic verification core (this increment).** Extract the pure rule engine
   from `assessFindingVerification` into `evaluateEvidence(poe, quotes, bodies) (status,
   note)`, operating on already-read `boundBody` values regardless of origin. Behaviour-
   preserving; covered by unit tests with no DB. Non-regression: the existing
   `finding_verification_test.go` suite stays green.
2. **Command-output evidence store + binding.** A new evidence kind holding captured tool
   output (reuse the spill/evidence store), a binding role analogous to proof/verification,
   and a `readCommandOutput` producer mirroring `readBoundResponse` (same cap / non-text /
   truncated handling).
3. **Wire both sources** in `assessFindingVerification`: gather HTTP proof bodies AND
   command-output bodies, verify quotes against the union; "no proof bound" only when
   neither exists.
4. **Agent tool + report path** so a worker can bind the exact command output slice that
   proves a finding (`report_finding` / `update_finding_report`), without fabricating fake
   HTTP traffic bindings.

## Rules kept (no softening)
- A model can never award `verified` on its own; the deterministic checker does.
- Same thresholds: POE ≥ 3, quote ≥ 8 runes, verbatim after whitespace normalization,
  4 MiB read cap, fail-closed (`not_assessed`) on unreadable or non-text evidence.
- No fake HTTP traffic bindings to satisfy the HTTP-only path.

## Consequences
- Non-HTTP findings (AD, network, wifi, C2, binary) can reach `verified` with real,
  rerunnable proof, attacking the market's #1 complaint (#3).
- Touches the core (`server/finding_verification.go`, db schema for the new binding,
  evidence store, one agent tool). Allowed per ADR-0002 (this is a fork).
