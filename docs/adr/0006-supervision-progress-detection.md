# ADR-0006: Supervision — deterministic no-progress detection

Status: accepted (2026-11-26) — #35. Decision: advisory (operator chose option (a)); the hard guard (b) stays an opt-in setting for a later increment.

## Context
#35 proposes importing PentAGI's supervision triad (Adviser / Planner / Reflector).
Auditing ARTEX's core shows two of the three are largely already present, so #35 should
not reimplement them:

- **Reflector (clean termination near budget)** — present. `agent/budget.go` has a
  per-task/intent/round budget ledger with a wrap-up reserve (`BudgetMarginPercent` 5%);
  `BeginWrapUp` fires once and running workers then see an exhausted budget, and
  `settleWrapUpPrompt` / `settleWrapUpSettlement` make the worker write back its findings
  and a summary before stopping. That is the Reflector.
- **Planner decomposition + anti-stall** — present. `agent/planner.go` has a "hard floor"
  (when the goal is unmet and no intent is open/running, the round must open at least one),
  and it already inspects each `recent_done` intent's state (`exhausted`/`blocked`) and
  tells the model to read `get_worker_trace` and, when "stuck at the same spot every time",
  change tactics.

The real gap is that the loop/no-progress judgment lives **in the planner prompt as LLM
judgment**, with no deterministic signal. On the lab, intents were re-dispatched and
repeated work without a hard "this direction is not progressing" marker. A cheap, honest
LLM (DeepSeek Flash) is exactly the case where an LLM-only loop check is unreliable.

## Decision (proposed)
Add a **deterministic no-progress signal** the planner can trust, without replacing its
judgment:

1. Track, per exploration direction (intent lineage / re-dispatch chain), the outcome of
   each attempt: facts written, assets written, findings written, and terminal state.
2. A pure detector flags a direction as **stuck** when the last N attempts (default 2–3)
   all wrote zero new facts/assets/findings and did not end `blocked` by a pure transport
   failure (which deserves a retry, not a tactic change).
3. Surface "stuck directions" in the planner's situation (the graph_overview tail) as a
   deterministic list, so the model is told which directions are provably not progressing
   and must change tactics or be dropped — instead of inferring it.
4. Optionally (increment 3, behind a setting) a hard guard: refuse to re-dispatch an
   identical stuck direction more than the threshold, forcing a new direction or completion.

Increment 1 (this ADR's first code step): the pure detector `stuckDirection(attempts,
threshold)` with unit tests, no engine wiring. Increment 2 wires attempt outcomes and the
planner situation line. Increment 3 adds the optional hard guard.

## Open question for the operator
How aggressive should the intervention be?
- (a) **Advisory only** — surface "stuck directions" to the planner; the model still decides.
  Safer, keeps ARTEX's LLM-judgment philosophy. Recommended default.
- (b) **Hard guard** — the engine refuses to re-dispatch a stuck direction past the
  threshold. Stronger anti-loop, but can override a model that had a good reason to retry.

Proposed: ship (a) first (advisory), make (b) an opt-in setting.

## Consequences
- Touches the planner situation assembly and needs per-direction attempt tracking
  (core change, allowed per ADR-0002). No schema change for increment 1.
- Avoids reimplementing the Reflector and the budget wrap-up, which already exist.
