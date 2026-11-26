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

**Correction after reading the code**: a deterministic detector already exists too.
`agent/tools.go` `detectStagnation` (#99, "ouroboros") flags a direction whose normalized
summary repeats >= 3 times among finished intents while no finding was produced since its
first attempt, and `graphOverviewData` surfaces it to the planner as `stagnation_warning`
with a self-describing instruction. So the supervision triad is largely already present;
#35 must not reimplement it.

The one real gap `detectStagnation` leaves: it keys on the **same summary repeating**, so a
task that churns through MANY DISTINCT empty directions (no single summary repeats 3x) is
never flagged even though nothing is being produced — exactly the failure a cheap model
(DeepSeek Flash) is prone to.

## Decision
Do not reimplement the existing stagnation detection; **close its one gap** and reuse its
surfacing. Add `detectNoYieldStreak(recentDone, yieldsOf, threshold)`: it flags when the
most recent `threshold` (default 3) intents that ran to completion (`state == "done"`) each
produced **no yields** (no downstream facts/findings), regardless of whether their summaries
repeat. `blocked`/`exhausted` intents (which did not fully run) are skipped — they deserve a
retry, not a tactic change. Its result is appended to the existing `stagnation_warning`
directions, with a generalized instruction, so no prompt-template change and no new surface
are needed.

This is inherently **advisory** (the operator's chosen option): `stagnation_warning` is data
in the planner's situation; the model still decides. A hard guard (engine refuses to
re-dispatch) stays an opt-in setting for a later increment if wanted.

Implementation note: an earlier draft added a speculative `StuckDirection`/`AttemptOutcome`
abstraction before reading the data shapes; it was replaced by `detectNoYieldStreak`, which
operates on the real `recentDone []*db.Node` + `yieldsOf` map already built in
`graphOverviewData`, and is unit-tested without a store.

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
