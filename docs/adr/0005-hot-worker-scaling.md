# ADR-0005: Scale a running task's workers without restarting it

Status: accepted (2026-11-26) — #32

## Context
`Engine.Run` reads `workers := m.Workers()` once at task start and launches exactly
that many `workerLoop` goroutines (`work#1..#N`). When `Run` is called again for an
already-started task it only nudges the planner — it never adds worker loops. So raising
the global `workers` setting mid-task has no effect: the task stays at the concurrency it
started with (observed on the lab: a task stuck at 3 after the setting was raised to 5).
Recreating the task to get more workers loses its intent context and evidence.

## Decision
Add `Engine.ScaleWorkers(ctx, task, target)` that adds worker loops to a *running* task's
existing `taskRuntime` and an endpoint `POST /api/tasks/{id}/scale` to trigger it.

- The per-task current worker count lives on `taskRuntime.workers`, guarded by `runtimeMu`.
- Scaling up to `target` reserves `target-current` more routines (`rt.wg.Add`) and starts
  that many new `workerLoop`s named `work#(current+1)..work#target`, then nudges the
  planner so it opens intents for the new slots.
- Scaling to `target <= current` is a no-op: in-flight workers are never killed (per #32).
- A task that is not running (no runtime, or the engine is draining) returns "not running"
  so the caller recreates/starts it instead.
- The naming/accounting is a pure helper `scaleWorkerNames(current, target)`, unit-tested
  without goroutines; `ScaleWorkers` wraps it with the wg/goroutine/notify side effects.

The request body is `{"workers": N}`; omitted/0 means "scale to the current global
`workers` setting". N is clamped to >= 1.

## Consequences
- Operators raise concurrency on a live task and poke it, no restart, no lost context (#32,
  resolves the live half of #6).
- Lowering concurrency mid-task is deliberately not supported here (would need to cancel a
  specific loop's context); the setting still lowers the count for the next task.
- Touches the core engine (allowed, ADR-0002). No schema change.
