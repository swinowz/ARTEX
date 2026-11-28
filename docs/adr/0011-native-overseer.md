# ADR-0011: Native task Overseer

Cadence is configurable per Overseer agent: time mode reviews at a configured seconds interval (default 90 seconds), while rounds mode reviews after a configured number of completed `Worker.Execute` runs. The rounds signal is emitted when each worker execution returns, so idle tasks do not trigger reviews.

Status: implemented on `issue-44-native-overseer` (2026-11-27) — #44.

## Context

The external `cdocs/overseer` pilot can analyze a task, but it is absent from Agent Management and Sessions, runs outside the task lifecycle, and uses a separate model client. The Planner already detects stagnation; a separate agent can turn that signal and recent worker/finding evidence into directed help.

## Decision

Seed `overseer` as a built-in ARTEX agent, disabled by default. Its activation and LLM profile binding are configured in the LLM settings; its prompt remains editable in Agent Management. A task-owned loop runs the reviewer periodically when enabled, with cancellation and pause matching the Planner and Worker loops. It publishes its reasoning summary, decisions and action results to the task activity stream under `worker="overseer"`; Sessions presents that stream as its own pane.

The reviewer receives bounded, task-local evidence. It may guide a running intent or open a directed follow-up intent after validating task ownership. The model itself has no direct shell or attack tool access; worker capabilities remain unchanged.

## Consequences

- A configured Overseer no longer needs a separate script, tunnel, or model key path.
- The role's model can differ from the Planner and Workers without changing their model bindings.
- A failed or malformed review writes an error activity and leaves workers running.
