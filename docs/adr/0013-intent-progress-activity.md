# ADR-0013: Intent progress in the activity stream

## Decision

Emit intent progress as `progress` activity rows, tagged with the intent node and
worker. The row metadata carries `state`: `waiting-model`, `executing`, or
`waiting-approval`. Emit at the start, on tool and approval transitions, and
every two minutes while the intent runs. The Sessions UI reads the newest state
from its existing history and SSE cache. Live token usage stays on the existing
`usage` rows.

## Reason

The activity stream already persists worker events and replays them after SSE
reconnects. Using it gives a running intent durable liveness and state without a
second state store or endpoint. A periodic row covers silent model and tool waits.

## Consequences

Long intents add one activity row per two minutes. Progress rows are excluded
from token accounting and remain visible in execution history.
