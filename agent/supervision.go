package agent

import (
	"encoding/json"

	"github.com/Autumn-27/artex/db"
)

// Supervision: deterministic no-progress detection (ADR-0006, #35).
//
// ARTEX already carries most of PentAGI's supervision triad: the budget wrap-up
// reserve (agent/budget.go) is the Reflector, the planner has a hard-floor anti-stall,
// and detectStagnation (#99) already flags a direction whose SAME summary repeats and
// yields no finding, surfaced to the planner as stagnation_warning.
//
// The one gap detectStagnation leaves is a task that churns through MANY DISTINCT empty
// directions — no single summary repeats, so it is never flagged even though nothing is
// being produced. detectNoYieldStreak closes that: it flags when the most recent
// completed intents each produced no yields at all.

// noYieldStreakMin is the number of consecutive completed (state "done") intents that
// must each have produced nothing before the task is flagged as churning empty directions.
const noYieldStreakMin = 3

// detectNoYieldStreak flags that the most recent `threshold` intents that ran to
// completion (state "done") each produced no yields (no downstream facts/findings),
// regardless of whether their summaries repeat. recentDone is newest-first. Intents that
// did not fully run (state "blocked" — a transport failure — or "exhausted" — cut off by
// budget) are skipped: they are not counted as empty and do not break the streak, since
// they deserve a retry, not a tactic change. yieldsOf maps an intent id to the downstream
// nodes it produced. Returns the offending directions (newest first), or nil when there
// are fewer than `threshold` completed intents or any of them produced something.
func detectNoYieldStreak(recentDone []*db.Node, yieldsOf map[int64][]int64, threshold int) []map[string]any {
	if threshold < 1 {
		threshold = 1
	}
	var out []map[string]any
	for _, n := range recentDone {
		if n.State != "done" {
			continue // blocked/exhausted did not fully run: skip, don't count
		}
		if len(yieldsOf[n.ID]) > 0 {
			return nil // the most recent completed direction produced something: not stuck
		}
		var p map[string]any
		_ = json.Unmarshal(n.Payload, &p)
		summ, _ := p["summary"].(string)
		out = append(out, map[string]any{"id": n.ID, "direction": summ})
		if len(out) >= threshold {
			return out
		}
	}
	return nil // fewer than threshold completed intents: not enough evidence
}
