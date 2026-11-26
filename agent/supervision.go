package agent

// Supervision: deterministic no-progress detection (ADR-0006, #35). ARTEX already has
// the budget wrap-up (the Reflector) and a planner anti-stall hard floor; the missing
// piece is a deterministic signal that an exploration direction is not progressing, so the
// planner is told which directions to change tactics on instead of inferring it from an
// LLM read of the traces.

// AttemptOutcome summarizes what one attempt at an exploration direction wrote back.
type AttemptOutcome struct {
	FactsWritten    int
	AssetsWritten   int
	FindingsWritten int
	// TransportFailed is true when the attempt ended blocked by a pure transport/model
	// failure (network, provider 5xx, rate limit) rather than by exploring and finding
	// nothing. A transport failure deserves a retry, not a tactic change, so it never
	// counts as "stuck".
	TransportFailed bool
}

// producedSomething reports whether an attempt wrote any new graph content.
func (a AttemptOutcome) producedSomething() bool {
	return a.FactsWritten > 0 || a.AssetsWritten > 0 || a.FindingsWritten > 0
}

// StuckThresholdDefault is the number of consecutive empty attempts after which a
// direction is considered stuck (change tactics or drop it).
const StuckThresholdDefault = 2

// StuckDirection reports whether an exploration direction is provably not progressing:
// its last `threshold` attempts each wrote nothing new (no facts, assets or findings) and
// none was a pure transport failure. A threshold below 1 is treated as 1. With fewer
// attempts than the threshold it is never stuck — there is not enough evidence yet.
func StuckDirection(attempts []AttemptOutcome, threshold int) bool {
	if threshold < 1 {
		threshold = 1
	}
	if len(attempts) < threshold {
		return false
	}
	for _, a := range attempts[len(attempts)-threshold:] {
		if a.TransportFailed || a.producedSomething() {
			return false
		}
	}
	return true
}
