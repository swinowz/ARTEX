package agent

import "testing"

func TestStuckDirectionEmptyAttemptsReachThreshold(t *testing.T) {
	attempts := []AttemptOutcome{{}, {}}
	if !StuckDirection(attempts, 2) {
		t.Fatal("two empty attempts should be stuck at threshold 2")
	}
}

func TestStuckDirectionBelowThresholdNotStuck(t *testing.T) {
	if StuckDirection([]AttemptOutcome{{}}, 2) {
		t.Fatal("one attempt is not enough evidence to be stuck at threshold 2")
	}
}

func TestStuckDirectionProgressResets(t *testing.T) {
	// The last two attempts must be empty; a productive one in the window clears it.
	attempts := []AttemptOutcome{{}, {FactsWritten: 1}}
	if StuckDirection(attempts, 2) {
		t.Fatal("a fact written in the window means progress, not stuck")
	}
}

func TestStuckDirectionOnlyLastNCount(t *testing.T) {
	// Earlier productive attempts do not matter once the last N are all empty.
	attempts := []AttemptOutcome{{FindingsWritten: 1}, {}, {}}
	if !StuckDirection(attempts, 2) {
		t.Fatal("last two empty attempts should be stuck regardless of earlier progress")
	}
}

func TestStuckDirectionTransportFailureIsNotStuck(t *testing.T) {
	// A transport failure deserves a retry, not a tactic change.
	attempts := []AttemptOutcome{{}, {TransportFailed: true}}
	if StuckDirection(attempts, 2) {
		t.Fatal("a transport failure in the window must not count as stuck")
	}
}

func TestStuckDirectionAssetOrFindingCountsAsProgress(t *testing.T) {
	if StuckDirection([]AttemptOutcome{{AssetsWritten: 1}, {}}, 2) {
		t.Fatal("an asset written is progress")
	}
	if StuckDirection([]AttemptOutcome{{}, {FindingsWritten: 1}}, 2) {
		t.Fatal("a finding written is progress")
	}
}

func TestStuckDirectionThresholdClamp(t *testing.T) {
	if !StuckDirection([]AttemptOutcome{{}}, 0) {
		t.Fatal("threshold 0 clamps to 1; one empty attempt is then stuck")
	}
}
