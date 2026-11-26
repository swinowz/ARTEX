package agent

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

func doneIntent(id int64, summary string) *db.Node {
	return &db.Node{ID: id, State: "done", Payload: []byte(`{"summary":"` + summary + `"}`)}
}

func TestNoYieldStreakFlagsThreeEmptyCompletions(t *testing.T) {
	// Three distinct completed directions, none produced a yield, newest first.
	recent := []*db.Node{doneIntent(30, "try path A"), doneIntent(20, "try path B"), doneIntent(10, "try path C")}
	got := detectNoYieldStreak(recent, map[int64][]int64{}, 3)
	if len(got) != 3 {
		t.Fatalf("three empty completed intents should be flagged, got %d: %v", len(got), got)
	}
	if got[0]["id"].(int64) != 30 {
		t.Fatalf("directions should be newest-first, got %v", got)
	}
}

func TestNoYieldStreakProductiveMostRecentClears(t *testing.T) {
	recent := []*db.Node{doneIntent(30, "A"), doneIntent(20, "B"), doneIntent(10, "C")}
	yields := map[int64][]int64{30: {999}} // the most recent produced a fact/finding
	if got := detectNoYieldStreak(recent, yields, 3); got != nil {
		t.Fatalf("a productive most-recent completion must clear the streak, got %v", got)
	}
}

func TestNoYieldStreakBelowThresholdNotFlagged(t *testing.T) {
	recent := []*db.Node{doneIntent(20, "A"), doneIntent(10, "B")}
	if got := detectNoYieldStreak(recent, map[int64][]int64{}, 3); got != nil {
		t.Fatalf("two completions is not enough evidence at threshold 3, got %v", got)
	}
}

func TestNoYieldStreakBlockedSkippedNotCounted(t *testing.T) {
	// A blocked (transport failure) between empties is skipped, not counted and not a break;
	// but with only 2 real completions it is still below threshold 3.
	recent := []*db.Node{
		doneIntent(40, "A"),
		{ID: 35, State: "blocked", Payload: []byte(`{"summary":"net fail"}`)},
		doneIntent(20, "B"),
	}
	if got := detectNoYieldStreak(recent, map[int64][]int64{}, 3); got != nil {
		t.Fatalf("blocked skipped leaves only 2 completions, below threshold 3, got %v", got)
	}
	// With a third real completion it flags, ignoring the blocked one.
	recent = append(recent, doneIntent(10, "C"))
	if got := detectNoYieldStreak(recent, map[int64][]int64{}, 3); len(got) != 3 {
		t.Fatalf("three completions (blocked ignored) should flag, got %v", got)
	}
}

func TestNoYieldStreakThresholdClamp(t *testing.T) {
	if got := detectNoYieldStreak([]*db.Node{doneIntent(10, "A")}, map[int64][]int64{}, 0); len(got) != 1 {
		t.Fatalf("threshold 0 clamps to 1; one empty completion flags, got %v", got)
	}
}
