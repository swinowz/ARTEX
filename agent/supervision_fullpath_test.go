package agent

import (
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestStagnationWarningSurfacesInGraphOverview is the end-to-end (#35) proof:
// three intents that each RAN TO COMPLETION with zero downstream facts/findings
// must make the LIVE planner situational snapshot (graphOverviewData — the exact
// map the planner receives each round) carry a stagnation_warning. This exercises
// the whole path (store -> edges/yields -> detectNoYieldStreak -> snapshot), not
// just the pure detector, against a real database.
func TestStagnationWarningSurfacesInGraphOverview(t *testing.T) {
	s := guardTaskStore(t)

	// Three DISTINCT directions, each completed (state "done") with no yield —
	// the exact shape task #8 hit when it churned the golden-ticket attempt 3x.
	addGuardNode(t, s, db.KindIntent, map[string]any{"summary": "forge inter-realm golden ticket and DCSync winterfell"}, "done")
	addGuardNode(t, s, db.KindIntent, map[string]any{"summary": "coerce DC auth via PetitPotam and relay to LDAP"}, "done")
	addGuardNode(t, s, db.KindIntent, map[string]any{"summary": "abuse ADCS ESC1 on the sevenkingdoms CA"}, "done")

	ov := NewToolSet(s, "planner").graphOverviewData()

	warn, ok := ov["stagnation_warning"].(map[string]any)
	if !ok {
		t.Fatalf("stagnation_warning absent from the live planner snapshot (keys present: %v)", mapKeys(ov))
	}
	dirs, _ := warn["directions"].([]map[string]any)
	if len(dirs) < 3 {
		t.Fatalf("want >=3 flagged no-yield directions in the snapshot, got %d: %#v", len(dirs), dirs)
	}
	if instr, _ := warn["instruction"].(string); instr == "" {
		t.Fatalf("stagnation_warning carries no instruction for the planner: %#v", warn)
	}
	t.Logf("#35 end-to-end: live planner snapshot carries stagnation_warning with %d no-yield directions", len(dirs))
}

func mapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
