package server

import (
	"fmt"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// Issue #7: GET /api/tasks/{id}/goals flags goals marked "met" without a
// linked RelProves observation/finding so the UI can surface unverified ones.
func TestListGoalsProofFlags(t *testing.T) {
	g := newGateServer(t)
	task, err := g.m.CreateTask("goal proof flags", "verify unverified_met flag", nil, 0, 0)
	if err != nil {
		t.Fatalf("CreateTask: %v", err)
	}

	openID, err := task.Store.AddNode(db.KindGoal, map[string]any{"text": "open goal"}, 5, "open", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}
	unverifiedMetID, err := task.Store.AddNode(db.KindGoal, map[string]any{"text": "legacy met without proof"}, 5, "met", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}
	provenMetID, err := task.Store.AddNode(db.KindGoal, map[string]any{"text": "proven met goal"}, 5, "met", "planner", nil)
	if err != nil {
		t.Fatal(err)
	}
	factID, err := task.Store.AddNode(db.KindFact, map[string]any{
		"summary":    "nmap observed port 22 open",
		"source":     "tool_output",
		"confidence": "observed",
	}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := task.Store.Link(factID, db.RelProves, provenMetID); err != nil {
		t.Fatal(err)
	}

	code, out := g.do(t, "GET", fmt.Sprintf("/api/tasks/%s/goals", task.ID), "")
	if code != 200 {
		t.Fatalf("GET /goals: code=%d out=%v", code, out)
	}
	rawGoals, _ := out["goals"].([]any)
	byID := map[string]map[string]any{}
	for _, item := range rawGoals {
		m, _ := item.(map[string]any)
		if id, _ := m["id"].(string); id != "" {
			byID[id] = m
		}
	}

	check := func(id int64, wantProof, wantUnverified bool) {
		t.Helper()
		m, ok := byID[fmt.Sprint(id)]
		if !ok {
			t.Fatalf("goal %d missing from response: %v", id, byID)
		}
		gotProof, _ := m["has_proof"].(bool)
		gotUnverified, _ := m["unverified_met"].(bool)
		if gotProof != wantProof || gotUnverified != wantUnverified {
			t.Fatalf("goal %d: has_proof=%v unverified_met=%v, want %v/%v", id, gotProof, gotUnverified, wantProof, wantUnverified)
		}
	}

	check(openID, false, false)
	check(unverifiedMetID, false, true)
	check(provenMetID, true, false)
}
