package server

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Autumn-27/artex/db"
)

func TestTaskCloneCopiesConfigurationIntoFreshGraph(t *testing.T) {
	g := newGateServer(t)
	related, err := g.m.CreateTask("clone related source", "source context", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	g.cleanupTask(t, related.ID)
	source, err := g.m.CreateTaskWithOptions("clone source", "audit clone behavior", db.TaskCreateOptions{SourceTaskIDs: []int64{atoi64(related.ID)}})
	if err != nil {
		t.Fatal(err)
	}
	g.cleanupTask(t, source.ID)
	goalID, err := source.Store.AddNode(db.KindGoal, map[string]any{"text": "check the exposed admin panel", "vulnclass": "access-control"}, 5, "open", "human", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.m.Assets().AddAgentScope(atoi64(source.ID), "root_domain", "clone.example", "test target", "manual"); err != nil {
		t.Fatal(err)
	}
	if _, err := source.Store.AddIntent(map[string]any{"summary": "old intent"}, 5, nil, "planner"); err != nil {
		t.Fatal(err)
	}
	findingNode, err := source.Store.AddNode(db.KindFinding, map[string]any{"summary": "old finding", "severity": "high"}, 5, "confirmed", "worker", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := g.m.PG().AddFinding(atoi64(source.ID), findingNode, "test", "old finding", "high", "summary", "evidence", "worker", nil); err != nil {
		t.Fatal(err)
	}
	if err := g.m.SetTaskStatus(source.ID, "timeout"); err != nil {
		t.Fatal(err)
	}
	if code, _ := g.do(t, "POST", "/api/tasks/"+source.ID+"/control", `{"action":"resume"}`); code != 409 {
		t.Fatalf("resume terminal task status=%d; want 409", code)
	}
	status, body := g.do(t, "POST", "/api/tasks/"+source.ID+"/clone", "{}")
	if status != 201 {
		t.Fatalf("clone: status=%d body=%v", status, body)
	}
	cloneID := fmt.Sprint(body["id"])
	g.cleanupTask(t, cloneID)
	if cloneID == source.ID || body["parent_ref"] != source.ID || body["description"] != source.Description || body["goal"] != source.Goal {
		t.Fatalf("clone identity/configuration not preserved: %v", body)
	}
	clone, ok := g.m.Task(cloneID)
	if !ok {
		t.Fatal("cloned task not in manager")
	}
	if intents, err := clone.Store.ListByKind(db.KindIntent, 100); err != nil || len(intents) != 0 {
		t.Fatalf("clone intents=%d err=%v; want zero", len(intents), err)
	}
	if findings, err := clone.Store.ListByKind(db.KindFinding, 100); err != nil || len(findings) != 0 {
		t.Fatalf("clone finding nodes=%d err=%v; want zero", len(findings), err)
	}
	findingRows, _, err := g.m.PG().ListFindingsPage(db.FindingFilter{TaskID: cloneID}, 1, 50)
	if err != nil || len(findingRows) != 0 {
		t.Fatalf("clone finding records=%d err=%v; want zero", len(findingRows), err)
	}
	goals, err := clone.Store.ListByKind(db.KindGoal, 100)
	if err != nil || len(goals) != 1 || goals[0].ID == goalID {
		t.Fatalf("clone goals=%d err=%v; want one fresh goal node", len(goals), err)
	}
	var clonedGoal struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal(goals[0].Payload, &clonedGoal); err != nil || clonedGoal.Text != "check the exposed admin panel" {
		t.Fatalf("cloned goal payload=%s err=%v", goals[0].Payload, err)
	}
	goalCode, goalBody := g.do(t, "GET", "/api/tasks/"+cloneID+"/goals", "")
	goalRows, _ := goalBody["goals"].([]any)
	if goalCode != 200 || len(goalRows) != 1 {
		t.Fatalf("cloned goal API response=%d %v", goalCode, goalBody)
	}
	scopeCode, scopeBody := g.do(t, "GET", "/api/tasks/"+cloneID+"/scope", "")
	scope, _ := scopeBody["scope"].([]any)
	if scopeCode != 200 || len(scope) != 1 {
		t.Fatalf("cloned scope response=%d %v", scopeCode, scopeBody)
	}
	foundDomain := false
	for _, raw := range scope {
		row, _ := raw.(map[string]any)
		if row["domain"] == "clone.example" && fmt.Sprint(row["task_id"]) == cloneID {
			foundDomain = true
		}
	}
	if !foundDomain {
		t.Fatalf("scope row was not copied into the cloned task: %v", scope)
	}
	if fmt.Sprint(body["source_task_ids"]) != fmt.Sprint([]any{related.ID}) {
		t.Fatalf("source tasks=%v; want original sources", body["source_task_ids"])
	}
}

func atoi64(value string) int64 {
	var n int64
	_, _ = fmt.Sscan(value, &n)
	return n
}
