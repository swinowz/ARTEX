package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
)

func TestParseOverseerDecision(t *testing.T) {
	decision, err := parseOverseerDecision("```json\n{\"assessment\":\"Worker repeats a request\",\"actions\":[{\"type\":\"guide_worker\",\"intent_id\":42,\"instruction\":\"Inspect the response body\"}]}\n```")
	if err != nil {
		t.Fatal(err)
	}
	if decision.Assessment != "Worker repeats a request" || len(decision.Actions) != 1 || decision.Actions[0].IntentID != 42 {
		t.Fatalf("unexpected decision: %+v", decision)
	}
	if _, err := parseOverseerDecision("no structured decision"); err == nil {
		t.Fatal("invalid model output accepted")
	}
}

func TestOverseerSessionFilter(t *testing.T) {
	filter, ok := parseActivitySession("overseer")
	if !ok || filter.Worker != "overseer" || filter.NodeID != nil {
		t.Fatalf("overseer session routed incorrectly: %+v, %v", filter, ok)
	}
	if _, ok := parseActivitySession("overseer:other"); ok {
		t.Fatal("unknown session key accepted")
	}
}

func TestOverseerPromptActionsMatchRuntime(t *testing.T) {
	prompt := agent.BuiltinPromptSeeds()["overseer"]
	for _, action := range []string{"guide_worker", "deepen_finding"} {
		if !strings.Contains(prompt, action) {
			t.Fatalf("prompt missing %s", action)
		}
	}
	if strings.Contains(prompt, "escalate_finding") {
		t.Fatal("prompt advertises unsupported escalation")
	}
}
