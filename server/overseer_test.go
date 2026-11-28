package server

import (
	"strings"
	"testing"
	"time"

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

func TestNormalizeOverseerCadence(t *testing.T) {
	if got := normalizeOverseerCadence("seconds", 7, 5); got.Mode != "seconds" || got.Seconds != 7 {
		t.Fatalf("seconds cadence: %+v", got)
	}
	if got := normalizeOverseerCadence("rounds", 90, 3); got.Mode != "rounds" || got.Rounds != 3 {
		t.Fatalf("rounds cadence: %+v", got)
	}
	if got := normalizeOverseerCadence("broken", 0, 0); got.Mode != "seconds" || got.Seconds != 90 {
		t.Fatalf("fallback cadence: %+v", got)
	}
	if got := overseerCadenceDelay(normalizeOverseerCadence("seconds", 7, 5)); got != 7*time.Second {
		t.Fatalf("seconds delay=%s, want 7s", got)
	}
}

func TestWorkerRoundCadenceDoesNotFireWhileIdle(t *testing.T) {
	e := NewEngine(nil)
	wake := e.WorkerRoundWake("cadence-test")
	select {
	case <-wake:
		t.Fatal("idle task emitted a worker round")
	default:
	}
	e.workerRoundCompleted("cadence-test")
	select {
	case <-wake:
	default:
		t.Fatal("completed worker round did not wake overseer")
	}
	if got := e.CompletedWorkerRounds("cadence-test"); got != 1 {
		t.Fatalf("completed rounds=%d, want 1", got)
	}
}

func TestOverseerRoundGateThresholdAndIdle(t *testing.T) {
	g := overseerRoundGate{}
	if g.Observe(0, 2) {
		t.Fatal("idle task triggered review")
	}
	if g.Observe(1, 2) {
		t.Fatal("review fired before threshold")
	}
	if !g.Observe(2, 2) {
		t.Fatal("review did not fire at threshold")
	}
	if g.Observe(2, 2) {
		t.Fatal("idle task retriggered review")
	}
}
