package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/transcript"
)

const overseerDefaultInterval = 90 * time.Second

type overseerCadence struct {
	Mode            string
	Seconds, Rounds int
}

type overseerRoundGate struct{ last, pending int64 }

func (g *overseerRoundGate) Observe(completed int64, interval int) bool {
	g.pending += completed - g.last
	g.last = completed
	if interval < 1 || g.pending < int64(interval) {
		return false
	}
	g.pending %= int64(interval)
	return true
}

func normalizeOverseerCadence(mode string, seconds, rounds int) overseerCadence {
	if mode != "seconds" && mode != "rounds" {
		mode = "seconds"
	}
	if seconds < 1 {
		seconds = 90
	}
	if rounds < 1 {
		rounds = 5
	}
	return overseerCadence{Mode: mode, Seconds: seconds, Rounds: rounds}
}

func overseerCadenceDelay(c overseerCadence) time.Duration {
	return time.Duration(c.Seconds) * time.Second
}

type overseerAction struct {
	Type        string `json:"type"`
	IntentID    int64  `json:"intent_id"`
	FindingID   int64  `json:"finding_id"`
	Instruction string `json:"instruction"`
}

type overseerDecision struct {
	Assessment string           `json:"assessment"`
	Actions    []overseerAction `json:"actions"`
}

type overseerNode struct {
	ID      int64  `json:"id"`
	State   string `json:"state"`
	Summary string `json:"summary"`
}

type overseerFinding struct {
	overseerNode
	Verification string `json:"verification"`
}

type overseerStep struct {
	IntentID int64  `json:"intent_id,omitempty"`
	Worker   string `json:"worker"`
	At       string `json:"at"`
	Kind     string `json:"kind"`
	Tool     string `json:"tool,omitempty"`
	Summary  string `json:"summary"`
}

type overseerSnapshot struct {
	ObservedAt string            `json:"observed_at"`
	Goal       string            `json:"goal"`
	Intents    []overseerNode    `json:"intents"`
	Findings   []overseerFinding `json:"findings"`
	Facts      []overseerNode    `json:"facts"`
	Steps      []overseerStep    `json:"recent_steps"`
}

func overseerSummary(node *db.Node) string {
	var payload struct {
		Summary string `json:"summary"`
	}
	_ = json.Unmarshal(node.Payload, &payload)
	return preview(payload.Summary, 240)
}

func (s *Server) overseerSnapshot(t *Task) (overseerSnapshot, error) {
	out := overseerSnapshot{ObservedAt: time.Now().UTC().Format(time.RFC3339), Goal: preview(t.Goal, 1000)}
	for _, kind := range []string{db.KindIntent, db.KindFinding, db.KindFact} {
		nodes, err := t.Store.ListByKind(kind, 30)
		if err != nil {
			return out, err
		}
		for _, node := range nodes {
			item := overseerNode{ID: node.ID, State: node.State, Summary: overseerSummary(node)}
			switch kind {
			case db.KindIntent:
				out.Intents = append(out.Intents, item)
			case db.KindFact:
				out.Facts = append(out.Facts, item)
			case db.KindFinding:
				out.Findings = append(out.Findings, overseerFinding{overseerNode: item})
			}
		}
	}
	if id, err := strconv.ParseInt(t.ID, 10, 64); err == nil {
		quality, err := s.m.pg.FindingQualityByNodeID(id)
		if err != nil {
			return out, err
		}
		for i := range out.Findings {
			out.Findings[i].Verification = quality[out.Findings[i].ID].VerificationStatus
		}
	}
	// ActivityPage reads the newest rows, then returns that window in time order.
	rows, _, err := t.Store.ActivityPage(db.ActivitySessionFilter{}, 0, 35)
	if err != nil {
		return out, err
	}
	for _, row := range rows {
		if row.Worker == "overseer" || row.Kind == "usage" {
			continue
		}
		step := overseerStep{Worker: row.Worker, At: row.CreatedAt.UTC().Format(time.RFC3339), Kind: row.Kind, Tool: preview(row.Tool, 80), Summary: preview(row.Summary, 180)}
		if row.NodeID != nil {
			step.IntentID = *row.NodeID
		}
		out.Steps = append(out.Steps, step)
	}
	return out, nil
}

func parseOverseerDecision(raw string) (overseerDecision, error) {
	var result overseerDecision
	// Models may wrap JSON in prose/fences. Decode the first complete object,
	// then reject ill-typed actions instead of executing a guessed command.
	for _, loc := range regexp.MustCompile(`\{`).FindAllStringIndex(raw, -1) {
		var candidate overseerDecision
		if err := json.NewDecoder(strings.NewReader(raw[loc[0]:])).Decode(&candidate); err == nil {
			result = candidate
			if len(result.Actions) > 2 {
				result.Actions = result.Actions[:2]
			}
			return result, nil
		}
	}
	return result, fmt.Errorf("overseer returned invalid JSON")
}

func (s *Server) overseerReview(ctx context.Context, t *Task, snapshot overseerSnapshot) (overseerDecision, error) {
	var result overseerDecision
	role, err := s.m.pg.GetAgentByKey("overseer")
	if err != nil || role == nil || !role.Enabled {
		return result, fmt.Errorf("overseer unavailable")
	}
	prompt, err := s.m.pg.CurrentPrompt(role.ID)
	if err != nil {
		return result, err
	}
	if prompt == "" {
		prompt = agent.BuiltinPromptSeeds()["overseer"]
	}
	input, err := json.Marshal(snapshot)
	if err != nil {
		return result, err
	}
	provider := &taskLLMRuntime{s: s, taskID: t.ID, agentKey: "overseer"}
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	ctx = transcript.WithSessionID(ctx, "overseer-"+transcript.NewSessionID())
	req := llm.CompletionRequest{System: []string{prompt}, Messages: []llm.Message{llm.UserText(string(input))}, MaxTokens: 3500}
	var text strings.Builder
	s.engine.BeginLLMCall(t.ID)
	defer s.engine.EndLLMCall(t.ID)
	for event, err := range provider.Stream(ctx, req) {
		if err != nil {
			return result, err
		}
		if event.Type == llm.SEToolUseStart {
			return result, fmt.Errorf("overseer model attempted a tool call")
		}
		if event.Type == llm.SETextDelta {
			text.WriteString(event.Text)
		}
	}
	return parseOverseerDecision(text.String())
}

func (s *Server) applyOverseerAction(t *Task, snapshot overseerSnapshot, action overseerAction) (string, error) {
	instruction := strings.TrimSpace(action.Instruction)
	if len([]rune(instruction)) > 4000 || instruction == "" {
		return "", fmt.Errorf("empty or oversized instruction")
	}
	switch action.Type {
	case "guide_worker":
		if !hasOverseerIntent(snapshot.Intents, action.IntentID, "running") {
			return "", fmt.Errorf("intent is not running in this task")
		}
		if err := s.engine.SteerWork(action.IntentID, instruction); err != nil {
			return "", err
		}
		return fmt.Sprintf("Guidance queued for worker intent #%d", action.IntentID), nil
	case "deepen_finding":
		if !hasOverseerFinding(snapshot.Findings, action.FindingID) {
			return "", fmt.Errorf("finding is not in this task")
		}
		id, err := t.Store.AddIntent(map[string]any{"summary": fmt.Sprintf("Follow up finding #%d: %s", action.FindingID, instruction)}, 10, nil, "overseer")
		if err != nil {
			return "", err
		}
		t.Notify()
		return fmt.Sprintf("Opened follow-up intent #%d for finding #%d", id, action.FindingID), nil
	default:
		return "", fmt.Errorf("unsupported overseer action %q", action.Type)
	}
}

func hasOverseerIntent(items []overseerNode, id int64, state string) bool {
	for _, item := range items {
		if item.ID == id && item.State == state {
			return true
		}
	}
	return false
}

func hasOverseerFinding(items []overseerFinding, id int64) bool {
	for _, item := range items {
		if item.ID == id {
			return true
		}
	}
	return false
}

func (s *Server) overseerLoop(ctx context.Context, t *Task) {
	lastRounds := s.engine.CompletedWorkerRounds(t.ID)
	pendingRounds := int64(0)
	previousMode := ""
	roundWake := s.engine.WorkerRoundWake(t.ID)
	lastActions := map[string]struct{}{}
	for {
		role, err := s.m.pg.GetAgentByKey("overseer")
		cadence := normalizeOverseerCadence("seconds", 90, 5)
		if err != nil || role == nil {
			log.Printf("[overseer] task %s cannot read cadence config; using 90-second default: %v", t.ID, err)
		} else {
			cadence = normalizeOverseerCadence(role.OverseerCadenceMode, role.OverseerIntervalSeconds, role.OverseerIntervalRounds)
		}
		if cadence.Mode != previousMode {
			if cadence.Mode == "rounds" {
				lastRounds = s.engine.CompletedWorkerRounds(t.ID)
				pendingRounds = 0
			}
			previousMode = cadence.Mode
		}
		var timer *time.Timer
		var trigger <-chan time.Time
		if cadence.Mode == "seconds" {
			timer = time.NewTimer(overseerCadenceDelay(cadence))
			trigger = timer.C
		}
		var roundEvents <-chan struct{}
		if cadence.Mode == "rounds" {
			roundEvents = roundWake
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-trigger:
		case <-roundEvents:
			if timer != nil {
				timer.Stop()
			}
			completed := s.engine.CompletedWorkerRounds(t.ID)
			gate := overseerRoundGate{last: lastRounds, pending: pendingRounds}
			shouldReview := gate.Observe(completed, cadence.Rounds)
			lastRounds, pendingRounds = gate.last, gate.pending
			if cadence.Mode != "rounds" || !shouldReview {
				continue
			}
		}
		role, err = s.m.pg.GetAgentByKey("overseer")
		if err != nil || role == nil || !role.Enabled || s.engine.IsPaused(t.ID) || s.engine.IsDeleting(t.ID) || s.engine.isSettling(t.ID) || isTerminalStatus(t.lifecycleSnapshot().Status) {
			continue
		}
		if !s.engine.beginTaskOperation(t.ID) {
			continue
		}
		s.overseerRound(s.engine.execContextFor(ctx, t.ID), t, lastActions)
		s.engine.decInflight(t.ID)
	}
}

func (s *Server) overseerRound(ctx context.Context, t *Task, lastActions map[string]struct{}) {
	emit := func(kind, summary string, failed bool) {
		s.engine.emitActivity(t, db.Activity{Worker: "overseer", Kind: kind, Summary: summary, IsError: failed})
	}
	snapshot, err := s.overseerSnapshot(t)
	if err != nil {
		emit("text", "Overseer could not read task state: "+preview(err.Error(), 180), true)
		return
	}
	if len(snapshot.Intents) == 0 && len(snapshot.Findings) == 0 {
		return
	}
	emit("round", "Overseer review started", false)
	decision, err := s.overseerReview(ctx, t, snapshot)
	if err != nil {
		if ctx.Err() == nil {
			emit("text", "Overseer review failed: "+preview(err.Error(), 180), true)
		}
		return
	}
	emit("text", "Overseer: "+preview(decision.Assessment, 500), false)
	for _, action := range decision.Actions {
		if ctx.Err() != nil || s.engine.IsPaused(t.ID) || s.engine.IsDeleting(t.ID) || isTerminalStatus(t.lifecycleSnapshot().Status) {
			return
		}
		key := fmt.Sprintf("%s:%d:%d:%s", action.Type, action.IntentID, action.FindingID, action.Instruction)
		if _, seen := lastActions[key]; seen {
			continue
		}
		summary, err := s.applyOverseerAction(t, snapshot, action)
		if err != nil {
			emit("text", "Overseer action rejected: "+preview(err.Error(), 180), true)
			continue
		}
		lastActions[key] = struct{}{}
		emit("text", summary, false)
	}
	log.Printf("[overseer] task %s review finished (%d actions)", t.ID, len(decision.Actions))
}
