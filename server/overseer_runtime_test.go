package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// TestOverseerRuntimeCadenceProof is a runtime integration demonstration, not
// just a gate unit test: it starts Engine.Run, which launches overseerLoop,
// uses a real PG-backed task/activity store, and sends reviews through the
// configured Overseer profile to a local stub Anthropic endpoint.
func TestOverseerRuntimeCadenceProof(t *testing.T) {
	skipWithoutDSN(t)
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close() })
	if m.pg == nil {
		db.SkipNoPG(t)
	}
	// Make reruns against a persistent test database clean: retire artifacts from
	// a previous interrupted proof before Server.New restores its task goroutines.
	if err := m.pg.SetAgentEnabled("overseer", false); err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetAgentLLMProfile("overseer", nil); err != nil {
		t.Fatal(err)
	}
	m.LoadExisting()
	for _, old := range m.List() {
		if strings.HasPrefix(old.Description, "runtime proof:") || strings.Contains(old.Goal, "Internal runtime cadence proof") {
			if _, err := m.DeleteTask(old.ID, DeleteTaskOptions{}); err != nil {
				t.Fatalf("remove stale proof task %s: %v", old.ID, err)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())

	var malformed atomic.Bool
	var calls atomic.Int64
	var actionIntent atomic.Int64
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		w.Header().Set("Content-Type", "text/event-stream")
		decision := "not-json"
		if !malformed.Load() {
			decision = fmt.Sprintf(`{"assessment":"runtime proof review","actions":[{"type":"guide_worker","intent_id":%d,"instruction":"Inspect the simulated worker output"}]}`, actionIntent.Load())
		}
		body, _ := json.Marshal(map[string]any{"type": "message_start", "message": map[string]any{"id": "msg-runtime-proof", "usage": map[string]int{"input_tokens": 11, "output_tokens": 1}}})
		_, _ = fmt.Fprintf(w, "event: message_start\ndata: %s\n\n", body)
		body, _ = json.Marshal(map[string]any{"type": "content_block_delta", "index": 0, "delta": map[string]string{"type": "text_delta", "text": decision}})
		_, _ = fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", body)
		body, _ = json.Marshal(map[string]any{"type": "message_delta", "delta": map[string]string{"stop_reason": "end_turn"}, "usage": map[string]int{"output_tokens": 7}})
		_, _ = fmt.Fprintf(w, "event: message_delta\ndata: %s\n\n", body)
		_, _ = io.WriteString(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
		t.Logf("STUB_LLM call=%d response=%s intent_id=%d", call, map[bool]string{true: "malformed", false: "valid"}[malformed.Load()], actionIntent.Load())
	}))
	t.Cleanup(stub.Close)
	t.Cleanup(func() {
		stopTestServer(t, s, cancel)
		for _, task := range m.List() {
			if strings.HasPrefix(task.Description, "runtime proof:") || strings.Contains(task.Goal, "Internal runtime cadence proof") {
				if _, err := m.DeleteTask(task.ID, DeleteTaskOptions{}); err != nil {
					t.Errorf("delete proof task %s during cleanup: %v", task.ID, err)
				}
			}
		}
	})

	profileID, err := m.pg.SaveProfile(&db.LLMProfile{
		Name: fmt.Sprintf("runtime-proof-stub-%d", time.Now().UnixNano()), Format: "anthropic", BaseURL: stub.URL, Model: "claude-runtime-proof",
		APIKey: "runtime-proof-only", Streaming: true, Role: "overseer",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetAgentLLMProfile("overseer", &profileID); err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetAgentEnabled("overseer", true); err != nil {
		t.Fatal(err)
	}

	launchTask := func(name, mode string, seconds, rounds int) (*Task, int64) {
		t.Helper()
		if err := m.pg.SetOverseerCadence("overseer", mode, seconds, rounds); err != nil {
			t.Fatal(err)
		}
		task, err := m.CreateTask(name, "Internal runtime cadence proof; no target operations", nil, 0, 300)
		if err != nil {
			t.Fatal(err)
		}
		intentID, err := task.Store.AddIntent(map[string]any{"summary": "Simulated running worker for Overseer guidance proof"}, 10, nil, "test")
		if err != nil {
			t.Fatal(err)
		}
		if err := task.Store.SetIntentState(intentID, "running"); err != nil {
			t.Fatal(err)
		}
		_, workCancel := context.WithCancelCause(context.Background())
		s.engine.registerWork(intentID, workCancel)
		t.Cleanup(func() {
			_, finish := s.engine.detachWork(intentID)
			workCancel(context.Canceled)
			finish(nil)
		})
		actionIntent.Store(intentID)
		s.engine.Run(ctx, task)
		return task, intentID
	}
	activities := func(task *Task) []db.Activity {
		t.Helper()
		rows, _, err := task.Store.ActivityPage(db.ActivitySessionFilter{Worker: "overseer"}, 0, 100)
		if err != nil {
			t.Fatalf("read Overseer activity for task %s: %v", task.ID, err)
		}
		return rows
	}
	reviewStarts := func(rows []db.Activity) []db.Activity {
		var out []db.Activity
		for _, row := range rows {
			if row.Kind == "round" && row.Summary == "Overseer review started" {
				out = append(out, row)
			}
		}
		return out
	}
	waitFor := func(label string, timeout time.Duration, check func() bool) {
		t.Helper()
		deadline := time.Now().Add(timeout)
		for time.Now().Before(deadline) {
			if check() {
				return
			}
			time.Sleep(20 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for %s", label)
	}
	stopProofTask := func(task *Task, intentID int64) {
		t.Helper()
		s.engine.BeginDelete(task.ID)
		s.engine.StopTask(task.ID)
		_, finish := s.engine.detachWork(intentID)
		finish(nil)
		if _, err := m.DeleteTask(task.ID, DeleteTaskOptions{}); err != nil {
			t.Fatalf("delete proof task %s: %v", task.ID, err)
		}
	}

	// Seconds mode: allow only the Overseer profile to call the stub and verify
	// persisted rounds occur at roughly the configured one-second cadence.
	secondsTask, secondsIntent := launchTask("runtime proof: seconds cadence", "seconds", 1, 2)
	waitFor("two seconds-mode review rounds", 4*time.Second, func() bool { return len(reviewStarts(activities(secondsTask))) >= 2 })
	secondsReviews := reviewStarts(activities(secondsTask))
	interval := secondsReviews[1].CreatedAt.Sub(secondsReviews[0].CreatedAt)
	if interval < 700*time.Millisecond || interval > 1800*time.Millisecond {
		t.Fatalf("seconds-mode review interval=%s, want approximately 1s", interval)
	}
	for _, row := range activities(secondsTask) {
		t.Logf("SECONDS_ACTIVITY activity=%d worker=%s kind=%s error=%t summary=%q", row.ID, row.Worker, row.Kind, row.IsError, row.Summary)
	}
	if guidance, ok := s.engine.drainSteer(secondsIntent); !ok || guidance != "Inspect the simulated worker output" {
		t.Fatalf("valid stub decision did not queue guidance: %q, %v", guidance, ok)
	}
	t.Logf("SECONDS_PROOF task=%s intent=%d reviews=[activity:%d at:%s, activity:%d at:%s] interval=%s",
		secondsTask.ID, secondsIntent, secondsReviews[0].ID, secondsReviews[0].CreatedAt.Format(time.RFC3339Nano),
		secondsReviews[1].ID, secondsReviews[1].CreatedAt.Format(time.RFC3339Nano), interval)
	for _, row := range activities(secondsTask) {
		if row.Summary == "Guidance queued for worker intent #"+fmt.Sprint(secondsIntent) {
			t.Logf("VALID_ACTION_PROOF task=%s activity=%d worker=%s summary=%q", secondsTask.ID, row.ID, row.Worker, row.Summary)
		}
	}
	stopProofTask(secondsTask, secondsIntent)

	// Rounds mode: no action after the first simulated completion, then a review
	// promptly after the second completion; the counters route through the same
	// Engine signal consumed by the production overseerLoop.
	roundsTask, roundsIntent := launchTask("runtime proof: rounds cadence", "rounds", 1, 2)
	waitFor("rounds-mode loop initialization", time.Second, func() bool { _, ok := s.engine.workerRoundWake.Load(roundsTask.ID); return ok })
	time.Sleep(150 * time.Millisecond)
	if got := len(reviewStarts(activities(roundsTask))); got != 0 {
		t.Fatalf("rounds-mode task reviewed before worker completion: %d", got)
	}
	s.engine.workerRoundCompleted(roundsTask.ID)
	t.Logf("WORKER_COMPLETION task=%s completed_round=1", roundsTask.ID)
	time.Sleep(150 * time.Millisecond)
	if got := len(reviewStarts(activities(roundsTask))); got != 0 {
		t.Fatalf("rounds-mode task reviewed after only one completion: %d", got)
	}
	secondCompletionAt := time.Now()
	s.engine.workerRoundCompleted(roundsTask.ID)
	t.Logf("WORKER_COMPLETION task=%s completed_round=2", roundsTask.ID)
	waitFor("rounds-mode review after second worker completion", 2*time.Second, func() bool { return len(reviewStarts(activities(roundsTask))) >= 1 })
	roundsReview := reviewStarts(activities(roundsTask))[0]
	completionDelay := roundsReview.CreatedAt.Sub(secondCompletionAt)
	if completionDelay < 0 || completionDelay > 750*time.Millisecond {
		t.Fatalf("rounds-mode review delay after second completion=%s, want <=750ms", completionDelay)
	}
	t.Logf("ROUNDS_PROOF task=%s intent=%d review_activity=%d at=%s delay_after_second_completion=%s",
		roundsTask.ID, roundsIntent, roundsReview.ID, roundsReview.CreatedAt.Format(time.RFC3339Nano), completionDelay)
	stopProofTask(roundsTask, roundsIntent)

	// Same rounds interval and observation window, but no worker completions.
	idleTask, _ := launchTask("runtime proof: idle rounds cadence", "rounds", 1, 2)
	idleWindow := 2100 * time.Millisecond
	time.Sleep(idleWindow)
	if got := len(reviewStarts(activities(idleTask))); got != 0 {
		t.Fatalf("rounds-mode idle task reviewed with zero worker completions: %d", got)
	}
	t.Logf("ROUNDS_IDLE_PROOF task=%s window=%s worker_completions=0 review_rounds=0", idleTask.ID, idleWindow)
	stopProofTask(idleTask, 0)

	// Malformed response: actual review loop reaches the stub, writes an error
	// activity, and leaves the simulated worker steering queue untouched.
	malformed.Store(true)
	badTask, badIntent := launchTask("runtime proof: malformed response", "rounds", 1, 2)
	waitFor("malformed-test rounds loop initialization", time.Second, func() bool { _, ok := s.engine.workerRoundWake.Load(badTask.ID); return ok })
	s.engine.workerRoundCompleted(badTask.ID)
	s.engine.workerRoundCompleted(badTask.ID)
	waitFor("malformed response error activity", 2*time.Second, func() bool {
		for _, row := range activities(badTask) {
			if row.Worker == "overseer" && row.IsError && row.Kind == "text" {
				return true
			}
		}
		return false
	})
	badRows := activities(badTask)
	for _, row := range badRows {
		if row.IsError && row.Kind == "text" {
			t.Logf("MALFORMED_REJECTED_PROOF task=%s activity=%d worker=%s summary=%q", badTask.ID, row.ID, row.Worker, row.Summary)
		}
	}
	if guidance, ok := s.engine.drainSteer(badIntent); ok {
		t.Fatalf("malformed stub response unexpectedly queued guidance %q", guidance)
	}
	badIntents, err := badTask.Store.ListByKind(db.KindIntent, 30)
	if err != nil {
		t.Fatal(err)
	}
	var badIntentState string
	for _, node := range badIntents {
		if node.ID == badIntent {
			badIntentState = node.State
			break
		}
	}
	if badIntentState != "running" {
		t.Fatalf("malformed response mutated simulated intent state to %q", badIntentState)
	}
	t.Logf("MALFORMED_NO_MUTATION task=%s intent=%d state=running queued_guidance=false stub_calls=%d", badTask.ID, badIntent, calls.Load())
	stopProofTask(badTask, badIntent)
	if err := m.pg.SetAgentEnabled("overseer", false); err != nil {
		t.Fatal(err)
	}
	if err := m.pg.SetAgentLLMProfile("overseer", nil); err != nil {
		t.Fatal(err)
	}
}
