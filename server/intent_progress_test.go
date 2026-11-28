package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

// The HTTP server and its activity store run while a stub intent remains busy.
// The short interval exercises the same timer used by production's two-minute tick.
func TestIntentProgressActivityWhileRunning(t *testing.T) {
	skipWithoutDSN(t)
	dir, err := os.MkdirTemp("", "intent-progress-*")
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewManager(dir, "")
	if err != nil {
		_ = os.RemoveAll(dir)
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close(); _ = os.RemoveAll(dir) })
	task, err := m.CreateTaskWithOptions("progress test", "stub intent", db.TaskCreateOptions{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = m.DeleteTask(task.ID, DeleteTaskOptions{}) })
	intentID, err := task.Store.AddIntent(map[string]any{"summary": "long stub"}, 1, nil, "planner")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := New(ctx, m, t.TempDir(), t.TempDir(), t.TempDir())
	defer stopTestServer(t, s, cancel)
	jwt, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatal(err)
	}
	httpServer := httptest.NewServer(s.Handler())
	defer httpServer.Close()
	read := func() []struct {
		Kind, Summary string
		Metadata      struct{ State string }
	} {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/exploration/activity?task=%s&intent=%d", httpServer.URL, task.ID, intentID), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+jwt)
		resp, err := httpServer.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("activity status: %s", resp.Status)
		}
		var body struct {
			Items []struct {
				Kind, Summary string
				Metadata      struct{ State string }
			}
		}
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		return body.Items
	}
	emit := func(a db.Activity) {
		a.NodeID, a.Worker = &intentID, "work#1"
		s.engine.emitActivity(task, a)
	}
	p := startIntentProgress(200*time.Millisecond, emit)
	defer p.close()
	p.observe(db.Activity{Kind: "tool_use"})
	p.observe(db.Activity{Kind: "intercept_request"})
	p.observe(db.Activity{Kind: "tool_result"})
	deadline := time.Now().Add(2 * time.Second)
	var items []struct {
		Kind, Summary string
		Metadata      struct{ State string }
	}
	for time.Now().Before(deadline) {
		items = read()
		periodic := 0
		for _, a := range items {
			if a.Kind == "progress" && a.Summary == "intent in progress" {
				periodic++
			}
		}
		if periodic >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	want := []string{"waiting-model", "executing", "waiting-approval", "waiting-model", "waiting-model", "waiting-model"}
	var got []string
	for _, a := range items {
		if a.Kind == "progress" {
			got = append(got, a.Metadata.State)
		}
	}
	if len(got) < len(want) {
		t.Fatalf("progress rows = %v, want at least %v", got, want)
	}
	for i, state := range want {
		if got[i] != state {
			t.Fatalf("state[%d] = %q, want %q; all=%v", i, got[i], state, got)
		}
	}
	for _, a := range items {
		if a.Kind == "progress" {
			t.Logf("activity endpoint: kind=%s summary=%q state=%s", a.Kind, a.Summary, a.Metadata.State)
		}
	}
}
