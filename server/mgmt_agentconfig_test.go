package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestAgentConfigGetSymmetric covers GET /api/agents/{key}/config: it must exist
// (the PUT had no read counterpart, so GET returned 405) and must expose the
// same flat config fields the PUT accepts, including the Overseer cadence, with
// a PUT round-trip reflected by the following GET.
func TestAgentConfigGetSymmetric(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		db.SkipPGUnavailable(t, err)
	}
	if m.pg == nil {
		db.SkipNoPG(t)
	}
	defer m.Close()
	td := t.TempDir()
	ctx, cancel := context.WithCancel(context.Background())
	s := New(ctx, m, td, td, td)
	defer stopTestServer(t, s, cancel)
	h := s.Handler()
	tok, err := signJWT(s.jwtKey)
	if err != nil {
		t.Fatalf("sign jwt: %v", err)
	}

	do := func(method, path string, body any) (int, map[string]any) {
		var r *http.Request
		if body != nil {
			b, _ := json.Marshal(body)
			r = httptest.NewRequest(method, path, bytes.NewReader(b))
		} else {
			r = httptest.NewRequest(method, path, nil)
		}
		r.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		var out map[string]any
		json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	// GET without a prior PUT: the route exists and returns the stored config
	// (previously this was a 405 because only PUT was registered).
	code, out := do("GET", "/api/agents/overseer/config", nil)
	if code != 200 {
		t.Fatalf("GET overseer config: got %d (%v), want 200", code, out)
	}
	for _, f := range []string{
		"enabled", "llm_profile_id", "max_turns", "run_seconds",
		"overseer_cadence_mode", "overseer_interval_seconds", "overseer_interval_rounds",
	} {
		if _, ok := out[f]; !ok {
			t.Fatalf("GET overseer config missing %q: %v", f, out)
		}
	}
	if mode, _ := out["overseer_cadence_mode"].(string); mode != "seconds" && mode != "rounds" {
		t.Fatalf("overseer_cadence_mode = %v, want seconds or rounds", out["overseer_cadence_mode"])
	}

	// Round-trip: PUT new values, then GET must reflect them.
	code, _ = do("PUT", "/api/agents/overseer/config", map[string]any{
		"overseer_cadence_mode":     "rounds",
		"overseer_interval_seconds": 37,
		"overseer_interval_rounds":  6,
		"max_turns":                 9,
	})
	if code != 200 {
		t.Fatalf("PUT overseer config: %d", code)
	}
	code, out = do("GET", "/api/agents/overseer/config", nil)
	if code != 200 {
		t.Fatalf("GET after PUT: %d (%v)", code, out)
	}
	if out["overseer_cadence_mode"] != "rounds" ||
		out["overseer_interval_seconds"] != float64(37) ||
		out["overseer_interval_rounds"] != float64(6) ||
		out["max_turns"] != float64(9) {
		t.Fatalf("GET did not reflect the PUT: %v", out)
	}

	// Unknown key keeps the handlers' 404 style.
	code, _ = do("GET", "/api/agents/no-such-agent/config", nil)
	if code != 404 {
		t.Fatalf("unknown agent key should be 404, got %d", code)
	}
}
