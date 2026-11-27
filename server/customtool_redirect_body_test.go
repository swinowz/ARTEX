package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCustomHTTPBodyNotReplayedAcrossOrigins(t *testing.T) {
	var foreignHits atomic.Int64
	foreign := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreignHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer foreign.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, foreign.URL+"/receive", http.StatusTemporaryRedirect)
	}))
	defer origin.Close()
	spec, err := json.Marshal(httpExec{Method: "POST", URL: origin.URL + "/start", Body: "stored-secret"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := (&Server{}).runHTTPTool(context.Background(), "probe", spec, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError || !strings.Contains(result.Flatten(), "cross-origin") || foreignHits.Load() != 0 {
		t.Fatalf("result=%+v, foreign hits=%d", result, foreignHits.Load())
	}
}
