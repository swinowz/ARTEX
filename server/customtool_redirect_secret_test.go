package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCustomHTTPConfiguredHeadersStayOnOriginalOrigin(t *testing.T) {
	const header = "X-Custom-Secret"
	const secret = "private-token"
	var initial, sameOrigin, foreign, returned string
	var other *httptest.Server
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start":
			initial = r.Header.Get(header)
			http.Redirect(w, r, "/same", http.StatusFound)
		case "/same":
			sameOrigin = r.Header.Get(header)
			http.Redirect(w, r, other.URL+"/foreign", http.StatusFound)
		case "/back":
			returned = r.Header.Get(header)
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer origin.Close()
	other = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		foreign = r.Header.Get(header)
		http.Redirect(w, r, origin.URL+"/back", http.StatusFound)
	}))
	defer other.Close()

	spec, err := json.Marshal(httpExec{URL: origin.URL + "/start", Headers: map[string]string{header: secret}})
	if err != nil {
		t.Fatal(err)
	}
	result, err := (&Server{}).runHTTPTool(context.Background(), "probe", spec, nil, nil)
	if err != nil || result.IsError {
		t.Fatalf("HTTP tool: %+v, %v", result, err)
	}
	if initial != secret || sameOrigin != secret || foreign != "" || returned != "" {
		t.Fatalf("headers: initial=%q same=%q foreign=%q returned=%q", initial, sameOrigin, foreign, returned)
	}
}
