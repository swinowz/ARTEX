package server

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Autumn-27/artex/intercept"
)

// The client controls the proxy connection and requested URL, but cannot
// observe or constrain the peer that a separate forward proxy dials.
func TestCustomHTTPProxySelectsPeerOutsideClientPin(t *testing.T) {
	var peerHits atomic.Int64
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peerHits.Add(1)
		_, _ = w.Write([]byte("unapproved-peer"))
	}))
	defer peer.Close()
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// A proxy can ignore the absolute-form URL and choose another peer.
		resp, err := http.Get(peer.URL + r.URL.Path)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		_, _ = fmt.Fprint(w, "proxy response")
	}))
	defer proxy.Close()

	ctx := intercept.WithTargetScope(context.Background(), intercept.TargetScope{
		TaskID: "test", Enabled: func() bool { return true },
	})
	spec := httpExec{Proxy: proxy.URL}
	tr := (&Server{}).httpToolTransport(ctx, "probe", spec)
	if tr == nil || tr.DialContext != nil {
		t.Fatalf("proxy transport: %+v", tr)
	}
	req, err := http.NewRequestWithContext(ctx, "GET", "http://approved.example.invalid/probe", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || peerHits.Load() != 1 {
		t.Fatalf("status %d, unapproved peer hits %d", resp.StatusCode, peerHits.Load())
	}
}
