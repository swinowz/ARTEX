package server

// End-to-end contract test for MCP capability servers (issue #13).
//
// It proves the complete operator path with a real worker and a real model
// script, for both Streamable HTTP and stdio:
//
//	POST /api/mcp
//	  -> discovery lists the tools and caches them for the UI
//	  -> the worker agent's assembled tool set contains mcp__<server>__<tool>
//	  -> the model discovers it with SearchExtraTools then calls it through
//	     ExecuteExtraTool and receives the server's text
//	  -> the same text is persisted through the native record_fact and
//	     report_finding tools, so a capability server needs no core changes.
//
// The model is a deterministic script; its decision quality is out of scope.
// What is pinned here is the contract every capability issue (#15–#27) relies
// on, including the deferred-tools path (MCP schemas are withheld by design).

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
)

const mcpContractOutput = "host=10.0.0.5 port=445 state=open service=microsoft-ds"

// registerMCPContractServer adds a server through the real authenticated API
// and removes it afterwards. Discovery runs inside the request when the server
// is new and enabled.
func registerMCPContractServer(t *testing.T, g *gateServer, body map[string]any) int64 {
	t.Helper()
	raw, _ := json.Marshal(body)
	code, out := g.do(t, "POST", "/api/mcp", string(raw))
	if code != 200 {
		t.Fatalf("POST /api/mcp: %d %v", code, out)
	}
	id, _ := out["id"].(float64)
	if id == 0 {
		t.Fatalf("POST /api/mcp returned no id: %v", out)
	}
	t.Cleanup(func() { _ = g.m.pg.DeleteMCP(int64(id)) })
	return int64(id)
}

func assertMCPDiscovery(t *testing.T, g *gateServer, id int64, full string) {
	t.Helper()
	code, out := g.do(t, "GET", fmt.Sprintf("/api/mcp/%d/tools", id), "")
	if code != 200 {
		t.Fatalf("GET mcp tools: %d %v", code, out)
	}
	tools, _ := out["tools"].([]any)
	for _, item := range tools {
		m, _ := item.(map[string]any)
		if m["name"] == full {
			return
		}
	}
	t.Fatalf("%s missing from the cached tool list: %v", full, out)
}

// grantMCPVisibility makes the server visible to the worker for this test and
// restores the previous visibility set afterwards (the test database is shared).
func grantMCPVisibility(t *testing.T, g *gateServer, mcpID int64) {
	t.Helper()
	worker, err := g.m.pg.GetAgentByKey("worker")
	if err != nil || worker == nil {
		t.Fatalf("worker agent: %v", err)
	}
	orig, err := g.m.pg.AgentVisible(worker.ID, "mcp")
	if err != nil {
		t.Fatal(err)
	}
	want := append(append([]int64{}, orig...), mcpID)
	if err := g.m.pg.SetAgentVisibilityKind(worker.ID, "mcp", want); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = g.m.pg.SetAgentVisibilityKind(worker.ID, "mcp", orig) })
}

// runMCPContractWorker drives a real worker through the deferred MCP path and
// then through the native writers. It returns once the worker run ends.
func runMCPContractWorker(t *testing.T, g *gateServer, full string) {
	t.Helper()
	task := g.newTask(t, db.TaskCreateOptions{})
	callMCP := fmt.Sprintf(`{"tool_name":%q,"params":{"target":"10.0.0.5"}}`, full)
	factInput, _ := json.Marshal(map[string]any{"facts": []map[string]any{{
		"summary":    "MCP contract scan result",
		"detail":     mcpContractOutput,
		"evidence":   mcpContractOutput,
		"confidence": "observed",
		"source":     "tool_output",
	}}})
	findingInput, _ := json.Marshal(map[string]any{
		"vulnclass": "MCP_CONTRACT",
		"name":      "MCP contract finding",
		"severity":  "low",
		"summary":   "finding persisted from an MCP tool result",
		"evidence":  mcpContractOutput,
	})
	p := &toolScript{
		calls: []scriptedCall{
			{"SearchExtraTools", fmt.Sprintf(`{"query":"select:%s"}`, full)},
			{"ExecuteExtraTool", callMCP},
			{"record_fact", string(factInput)},
			{"report_finding", string(findingInput)},
		},
		results: make(chan string, 8),
		hold:    map[int64]chan struct{}{},
	}
	done := runScriptedWorker(t, g, task, p)

	// Turn 2's result is the schema discovery; turn 3's is the MCP call itself.
	if r := p.next(t); !strings.Contains(r, full) || !strings.Contains(r, "params schema") {
		t.Fatalf("SearchExtraTools did not reveal the MCP schema: %q", r)
	}
	if r := p.next(t); !strings.Contains(r, mcpContractOutput) {
		t.Fatalf("the MCP tool result did not reach the model: %q", r)
	}
	// Tool results reach the model inside the untrusted-output envelope, so the
	// native writers are recognised by their payload, not by a bare prefix.
	if r := p.next(t); strings.Contains(r, "[error]") || !strings.Contains(r, `"ids":[`) {
		t.Fatalf("record_fact did not persist the MCP output: %q", r)
	}
	if r := p.next(t); strings.Contains(r, "[error]") || !strings.Contains(r, "finding recorded: ") {
		t.Fatalf("report_finding did not persist the MCP evidence: %q", r)
	}
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("the worker run did not end")
	}
}

func TestMCPContractEndToEnd(t *testing.T) {
	t.Run("streamable-http", func(t *testing.T) {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var req struct {
				ID     int    `json:"id"`
				Method string `json:"method"`
			}
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				http.Error(w, "bad json", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			reply := func(result any) {
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": result})
			}
			switch req.Method {
			case "initialize":
				reply(map[string]any{
					"protocolVersion": "2025-11-25",
					"capabilities":    map[string]any{"tools": map[string]any{}},
					"serverInfo":      map[string]any{"name": "contract_http", "version": "0"},
				})
			case "notifications/initialized":
				w.WriteHeader(http.StatusAccepted)
			case "tools/list":
				reply(map[string]any{"tools": []map[string]any{{
					"name":        "scan_host",
					"description": "fixed scan for the contract test",
					"inputSchema": map[string]any{
						"type":       "object",
						"properties": map[string]any{"target": map[string]any{"type": "string"}},
						"required":   []string{"target"},
					},
				}}})
			case "tools/call":
				calls.Add(1)
				reply(map[string]any{"content": []map[string]any{{"type": "text", "text": mcpContractOutput}}})
			default:
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"jsonrpc":"2.0","error":{"code":-32601,"message":"unknown method"}}`))
			}
		}))
		t.Cleanup(srv.Close)

		g := newGateServer(t)
		const full = "mcp__contract_http__scan_host"
		id := registerMCPContractServer(t, g, map[string]any{
			"name": "contract_http", "transport": "http", "url": srv.URL, "enabled": true,
		})
		assertMCPDiscovery(t, g, id, full)
		grantMCPVisibility(t, g, id)
		runMCPContractWorker(t, g, full)
		if calls.Load() == 0 {
			t.Fatal("the MCP server never received a tools/call")
		}
	})

	t.Run("stdio", func(t *testing.T) {
		if _, err := exec.LookPath("python3"); err != nil {
			t.Skip("python3 is required for the stdio MCP fixture")
		}
		dir := t.TempDir()
		script := filepath.Join(dir, "mcp_fixture.py")
		if err := os.WriteFile(script, []byte(stdioFixture), 0o600); err != nil {
			t.Fatal(err)
		}

		g := newGateServer(t)
		const full = "mcp__contract_stdio__scan_host"
		id := registerMCPContractServer(t, g, map[string]any{
			"name": "contract_stdio", "transport": "stdio",
			"command": "python3", "args": []string{script}, "enabled": true,
		})
		assertMCPDiscovery(t, g, id, full)
		grantMCPVisibility(t, g, id)
		runMCPContractWorker(t, g, full)
	})
}

// stdioFixture is a minimal MCP server over stdio: line-delimited JSON-RPC,
// initialize + tools/list + tools/call. It is dependency-free so the contract
// test runs anywhere python3 exists.
const stdioFixture = `import json
import sys

def send(obj):
    sys.stdout.write(json.dumps(obj) + "\n")
    sys.stdout.flush()

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        req = json.loads(line)
    except Exception:
        continue
    method = req.get("method")
    rid = req.get("id")
    if method == "initialize":
        send({"jsonrpc": "2.0", "id": rid, "result": {
            "protocolVersion": "2025-11-25",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "contract_stdio", "version": "0"}}})
    elif method == "notifications/initialized":
        pass
    elif method == "tools/list":
        send({"jsonrpc": "2.0", "id": rid, "result": {"tools": [{
            "name": "scan_host",
            "description": "fixed scan for the contract test",
            "inputSchema": {"type": "object",
                            "properties": {"target": {"type": "string"}},
                            "required": ["target"]}}]}})
    elif method == "tools/call":
        args = (req.get("params") or {}).get("arguments") or {}
        text = "host=%s port=445 state=open service=microsoft-ds" % args.get("target", "?")
        send({"jsonrpc": "2.0", "id": rid, "result": {"content": [{"type": "text", "text": text}]}})
    elif rid is not None:
        send({"jsonrpc": "2.0", "id": rid, "error": {"code": -32601, "message": "unknown method"}})
`
