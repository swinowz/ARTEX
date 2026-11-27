package agent

import (
	"context"
	"encoding/json"
	actool "github.com/Autumn-27/norma/tool"
	"testing"
	"time"
)

type commandProbe struct {
	called       bool
	id           int64
	dir, command string
	timeout      time.Duration
}

func (p *commandProbe) Execute(_ context.Context, id int64, dir, cmd string, timeout time.Duration, env []string) ([]byte, error) {
	p.called = true
	p.id = id
	p.dir = dir
	p.command = cmd
	p.timeout = timeout
	return []byte("sandbox proof"), nil
}
func TestSandboxBashRoutesOriginalCommand(t *testing.T) {
	probe := &commandProbe{}
	tool := &sandboxBash{CoreTool: actool.NewBash(), backend: probe, taskID: 42}
	result, err := tool.Call(context.Background(), json.RawMessage(`{"command":"printf '%s' '$(id)'","timeout_ms":9999999}`), &actool.ToolContext{WorkingDir: "/task/i1"})
	if err != nil || result.IsError || result.Flatten() != "sandbox proof" || probe.id != 42 || probe.command != "printf '%s' '$(id)'" || probe.dir != "/task/i1" || probe.timeout != 600*time.Second {
		t.Fatalf("bad dispatch: %+v %+v %v", probe, result, err)
	}
	probe.called = false
	result, _ = tool.Call(context.Background(), json.RawMessage(`{"command":"true","run_in_background":true}`), &actool.ToolContext{WorkingDir: "/task/i1"})
	if probe.called || !result.IsError {
		t.Fatal("unsupported background silently dispatched")
	}
}
func TestSandboxPreservesNonBashTools(t *testing.T) {
	tools := append(defaultTools("."), actool.ShellSessionTools()...)
	result := sandboxWorkerTools(tools, &commandProbe{}, 42)
	bash := 0
	seen := map[string]bool{}
	for _, tool := range result {
		seen[tool.Name()] = true
		switch tool.Name() {
		case "Bash":
			bash++
			if _, ok := tool.(*sandboxBash); !ok {
				t.Fatal("host Bash retained")
			}
		}
	}
	if bash != 1 {
		t.Fatal("missing Bash")
	}
	for _, tool := range tools {
		if !seen[tool.Name()] {
			t.Fatalf("non-Bash tool removed: %s", tool.Name())
		}
	}
}

func TestSandboxAssemblyPreservesMCPAugmentation(t *testing.T) {
	called := false
	SetToolAugment(func(context.Context, string) ([]actool.CoreTool, DeferredInfo, func()) {
		called = true
		return []actool.CoreTool{actool.Build(actool.Spec{Name: "mcp__remote__query", Description: "query", Schema: map[string]any{"type": "object"}, Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			return actool.Text("ok"), nil
		}})}, DeferredInfo{Deferred: []string{"mcp__remote__query"}}, nil
	})
	defer SetToolAugment(nil)
	tools, def, cleanup := assembleWorkerTools(context.Background(), []actool.CoreTool{actool.NewBash()}, nil, &commandProbe{}, 42)
	defer cleanup()
	if !called || len(def.Deferred) != 1 || def.Deferred[0] != "mcp__remote__query" {
		t.Fatalf("MCP augmentation lost: called=%v deferred=%v", called, def.Deferred)
	}
	foundMCP := false
	for _, tool := range tools {
		if tool.Name() == "mcp__remote__query" {
			foundMCP = true
		}
	}
	if !foundMCP {
		t.Fatal("MCP tool removed from sandbox agent")
	}
	foundBash := false
	for _, tool := range tools {
		if tool.Name() == "Bash" {
			_, foundBash = tool.(*sandboxBash)
		}
	}
	if !foundBash {
		t.Fatal("container Bash missing")
	}
}
func TestPlannerSandboxPreservesMCPAugmentation(t *testing.T) {
	called := false
	SetToolAugment(func(context.Context, string) ([]actool.CoreTool, DeferredInfo, func()) {
		called = true
		return nil, DeferredInfo{Deferred: []string{"mcp__remote__query"}}, nil
	})
	defer SetToolAugment(nil)
	_, def, cleanup := assembleTaskTools(context.Background(), "planner", []actool.CoreTool{actool.NewBash()}, &commandProbe{}, 42)
	defer cleanup()
	if !called || len(def.Deferred) != 1 {
		t.Fatalf("planner MCP augmentation lost: called=%v deferred=%v", called, def.Deferred)
	}
}
