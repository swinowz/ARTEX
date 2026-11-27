package agent

import (
	"context"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

type sessionSandboxProbe struct {
	key, root, dir, command string
	removed                 string
	removeErr               error
	calls                   int
}

func (p *sessionSandboxProbe) ExecuteSession(_ context.Context, key, root, dir, command string, _ time.Duration, _ []string) ([]byte, error) {
	p.key, p.root, p.dir, p.command = key, root, dir, command
	p.calls++
	return []byte("sandbox output"), nil
}
func (p *sessionSandboxProbe) RemoveSession(_ context.Context, key string) error {
	p.removed = key
	return p.removeErr
}

func TestChatSessionSandboxRoutesBashAndRemovesTurn(t *testing.T) {
	workDir := t.TempDir()
	probe := &sessionSandboxProbe{}
	chat := NewChatAgent(toolCallThenStop("Bash", `{"command":"printf isolated"}`), "test-model", workDir, nil, 0)
	chat.SetSessionSandbox(probe)
	if _, err := chat.Chat(t.Context(), "assistant", "conv-isolated", "run", 3, 0, false, nil); err != nil {
		t.Fatal(err)
	}
	wantRoot := filepath.Join(workDir, "sessions", "conv-isolated")
	if probe.calls != 1 || probe.root != wantRoot || probe.dir != wantRoot || probe.command != "printf isolated" {
		t.Fatalf("session command dispatch: %+v", probe)
	}
	if len(probe.key) != 32 || probe.removed != probe.key {
		t.Fatalf("session container lifecycle: %+v", probe)
	}
}

func TestMainAgentSessionSandboxRoutesBashAfterTaskContainer(t *testing.T) {
	f := newHookReachFixture(t)
	probe := &sessionSandboxProbe{}
	main := NewMainAgent(toolCallThenStop("Bash", `{"command":"printf main"}`), "test-model", f.workDir, nil, 0, 3)
	main.SetSessionSandbox(probe)
	if _, err := main.Chat(t.Context(), f.expID, 0, nil, f.ts, "goal", "run", passHooks{}, nil, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	wantRoot := filepath.Join(f.workDir, "tasks", f.taskID, "main")
	if probe.calls != 1 || probe.root != wantRoot || probe.dir != wantRoot || probe.command != "printf main" || probe.removed != probe.key {
		t.Fatalf("main sandbox dispatch: %+v", probe)
	}
}

func TestSessionSandboxAugmentationKeepsMCPAndAttribution(t *testing.T) {
	probe := &sessionSandboxProbe{}
	root := t.TempDir()
	ctx := WithRunInfo(t.Context(), RunInfo{TaskID: 42, SessionID: "conv-42"})
	var err error
	var key string
	ctx, key, err = startSessionSandbox(ctx, probe, root)
	if err != nil {
		t.Fatal(err)
	}
	info := RunInfoFrom(ctx)
	if !info.SessionSandbox || info.SessionSandboxKey != key || info.SessionSandboxRoot != root || info.TaskID != 42 || info.SessionID != "conv-42" {
		t.Fatalf("lost run attribution: %+v", info)
	}
	SetToolAugment(func(received context.Context, _ string) ([]actool.CoreTool, DeferredInfo, func()) {
		if got := RunInfoFrom(received); got.SessionSandboxKey != key {
			t.Fatalf("augment received wrong context: %+v", got)
		}
		mcp := actool.Build(actool.Spec{Name: "mcp__probe__query", Description: "query", Schema: map[string]any{"type": "object"}, Run: func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
			return actool.Text("ok"), nil
		}})
		return []actool.CoreTool{mcp}, DeferredInfo{Deferred: []string{"mcp__probe__query"}}, nil
	})
	defer SetToolAugment(nil)
	tools, def, cleanup := AugmentTools(ctx, "assistant", []actool.CoreTool{actool.NewBash()})
	defer cleanup()
	tools = sessionSandboxTools(tools, probe, key, root)
	if len(def.Deferred) != 1 || def.Deferred[0] != "mcp__probe__query" {
		t.Fatalf("MCP deferred metadata lost: %+v", def)
	}
	var bash, mcp bool
	for _, tool := range tools {
		switch tool.Name() {
		case "Bash":
			_, bash = tool.(*sandboxBash)
		case "mcp__probe__query":
			mcp = true
		}
	}
	if !bash || !mcp {
		t.Fatalf("tools lost: Bash=%v MCP=%v", bash, mcp)
	}
}
