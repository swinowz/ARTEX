package server

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/sandbox"
	actool "github.com/Autumn-27/norma/tool"
)

func TestCustomCommandUsesTaskSandbox(t *testing.T) {
	base := t.TempDir()
	work := filepath.Join(base, "tasks", "42", "intent")
	if err := os.MkdirAll(work, 0o750); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	d, err := sandbox.NewDocker(sandbox.Config{Image: "sha256:" + strings.Repeat("a", 64), Network: "none", UID: 10001, GID: 10001}, func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if args[0] == "exec" {
			return []byte("container-result"), nil
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := sandbox.NewService(d, base)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{commandSandbox: svc}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 42, TaskSandbox: true})
	res, err := s.runCommandTool(ctx, "probe", json.RawMessage(`{"command":"printf '%s' {target}"}`), map[string]any{"target": "safe"}, &actool.ToolContext{WorkingDir: work})
	if err != nil || res.IsError || !strings.Contains(res.Flatten(), "container-result") {
		t.Fatalf("command result: %+v, %v", res, err)
	}
	found := false
	for _, call := range calls {
		if len(call) > 0 && call[0] == "exec" && strings.Contains(strings.Join(call, " "), "printf '%s' 'safe'") {
			found = true
		}
	}
	if !found {
		t.Fatalf("rendered command never reached the task container: %v", calls)
	}
}

func TestCustomScriptUsesTaskSandbox(t *testing.T) {
	base := t.TempDir()
	work := filepath.Join(base, "tasks", "43", "intent")
	if err := os.MkdirAll(work, 0o750); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	d, err := sandbox.NewDocker(sandbox.Config{Image: "sha256:" + strings.Repeat("a", 64), Network: "none", UID: 10001, GID: 10001}, func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if args[0] == "exec" {
			return []byte("script-container-result"), nil
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := sandbox.NewService(d, base)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{commandSandbox: svc}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 43, TaskSandbox: true})
	res, err := s.runScriptTool(ctx, "probe", json.RawMessage(`{"code":"print('sandbox-script-marker')"}`), map[string]any{"target": "safe"}, &actool.ToolContext{WorkingDir: work})
	if err != nil || res.IsError || !strings.Contains(res.Flatten(), "script-container-result") {
		t.Fatalf("script result: %+v, %v", res, err)
	}
	if _, err := os.Stat(filepath.Join(work, ".tools")); !os.IsNotExist(err) {
		t.Fatalf("host script file created in task directory: %v", err)
	}
	found := false
	for _, call := range calls {
		if len(call) > 0 && call[0] == "exec" && strings.Contains(strings.Join(call, " "), "python3") {
			found = true
		}
	}
	if !found {
		t.Fatalf("Python never reached the task container: %v", calls)
	}
}

func TestSandboxPythonCommandPreservesScriptInputs(t *testing.T) {
	command, err := sandboxPythonCommand(`import json,os,sys
print(json.load(sys.stdin)["target"])
print(os.environ["TOOL_TARGET"])`, map[string]any{"target": "a'b"})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("bash", "-c", command)
	cmd.Env = append(os.Environ(), "TOOL_TARGET=a'b")
	out, err := cmd.CombinedOutput()
	if err != nil || string(out) != "a'b\na'b\n" {
		t.Fatalf("script wrapper output %q, error %v", out, err)
	}
}

func TestPostCompletionCustomCommandRequiresSessionSandboxIdentity(t *testing.T) {
	base := t.TempDir()
	d, err := sandbox.NewDocker(sandbox.Config{Image: "sha256:" + strings.Repeat("a", 64), Network: "none", UID: 10001, GID: 10001}, func(context.Context, ...string) ([]byte, error) {
		t.Fatal("retired task must not restart its container")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := sandbox.NewService(d, base)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{commandSandbox: svc}
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 42}) // main agent: no active task sandbox
	res, err := s.runCommandTool(ctx, "probe", json.RawMessage(`{"command":"printf 'post-completion'"}`), nil, &actool.ToolContext{WorkingDir: t.TempDir()})
	if err != nil || !res.IsError || !strings.Contains(res.Flatten(), "sandbox run identity is unavailable") {
		t.Fatalf("custom command fell back to host without a session sandbox: %+v, %v", res, err)
	}
}

func TestSessionCustomToolsUseSessionContainer(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "sessions", "conv-1")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	d, err := sandbox.NewDocker(sandbox.Config{Image: "sha256:" + strings.Repeat("a", 64), Network: "none", UID: 10001, GID: 10001}, func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if args[0] == "exec" {
			return []byte("session-container-result"), nil
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := sandbox.NewService(d, base)
	if err != nil {
		t.Fatal(err)
	}
	const key = "0123456789abcdef0123456789abcdef"
	ctx := agent.WithRunInfo(context.Background(), agent.RunInfo{SessionSandbox: true, SessionSandboxKey: key, SessionSandboxRoot: root})
	s := &Server{commandSandbox: svc}
	tc := &actool.ToolContext{WorkingDir: root}
	command, err := s.runCommandTool(ctx, "probe", json.RawMessage(`{"command":"printf host"}`), nil, tc)
	if err != nil || command.IsError || !strings.Contains(command.Flatten(), "session-container-result") {
		t.Fatalf("session custom command: %+v, %v", command, err)
	}
	script, err := s.runScriptTool(ctx, "probe", json.RawMessage(`{"code":"print('host')"}`), nil, tc)
	if err != nil || script.IsError || !strings.Contains(script.Flatten(), "session-container-result") {
		t.Fatalf("session custom script: %+v, %v", script, err)
	}
	if len(calls) != 4 || calls[0][0] != "create" || calls[1][0] != "start" || calls[2][0] != "exec" || calls[3][0] != "exec" {
		t.Fatalf("unexpected session calls: %v", calls)
	}
}
