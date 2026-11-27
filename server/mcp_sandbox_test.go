package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/sandbox"
	actool "github.com/Autumn-27/norma/tool"
)

func TestConfiguredSandboxMCPStdioRequiresRunIdentity(t *testing.T) {
	d, err := sandbox.NewDocker(sandbox.Config{Image: "sha256:" + strings.Repeat("a", 64), Network: "none", UID: 10001, GID: 10001}, func(context.Context, ...string) ([]byte, error) {
		t.Fatal("MCP server must not start without a sandbox run identity")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := sandbox.NewService(d, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	client, err := connectMCPForRun(t.Context(), &db.MCPServer{Name: "fixture", Transport: "stdio", Command: "unavailable-on-host"}, ExecPrivilege{}, svc)
	if err == nil || client != nil || !strings.Contains(err.Error(), "sandbox run identity is unavailable") {
		t.Fatalf("MCP stdio fell back to host: client=%v err=%v", client, err)
	}
}

func TestTaskMCPStdioKeepsToolCallable(t *testing.T) {
	bin := t.TempDir()
	argsFile := filepath.Join(bin, "args")
	serverScript := `import json,sys
for line in sys.stdin:
 req=json.loads(line)
 if 'id' not in req: continue
 method=req['method']
 if method=='initialize': result={'protocolVersion':'2024-11-05','capabilities':{},'serverInfo':{'name':'fixture','version':'1'}}
 elif method=='tools/list': result={'tools':[{'name':'probe','description':'probe','inputSchema':{'type':'object'}}]}
 elif method=='tools/call': result={'content':[{'type':'text','text':'mcp-container-proof'}]}
 else: result={}
 print(json.dumps({'jsonrpc':'2.0','id':req['id'],'result':result}),flush=True)
`
	shim := "#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FAKE_DOCKER_ARGS\"\nexec python3 -u -c " + shellQuote(serverScript) + "\n"
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(shim), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_DOCKER_ARGS", argsFile)
	base := t.TempDir()
	d, err := sandbox.NewDocker(sandbox.Config{Image: "sha256:" + strings.Repeat("a", 64), Network: "none", UID: 10001, GID: 10001}, func(context.Context, ...string) ([]byte, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	svc, err := sandbox.NewService(d, base)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 42, TaskSandbox: true}), 5*time.Second)
	defer cancel()
	client, err := connectMCPForRun(ctx, &db.MCPServer{Name: "fixture", Transport: "stdio", Command: "unavailable-on-host", Env: json.RawMessage(`{"MCP_SANDBOX_TOKEN":"configured"}`)}, ExecPrivilege{}, svc)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	tools, err := client.Tools(ctx)
	if err != nil || len(tools) != 1 || tools[0].Name() != "mcp__fixture__probe" {
		t.Fatalf("MCP tools: %v, %v", tools, err)
	}
	result, err := tools[0].Call(ctx, json.RawMessage(`{}`), &actool.ToolContext{WorkingDir: filepath.Join(base, "tasks", "42")})
	if err != nil || result.IsError || !strings.Contains(result.Flatten(), "mcp-container-proof") {
		t.Fatalf("MCP call: %+v, %v", result, err)
	}
	args, err := os.ReadFile(argsFile)
	if err != nil || !strings.Contains(string(args), "--env\nMCP_SANDBOX_TOKEN=configured\n") || !strings.Contains(string(args), "artex-task-42\nunavailable-on-host") {
		t.Fatalf("Docker stdio args %q, %v", args, err)
	}
	sessionRoot := filepath.Join(base, "sessions", "conv-1")
	if err := os.MkdirAll(sessionRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	const key = "0123456789abcdef0123456789abcdef"
	sessionCtx := agent.WithRunInfo(ctx, agent.RunInfo{SessionSandbox: true, SessionSandboxKey: key, SessionSandboxRoot: sessionRoot})
	sessionClient, err := connectMCPForRun(sessionCtx, &db.MCPServer{Name: "fixture", Transport: "stdio", Command: "unavailable-on-host"}, ExecPrivilege{}, svc)
	if err != nil {
		t.Fatal(err)
	}
	defer sessionClient.Close()
	sessionTools, err := sessionClient.Tools(sessionCtx)
	if err != nil || len(sessionTools) != 1 {
		t.Fatalf("session MCP tools: %v, %v", sessionTools, err)
	}
	sessionResult, err := sessionTools[0].Call(sessionCtx, json.RawMessage(`{}`), &actool.ToolContext{WorkingDir: sessionRoot})
	if err != nil || sessionResult.IsError || !strings.Contains(sessionResult.Flatten(), "mcp-container-proof") {
		t.Fatalf("session MCP call: %+v, %v", sessionResult, err)
	}
	args, err = os.ReadFile(argsFile)
	if err != nil || !strings.Contains(string(args), "artex-session-"+key+"\nunavailable-on-host") {
		t.Fatalf("session Docker stdio args %q, %v", args, err)
	}
	if err := svc.RemoveSession(context.Background(), key); err != nil {
		t.Fatal(err)
	}
}

func TestTaskMCPAndSkillDockerIntegration(t *testing.T) {
	image := os.Getenv("ARTEX_SANDBOX_TEST_IMAGE")
	if image == "" {
		t.Skip("set ARTEX_SANDBOX_TEST_IMAGE to a pinned local image with Python")
	}
	root := t.TempDir()
	skills := filepath.Join(root, "skills")
	if err := os.MkdirAll(skills, 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "server-secret")
	if err := os.WriteFile(secret, []byte("must-stay-outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	mcpScript := filepath.Join(skills, "proof.py")
	script := `import json,os,sys
for line in sys.stdin:
 req=json.loads(line)
 if 'id' not in req: continue
 method=req['method']
 if method=='initialize': result={'protocolVersion':'2024-11-05','capabilities':{},'serverInfo':{'name':'proof','version':'1'}}
 elif method=='tools/list': result={'tools':[{'name':'probe','description':'proof','inputSchema':{'type':'object'}}]}
 elif method=='tools/call':
  try:
   open(__file__,'a').write('unsafe')
   readonly='false'
  except OSError: readonly='true'
  result={'content':[{'type':'text','text':'skill=visible secret='+str(os.path.exists(` + jsonString(secret) + `)).lower()+' readonly='+readonly}]}
 else: result={}
 print(json.dumps({'jsonrpc':'2.0','id':req['id'],'result':result}),flush=True)
`
	if err := os.WriteFile(mcpScript, []byte(script), 0o644); err != nil {
		t.Fatal(err)
	}
	data := filepath.Join(root, "data")
	work := filepath.Join(data, "tasks", "990034", "intent")
	if err := os.MkdirAll(work, 0o750); err != nil {
		t.Fatal(err)
	}
	d, err := sandbox.NewDocker(sandbox.Config{Image: image, Network: "none", UID: 0, GID: 0, Rootless: true, SkillDir: skills}, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := sandbox.NewService(d, data)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := svc.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	ctx, cancel := context.WithTimeout(agent.WithRunInfo(context.Background(), agent.RunInfo{TaskID: 990034, TaskSandbox: true}), 30*time.Second)
	defer cancel()
	args, _ := json.Marshal([]string{"-u", mcpScript})
	client, err := connectMCPForRun(ctx, &db.MCPServer{Name: "proof", Transport: "stdio", Command: "python3", Args: args}, ExecPrivilege{}, svc)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	tools, err := client.Tools(ctx)
	if err != nil || len(tools) != 1 {
		t.Fatalf("tools/list: %v, %v", tools, err)
	}
	result, err := tools[0].Call(ctx, json.RawMessage(`{}`), &actool.ToolContext{WorkingDir: work})
	if err != nil || result.IsError || !strings.Contains(result.Flatten(), "skill=visible secret=false readonly=true") {
		t.Fatalf("MCP proof: %+v, %v", result, err)
	}
	s := &Server{commandSandbox: svc}
	res, err := s.runScriptTool(ctx, "probe", json.RawMessage(`{"code":"import json,sys; print('script='+json.load(sys.stdin)['target'])"}`), map[string]any{"target": "container"}, &actool.ToolContext{WorkingDir: work})
	if err != nil || res.IsError || !strings.Contains(res.Flatten(), "script=container") {
		t.Fatalf("custom script proof: %+v, %v", res, err)
	}
	res, err = s.runCommandTool(ctx, "probe", json.RawMessage(`{"command":"printf 'command=container'"}`), nil, &actool.ToolContext{WorkingDir: work})
	if err != nil || res.IsError || !strings.Contains(res.Flatten(), "command=container") {
		t.Fatalf("custom command proof: %+v, %v", res, err)
	}
	sessionRoot := filepath.Join(data, "sessions", "conv-isolated")
	if err := os.MkdirAll(sessionRoot, 0o750); err != nil {
		t.Fatal(err)
	}
	const sessionKey = "0123456789abcdef0123456789abcdef"
	sessionCtx := agent.WithRunInfo(ctx, agent.RunInfo{SessionSandbox: true, SessionSandboxKey: sessionKey, SessionSandboxRoot: sessionRoot})
	sessionMCP, err := connectMCPForRun(sessionCtx, &db.MCPServer{Name: "proof", Transport: "stdio", Command: "python3", Args: args}, ExecPrivilege{}, svc)
	if err != nil {
		t.Fatal(err)
	}
	sessionTools, err := sessionMCP.Tools(sessionCtx)
	if err != nil || len(sessionTools) != 1 {
		t.Fatalf("session MCP tools/list: %v, %v", sessionTools, err)
	}
	sessionProof, err := sessionTools[0].Call(sessionCtx, json.RawMessage(`{}`), &actool.ToolContext{WorkingDir: sessionRoot})
	if err != nil || sessionProof.IsError || !strings.Contains(sessionProof.Flatten(), "skill=visible secret=false readonly=true") {
		t.Fatalf("session MCP proof: %+v, %v", sessionProof, err)
	}
	_ = sessionMCP.Close()
	sessionScript, err := s.runScriptTool(sessionCtx, "probe", json.RawMessage(`{"code":"print('session-script=container')"}`), nil, &actool.ToolContext{WorkingDir: sessionRoot})
	if err != nil || sessionScript.IsError || !strings.Contains(sessionScript.Flatten(), "session-script=container") {
		t.Fatalf("session script proof: %+v, %v", sessionScript, err)
	}
	if err := svc.RemoveSession(context.Background(), sessionKey); err != nil {
		t.Fatal(err)
	}
}

func jsonString(value string) string {
	data, _ := json.Marshal(value)
	return string(data)
}
