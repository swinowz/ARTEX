package server

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/mcphttp"
	"github.com/Autumn-27/artex/mcps/adcore"
	"github.com/Autumn-27/artex/sandbox"
	"github.com/Autumn-27/norma/mcp"
	actool "github.com/Autumn-27/norma/tool"
)

// mcpClient is the shared surface of a connected MCP server (stdio, Streamable HTTP,
// or legacy SSE),
// so tools/list and cleanup are handled uniformly regardless of transport.
type mcpClient interface {
	Tools(context.Context) ([]actool.CoreTool, error)
	Close() error
}

// connectMCP dials one MCP server per its transport. Callers must Close the client.
func connectMCP(ctx context.Context, m *db.MCPServer, priv ExecPrivilege) (mcpClient, error) {
	return connectMCPEnv(ctx, m, priv, jsonStrMap(m.Env))
}

// connectMCPEnv is connectMCP with an already-built environment (agent runs add
// the task's credentials to it).
func connectMCPEnv(ctx context.Context, m *db.MCPServer, priv ExecPrivilege, env map[string]string) (mcpClient, error) {
	switch m.Transport {
	case "stdio":
		if m.Command == "" {
			return nil, fmt.Errorf("stdio transport is missing a command")
		}
		// The stdio command runs as the executor identity (see execpriv.go).
		command, args, err := execDropCommand(priv, m.Command, jsonStrSlice(m.Args))
		if err != nil {
			return nil, err
		}
		// The drop shim rebuilds the environment from the allowlist; the configured
		// variables of the server are named so it keeps them.
		return mcp.NewStdioClient(ctx, m.Name, command, withExecKeep(priv, env), args...)
	case "http":
		if m.URL == "" {
			return nil, fmt.Errorf("http transport is missing a URL")
		}
		// env map doubles as HTTP headers (e.g. Authorization).
		return mcphttp.New(ctx, m.Name, m.URL, env, m.Insecure, m.TimeoutSeconds)
	case "sse":
		if m.URL == "" {
			return nil, fmt.Errorf("sse transport is missing a URL")
		}
		return mcphttp.NewSSE(ctx, m.Name, m.URL, env, m.Insecure)
	default:
		return nil, fmt.Errorf("unknown transport %q", m.Transport)
	}
}

// Agent runs launch stdio MCP servers inside their task or session container.
// Administrative discovery uses connectMCP directly with the executor identity.
func connectMCPForRun(ctx context.Context, m *db.MCPServer, priv ExecPrivilege, taskSandbox *sandbox.Service, loadCreds func(int64) ([]db.TaskCredential, error)) (mcpClient, error) {
	info := agent.RunInfoFrom(ctx)
	env, err := withTaskCredentials(ctx, m, jsonStrMap(m.Env), loadCreds, info.TaskSandbox || info.SessionSandbox)
	if err != nil {
		return nil, err
	}
	if taskSandbox == nil || m.Transport != "stdio" {
		return connectMCPEnv(ctx, m, priv, env)
	}
	if info.SessionSandbox {
		command, args, err := taskSandbox.StdioCommandSession(ctx, info.SessionSandboxKey, info.SessionSandboxRoot, m.Command, jsonStrSlice(m.Args), env)
		if err != nil {
			return nil, err
		}
		return mcp.NewStdioClient(ctx, m.Name, command, nil, args...)
	}
	if !info.TaskSandbox || info.TaskID <= 0 {
		return nil, fmt.Errorf("MCP stdio sandbox run identity is unavailable")
	}
	command, args, err := taskSandbox.StdioCommand(ctx, info.TaskID, m.Command, jsonStrSlice(m.Args), env)
	if err != nil {
		return nil, err
	}
	return mcp.NewStdioClient(ctx, m.Name, command, nil, args...)
}

// withTaskCredentials adds this task's test accounts to a stdio server's
// environment when the operator flagged it in mcp_servers. The model only ever
// receives a ref: the accounts live in the child's environment (never in argv,
// never on disk) and the server holds them in memory for the run.
//
// Sandbox mode is refused: there the environment becomes docker exec argv, which
// any process on the host can read, and the sandbox images do not ship the AD
// toolbox anyway.
func withTaskCredentials(ctx context.Context, m *db.MCPServer, env map[string]string, load func(int64) ([]db.TaskCredential, error), sandboxed bool) (map[string]string, error) {
	if !m.TaskCredentials || m.Transport != "stdio" {
		return env, nil
	}
	if sandboxed {
		return nil, fmt.Errorf("task credentials are not supported in sandbox mode (the docker exec environment is host-visible)")
	}
	taskID := agent.RunInfoFrom(ctx).TaskID
	if taskID <= 0 || load == nil {
		return env, nil // chat run: the server starts and refuses credential_ref
	}
	rows, err := load(taskID)
	if err != nil {
		return nil, fmt.Errorf("load task credentials: %w", err)
	}
	creds := make([]adcore.Credential, 0, len(rows))
	for _, r := range rows {
		if strings.TrimSpace(r.Password) == "" {
			continue
		}
		creds = append(creds, adcore.Credential{
			Ref:      strconv.FormatInt(r.ID, 10),
			Domain:   r.Domain,
			Username: r.Username,
			Kind:     adcore.KindPassword,
			Secret:   r.Password,
		})
	}
	if len(creds) == 0 {
		return env, nil
	}
	raw, err := adcore.Encode(creds)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(env)+1)
	for k, v := range env {
		out[k] = v
	}
	out[adcore.EnvCredentials] = raw
	return out, nil
}

// discoverAndCacheMCP connects to one MCP, lists its tools, and persists the tool
// names to mcp_tools_cache so the UI shows them without a live connection.
func (s *Server) discoverAndCacheMCP(ctx context.Context, m *db.MCPServer) error {
	cl, err := connectMCP(ctx, m, s.execPriv)
	if err != nil {
		_ = s.m.pg.UpdateMCPHealth(m.ID, false, err.Error())
		return err
	}
	defer cl.Close()
	ts, err := cl.Tools(ctx)
	if err != nil {
		_ = s.m.pg.UpdateMCPHealth(m.ID, false, err.Error())
		return err
	}
	_ = s.m.pg.UpdateMCPHealth(m.ID, true, "")
	tools := make([]db.MCPTool, 0, len(ts))
	for _, t := range ts {
		tools = append(tools, db.MCPTool{Name: t.Name(), Description: t.Description()})
	}
	if err := s.m.pg.SaveMCPTools(m.ID, tools); err != nil {
		return err
	}
	log.Printf("[mcp] %s discovered %d tools and cached them", m.Name, len(tools))
	return nil
}

// discoverEmptyMCPsOnStartup fills the tool cache for any enabled MCP that has none
// yet (notably the seeded browser MCP on first run). Runs sequentially in one
// goroutine so we never spawn many stdio servers at once, and never blocks
// startup. Best-effort: a failure leaves the cache empty to retry next start.
func (s *Server) discoverEmptyMCPsOnStartup() {
	servers, err := s.m.pg.ListMCP()
	if err != nil {
		log.Printf("[mcp] startup auto-discovery: failed to read the list: %v", err)
		return
	}
	for _, m := range servers {
		if !m.Enabled || len(m.Tools) > 0 {
			continue
		}
		ctx, cancel := context.WithTimeout(s.ctx, 90*time.Second)
		if err := s.discoverAndCacheMCP(ctx, m); err != nil {
			log.Printf("[mcp] startup auto-discovery of %s failed: %v", m.Name, err)
		}
		cancel()
	}
}
