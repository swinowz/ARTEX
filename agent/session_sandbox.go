package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	actool "github.com/Autumn-27/norma/tool"
)

// SessionSandbox runs one human-facing agent turn in a disposable container.
// workspaceRoot is the only writable host directory mounted in that container.
type SessionSandbox interface {
	ExecuteSession(context.Context, string, string, string, string, time.Duration, []string) ([]byte, error)
	RemoveSession(context.Context, string) error
}

type sessionCommandBackend struct {
	sandbox SessionSandbox
	key     string
	root    string
}

func (b sessionCommandBackend) Execute(ctx context.Context, _ int64, dir, command string, timeout time.Duration, env []string) ([]byte, error) {
	return b.sandbox.ExecuteSession(ctx, b.key, b.root, dir, command, timeout, env)
}

// startSessionSandbox gives each turn a distinct identity, even when concurrent
// calls refer to the same transcript. MCP/custom tool assembly reads the same
// RunInfo before it starts any external process.
func startSessionSandbox(ctx context.Context, sandbox SessionSandbox, root string) (context.Context, string, error) {
	if sandbox == nil {
		return ctx, "", nil
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ctx, "", err
	}
	key := hex.EncodeToString(nonce[:])
	info := RunInfoFrom(ctx)
	info.SessionSandbox = true
	info.SessionSandboxKey = key
	info.SessionSandboxRoot = root
	return WithRunInfo(ctx, info), key, nil
}

func sessionSandboxTools(tools []actool.CoreTool, sandbox SessionSandbox, key, root string) []actool.CoreTool {
	if sandbox == nil {
		return tools
	}
	return sandboxWorkerTools(tools, sessionCommandBackend{sandbox: sandbox, key: key, root: root}, 0)
}

// finishSessionSandbox must run after MCP cleanup so stdio children exit before
// their container is removed. A fresh context survives a cancelled agent turn.
func finishSessionSandbox(sandbox SessionSandbox, key string) error {
	if sandbox == nil || key == "" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := sandbox.RemoveSession(ctx, key); err != nil {
		return errors.New("remove session sandbox: " + err.Error())
	}
	return nil
}
