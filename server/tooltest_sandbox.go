package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Autumn-27/artex/agent"
	actool "github.com/Autumn-27/norma/tool"
)

// prepareToolTestSandbox gives an editor command/script test its own workspace
// and disposable container. The sandbox service provisions on first execution;
// the returned cleanup also handles tests that fail before provisioning.
func (s *Server) prepareToolTestSandbox(ctx context.Context) (context.Context, *actool.ToolContext, func() error, error) {
	if s.commandSandbox == nil {
		return ctx, &actool.ToolContext{WorkingDir: s.m.dir}, func() error { return nil }, nil
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, nil, nil, fmt.Errorf("create tool test sandbox key: %w", err)
	}
	key := hex.EncodeToString(nonce[:])
	root := filepath.Join(s.m.dir, "sessions", "tool-tests", key)
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, nil, nil, fmt.Errorf("create tool test workspace: %w", err)
	}
	info := agent.RunInfo{SessionSandbox: true, SessionSandboxKey: key, SessionSandboxRoot: root}
	cleanup := func() error {
		removeCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := s.commandSandbox.RemoveSession(removeCtx, key); err != nil {
			return fmt.Errorf("remove tool test container: %w", err)
		}
		if err := os.RemoveAll(root); err != nil {
			return fmt.Errorf("remove tool test workspace: %w", err)
		}
		return nil
	}
	return agent.WithRunInfo(ctx, info), &actool.ToolContext{WorkingDir: root}, cleanup, nil
}
