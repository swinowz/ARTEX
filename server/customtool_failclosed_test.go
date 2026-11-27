package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/sandbox"
	actool "github.com/Autumn-27/norma/tool"
)

func TestConfiguredSandboxNeverFallsBackToHostWithoutRunIdentity(t *testing.T) {
	var dockerCalls int
	d, err := sandbox.NewDocker(sandbox.Config{Image: "sha256:" + strings.Repeat("a", 64), Network: "none", UID: 10001, GID: 10001}, func(context.Context, ...string) ([]byte, error) {
		dockerCalls++
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := sandbox.NewService(d, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{commandSandbox: svc}
	tc := &actool.ToolContext{WorkingDir: t.TempDir()}
	for _, spec := range []struct {
		name string
		call func() (actool.Result, error)
	}{
		{"command", func() (actool.Result, error) {
			return s.runCommandTool(t.Context(), "test", json.RawMessage(`{"command":"touch host-marker"}`), nil, tc)
		}},
		{"script", func() (actool.Result, error) {
			return s.runScriptTool(t.Context(), "test", json.RawMessage(`{"code":"print('host')"}`), nil, tc)
		}},
	} {
		t.Run(spec.name, func(t *testing.T) {
			result, err := spec.call()
			if err != nil || !result.IsError || !strings.Contains(result.Flatten(), "sandbox run identity is unavailable") {
				t.Fatalf("missing run identity: result=%+v err=%v", result, err)
			}
		})
	}
	if dockerCalls != 0 {
		t.Fatalf("unexpected Docker calls: %d", dockerCalls)
	}
}
