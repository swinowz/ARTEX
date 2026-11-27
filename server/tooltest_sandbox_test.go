package server

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/agent"
	"github.com/Autumn-27/artex/sandbox"
)

func TestEditorCustomToolTestsUseDisposableSessionSandbox(t *testing.T) {
	for _, kind := range []string{"command", "script"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
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
			s := &Server{m: &Manager{dir: base}, commandSandbox: svc}
			ctx, cancel := context.WithCancel(t.Context())
			ctx, tc, cleanup, err := s.prepareToolTestSandbox(ctx)
			if err != nil {
				t.Fatal(err)
			}
			info := agent.RunInfoFrom(ctx)
			if !info.SessionSandbox || len(info.SessionSandboxKey) != 32 || info.SessionSandboxRoot != tc.WorkingDir || !strings.HasPrefix(tc.WorkingDir, filepath.Join(base, "sessions", "tool-tests")+string(os.PathSeparator)) {
				t.Fatalf("bad test sandbox context: %+v, dir=%q", info, tc.WorkingDir)
			}
			var result string
			if kind == "command" {
				res, err := s.runCommandTool(ctx, "test", json.RawMessage(`{"command":"printf editor-test"}`), nil, tc)
				if err != nil || res.IsError {
					t.Fatalf("command result: %+v, %v", res, err)
				}
				result = res.Flatten()
			} else {
				res, err := s.runScriptTool(ctx, "test", json.RawMessage(`{"code":"print('editor-test')"}`), nil, tc)
				if err != nil || res.IsError {
					t.Fatalf("script result: %+v, %v", res, err)
				}
				result = res.Flatten()
			}
			if result != "container-result" {
				t.Fatalf("result did not come from container: %q", result)
			}
			cancel() // cleanup must work after request cancellation
			if err := cleanup(); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(tc.WorkingDir); !os.IsNotExist(err) {
				t.Fatalf("test workspace retained: %v", err)
			}
			if len(calls) != 4 || calls[0][0] != "create" || calls[1][0] != "start" || calls[2][0] != "exec" || calls[3][0] != "rm" {
				t.Fatalf("container lifecycle: %v", calls)
			}
		})
	}
}

func TestEditorCustomToolTestKeepsLegacyExecutionWithoutSandbox(t *testing.T) {
	base := t.TempDir()
	s := &Server{m: &Manager{dir: base}}
	ctx, tc, cleanup, err := s.prepareToolTestSandbox(t.Context())
	if err != nil || tc.WorkingDir != base || agent.RunInfoFrom(ctx).SessionSandbox {
		t.Fatalf("legacy test context: dir=%q err=%v", tc.WorkingDir, err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
}

func TestEditorCustomToolTestDoesNotFallBackAfterContainerFailure(t *testing.T) {
	base := t.TempDir()
	var calls [][]string
	d, err := sandbox.NewDocker(sandbox.Config{Image: "sha256:" + strings.Repeat("a", 64), Network: "none", UID: 10001, GID: 10001}, func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if args[0] == "create" {
			return nil, errors.New("container unavailable")
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
	s := &Server{m: &Manager{dir: base}, commandSandbox: svc}
	ctx, tc, cleanup, err := s.prepareToolTestSandbox(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	res, err := s.runCommandTool(ctx, "test", json.RawMessage(`{"command":"touch host-marker"}`), nil, tc)
	if err != nil || !res.IsError || !strings.Contains(res.Flatten(), "container unavailable") {
		t.Fatalf("container failure was hidden: %+v, %v", res, err)
	}
	if err := cleanup(); err != nil {
		t.Fatal(err)
	}
	if len(calls) != 1 || calls[0][0] != "create" {
		t.Fatalf("unexpected host/container calls: %v", calls)
	}
	if _, err := os.Stat(filepath.Join(base, "host-marker")); !os.IsNotExist(err) {
		t.Fatalf("command ran on host: %v", err)
	}
}
