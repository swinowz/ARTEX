package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const sessionTestKey = "0123456789abcdef0123456789abcdef"

func TestSessionContainerKeepsToolsAndWorkspace(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "sessions", "conv-1")
	if err := os.MkdirAll(root, 0o750); err != nil {
		t.Fatal(err)
	}
	var calls [][]string
	d, err := NewDocker(Config{Image: "sha256:" + strings.Repeat("a", 64), Network: "none", UID: 10001, GID: 10001}, func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		if args[0] == "exec" {
			return []byte("session-result"), nil
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(d, base)
	if err != nil {
		t.Fatal(err)
	}
	out, err := svc.ExecuteSession(context.Background(), sessionTestKey, root, root, "printf done", time.Second, nil)
	if err != nil || string(out) != "session-result" {
		t.Fatalf("session Bash: %q, %v", out, err)
	}
	command, args, err := svc.StdioCommandSession(context.Background(), sessionTestKey, root, "python3", []string{"-m", "mcp"}, nil)
	if err != nil || command != "docker" || !strings.Contains(strings.Join(args, " "), "artex-session-"+sessionTestKey+" python3 -m mcp") {
		t.Fatalf("session MCP: %s %v %v", command, args, err)
	}
	if err := svc.RemoveSession(context.Background(), sessionTestKey); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ExecuteSession(context.Background(), sessionTestKey, root, root, "true", time.Second, nil); err == nil {
		t.Fatal("retired session container was recreated")
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatal("session workspace removed", err)
	}
	if len(calls) != 4 || calls[0][0] != "create" || calls[1][0] != "start" || calls[2][0] != "exec" || calls[3][0] != "rm" {
		t.Fatalf("unexpected lifecycle %v", calls)
	}
}

func TestSessionContainerRejectsWorkspaceOutsideData(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	d, _ := NewDocker(Config{Image: "sha256:" + strings.Repeat("a", 64), Network: "none", UID: 10001, GID: 10001}, func(context.Context, ...string) ([]byte, error) {
		t.Fatal("Docker called for outside workspace")
		return nil, nil
	})
	svc, _ := NewService(d, base)
	if _, err := svc.ExecuteSession(context.Background(), sessionTestKey, outside, outside, "true", time.Second, nil); err == nil {
		t.Fatal("outside workspace mounted")
	}
}
