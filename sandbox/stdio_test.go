package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStdioCommandKeepsMCPInsideTaskContainer(t *testing.T) {
	base := t.TempDir()
	var calls [][]string
	d, err := NewDocker(Config{Image: "sha256:" + strings.Repeat("a", 64), Network: "none", UID: 10001, GID: 10001}, func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(d, base)
	if err != nil {
		t.Fatal(err)
	}
	command, args, err := svc.StdioCommand(context.Background(), 42, "python3", []string{"-m", "probe"}, map[string]string{"MCP_TOKEN": "configured"})
	if err != nil {
		t.Fatal(err)
	}
	if command != "docker" || len(args) < 9 || args[0] != "exec" || args[1] != "-i" {
		t.Fatalf("not an interactive container command: %s %v", command, args)
	}
	line := strings.Join(args, " ")
	for _, want := range []string{"--workdir " + filepath.Join(base, "tasks", "42"), "--env MCP_TOKEN=configured", "artex-task-42 python3 -m probe"} {
		if !strings.Contains(line, want) {
			t.Fatalf("missing %q in %s", want, line)
		}
	}
	if len(calls) != 2 || calls[0][0] != "create" || calls[1][0] != "start" {
		t.Fatalf("task container not provisioned: %v", calls)
	}
	if _, err := os.Stat(filepath.Join(base, "tasks", "42")); err != nil {
		t.Fatal(err)
	}
}
