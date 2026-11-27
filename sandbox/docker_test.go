package sandbox

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func validConfig() Config {
	return Config{Image: "example/tools@sha256:" + strings.Repeat("a", 64), Network: "none", UID: 1000, GID: 1000}
}

func TestRejectUnsafeConfiguration(t *testing.T) {
	for _, mutate := range []func(*Config){
		func(c *Config) { c.Image = "tools:latest" }, func(c *Config) { c.Network = "host" },
		func(c *Config) { c.Network = "" }, func(c *Config) { c.Network = "container:other" },
		func(c *Config) { c.UID = 0 }, func(c *Config) { c.GID = 0 },
	} {
		c := validConfig()
		mutate(&c)
		if _, err := NewDocker(c, nil); err == nil {
			t.Fatalf("accepted unsafe configuration: %+v", c)
		}
	}
}

func TestContainerLifecycleAndCommandBoundary(t *testing.T) {
	var calls [][]string
	d, err := NewDocker(validConfig(), func(_ context.Context, args ...string) ([]byte, error) {
		calls = append(calls, args)
		return []byte("ok"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := d.Create(ctx, 42); err != nil {
		t.Fatal(err)
	}
	if err := d.Start(ctx, 42); err != nil {
		t.Fatal(err)
	}
	command := "printf '%s' 'hello; $(id)'"
	if out, err := d.Exec(ctx, 42, command); err != nil || string(out) != "ok" {
		t.Fatalf("exec: %s %v", out, err)
	}
	if err := d.Remove(ctx, 42); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(calls[2], []string{"exec", "artex-task-42", "/bin/sh", "-c", command}) {
		t.Fatalf("command escaped its argument: %v", calls[2])
	}
	create := strings.Join(calls[0], " ")
	for _, flag := range []string{"--cap-drop=ALL", "--read-only", "--security-opt=no-new-privileges", "--network none", "--user 1000:1000", "type=volume,src=artex-task-42-work,dst=/work"} {
		if !strings.Contains(create, flag) {
			t.Fatalf("missing %s", flag)
		}
	}
	if !reflect.DeepEqual(calls[3], []string{"rm", "--force", "artex-task-42"}) {
		t.Fatal(calls[3])
	}
}

func TestInvalidTaskNeverCallsDocker(t *testing.T) {
	d, _ := NewDocker(validConfig(), func(context.Context, ...string) ([]byte, error) {
		t.Fatal("unexpected Docker invocation")
		return nil, nil
	})
	ctx := context.Background()
	for _, id := range []int64{0, -1} {
		if d.Create(ctx, id) == nil || d.Start(ctx, id) == nil || d.Remove(ctx, id) == nil {
			t.Fatal("invalid task accepted")
		}
		if _, err := d.Exec(ctx, id, "true"); err == nil {
			t.Fatal("invalid task accepted")
		}
	}
}

func TestDockerFailurePropagates(t *testing.T) {
	want := errors.New("daemon unavailable")
	d, _ := NewDocker(validConfig(), func(context.Context, ...string) ([]byte, error) { return nil, want })
	if err := d.Create(context.Background(), 1); !errors.Is(err, want) {
		t.Fatal(err)
	}
}

func TestRootlessRequiresVerifiedDaemon(t *testing.T) {
	c := validConfig()
	c.Rootless = true
	c.UID = 0
	c.GID = 0
	if _, err := NewDocker(c, func(context.Context, ...string) ([]byte, error) { return []byte(`["name=seccomp"]`), nil }); err == nil {
		t.Fatal("rootful daemon accepted as rootless")
	}
	if _, err := NewDocker(c, func(context.Context, ...string) ([]byte, error) { return []byte(`["name=rootless"]`), nil }); err != nil {
		t.Fatal(err)
	}
}

func TestSkillDirectoryMountedReadOnly(t *testing.T) {
	skills := filepath.Join(t.TempDir(), "skills")
	if err := os.Mkdir(skills, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := validConfig()
	cfg.SkillDir = skills
	var create []string
	d, err := NewDocker(cfg, func(_ context.Context, args ...string) ([]byte, error) {
		create = append([]string(nil), args...)
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Create(context.Background(), 42); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(create, " "), "type=bind,src="+skills+",dst="+skills+",readonly") {
		t.Fatalf("skills missing from sandbox as read-only mount: %v", create)
	}
}

func TestHostBindSourcesTranslateContainerPaths(t *testing.T) {
	runtimeBase := t.TempDir()
	hostBase := t.TempDir()
	runtimeSkills := t.TempDir()
	hostSkills := t.TempDir()
	workspace := filepath.Join(runtimeBase, "tasks", "42")
	hostWorkspace := filepath.Join(hostBase, "tasks", "42")
	for _, dir := range []string{workspace, hostWorkspace} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	cfg := validConfig()
	cfg.RuntimeDataDir = runtimeBase
	cfg.HostDataDir = hostBase
	cfg.SkillDir = runtimeSkills
	cfg.HostSkillDir = hostSkills
	var create []string
	d, err := NewDocker(cfg, func(_ context.Context, args ...string) ([]byte, error) {
		create = append([]string(nil), args...)
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Create(context.Background(), 42, workspace); err != nil {
		t.Fatal(err)
	}
	line := strings.Join(create, " ")
	for _, want := range []string{
		"type=bind,src=" + hostWorkspace + ",dst=" + workspace,
		"type=bind,src=" + hostSkills + ",dst=" + runtimeSkills + ",readonly",
	} {
		if !strings.Contains(line, want) {
			t.Fatalf("missing %q in Docker create %s", want, line)
		}
	}
}

func TestDaemonHostPathsNeedNotExistInServerNamespace(t *testing.T) {
	runtimeBase := t.TempDir()
	runtimeSkills := t.TempDir()
	workspace := filepath.Join(runtimeBase, "tasks", "44")
	if err := os.MkdirAll(workspace, 0o750); err != nil {
		t.Fatal(err)
	}
	missingHostRoot := filepath.Join(t.TempDir(), "daemon-only")
	cfg := validConfig()
	cfg.RuntimeDataDir = runtimeBase
	cfg.HostDataDir = filepath.Join(missingHostRoot, "data")
	cfg.SkillDir = runtimeSkills
	cfg.HostSkillDir = filepath.Join(missingHostRoot, "skills")
	var create []string
	d, err := NewDocker(cfg, func(_ context.Context, args ...string) ([]byte, error) {
		create = append([]string(nil), args...)
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Create(context.Background(), 44, workspace); err != nil {
		t.Fatalf("server must leave daemon-host source validation to Docker: %v", err)
	}
	if !strings.Contains(strings.Join(create, " "), "src="+filepath.Join(missingHostRoot, "data", "tasks", "44")+",dst="+workspace) {
		t.Fatalf("host source not translated: %v", create)
	}
}
