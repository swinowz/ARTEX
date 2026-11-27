package sandbox

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestNestedRootlessIntegration runs only through scripts/nested-sandbox-proof.sh.
// Its test process is root in an outer rootless-Docker container with the daemon
// socket, while task and session containers get only their workspace and skills.
func TestNestedRootlessIntegration(t *testing.T) {
	image := os.Getenv("ARTEX_NESTED_TEST_IMAGE")
	if image == "" {
		t.Skip("run scripts/nested-sandbox-proof.sh with ARTEX_NESTED_TEST_IMAGE")
	}
	hostData := os.Getenv("ARTEX_NESTED_HOST_DATA")
	hostSkills := os.Getenv("ARTEX_NESTED_HOST_SKILLS")
	taskID, err := strconv.ParseInt(os.Getenv("ARTEX_NESTED_TASK_ID"), 10, 64)
	if err != nil || taskID <= 0 || hostData == "" || hostSkills == "" {
		t.Fatal("missing nested proof host paths or task ID")
	}
	sessionKey := os.Getenv("ARTEX_NESTED_SESSION_KEY")
	if _, err := sessionName(sessionKey); err != nil {
		t.Fatal(err)
	}
	const data = "/app/data"
	const skills = "/app/skills"
	if _, err := os.Stat("/app/server-secret"); err != nil {
		t.Fatalf("server secret fixture missing: %v", err)
	}
	if _, err := os.Stat("/run/artex-docker.sock"); err != nil {
		t.Fatalf("server Docker socket fixture missing: %v", err)
	}
	work := filepath.Join(data, "tasks", strconv.FormatInt(taskID, 10), "i1")
	session := filepath.Join(data, "sessions", "nested-proof-"+sessionKey)
	for _, dir := range []string{work, session} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	d, err := NewDocker(Config{
		Rootless: true, UID: 0, GID: 0, Network: "none", Image: image,
		RuntimeDataDir: data, HostDataDir: hostData,
		SkillDir: skills, HostSkillDir: hostSkills,
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewService(d, data)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := svc.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	const boundary = `test ! -e /app/server-secret && test ! -S /run/artex-docker.sock && test ! -S /var/run/docker.sock`
	command := `printf 'task=ok\n' > proof.txt && cat /app/skills/proof && ` + boundary +
		` && if touch /app/skills/write-proof 2>/dev/null; then exit 88; fi`
	out, err := svc.Execute(ctx, taskID, work, command, 10*time.Second, nil)
	if err != nil || !strings.Contains(string(out), "skill=ok") {
		t.Fatalf("task command or skill boundary: %q: %v", out, err)
	}
	if body, err := os.ReadFile(filepath.Join(work, "proof.txt")); err != nil || string(body) != "task=ok\n" {
		t.Fatalf("task workspace: %q: %v", body, err)
	}
	command = `cat /app/skills/proof && ` + boundary + ` && printf 'session=ok\n' > proof.txt`
	out, err = svc.ExecuteSession(ctx, sessionKey, session, session, command, 10*time.Second, nil)
	if err != nil || !strings.Contains(string(out), "skill=ok") {
		t.Fatalf("session command or skill boundary: %q: %v", out, err)
	}
	if body, err := os.ReadFile(filepath.Join(session, "proof.txt")); err != nil || string(body) != "session=ok\n" {
		t.Fatalf("session workspace: %q: %v", body, err)
	}
	dockerCmd, args, err := svc.StdioCommandSession(ctx, sessionKey, session, "cat", []string{"/app/skills/proof"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	stdioOut, err := exec.CommandContext(ctx, dockerCmd, args...).CombinedOutput()
	if err != nil || string(stdioOut) != "skill=ok\n" {
		t.Fatalf("stdio bridge: %q: %v", stdioOut, err)
	}
	if err := svc.RemoveSession(ctx, sessionKey); err != nil {
		t.Fatal(err)
	}
	if err := svc.Remove(ctx, taskID); err != nil {
		t.Fatal(err)
	}
	t.Logf("nested task, session, skill, stdio, secret and socket boundaries passed (task %d)", taskID)
}
