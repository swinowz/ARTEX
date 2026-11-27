package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDockerIntegration(t *testing.T) {
	image := os.Getenv("ARTEX_SANDBOX_TEST_IMAGE")
	if image == "" {
		t.Skip("set ARTEX_SANDBOX_TEST_IMAGE to an immutable local image with bash/python3")
	}
	d, err := NewDocker(Config{Image: image, Network: "none", UID: 0, GID: 0, Rootless: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	base := t.TempDir()
	dir := filepath.Join(base, "tasks", "990033", "i1")
	if err = os.MkdirAll(dir, 0750); err != nil {
		t.Fatal(err)
	}
	svc, _ := NewService(d, base)
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := svc.Close(ctx); err != nil {
			t.Error(err)
		}
	}()
	ctx := context.Background()
	out, err := svc.Execute(ctx, 990033, dir, `test ! -S /var/run/docker.sock && test ! -e /home/sway/projects/ARTEX/secret.key && printf 'container-evidence' > proof.txt && id -u`, 5*time.Second, nil)
	if err != nil {
		t.Fatalf("execute: %s: %v", out, err)
	}
	body, err := os.ReadFile(filepath.Join(dir, "proof.txt"))
	if err != nil || string(body) != "container-evidence" {
		t.Fatalf("shared proof: %s %v", body, err)
	}
	out, err = svc.Execute(ctx, 990033, dir, `sleep 30; echo leaked > timeout-leak`, 100*time.Millisecond, nil)
	if err == nil {
		t.Fatalf("timeout succeeded: %s", out)
	}
	cancelCtx, cancel := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() {
		_, err := svc.Execute(cancelCtx, 990033, dir, `touch started; sleep 30; echo leaked > cancel-leak`, time.Minute, nil)
		done <- err
	}()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := os.Stat(filepath.Join(dir, "started")); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			t.Fatal("command never started")
		}
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	if err := <-done; err == nil {
		t.Fatal("cancellation succeeded")
	}
	out, err = svc.Execute(ctx, 990033, dir, `python3 - <<'CHECK'
import pathlib
for proc in pathlib.Path('/proc').iterdir():
 try:
  if proc.name.isdigit() and (proc/'comm').read_text().strip()=='sleep' and b'30' in (proc/'cmdline').read_bytes().split(b'\0'):
   print('orphan sleep 30')
 except (FileNotFoundError,PermissionError,ProcessLookupError): pass
CHECK`, 5*time.Second, nil)
	if err != nil || strings.Contains(string(out), "sleep 30") {
		t.Fatalf("orphan process: %s %v", out, err)
	}
	if err = svc.Remove(ctx, 990033); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Execute(ctx, 990033, dir, "true", time.Second, nil); err == nil {
		t.Fatal("retired task recreated")
	}
	if _, err = os.Stat(filepath.Join(dir, "proof.txt")); err != nil {
		t.Fatal("cleanup deleted evidence", err)
	}
}
