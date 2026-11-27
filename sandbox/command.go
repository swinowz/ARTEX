package sandbox

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// The lock makes cancellation atomic with process creation. A cancel arriving
// before the exec starts leaves a tombstone so that the command never starts.
// Each command has its own process group; cancelling one worker leaves others up.
const commandScript = `
import fcntl,os,signal,subprocess,sys
op,command,seconds=sys.argv[1:]
base='/tmp/artex-'+op
with open(base+'.lock','a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 if os.path.exists(base+'.cancel'): sys.exit(125)
 p=subprocess.Popen(['/bin/bash','-c',command],start_new_session=True)
 with open(base+'.pid','w') as f: f.write(str(p.pid))
try:
 code=p.wait(timeout=float(seconds))
except subprocess.TimeoutExpired:
 code=124
finally:
 with open(base+'.lock','a') as lock:
  fcntl.flock(lock,fcntl.LOCK_EX)
  try: os.killpg(p.pid,signal.SIGKILL)
  except ProcessLookupError: pass
  try: os.unlink(base+'.pid')
  except FileNotFoundError: pass
sys.exit(code if code>=0 else 128-code)
`
const cancelScript = `
import fcntl,os,signal,sys
base='/tmp/artex-'+sys.argv[1]
with open(base+'.lock','a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 open(base+'.cancel','w').close()
 try:
  with open(base+'.pid') as f: pid=int(f.read())
  os.killpg(pid,signal.SIGKILL)
 except (FileNotFoundError,ProcessLookupError): pass
`

// Command executes in a task-mounted directory, never a host shell. The caller
// validates dir against the task workspace. The image must contain python3/bash.
func (d *Docker) Command(ctx context.Context, id int64, dir, command string, timeout time.Duration, env []string) ([]byte, error) {
	name, err := taskName(id)
	if err != nil {
		return nil, err
	}
	return d.commandNamed(ctx, name, dir, command, timeout, env)
}

func (d *Docker) CommandSession(ctx context.Context, key, dir, command string, timeout time.Duration, env []string) ([]byte, error) {
	name, err := sessionName(key)
	if err != nil {
		return nil, err
	}
	return d.commandNamed(ctx, name, dir, command, timeout, env)
}

func (d *Docker) commandNamed(ctx context.Context, name, dir, command string, timeout time.Duration, env []string) ([]byte, error) {
	token := make([]byte, 16)
	if _, err := rand.Read(token); err != nil {
		return nil, err
	}
	op := hex.EncodeToString(token)
	args := []string{"exec", "--workdir", dir}
	for _, kv := range env {
		args = append(args, "--env", kv)
	}
	args = append(args, name, "python3", "-c", commandScript, op, command, fmt.Sprint(timeout.Seconds()))
	out, err := d.run(ctx, args...)
	if ctx.Err() != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, killErr := d.run(cleanup, "exec", name, "python3", "-c", cancelScript, op); killErr != nil {
			return out, fmt.Errorf("command cancellation cleanup failed: %w", killErr)
		}
		return out, ctx.Err()
	}
	return out, err
}
