// Package sandbox manages disposable task execution containers. It does not
// expose the Docker daemon or the server environment to the task.
package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var imageDigest = regexp.MustCompile(`^([a-zA-Z0-9][a-zA-Z0-9._:/-]*@)?sha256:[a-f0-9]{64}$`)
var networkName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)
var sessionKeyPattern = regexp.MustCompile(`^[a-f0-9]{32}$`)

// Config is operator-owned; never populate it from agent tool input.
// Network must name an existing Docker network, or "none". Network policy is
// provisioned by the operator; a Docker bridge alone does not enforce scope.
type Config struct {
	Rootless       bool   `json:"rootless,omitempty"`
	Image          string `json:"image"`
	Network        string `json:"network"`
	UID            uint32 `json:"uid"`
	GID            uint32 `json:"gid"`
	HostDataDir    string `json:"host_data_dir,omitempty"`  // daemon-side source of RuntimeDataDir
	HostSkillDir   string `json:"host_skill_dir,omitempty"` // daemon-side source of SkillDir
	RuntimeDataDir string `json:"-"`                        // server-resolved data path
	SkillDir       string `json:"-"`                        // server-resolved skill path
}

// Runner executes a Docker CLI invocation. Implementations must honor ctx.
type Runner func(context.Context, ...string) ([]byte, error)

type Docker struct {
	config Config
	run    Runner
}

func NewDocker(c Config, run Runner) (*Docker, error) {
	if !imageDigest.MatchString(c.Image) {
		return nil, errors.New("sandbox image must be pinned by sha256 digest")
	}
	if !networkName.MatchString(c.Network) || c.Network == "host" || c.Network == "default" {
		return nil, errors.New("sandbox requires an explicit network or none")
	}
	if (c.UID == 0 || c.GID == 0) && !c.Rootless {
		return nil, errors.New("sandbox requires a non-root UID and GID")
	}
	if c.SkillDir != "" {
		if err := validMountDir(c.SkillDir, "skill directory"); err != nil {
			return nil, err
		}
	}
	// The daemon interprets host paths in its own mount namespace. They may not
	// exist inside the ARTEX server container, so validate syntax here and let
	// Docker's --mount require the source to exist on the daemon host.
	for label, path := range map[string]string{"host data directory": c.HostDataDir, "host skill directory": c.HostSkillDir} {
		if path != "" {
			if err := validMountPath(path, label); err != nil {
				return nil, err
			}
		}
	}
	if c.HostDataDir != "" {
		if c.RuntimeDataDir == "" {
			return nil, errors.New("host data directory requires runtime data directory")
		}
		if err := validMountDir(c.RuntimeDataDir, "runtime data directory"); err != nil {
			return nil, err
		}
	}
	if c.HostSkillDir != "" && c.SkillDir == "" {
		return nil, errors.New("host skill directory requires skill directory")
	}
	if c.HostDataDir != "" && c.SkillDir != "" && c.HostSkillDir == "" {
		return nil, errors.New("host data directory also requires host skill directory")
	}
	if run == nil {
		run = func(ctx context.Context, args ...string) ([]byte, error) {
			cmd := exec.CommandContext(ctx, "docker", args...)
			var output cappedOutput
			cmd.Stdout = &output
			cmd.Stderr = &output
			err := cmd.Run()
			return output.Bytes(), err
		}
	}
	if c.Rootless {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		out, err := run(ctx, "info", "--format", "{{json .SecurityOptions}}")
		var options []string
		if err != nil || json.Unmarshal(out, &options) != nil {
			return nil, errors.New("cannot verify rootless Docker daemon")
		}
		verified := false
		for _, option := range options {
			if option == "name=rootless" {
				verified = true
			}
		}
		if !verified {
			return nil, errors.New("rootless mode requires a verified rootless Docker daemon")
		}
	}
	return &Docker{c, run}, nil
}

func validMountDir(path, label string) error {
	if err := validMountPath(path, label); err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || resolved != filepath.Clean(path) {
		return fmt.Errorf("%s must exist and contain no symlinks", label)
	}
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return fmt.Errorf("%s must exist as a directory", label)
	}
	return nil
}

func validMountPath(path, label string) error {
	if !filepath.IsAbs(path) || strings.ContainsAny(path, ",\n\r") || filepath.Clean(path) != path {
		return fmt.Errorf("%s must be a clean absolute path without mount separators", label)
	}
	return nil
}

func taskName(id int64) (string, error) {
	if id <= 0 {
		return "", errors.New("sandbox requires a positive task ID")
	}
	return "artex-task-" + strconv.FormatInt(id, 10), nil
}

func sessionName(key string) (string, error) {
	if !sessionKeyPattern.MatchString(key) {
		return "", errors.New("invalid session sandbox key")
	}
	return "artex-session-" + key, nil
}

// Create makes one container per task. A named volume persists its evidence until
// explicitly removed by the operator. Task workspace and the read-only skill tree
// are the only optional host mounts; server secrets and the daemon socket stay out.
// Duplicate creation fails rather than silently reusing another container.
func (d *Docker) Create(ctx context.Context, id int64, workspace ...string) error {
	name, err := taskName(id)
	if err != nil {
		return err
	}
	return d.createNamed(ctx, name, "artex.task="+strconv.FormatInt(id, 10), workspace...)
}

func (d *Docker) createNamed(ctx context.Context, name, label string, workspace ...string) error {
	args := []string{"create", "--name", name, "--label", label,
		"--network", d.config.Network, "--user", fmt.Sprintf("%d:%d", d.config.UID, d.config.GID),
		"--init", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--read-only", "--pids-limit=256",
		"--memory=2g", "--cpus=2", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
		"--mount", "type=volume,src=" + name + "-work,dst=/work"}
	if d.config.SkillDir != "" {
		source := d.config.SkillDir
		if d.config.HostSkillDir != "" {
			source = d.config.HostSkillDir
		}
		args = append(args, "--mount", "type=bind,src="+source+",dst="+d.config.SkillDir+",readonly")
	}
	args = append(args, "--workdir", "/work", "--env", "HOME=/work", "--entrypoint", "/bin/sh", d.config.Image, "-c", "exec sleep infinity")
	if len(workspace) > 0 {
		path := workspace[0]
		if !filepath.IsAbs(path) || strings.ContainsAny(path, ",\n\r") {
			return errors.New("workspace must be an absolute path without mount separators")
		}
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		if resolved != filepath.Clean(path) {
			return errors.New("workspace must not contain symlinks")
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return errors.New("workspace must be a directory")
		}
		source := path
		if d.config.HostDataDir != "" {
			rel, err := filepath.Rel(d.config.RuntimeDataDir, path)
			if err != nil || rel == "." || !filepath.IsLocal(rel) {
				return errors.New("workspace outside runtime data directory")
			}
			source = filepath.Join(d.config.HostDataDir, rel)
			if err := validMountPath(source, "host workspace"); err != nil {
				return err
			}
		}
		for i := range args {
			if args[i] == "type=volume,src="+name+"-work,dst=/work" {
				args[i] = "type=bind,src=" + source + ",dst=" + path
			}
			if args[i] == "/work" {
				args[i] = path
			}
			if args[i] == "HOME=/work" {
				args[i] = "HOME=" + path
			}
		}
	}
	if _, err := d.run(ctx, args...); err != nil {
		return fmt.Errorf("create sandbox %s: %w", name, err)
	}
	return nil
}

func (d *Docker) CreateSession(ctx context.Context, key, workspace string) error {
	name, err := sessionName(key)
	if err != nil {
		return err
	}
	return d.createNamed(ctx, name, "artex.session="+key, workspace)
}

func (d *Docker) Start(ctx context.Context, id int64) error {
	name, err := taskName(id)
	if err != nil {
		return err
	}
	_, err = d.run(ctx, "start", name)
	return err
}

func (d *Docker) StartSession(ctx context.Context, key string) error {
	name, err := sessionName(key)
	if err != nil {
		return err
	}
	_, err = d.run(ctx, "start", name)
	return err
}

// Exec returns combined output. Cancellation stops the CLI; terminating commands
// inside Docker requires Remove, which the task lifecycle must call separately.
func (d *Docker) Exec(ctx context.Context, id int64, command string) ([]byte, error) {
	name, err := taskName(id)
	if err != nil {
		return nil, err
	}
	return d.run(ctx, "exec", name, "/bin/sh", "-c", command)
}

// Remove terminates all processes, including detached handlers, but keeps evidence.
func (d *Docker) Remove(ctx context.Context, id int64) error {
	name, err := taskName(id)
	if err != nil {
		return err
	}
	_, err = d.run(ctx, "rm", "--force", name)
	return err
}

func (d *Docker) RemoveSession(ctx context.Context, key string) error {
	name, err := sessionName(key)
	if err != nil {
		return err
	}
	_, err = d.run(ctx, "rm", "--force", name)
	return err
}

// Bound host memory even when a command produces unlimited output. exec.Cmd
// serializes writes when stdout and stderr use the same comparable writer.
type cappedOutput struct{ bytes.Buffer }

func (b *cappedOutput) Write(p []byte) (int, error) {
	n := len(p)
	remaining := (2 << 20) - b.Len()
	if remaining > 0 {
		_, _ = b.Buffer.Write(p[:min(n, remaining)])
	}
	return n, nil
}
