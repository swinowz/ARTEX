package sandbox

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Service serializes provisioning and teardown for concurrent task workers.
// A task's workspace is the only writable host directory mounted into its
// container, at the same absolute path. The skill tree may be mounted read-only.
type Service struct {
	docker          *Docker
	base            string
	mu              sync.Mutex
	tasks           map[int64]string
	retired         map[int64]bool
	sessions        map[string]string
	retiredSessions map[string]bool
	closed          bool
}

func NewService(d *Docker, base string) (*Service, error) {
	abs, err := filepath.Abs(base)
	if err != nil {
		return nil, err
	}
	return &Service{docker: d, base: abs, tasks: map[int64]string{}, retired: map[int64]bool{}, sessions: map[string]string{}, retiredSessions: map[string]bool{}}, nil
}
func (s *Service) ensure(ctx context.Context, id int64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.retired[id] {
		return "", fmt.Errorf("task sandbox is closed")
	}
	if root, ok := s.tasks[id]; ok {
		return root, nil
	}
	if _, err := taskName(id); err != nil {
		return "", err
	}
	root := filepath.Join(s.base, "tasks", strconv.FormatInt(id, 10))
	if err := os.MkdirAll(root, 0750); err != nil {
		return "", err
	}
	if err := s.docker.Create(ctx, id, root); err != nil {
		return "", err
	}
	if err := s.docker.Start(ctx, id); err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.docker.Remove(cleanup, id)
		return "", err
	}
	s.tasks[id] = root
	log.Printf("[sandbox] task %d container started", id)
	return root, nil
}
func (s *Service) Execute(ctx context.Context, id int64, dir, command string, timeout time.Duration, env []string) ([]byte, error) {
	root, err := s.ensure(ctx, id)
	if err != nil {
		return nil, err
	}
	abs, err := commandWorkdir(root, dir)
	if err != nil {
		return nil, err
	}
	log.Printf("[sandbox] task %d executing container command", id)
	return s.docker.Command(ctx, id, abs, command, timeout, env)
}

func commandWorkdir(root, dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(root, resolved)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return "", fmt.Errorf("command directory outside task workspace")
	}
	return abs, nil
}

var stdioEnvName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// StdioCommand provisions the task container and returns a Docker CLI command
// whose stdin/stdout carry the MCP protocol. Only the MCP server runs inside the
// container; the trusted Docker CLI stays on the host with no configured MCP
// variables in its own environment.
func (s *Service) StdioCommand(ctx context.Context, id int64, command string, commandArgs []string, env map[string]string) (string, []string, error) {
	if strings.TrimSpace(command) == "" {
		return "", nil, fmt.Errorf("MCP stdio command is empty")
	}
	for key := range env {
		if !stdioEnvName.MatchString(key) {
			return "", nil, fmt.Errorf("invalid MCP environment name %q", key)
		}
	}
	root, err := s.ensure(ctx, id)
	if err != nil {
		return "", nil, err
	}
	name, err := taskName(id)
	if err != nil {
		return "", nil, err
	}
	return "docker", stdioArgs(name, root, command, commandArgs, env), nil
}

func stdioArgs(name, root, command string, commandArgs []string, env map[string]string) []string {
	args := []string{"exec", "-i", "--workdir", root}
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--env", key+"="+env[key])
	}
	args = append(args, name, command)
	args = append(args, commandArgs...)
	return args
}

// ensureSession provisions one container for one conversational turn. The
// persistent workspace must be inside ARTEX's data directory, and the random
// key cannot be reused after removal.
func (s *Service) ensureSession(ctx context.Context, key, workspaceRoot string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.retiredSessions[key] {
		return "", fmt.Errorf("session sandbox is closed")
	}
	if _, err := sessionName(key); err != nil {
		return "", err
	}
	if root, ok := s.sessions[key]; ok {
		if root != workspaceRoot {
			return "", fmt.Errorf("session sandbox workspace changed")
		}
		return root, nil
	}
	root, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(root)
	if err != nil || resolved != filepath.Clean(root) {
		return "", fmt.Errorf("session workspace must exist without symlinks")
	}
	rel, err := filepath.Rel(s.base, root)
	if err != nil || rel == "." || !filepath.IsLocal(rel) {
		return "", fmt.Errorf("session workspace outside data directory")
	}
	if err := s.docker.CreateSession(ctx, key, root); err != nil {
		return "", err
	}
	if err := s.docker.StartSession(ctx, key); err != nil {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = s.docker.RemoveSession(cleanup, key)
		return "", err
	}
	s.sessions[key] = root
	log.Printf("[sandbox] session container started")
	return root, nil
}

func (s *Service) ExecuteSession(ctx context.Context, key, workspaceRoot, dir, command string, timeout time.Duration, env []string) ([]byte, error) {
	root, err := s.ensureSession(ctx, key, workspaceRoot)
	if err != nil {
		return nil, err
	}
	abs, err := commandWorkdir(root, dir)
	if err != nil {
		return nil, err
	}
	return s.docker.CommandSession(ctx, key, abs, command, timeout, env)
}

func (s *Service) StdioCommandSession(ctx context.Context, key, workspaceRoot, command string, commandArgs []string, env map[string]string) (string, []string, error) {
	if strings.TrimSpace(command) == "" {
		return "", nil, fmt.Errorf("MCP stdio command is empty")
	}
	for name := range env {
		if !stdioEnvName.MatchString(name) {
			return "", nil, fmt.Errorf("invalid MCP environment name %q", name)
		}
	}
	root, err := s.ensureSession(ctx, key, workspaceRoot)
	if err != nil {
		return "", nil, err
	}
	name, err := sessionName(key)
	if err != nil {
		return "", nil, err
	}
	return "docker", stdioArgs(name, root, command, commandArgs, env), nil
}

func (s *Service) RemoveSession(ctx context.Context, key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, err := sessionName(key); err != nil {
		return err
	}
	s.retiredSessions[key] = true
	if _, ok := s.sessions[key]; !ok {
		return nil
	}
	if err := s.docker.RemoveSession(ctx, key); err != nil {
		return err
	}
	delete(s.sessions, key)
	log.Printf("[sandbox] session container removed; workspace retained")
	return nil
}
func (s *Service) Remove(ctx context.Context, id int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.retired[id] = true
	if _, ok := s.tasks[id]; !ok {
		return nil
	}
	if err := s.docker.Remove(ctx, id); err != nil {
		return err
	}
	delete(s.tasks, id)
	log.Printf("[sandbox] task %d container removed; workspace retained", id)
	return nil
}
func (s *Service) Close(ctx context.Context) error {
	s.mu.Lock()
	s.closed = true
	ids := make([]int64, 0, len(s.tasks))
	for id := range s.tasks {
		ids = append(ids, id)
	}
	keys := make([]string, 0, len(s.sessions))
	for key := range s.sessions {
		keys = append(keys, key)
	}
	s.mu.Unlock()
	var first error
	for _, id := range ids {
		if err := s.Remove(ctx, id); err != nil && first == nil {
			first = err
		}
	}
	for _, key := range keys {
		if err := s.RemoveSession(ctx, key); err != nil && first == nil {
			first = err
		}
	}
	return first
}
