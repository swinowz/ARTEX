// Package adcore holds what the AD inventory capability servers share: the
// task-credential envelope the core injects at spawn, the coverage taxonomy
// returned to the model, artifact writing, and secret redaction.
package adcore

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
)

// EnvCredentials carries the task's test accounts from the core to a stdio
// server whose mcp_servers.task_credentials flag is set (issue #17). The value
// lives in the child's environment only: never on disk, never in argv, never in
// a tool result.
const EnvCredentials = "ARTEX_TASK_CREDENTIALS"

// Credential kinds a caller may reference today.
const (
	KindPassword = "password"
	KindNTLM     = "ntlm"
)

// Credential is one test account as handed to a capability server.
type Credential struct {
	Ref      string `json:"ref"`
	Domain   string `json:"domain"`
	Username string `json:"username"`
	Kind     string `json:"kind"`
	Secret   string `json:"secret"`
}

type envelope struct {
	Version     int          `json:"version"`
	Credentials []Credential `json:"credentials"`
}

// Encode serialises the credentials for the environment value.
func Encode(creds []Credential) (string, error) {
	if creds == nil {
		creds = []Credential{}
	}
	out, err := json.Marshal(envelope{Version: 1, Credentials: creds})
	if err != nil {
		return "", err
	}
	return string(out), nil
}

// Decode parses an envelope. It fails closed on an unknown version, an empty
// field, a bad kind or a duplicate ref.
func Decode(raw string) ([]Credential, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	var env envelope
	if err := json.Unmarshal([]byte(raw), &env); err != nil {
		return nil, fmt.Errorf("task credentials: %w", err)
	}
	if env.Version != 1 {
		return nil, fmt.Errorf("task credentials: unsupported version %d", env.Version)
	}
	seen := map[string]bool{}
	for i := range env.Credentials {
		c := &env.Credentials[i]
		c.Ref = strings.TrimSpace(c.Ref)
		if c.Ref == "" || strings.TrimSpace(c.Username) == "" || c.Secret == "" {
			return nil, errors.New("task credentials: ref, username and secret are required")
		}
		if c.Kind == "" {
			c.Kind = KindPassword
		}
		if c.Kind != KindPassword && c.Kind != KindNTLM {
			return nil, fmt.Errorf("task credentials: unsupported kind %q for ref %s", c.Kind, c.Ref)
		}
		if seen[c.Ref] {
			return nil, fmt.Errorf("task credentials: duplicate ref %s", c.Ref)
		}
		seen[c.Ref] = true
	}
	return env.Credentials, nil
}

// FromEnv builds the store from the injected environment. An absent variable is
// not an error: the server runs in anonymous mode and refuses credential_ref.
func FromEnv() (*Store, error) {
	creds, err := Decode(os.Getenv(EnvCredentials))
	if err != nil {
		return nil, err
	}
	return newStore(creds), nil
}

// Store resolves a credential_ref to one account. Secrets never leave it except
// through Get, and callers must not copy them into a result.
type Store struct {
	byRef map[string]Credential
}

func newStore(creds []Credential) *Store {
	s := &Store{byRef: make(map[string]Credential, len(creds))}
	for _, c := range creds {
		s.byRef[c.Ref] = c
	}
	return s
}

// NewStore builds a store from decoded credentials (tests and servers).
func NewStore(creds []Credential) *Store { return newStore(creds) }

// Len is the number of available accounts.
func (s *Store) Len() int {
	if s == nil {
		return 0
	}
	return len(s.byRef)
}

// Get resolves one ref.
func (s *Store) Get(ref string) (Credential, bool) {
	if s == nil {
		return Credential{}, false
	}
	c, ok := s.byRef[strings.TrimSpace(ref)]
	return c, ok
}

// Refs lists the available refs with their domain (never a username or secret),
// so an error message can tell the model which ids it may pass.
func (s *Store) Refs() []Ref {
	if s == nil {
		return nil
	}
	out := make([]Ref, 0, len(s.byRef))
	for ref, c := range s.byRef {
		out = append(out, Ref{Ref: ref, Domain: c.Domain, Kind: c.Kind})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Ref < out[j].Ref })
	return out
}

// Ref is the non-secret identity of a credential in a tool result.
type Ref struct {
	Ref    string `json:"ref"`
	Domain string `json:"domain,omitempty"`
	Kind   string `json:"kind"`
}

// UnknownRefError tells the model which refs it may use, without leaking a
// username or a secret.
func (s *Store) UnknownRefError(ref string) error {
	available := s.Refs()
	if len(available) == 0 {
		return fmt.Errorf("credential_ref %q is unknown and this task has no stored credential: ask the operator for a test account, or run the check anonymously", ref)
	}
	names := make([]string, len(available))
	for i, r := range available {
		names[i] = r.Ref
	}
	return fmt.Errorf("credential_ref %q is unknown; available refs: %s", ref, strings.Join(names, ", "))
}
