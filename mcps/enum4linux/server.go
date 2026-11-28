// Package enum4linux implements ARTEX's bounded enum4linux-ng enumeration server
// (issue #17). One tool, enumerate, runs the tool's own JSON-exporting run
// inside the signed mission scope and returns objects plus the checks that were
// attempted, skipped, denied or unsupported. The JSON export carries the
// credential in clear, so it is stripped before it is stored or returned.
package enum4linux

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/artex/mcps/adcore"
	"github.com/Autumn-27/artex/mcps/mcpserver"
	"github.com/Autumn-27/artex/scope"
)

// DefaultTimeout is the 10-minute budget of one enumerate call.
const DefaultTimeout = 10 * time.Minute

// Operation is the scope operation name this server charges.
const Operation = "enumerate"

// Profiles: inventory is the tool's own "-A" set; deep adds group members and a
// bounded RID cycle.
const (
	ProfileInventory = "inventory"
	ProfileDeep      = "deep"
)

// Runner executes enum4linux-ng. Tests inject a fake.
type Runner func(ctx context.Context, name string, args []string, env []string) (stdout, stderr []byte, err error)

// Server holds the guard, credential store and artifact directory.
type Server struct {
	Guard       *scope.Guard
	Runner      Runner
	Resolve     scope.Resolver
	Creds       *adcore.Store
	ArtifactDir string
	Binary      string
	Timeout     time.Duration
	Now         func() time.Time
}

// Request is the closed input of enumerate.
type Request struct {
	TargetRef     string `json:"target_ref"`
	CredentialRef string `json:"credential_ref,omitempty"`
	ProfileRef    string `json:"profile_ref,omitempty"`
}

// Result is the parsed enumeration returned to the model.
type Result struct {
	Target     string             `json:"target"`
	Profile    string             `json:"profile"`
	Credential *adcore.Ref        `json:"credential,omitempty"`
	Auth       adcore.AuthResult  `json:"auth"`
	Domains    []adcore.Domain    `json:"domains,omitempty"`
	Hosts      []adcore.Host      `json:"hosts,omitempty"`
	Shares     []adcore.Share     `json:"shares,omitempty"`
	Objects    adcore.Objects     `json:"objects"`
	Coverage   adcore.Coverage    `json:"coverage"`
	Candidates []adcore.Candidate `json:"candidates,omitempty"`
	Evidence   []string           `json:"evidence,omitempty"`
	Stopped    *adcore.Stop       `json:"stopped,omitempty"`
	Artifacts  map[string]string  `json:"artifacts,omitempty"`
	Note       string             `json:"note"`
	Warnings   []string           `json:"warnings,omitempty"`
}

// New builds a server. A nil runner uses the enum4linux-ng binary from PATH.
func New(guard *scope.Guard, creds *adcore.Store, artifactDir string) *Server {
	return &Server{
		Guard:       guard,
		Creds:       creds,
		Runner:      execRunner,
		Resolve:     netResolver,
		ArtifactDir: artifactDir,
		Binary:      "enum4linux-ng",
		Timeout:     DefaultTimeout,
		Now:         time.Now,
	}
}

func execRunner(ctx context.Context, name string, args []string, env []string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = env
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return []byte(out.String()), []byte(errb.String()), err
}

func netResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// Enumerate validates, scopes, runs and parses one bounded enumeration.
func (s *Server) Enumerate(ctx context.Context, req Request) (Result, error) {
	if s == nil || s.Guard == nil {
		return Result{}, fmt.Errorf("enum4linux: no mission guard configured")
	}
	profile := strings.ToLower(strings.TrimSpace(req.ProfileRef))
	if profile == "" {
		profile = ProfileInventory
	}
	if profile != ProfileInventory && profile != ProfileDeep {
		return Result{}, errors.New("profile_ref must be inventory or deep")
	}
	target, ok := scope.Normalize(strings.TrimSpace(req.TargetRef))
	if !ok {
		return Result{}, errors.New("invalid target_ref")
	}
	if target.Kind == scope.TargetDomain && strings.ContainsAny(target.Host, " \t\n") {
		return Result{}, errors.New("invalid target_ref")
	}
	if target.Kind == scope.TargetCIDR {
		return Result{}, errors.New("target_ref must be a single host or IP, not a CIDR: enum4linux-ng enumerates one host")
	}

	cred, credRef, err := s.resolveCredential(req.CredentialRef)
	if err != nil {
		return Result{}, err
	}

	var dns []netip.Addr
	arg := target.Host
	if target.Kind == scope.TargetDomain {
		dns, err = scope.ResolveTargets(ctx, s.Resolve, target)
		if err != nil {
			return Result{}, fmt.Errorf("resolve %s: %w", target.Host, err)
		}
		if len(dns) > 0 {
			arg = dns[0].String()
		}
	}

	sreq := scope.Request{Operation: Operation, Target: target, DNS: dns}
	d := s.Guard.Check(ctx, sreq)
	if !d.Allow {
		return Result{}, scope.ToolError(d)
	}
	d, err = s.Guard.Charge(ctx, sreq, d)
	if err != nil || !d.Allow {
		return Result{}, scope.ToolError(d)
	}
	charged := true
	defer func() {
		if charged {
			_ = s.Guard.Ledger.Release(s.Guard.Manifest.MissionID, s.Guard.Manifest.Server, 1)
		}
	}()

	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	work, err := os.MkdirTemp("", "artex-e4l-")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(work)

	args := []string{arg, "-t", "5", "-oJ", filepath.Join(work, "out")}
	if profile == ProfileDeep {
		args = append(args, "-A", "-Gm", "-R")
	} else {
		args = append(args, "-A")
	}
	secrets := []string{}
	if cred != nil {
		secrets = append(secrets, cred.Secret)
		if cred.Kind == adcore.KindNTLM {
			args = append(args, "-u", cred.Username, "-H", cred.Secret)
		} else {
			args = append(args, "-u", cred.Username, "-p", cred.Secret)
		}
		if cred.Domain != "" {
			args = append(args, "-w", cred.Domain)
		}
	}

	stdout, stderr, runErr := s.Runner(runCtx, s.Binary, args, childEnv())

	res := Result{
		Target:  target.Host,
		Profile: profile,
		Auth:    adcore.AuthResult{Outcome: "anonymous", Attempts: 0},
		Objects: adcore.Objects{},
	}
	if cred != nil {
		ref := adcore.Ref{Ref: credRef, Domain: cred.Domain, Kind: cred.Kind}
		res.Credential = &ref
		res.Auth = adcore.AuthResult{Outcome: "success", Attempts: 1}
	}

	raw, jsonErr := os.ReadFile(filepath.Join(work, "out.json"))
	if jsonErr != nil {
		res.Warnings = append(res.Warnings, "enum4linux-ng produced no JSON export: "+jsonErr.Error())
	}
	parsed, perr := parseExport(raw, target.Host, profile)
	if perr != nil {
		res.Coverage.Fail("export", perr.Error())
	} else {
		res.Domains = parsed.Domains
		res.Hosts = parsed.Hosts
		res.Shares = parsed.Shares
		res.Objects = parsed.Objects
		res.Coverage = parsed.Coverage
		res.Candidates = parsed.Candidates
		res.Auth.Outcome = parsed.AuthOutcome(res.Auth.Outcome)
		res.Auth.LockoutThreshold = parsed.LockoutThreshold
	}
	if perr == nil && len(raw) > 0 {
		cleaned := parsed.redactedJSON
		path, aerr := adcore.WriteArtifact(s.ArtifactDir, "enum4linux", "json", cleaned, s.Now())
		if aerr != nil {
			res.Warnings = append(res.Warnings, "JSON artifact not saved: "+aerr.Error())
		} else {
			res.Artifacts = map[string]string{"raw_json": path}
		}
	}

	// Evidence: the tool's own success/failure lines, redacted, so a fact can
	// quote them verbatim.
	for _, line := range strings.Split(string(stdout), "\n") {
		line = strings.TrimSpace(adcore.Redact(line, secrets...))
		if strings.HasPrefix(line, "[+]") || strings.HasPrefix(line, "[-]") {
			if len(res.Evidence) < 40 {
				res.Evidence = append(res.Evidence, line)
			}
		}
	}
	if text := strings.TrimSpace(string(stderr)); text != "" {
		res.Warnings = append(res.Warnings, adcore.Tail(adcore.Redact(text, secrets...), 2000))
	}
	if runErr != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			res.Stopped = &adcore.Stop{Reason: adcore.ReasonTimeBudget, Detail: fmt.Sprintf("stopped after %s", timeout)}
		} else {
			res.Warnings = append(res.Warnings, "enum4linux-ng exited with an error; the parsed output is partial")
		}
		res.Coverage.Fail("run", runErr.Error())
	}
	if res.Stopped == nil && len(res.Coverage.Collected) == 0 {
		res.Stopped = &adcore.Stop{Reason: "no_data", Detail: "no check produced data; see coverage for the reasons"}
	}

	res.Note = "Raw observations from a bounded enumeration. A candidate is a lead, never a confirmed vulnerability; an absent object means 'not observed', not 'absent from the domain'."
	charged = false
	return res, nil
}

func (s *Server) resolveCredential(ref string) (*adcore.Credential, string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, "", nil
	}
	if s.Creds == nil {
		return nil, "", errors.New("no task credential is available in this run: omit credential_ref for an anonymous enumeration")
	}
	c, ok := s.Creds.Get(ref)
	if !ok {
		return nil, "", s.Creds.UnknownRefError(ref)
	}
	return &c, c.Ref, nil
}

// childEnv is the complete environment of the tool: no ARTEX_* variable crosses.
func childEnv() []string {
	keep := []string{"PATH", "HOME", "LANG", "LANGUAGE", "TMPDIR", "TERM", "NO_COLOR"}
	env := make([]string, 0, len(keep)+1)
	for _, k := range keep {
		if v, ok := os.LookupEnv(k); ok && v != "" {
			env = append(env, k+"="+v)
		}
	}
	return append(env, "PYTHONUNBUFFERED=1")
}

// ToolDescription is the model-facing description of enumerate.
const ToolDescription = "Enumerate one SMB/Samba host with enum4linux-ng inside the signed mission scope (read-only). Inputs are closed: target_ref (one host or IP), optional credential_ref (an id from list_task_credentials; the secret never appears in the result), optional profile_ref (inventory|deep). Returns domain/host info, shares, users/groups/computers and an explicit coverage split (collected / not_collected / permission_denied / unsupported / failed). The raw JSON export is stored redacted. A candidate is not a confirmed finding."

// ToolSchema is the input schema; additionalProperties is false.
func ToolSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"target_ref":     map[string]any{"type": "string", "description": "One host or IP inside the mission scope."},
			"credential_ref": map[string]any{"type": "string", "description": "id of a task credential; omit for a null-session enumeration."},
			"profile_ref":    map[string]any{"type": "string", "enum": []string{ProfileInventory, ProfileDeep}, "description": "inventory (default) or deep (adds group members and a bounded RID cycle)."},
		},
		"required":             []string{"target_ref"},
		"additionalProperties": false,
	}
}

func decodeRequest(raw json.RawMessage) (Request, error) {
	var req Request
	if err := mcpserver.DecodeStrict(raw, &req); err != nil {
		return req, err
	}
	if strings.TrimSpace(req.TargetRef) == "" {
		return req, errors.New("target_ref is required")
	}
	return req, nil
}

// Serve runs the stdio MCP loop with the single bounded enumerate tool.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	return mcpserver.Serve(ctx, in, out, "enum4linux", mcpserver.Tool{
		Name:        "enumerate",
		Description: ToolDescription,
		Schema:      ToolSchema(),
		Call: func(ctx context.Context, raw json.RawMessage) (any, error) {
			req, err := decodeRequest(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid enumerate input: %w", err)
			}
			return s.Enumerate(ctx, req)
		},
	})
}
