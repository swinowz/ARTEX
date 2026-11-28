// Package netexec implements ARTEX's bounded NetExec inventory server (issue
// #17). One tool, inventory, enumerates a closed set of read-only AD/SMB checks
// inside the signed mission scope, returns structured objects with an explicit
// coverage split, and never returns a credential.
package netexec

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

// DefaultTimeout is the 10-minute budget of one inventory call.
const DefaultTimeout = 10 * time.Minute

const (
	maxTargetRefs      = 16
	maxTargetAddresses = 256
)

// Operation is the scope operation name this server charges.
const Operation = "inventory"

// Runner executes the NetExec binary. Tests inject a fake.
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

// Request is the closed input of inventory.
type Request struct {
	TargetRefs    []string `json:"target_refs"`
	Protocol      string   `json:"protocol,omitempty"`       // smb | ldap
	CredentialRef string   `json:"credential_ref,omitempty"` // id of a task credential
	ProfileRef    string   `json:"profile_ref,omitempty"`    // inventory | deep
}

// Result is the parsed inventory returned to the model.
type Result struct {
	Protocol   string            `json:"protocol"`
	Profile    string            `json:"profile"`
	Targets    []string          `json:"targets"`
	Credential *adcore.Ref       `json:"credential,omitempty"`
	Auth       AuthResult        `json:"auth"`
	Domains    []Domain          `json:"domains,omitempty"`
	Hosts      []Host            `json:"hosts,omitempty"`
	Shares     []Share           `json:"shares,omitempty"`
	Objects    Objects           `json:"objects"`
	Access     []Access          `json:"access,omitempty"`
	Coverage   adcore.Coverage   `json:"coverage"`
	Candidates []Candidate       `json:"candidates,omitempty"`
	Evidence   []string          `json:"evidence,omitempty"`
	Stopped    *Stop             `json:"stopped,omitempty"`
	Artifacts  map[string]string `json:"artifacts,omitempty"`
	Note       string            `json:"note"`
	Warnings   []string          `json:"warnings,omitempty"`
}

// The inventory wire format lives in adcore so both AD servers return the same
// shapes (adcore/result.go).
type AuthResult = adcore.AuthResult
type Domain = adcore.Domain
type PasswordPolicy = adcore.PasswordPolicy
type Host = adcore.Host
type Share = adcore.Share
type Object = adcore.Object
type Objects = adcore.Objects
type Access = adcore.Access
type Candidate = adcore.Candidate
type Stop = adcore.Stop

// New builds a server. A nil runner uses the nxc binary from PATH.
func New(guard *scope.Guard, creds *adcore.Store, artifactDir string) *Server {
	return &Server{
		Guard:       guard,
		Creds:       creds,
		Runner:      execRunner,
		Resolve:     netResolver,
		ArtifactDir: artifactDir,
		Binary:      "nxc",
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

// scopeTarget is one approved target and what is passed to the tool.
type scopeTarget struct {
	ref    string
	label  string // for the result
	arg    string // IP, CIDR or hostname handed to the tool
	req    scope.Request
	charge scope.Decision
}

// Inventory validates, scopes, runs and parses one bounded enumeration.
func (s *Server) Inventory(ctx context.Context, req Request) (Result, error) {
	if s == nil || s.Guard == nil {
		return Result{}, fmt.Errorf("netexec: no mission guard configured")
	}
	protocol, profile, err := normalizeProtocolProfile(req.Protocol, req.ProfileRef)
	if err != nil {
		return Result{}, err
	}
	if len(req.TargetRefs) == 0 {
		return Result{}, errors.New("target_refs must name at least one target")
	}
	if len(req.TargetRefs) > maxTargetRefs {
		return Result{}, fmt.Errorf("too many targets (max %d per call)", maxTargetRefs)
	}

	cred, credRef, err := s.resolveCredential(req.CredentialRef, profile)
	if err != nil {
		return Result{}, err
	}

	targets, total, err := s.approveTargets(ctx, req.TargetRefs)
	if err != nil {
		return Result{}, err
	}
	if total > maxTargetAddresses {
		return Result{}, fmt.Errorf("targets cover more than %d addresses; split the work into approved slices", maxTargetAddresses)
	}

	// Charge every target before any side effect, and release the whole charge
	// when the run never happened.
	charged := 0
	committed := false
	defer func() {
		if !committed && charged > 0 {
			_ = s.Guard.Ledger.Release(s.Guard.Manifest.MissionID, s.Guard.Manifest.Server, charged)
		}
	}()
	for i := range targets {
		d, err := s.Guard.Charge(ctx, targets[i].req, targets[i].charge)
		if err != nil || !d.Allow {
			return Result{}, scope.ToolError(d)
		}
		targets[i].charge = d
		charged++
	}

	work, err := os.MkdirTemp("", "artex-netexec-")
	if err != nil {
		return Result{}, err
	}
	defer os.RemoveAll(work) // the workspace DB stores credentials: never keep it

	nxcPath := filepath.Join(work, "nxc")
	if err := s.prepareWorkspace(ctx, nxcPath); err != nil {
		return Result{}, err
	}

	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	args, exportPath, err := s.buildRun(work, protocol, profile, targets, cred)
	if err != nil {
		return Result{}, err
	}
	env := childEnv(nxcPath)

	res := Result{
		Protocol: protocol,
		Profile:  profile,
		Targets:  targetLabels(targets),
		Auth:     AuthResult{Outcome: "anonymous"},
		Objects:  Objects{},
	}
	if cred != nil {
		ref := adcore.Ref{Ref: credRef, Domain: cred.Domain, Kind: cred.Kind}
		res.Credential = &ref
	}

	stdout, stderr, runErr := s.Runner(runCtx, s.Binary, args, env)

	// Artifacts first: the log is the evidence source, redacted before it leaves
	// this process.
	secrets := adcore.SecretString(credList(cred))
	logText := adcore.Redact(string(stdout), secrets...)
	artifactPath, aerr := adcore.WriteArtifact(s.ArtifactDir, "netexec", "log", []byte(logText), s.Now())
	if aerr == nil {
		res.Artifacts = map[string]string{"log": artifactPath}
	} else {
		res.Warnings = append(res.Warnings, "log artifact not saved: "+aerr.Error())
	}

	x := extractInput{
		Protocol: protocol,
		Profile:  profile,
		Stdout:   logText, // redacted: evidence lines are what the model receives
		WorkDir:  work,
		Export:   exportPath,
	}
	applyExtraction(&res, extract(x))

	// The DB was read above; the temp dir is removed by the deferred cleanup.

	if text := strings.TrimSpace(string(stderr)); text != "" {
		res.Warnings = append(res.Warnings, adcore.Tail(adcore.Redact(text, secrets...), 2000))
	}
	if runErr != nil {
		if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
			res.Stopped = &Stop{Reason: adcore.ReasonTimeBudget, Detail: fmt.Sprintf("stopped after %s", timeout)}
		} else {
			res.Warnings = append(res.Warnings, "nxc exited with an error; the parsed output is partial")
		}
		res.Coverage.Fail("run", firstNonEmpty(strings.TrimSpace(string(stderr)), runErr.Error()))
	}

	switch res.Auth.Outcome {
	case "account_locked_out":
		res.Stopped = &Stop{Reason: "account_locked_out", Detail: "the target reported the account is locked: no further attempt was made"}
	case "logon_failure":
		res.Stopped = &Stop{Reason: "authentication_failed", Detail: "the credential was refused: remaining authenticated checks are not collected"}
	}
	if res.Stopped == nil && res.Coverage.Collected == nil {
		res.Stopped = &Stop{Reason: "no_data", Detail: "no check produced data; see coverage for the reasons"}
	}

	res.Note = "Raw observations from a bounded read-only enumeration. A candidate is a lead, never a confirmed vulnerability; an absent object means 'not observed', not 'absent from the domain'."
	committed = true // the operation ran: keep the budget charged
	return res, nil
}

// approveTargets normalises and authorises every target before anything runs.
func (s *Server) approveTargets(ctx context.Context, refs []string) ([]scopeTarget, int, error) {
	out := make([]scopeTarget, 0, len(refs))
	total := 0
	for _, raw := range refs {
		t, ok := scope.Normalize(strings.TrimSpace(raw))
		if !ok {
			return nil, 0, fmt.Errorf("invalid target %q", raw)
		}
		if t.Kind == scope.TargetDomain && strings.ContainsAny(t.Host, " \t\n") {
			return nil, 0, fmt.Errorf("invalid target %q", raw)
		}
		n, err := targetAddressCount(t)
		if err != nil {
			return nil, 0, err
		}
		total += n

		var dns []netip.Addr
		arg := t.Host
		if t.Kind == scope.TargetDomain {
			dns, err = scope.ResolveTargets(ctx, s.Resolve, t)
			if err != nil {
				return nil, 0, fmt.Errorf("resolve %s: %w", t.Host, err)
			}
			// Pin the address the guard approved instead of letting the tool
			// resolve the name a second time.
			if len(dns) > 0 {
				arg = dns[0].String()
			}
		}
		sreq := scope.Request{Operation: Operation, Target: t, DNS: dns}
		d := s.Guard.Check(ctx, sreq)
		if !d.Allow {
			return nil, 0, scope.ToolError(d)
		}
		out = append(out, scopeTarget{ref: raw, label: raw, arg: arg, req: sreq, charge: d})
	}
	return out, total, nil
}

func targetAddressCount(t scope.Target) (int, error) {
	if t.Kind != scope.TargetCIDR {
		return 1, nil
	}
	p, err := netip.ParsePrefix(t.Host)
	if err != nil {
		return 0, fmt.Errorf("invalid CIDR %q", t.Host)
	}
	bits := 128 - p.Bits()
	if p.Addr().Is4() {
		bits = 32 - p.Bits()
	}
	if bits > 20 {
		return 0, fmt.Errorf("CIDR %s is too large", t.Host)
	}
	return 1 << bits, nil
}

func targetLabels(in []scopeTarget) []string {
	out := make([]string, len(in))
	for i, t := range in {
		out[i] = t.label
	}
	return out
}

func normalizeProtocolProfile(protocol, profile string) (string, string, error) {
	protocol = strings.ToLower(strings.TrimSpace(protocol))
	if protocol == "" {
		protocol = "smb"
	}
	if protocol != "smb" && protocol != "ldap" {
		return "", "", errors.New("protocol must be smb or ldap")
	}
	profile = strings.ToLower(strings.TrimSpace(profile))
	if profile == "" {
		profile = ProfileInventory
	}
	if profile != ProfileInventory && profile != ProfileDeep {
		return "", "", errors.New("profile_ref must be inventory or deep")
	}
	return protocol, profile, nil
}

func (s *Server) resolveCredential(ref, profile string) (*adcore.Credential, string, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		if profile == ProfileDeep {
			return nil, "", errors.New("profile_ref deep needs a credential_ref: it cannot run anonymously")
		}
		return nil, "", nil
	}
	if s.Creds == nil {
		return nil, "", fmt.Errorf("no task credential is available in this run: pass an empty credential_ref for an anonymous enumeration")
	}
	c, ok := s.Creds.Get(ref)
	if !ok {
		return nil, "", s.Creds.UnknownRefError(ref)
	}
	return &c, c.Ref, nil
}

func credList(c *adcore.Credential) []adcore.Credential {
	if c == nil {
		return nil
	}
	return []adcore.Credential{*c}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return "unknown error"
}

// prepareWorkspace lets NetExec create its first-run layout (protocol databases,
// default config) and then turns audit_mode on, which masks the password in the
// success line. Writing the config beforehand would skip the first-run setup and
// leave NetExec without its tables, so the setup runs once, bounded, first.
func (s *Server) prepareWorkspace(ctx context.Context, nxcPath string) error {
	if err := os.MkdirAll(nxcPath, 0o700); err != nil {
		return err
	}
	prepCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	_, stderr, err := s.Runner(prepCtx, s.Binary, []string{"--version"}, childEnv(nxcPath))
	if err != nil {
		return fmt.Errorf("netexec is not usable: %v: %s", err, adcore.Tail(strings.TrimSpace(string(stderr)), 300))
	}
	confPath := filepath.Join(nxcPath, "nxc.conf")
	raw, err := os.ReadFile(confPath)
	if err != nil {
		return fmt.Errorf("netexec did not create its configuration: %w", err)
	}
	if err := os.WriteFile(confPath, []byte(maskPasswordsInConfig(string(raw))), 0o600); err != nil {
		return err
	}
	return nil
}

// maskPasswordsInConfig sets audit_mode in an nxc config. The value is used as
// the mask itself (nxc/config.py process_secret), so it reads as "********".
func maskPasswordsInConfig(conf string) string {
	lines := strings.Split(conf, "\n")
	replaced := false
	for i, line := range lines {
		if strings.HasPrefix(strings.TrimSpace(line), "audit_mode") && strings.Contains(line, "=") {
			lines[i] = "audit_mode = ********"
			replaced = true
		}
	}
	if !replaced {
		for i, line := range lines {
			if strings.TrimSpace(line) == "[nxc]" {
				lines = append(lines[:i+1], append([]string{"audit_mode = ********"}, lines[i+1:]...)...)
				break
			}
		}
	}
	return strings.Join(lines, "\n")
}

// buildRun returns the argv of the inventory run. The child environment is built
// separately so no ARTEX_* variable crosses.
func (s *Server) buildRun(work, protocol, profile string, targets []scopeTarget, cred *adcore.Credential) (args []string, exportPath string, err error) {
	exportPath = filepath.Join(work, "users.txt")

	args = []string{protocol, "--no-progress", "--users-export", exportPath}
	args = append(args, checkArgs(protocol, profile)...)

	if cred != nil {
		secretPath := filepath.Join(work, "secret")
		if err := os.WriteFile(secretPath, []byte(cred.Secret), 0o600); err != nil {
			return nil, "", err
		}
		if cred.Kind == adcore.KindNTLM {
			args = append(args, "-H", secretPath)
		} else {
			args = append(args, "-p", secretPath)
		}
		args = append(args, "-u", cred.Username, "--ufail-limit", "1", "-t", "1")
		if cred.Domain != "" {
			args = append(args, "-d", cred.Domain)
		}
	} else {
		args = append(args, "-t", "16")
	}
	if protocol == "smb" {
		args = append(args, "--smb-timeout", "5")
	} else {
		args = append(args, "--ldap-timeout", "5")
	}
	for _, t := range targets {
		args = append(args, t.arg)
	}

	return args, exportPath, nil
}

// childEnv is the complete environment of the tool: the parent environment is
// not inherited, so ARTEX_TASK_CREDENTIALS never reaches nxc or its children.
func childEnv(nxcPath string) []string {
	keep := []string{"PATH", "HOME", "LANG", "LANGUAGE", "TMPDIR", "TERM", "NO_COLOR"}
	env := make([]string, 0, len(keep)+2)
	for _, k := range keep {
		if v, ok := os.LookupEnv(k); ok && v != "" {
			env = append(env, k+"="+v)
		}
	}
	env = append(env, "NXC_PATH="+nxcPath, "PYTHONUNBUFFERED=1")
	return env
}

// ToolDescription is the model-facing description of inventory.
const ToolDescription = "Enumerate a closed, read-only set of Active Directory / SMB inventory checks with NetExec inside the signed mission scope. Inputs are closed: target_refs (1-16 hosts/IPs/CIDRs, max 256 addresses), optional protocol (smb|ldap), optional credential_ref (an id from list_task_credentials; the secret never appears in the result) and optional profile_ref (inventory|deep). Returns domains, hosts, shares, users/groups/computers, access results and an explicit coverage split (collected / not_collected / permission_denied / unsupported / failed). No password spraying, no relay, no write, no credential dumping. A candidate is not a confirmed finding."

// ToolSchema is the input schema; additionalProperties is false.
func ToolSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"target_refs": map[string]any{
				"type":        "array",
				"items":       map[string]any{"type": "string"},
				"minItems":    1,
				"maxItems":    maxTargetRefs,
				"description": "Hosts, IPs or CIDRs (max 256 addresses total) inside the mission scope.",
			},
			"protocol":       map[string]any{"type": "string", "enum": []string{"smb", "ldap"}, "description": "smb (default) or ldap (enumerate a domain controller)."},
			"credential_ref": map[string]any{"type": "string", "description": "id of a task credential from list_task_credentials; omit for an anonymous/null-session enumeration."},
			"profile_ref":    map[string]any{"type": "string", "enum": []string{ProfileInventory, ProfileDeep}, "description": "inventory (default, read-only) or deep (read-only, adds rid-brute/sessions/delegation; needs a credential)."},
		},
		"required":             []string{"target_refs"},
		"additionalProperties": false,
	}
}

// decodeRequest rejects unknown fields so no flag can be smuggled in.
func decodeRequest(raw json.RawMessage) (Request, error) {
	var req Request
	if err := mcpserver.DecodeStrict(raw, &req); err != nil {
		return req, err
	}
	refs := make([]string, 0, len(req.TargetRefs))
	for _, r := range req.TargetRefs {
		if strings.TrimSpace(r) != "" {
			refs = append(refs, strings.TrimSpace(r))
		}
	}
	req.TargetRefs = refs
	if len(req.TargetRefs) == 0 {
		return req, errors.New("target_refs is required")
	}
	return req, nil
}

// applyExtraction copies the parsed inventory into the result.
func applyExtraction(res *Result, x extracted) {
	res.Auth = x.Auth
	res.Domains = x.Domains
	res.Hosts = x.Hosts
	res.Shares = x.Shares
	res.Objects = x.Objects
	res.Access = x.Access
	res.Candidates = x.Candidates
	res.Evidence = x.Evidence
	res.Coverage = x.Coverage
	res.Warnings = append(res.Warnings, x.Warnings...)
}

// Serve runs the stdio MCP loop with the single bounded inventory tool.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	return mcpserver.Serve(ctx, in, out, "netexec", mcpserver.Tool{
		Name:        "inventory",
		Description: ToolDescription,
		Schema:      ToolSchema(),
		Call: func(ctx context.Context, raw json.RawMessage) (any, error) {
			req, err := decodeRequest(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid inventory input: %w", err)
			}
			return s.Inventory(ctx, req)
		},
	})
}
