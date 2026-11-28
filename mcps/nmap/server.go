// Package nmap implements ARTEX's bounded nmap capability server (issue #15).
//
// The server exposes one MCP tool, discover, and no free-form nmap arguments.
// Every target is validated against the signed mission scope before nmap runs
// (issue #14), the port set is bounded, and the raw XML is kept as an artifact
// while the model receives a parsed summary.
package nmap

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
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/artex/mcps/mcpserver"
	"github.com/Autumn-27/artex/scope"
)

// DefaultTimeout bounds one scan. The issue's budget is 15 minutes.
const DefaultTimeout = 15 * time.Minute

// maxTargetAddresses bounds a CIDR scan (4096 addresses).
const maxTargetAddresses = 4096

// Runner executes nmap. Tests inject a fake.
type Runner func(ctx context.Context, name string, args ...string) (stdout, stderr []byte, err error)

// Server holds the guard, runner and artifact directory.
type Server struct {
	Guard       *scope.Guard
	Runner      Runner
	Resolve     scope.Resolver
	ArtifactDir string
	Timeout     time.Duration
	Now         func() time.Time
}

// DiscoverRequest is the closed input of discover.
type DiscoverRequest struct {
	Target  string `json:"target"`
	Ports   string `json:"ports,omitempty"`
	Profile string `json:"profile,omitempty"` // "connect" (default) | "syn"
}

// Host is one scanned host.
type Host struct {
	Address  string    `json:"address"`
	State    string    `json:"state"`
	Reason   string    `json:"reason,omitempty"`
	Services []Service `json:"services,omitempty"`
}

// Service is one open port.
type Service struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	State    string `json:"state"`
	Name     string `json:"name,omitempty"`
	Product  string `json:"product,omitempty"`
	Version  string `json:"version,omitempty"`
	Extra    string `json:"extra,omitempty"`
}

// Result is the parsed scan summary returned to the model.
type Result struct {
	Target      string   `json:"target"`
	Profile     string   `json:"profile"`
	Ports       string   `json:"ports"`
	Hosts       []Host   `json:"hosts"`
	Observed    bool     `json:"observed"`
	Incomplete  bool     `json:"incomplete,omitempty"`
	RawArtifact string   `json:"raw_artifact,omitempty"`
	Note        string   `json:"note"`
	Warnings    []string `json:"warnings,omitempty"`
}

// New builds a server. A nil runner uses the nmap binary from PATH.
func New(guard *scope.Guard, artifactDir string) *Server {
	return &Server{
		Guard:       guard,
		Runner:      execRunner,
		Resolve:     netResolver,
		ArtifactDir: artifactDir,
		Timeout:     DefaultTimeout,
		Now:         time.Now,
	}
}

func execRunner(ctx context.Context, name string, args ...string) ([]byte, []byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	return []byte(out.String()), []byte(errb.String()), err
}

func netResolver(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// Discover validates, scopes, runs and parses one bounded nmap scan.
func (s *Server) Discover(ctx context.Context, req DiscoverRequest) (Result, error) {
	if s == nil || s.Guard == nil {
		return Result{}, fmt.Errorf("nmap: no mission guard configured")
	}
	target, ok := scope.Normalize(strings.TrimSpace(req.Target))
	if !ok {
		return Result{}, fmt.Errorf("invalid target")
	}
	if target.Kind == scope.TargetDomain && strings.ContainsAny(target.Host, " \t\n") {
		return Result{}, fmt.Errorf("invalid target")
	}
	profile := strings.ToLower(strings.TrimSpace(req.Profile))
	if profile == "" {
		profile = "connect"
	}
	if profile != "connect" && profile != "syn" {
		return Result{}, fmt.Errorf("profile must be connect or syn")
	}
	portFlags, portLabel, err := portArguments(req.Ports)
	if err != nil {
		return Result{}, err
	}
	if err := checkTargetSize(target); err != nil {
		return Result{}, err
	}

	// Resolve a name once and scan the addresses the guard approved, not the
	// name again: a second lookup could reach a different host.
	var dns []netip.Addr
	scanTargets := []string{target.Host}
	if target.Kind == scope.TargetDomain {
		dns, err = scope.ResolveTargets(ctx, s.Resolve, target)
		if err != nil {
			return Result{}, fmt.Errorf("resolve %s: %w", target.Host, err)
		}
		scanTargets = make([]string, 0, len(dns))
		for _, a := range dns {
			scanTargets = append(scanTargets, a.String())
		}
	}

	sreq := scope.Request{Operation: "discover", Target: target, DNS: dns}
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

	// nmap's duration parser accepts integer seconds, not Go's "15m0s".
	args := []string{"-Pn", "-n", "--max-retries", "2", "--host-timeout", strconv.Itoa(int(timeout.Seconds())) + "s", "-oX", "-"}
	if profile == "syn" {
		args = append(args, "-sS")
	} else {
		args = append(args, "-sT")
	}
	args = append(args, portFlags...)
	args = append(args, scanTargets...)

	xmlOut, stderr, runErr := s.Runner(runCtx, "nmap", args...)

	res := Result{Target: target.Host, Profile: profile, Ports: portLabel}
	parsed, parseErr := parseXML(xmlOut)
	if parseErr == nil {
		res.Hosts = parsed.Hosts
		res.Incomplete = parsed.Incomplete
		res.Observed = parsed.Observed
		if parsed.Warning != "" {
			res.Warnings = append(res.Warnings, parsed.Warning)
		}
	}
	if text := strings.TrimSpace(string(stderr)); text != "" {
		res.Warnings = append(res.Warnings, tail(text, 2000))
	}
	if runErr != nil {
		if parseErr != nil {
			return Result{}, fmt.Errorf("nmap failed: %v: %s", runErr, tail(string(stderr), 500))
		}
		res.Incomplete = true
		res.Warnings = append(res.Warnings, "nmap exited with an error; the parsed output is partial")
	}
	if parseErr != nil {
		return Result{}, fmt.Errorf("nmap XML: %w", parseErr)
	}
	if !res.Observed {
		res.Note = "No hosts or services were observed. This is not evidence that the target is absent or that no risk exists."
	} else if res.Incomplete {
		res.Note = "Scan output was incomplete; treat these observations as partial and re-run if the result matters."
	} else {
		res.Note = "Parsed nmap observations. A banner or open port is an observation, not a finding by itself."
	}

	if s.ArtifactDir != "" && len(xmlOut) > 0 {
		path, err := s.writeArtifact(xmlOut)
		if err != nil {
			res.Warnings = append(res.Warnings, "raw XML artifact not saved: "+err.Error())
		} else {
			res.RawArtifact = path
		}
	}
	charged = false // the operation ran; keep the budget charged
	return res, nil
}

func checkTargetSize(t scope.Target) error {
	if t.Kind != scope.TargetCIDR {
		return nil
	}
	p, err := netip.ParsePrefix(t.Host)
	if err != nil {
		return fmt.Errorf("invalid CIDR")
	}
	bits := 128 - p.Bits()
	if p.Addr().Is4() {
		bits = 32 - p.Bits()
	}
	if bits > 12 { // more than 4096 addresses
		return fmt.Errorf("CIDR target %s is too large for one scan (max 4096 addresses)", t.Host)
	}
	return nil
}

var commonPorts = []int{21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
	1433, 1521, 2049, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017}

// portArguments maps the closed port input to nmap flags. Presets are code-owned;
// an explicit list is bounded to 1024 ports.
func portArguments(raw string) ([]string, string, error) {
	raw = strings.TrimSpace(strings.ToLower(raw))
	switch raw {
	case "", "common":
		return []string{"-p", joinInts(commonPorts, ",")}, "common", nil
	case "top100":
		return []string{"--top-ports", "100"}, "top100", nil
	case "top1000":
		return []string{"--top-ports", "1000"}, "top1000", nil
	}
	var ports []int
	seen := map[int]bool{}
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "-") {
			a, b, ok := strings.Cut(part, "-")
			if !ok {
				return nil, "", fmt.Errorf("invalid port range %q", part)
			}
			lo, err1 := strconv.Atoi(a)
			hi, err2 := strconv.Atoi(b)
			if err1 != nil || err2 != nil || lo < 1 || hi > 65535 || lo > hi {
				return nil, "", fmt.Errorf("invalid port range %q", part)
			}
			if hi-lo+1 > 1024 {
				return nil, "", fmt.Errorf("port range %q is too large (max 1024 ports)", part)
			}
			for p := lo; p <= hi; p++ {
				if !seen[p] {
					seen[p] = true
					ports = append(ports, p)
				}
			}
			continue
		}
		p, err := strconv.Atoi(part)
		if err != nil || p < 1 || p > 65535 {
			return nil, "", fmt.Errorf("invalid port %q", part)
		}
		if !seen[p] {
			seen[p] = true
			ports = append(ports, p)
		}
	}
	if len(ports) == 0 {
		return nil, "", fmt.Errorf("ports must name at least one port or a preset")
	}
	if len(ports) > 1024 {
		return nil, "", fmt.Errorf("too many ports (max 1024)")
	}
	label := joinInts(ports, ",")
	return []string{"-p", label}, label, nil
}

func joinInts(in []int, sep string) string {
	parts := make([]string, len(in))
	for i, n := range in {
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, sep)
}

func (s *Server) writeArtifact(xmlOut []byte) (string, error) {
	if err := os.MkdirAll(s.ArtifactDir, 0o700); err != nil {
		return "", err
	}
	now := s.Now()
	name := fmt.Sprintf("nmap-%s.xml", now.UTC().Format("20060102T150405.000000000Z"))
	path := filepath.Join(s.ArtifactDir, name)
	if err := os.WriteFile(path, xmlOut, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}

// ToolDescription is the model-facing description of discover.
const ToolDescription = "Run one bounded nmap scan inside the signed mission scope. Inputs are closed: target (host, IP or CIDR up to 4096 addresses), optional ports (common|top100|top1000 or an explicit comma list/range, max 1024), and optional profile (connect|syn). There is no free-form argument passthrough. Returns parsed hosts and services plus the path of the raw XML artifact. No hosts/services observed means 'not observed', never 'no risk'."

// ToolSchema is the input schema; additionalProperties is false so a model
// cannot smuggle extra_args into nmap.
func ToolSchema() map[string]any {
	return map[string]any{
		"type": "object",
		"properties": map[string]any{
			"target":  map[string]any{"type": "string", "description": "Host, IP or CIDR inside the mission scope."},
			"ports":   map[string]any{"type": "string", "description": "common (default), top100, top1000, or an explicit list/range such as 22,80,443 or 1-1024. Max 1024 ports."},
			"profile": map[string]any{"type": "string", "enum": []string{"connect", "syn"}, "description": "connect (default, unprivileged) or syn (requires privileges)."},
		},
		"required":             []string{"target"},
		"additionalProperties": false,
	}
}

// decodeRequest rejects unknown fields so a stray extra_args is an error, not a
// silent no-op.
func decodeRequest(raw json.RawMessage) (DiscoverRequest, error) {
	var req DiscoverRequest
	if err := mcpserver.DecodeStrict(raw, &req); err != nil {
		return req, err
	}
	if strings.TrimSpace(req.Target) == "" {
		return req, errors.New("target is required")
	}
	return req, nil
}

// Serve runs the stdio MCP loop with the single bounded discover tool.
func (s *Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	return mcpserver.Serve(ctx, in, out, "nmap", mcpserver.Tool{
		Name:        "discover",
		Description: ToolDescription,
		Schema:      ToolSchema(),
		Call: func(ctx context.Context, raw json.RawMessage) (any, error) {
			req, err := decodeRequest(raw)
			if err != nil {
				return nil, fmt.Errorf("invalid discover input: %w", err)
			}
			return s.Discover(ctx, req)
		},
	})
}
