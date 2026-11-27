package scope

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Resolver resolves a name to the addresses the caller will actually use.
type Resolver func(ctx context.Context, host string) ([]netip.Addr, error)

// Request describes one operation a capability server is about to perform.
type Request struct {
	Operation    string
	Server       string // optional; defaults to the manifest audience
	Target       Target
	URL          string       // optional; normalised when Target is zero
	DNS          []netip.Addr // addresses the caller will dial; required for a domain
	RedirectFrom string       // set on a redirect hop
	Now          time.Time    // optional; defaults to the guard's clock
}

// Guard is the per-process entry point: one manifest, one budget ledger, one
// clock and one resolver. It is safe for concurrent use.
type Guard struct {
	Manifest *Manifest
	Ledger   BudgetLedger
	Now      func() time.Time
	Resolve  Resolver

	mu       sync.Mutex
	pins     map[string][]netip.Addr
	runs     map[string]int
	unscoped bool
}

// NewGuard validates the manifest and installs defaults. A nil ledger becomes
// an in-memory ledger built from the signed budget.
func NewGuard(m *Manifest, ledger BudgetLedger) (*Guard, error) {
	if m == nil {
		return nil, denyErr(CodeManifestInvalid, "manifest is nil")
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if ledger == nil {
		ledger = NewMemoryLedger(m.Budgets.TotalOps, m.Budgets.PerServer)
	}
	return &Guard{
		Manifest: m,
		Ledger:   ledger,
		Now:      time.Now,
		pins:     map[string][]netip.Addr{},
		runs:     map[string]int{},
	}, nil
}

// NewUnscoped returns a guard that refuses every operation. It exists only for
// a development server started with an explicit ARTEX_SCOPE_ALLOW_UNSCOPED=1;
// the caller must announce that it is unguarded.
func NewUnscoped() *Guard {
	return &Guard{Now: time.Now, pins: map[string][]netip.Addr{}, runs: map[string]int{}, unscoped: true}
}

// Unscoped reports whether this guard is the explicit development placeholder.
func (g *Guard) Unscoped() bool { return g == nil || g.unscoped }

// FromEnv loads the manifest path and pinned keys from ARTEX_SCOPE_MANIFEST and
// ARTEX_SCOPE_PUBKEY. Missing configuration fails closed unless the operator set
// ARTEX_SCOPE_ALLOW_UNSCOPED=1, which logs loudly and denies every operation.
func FromEnv() (*Guard, error) {
	manifestPath := strings.TrimSpace(os.Getenv("ARTEX_SCOPE_MANIFEST"))
	keyPath := strings.TrimSpace(os.Getenv("ARTEX_SCOPE_PUBKEY"))
	if manifestPath == "" || keyPath == "" {
		if os.Getenv("ARTEX_SCOPE_ALLOW_UNSCOPED") == "1" {
			log.Printf("[scope] WARNING: unscoped development mode; every operation is denied. Set ARTEX_SCOPE_MANIFEST and ARTEX_SCOPE_PUBKEY for a real mission.")
			return NewUnscoped(), nil
		}
		return nil, fmt.Errorf("scope: ARTEX_SCOPE_MANIFEST and ARTEX_SCOPE_PUBKEY are required (or set ARTEX_SCOPE_ALLOW_UNSCOPED=1 for a development server that denies all operations)")
	}
	keys, err := LoadKeys(keyPath)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	m, err := LoadManifest(manifestPath, keys, now)
	if err != nil {
		return nil, err
	}
	return NewGuard(m, nil)
}

// Check decides whether req is inside the signed mission. It has no side
// effect other than pinning the first DNS answer it sees. Charge reserves the
// budget immediately before the operation runs.
func (g *Guard) Check(ctx context.Context, req Request) Decision {
	if g.Unscoped() {
		return Deny(CodeManifestInvalid, "server is running unscoped; configure a signed mission manifest")
	}
	m := g.Manifest
	now := req.Now
	if now.IsZero() {
		now = g.Now()
	}
	if now.Before(m.NotBefore) || !now.Before(m.NotAfter) {
		return Deny(CodeManifestExpired, "mission is not active at "+now.Format(time.RFC3339))
	}
	server := req.Server
	if server == "" {
		server = m.Server
	}
	if server != m.Server {
		return Deny(CodeServerNotAudience, fmt.Sprintf("manifest is for server %q, not %q", m.Server, server))
	}
	policy, ok := m.Operations[req.Operation]
	if !ok || !policy.Allowed {
		return Deny(CodeOperationDenied, fmt.Sprintf("operation %q is not granted", req.Operation))
	}
	if policy.RequiresApproval {
		return Deny(CodeApprovalRequired, fmt.Sprintf("operation %q requires operator approval", req.Operation))
	}
	g.mu.Lock()
	ran := g.runs[req.Operation]
	g.mu.Unlock()
	if policy.MaxPerRun > 0 && ran >= policy.MaxPerRun {
		return Deny(CodeScopeDenied, fmt.Sprintf("operation %q reached max_per_run=%d", req.Operation, policy.MaxPerRun))
	}

	t := req.Target
	if t.Kind == "" {
		if req.URL == "" {
			return Deny(CodeScopeDenied, "operation declares no target")
		}
		var ok bool
		if t, ok = Normalize(req.URL); !ok {
			return Deny(CodeScopeDenied, fmt.Sprintf("target URL %q cannot be normalised", req.URL))
		}
	}

	var dns []netip.Addr
	if t.Kind == TargetDomain {
		var d Decision
		dns, d = g.resolvePinned(ctx, t.Host, req.DNS)
		if !d.Allow {
			return d
		}
	}

	// Exclusions outrank every allow, regardless of specificity.
	for _, r := range m.Excluded {
		if ruleExcludes(r, t, dns) {
			return Decision{Code: CodeScopeDenied, Excluded: true, Rule: r.Kind + ":" + r.Value,
				Reason: fmt.Sprintf("%s is excluded by %s %s", t, r.Kind, r.Value)}
		}
	}

	if t.Kind == TargetDomain {
		domainAllowed := false
		for _, r := range m.Allowed {
			if r.Kind == TargetDomain && ruleMatches(r, t, dns) {
				domainAllowed = true
				break
			}
		}
		if !domainAllowed {
			for _, addr := range dns {
				if !anyRuleMatches(m.Allowed, Target{Kind: TargetIP, Host: addr.String(), Port: t.Port}) {
					return Deny(CodeScopeDenied, fmt.Sprintf("%s resolved to %s, which no rule allows", t, addr))
				}
			}
			if len(dns) == 0 {
				return Deny(CodeDNSFailed, fmt.Sprintf("%s did not resolve", t))
			}
		}
	} else if !anyRuleMatches(m.Allowed, t) {
		return Deny(CodeScopeDenied, fmt.Sprintf("%s is outside the signed scope", t))
	}

	return Decision{Allow: true, Remaining: g.remaining(server)}
}

func (g *Guard) resolvePinned(ctx context.Context, host string, supplied []netip.Addr) ([]netip.Addr, Decision) {
	dns := canonicalAddrs(supplied)
	if len(dns) == 0 {
		g.mu.Lock()
		pinned, ok := g.pins[host]
		g.mu.Unlock()
		if ok {
			return pinned, Decision{Allow: true}
		}
		if g.Resolve == nil {
			return nil, Deny(CodeDNSFailed, fmt.Sprintf("no resolver configured for %q", host))
		}
		got, err := g.Resolve(ctx, host)
		if err != nil {
			return nil, Deny(CodeDNSFailed, fmt.Sprintf("resolve %q: %v", host, err))
		}
		dns = canonicalAddrs(got)
		if len(dns) == 0 {
			return nil, Deny(CodeDNSFailed, fmt.Sprintf("%q returned no address", host))
		}
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if prev, ok := g.pins[host]; ok {
		if !sameAddrs(prev, dns) {
			return nil, Deny(CodeDNSChanged, fmt.Sprintf("%q now resolves to %v, earlier %v", host, dns, prev))
		}
		return prev, Decision{Allow: true}
	}
	g.pins[host] = dns
	return dns, Decision{Allow: true}
}

// Charge re-checks req and reserves one operation from the mission budget. It
// must be called once, immediately before the side effect; Release it only if
// the operation never ran.
func (g *Guard) Charge(ctx context.Context, req Request, d Decision) (Decision, error) {
	if !d.Allow {
		return d, nil
	}
	again := g.Check(ctx, req)
	if !again.Allow {
		return again, nil
	}
	server := req.Server
	if server == "" {
		server = g.Manifest.Server
	}
	remaining, err := g.Ledger.Reserve(g.Manifest.MissionID, server, 1)
	if err != nil {
		if code := CodeOf(err); code != "" {
			return Deny(code, err.Error()), nil
		}
		return Deny(CodeBudgetExhausted, err.Error()), err
	}
	g.mu.Lock()
	g.runs[req.Operation]++
	g.mu.Unlock()
	return Decision{Allow: true, Remaining: remaining}, nil
}

func (g *Guard) remaining(server string) int {
	if g.Ledger == nil {
		return -1
	}
	spent, err := g.Ledger.Spent(g.Manifest.MissionID, server)
	if err != nil {
		return -1
	}
	alloc, ok := g.Manifest.Budgets.PerServer[server]
	if !ok {
		if g.Manifest.Budgets.TotalOps == 0 && len(g.Manifest.Budgets.PerServer) == 0 {
			return -1 // unlimited
		}
		return 0
	}
	if left := alloc - spent; left > 0 {
		return left
	}
	return 0
}

// CheckRedirect re-runs the full decision on the redirect destination. A hop
// inherits no scope from the origin; a cross-host hop must be allowed on its
// own. Relative locations resolve against from.
func (g *Guard) CheckRedirect(ctx context.Context, from, to, op string) Decision {
	if base, err := url.Parse(from); err == nil {
		if ref, err := url.Parse(to); err == nil {
			to = base.ResolveReference(ref).String()
		}
	}
	d := g.Check(ctx, Request{Operation: op, URL: to, RedirectFrom: from})
	if !d.Allow {
		d.Reason = fmt.Sprintf("redirect from %s: %s", from, d.Reason)
		d.Code = CodeScopeDenied
		return d
	}
	// A cross-host hop must be explicitly allowed by name. Resolving into an
	// allowed IP range is not enough: a redirect is the classic way to hand an
	// in-scope URL to an attacker-controlled name.
	if t, ok := Normalize(to); ok && t.Kind == TargetDomain {
		allowed := false
		for _, r := range g.Manifest.Allowed {
			if r.Kind == TargetDomain && ruleMatches(r, t, nil) {
				allowed = true
				break
			}
		}
		if !allowed {
			return Deny(CodeScopeDenied, fmt.Sprintf("redirect from %s: %s is not an explicitly allowed domain", from, t))
		}
	}
	return d
}

// ToolError renders a deny for a tool result. It deliberately names the layer so
// an operator does not mistake it for the target's own defence.
func ToolError(d Decision) error {
	if d.Allow {
		return nil
	}
	msg := d.Code
	if d.Code == "" {
		msg = CodeScopeDenied
	}
	return &ToolDeniedError{Code: msg, Reason: d.Reason}
}

// ResolveTargets resolves t (a domain) through resolve and returns canonical
// addresses. IP and CIDR targets are returned as-is.
func ResolveTargets(ctx context.Context, resolve Resolver, t Target) ([]netip.Addr, error) {
	switch t.Kind {
	case TargetIP:
		a, ok := addrOf(t)
		if !ok {
			return nil, fmt.Errorf("scope: invalid IP %q", t.Host)
		}
		return []netip.Addr{a}, nil
	case TargetCIDR:
		return nil, fmt.Errorf("scope: a CIDR target has no single address")
	case TargetDomain:
		if resolve == nil {
			return nil, fmt.Errorf("scope: no resolver for %q", t.Host)
		}
		got, err := resolve(ctx, t.Host)
		if err != nil {
			return nil, err
		}
		out := canonicalAddrs(got)
		if len(out) == 0 {
			return nil, fmt.Errorf("scope: %q returned no address", t.Host)
		}
		return out, nil
	}
	return nil, fmt.Errorf("scope: unknown target kind %q", t.Kind)
}

func anyRuleMatches(rules []Rule, t Target, dns ...[]netip.Addr) bool {
	var addrs []netip.Addr
	if len(dns) > 0 {
		addrs = dns[0]
	}
	for _, r := range rules {
		if ruleMatches(r, t, addrs) {
			return true
		}
	}
	return false
}

func canonicalAddrs(in []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(in))
	for _, a := range in {
		if !a.IsValid() {
			continue
		}
		out = append(out, a.Unmap().WithZone(""))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Compare(out[j]) < 0 })
	// Remove duplicates so a resolver answering twice does not look like a change.
	uniq := out[:0]
	for i, a := range out {
		if i == 0 || a != out[i-1] {
			uniq = append(uniq, a)
		}
	}
	return uniq
}

func sameAddrs(a, b []netip.Addr) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
