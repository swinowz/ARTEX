package scope

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var testNow = time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

func baseManifest() *Manifest {
	return &Manifest{
		Version:   ManifestVersion,
		MissionID: "mission-1",
		Server:    "nmap",
		IssuedAt:  testNow,
		NotBefore: testNow.Add(-time.Hour),
		NotAfter:  testNow.Add(time.Hour),
		Allowed: []Rule{
			{Kind: TargetCIDR, Value: "10.0.0.0/8"},
			{Kind: TargetDomain, Value: "example.com"},
		},
		Excluded: []Rule{
			{Kind: TargetCIDR, Value: "10.1.2.0/24"},
		},
		Operations: map[string]OperationPolicy{"scan": {Allowed: true}},
		Budgets:    Budget{TotalOps: 100, PerServer: map[string]int{"nmap": 50}},
	}
}

func signed(t *testing.T, m *Manifest) ([]byte, []PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	env, err := Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	return env, []PublicKey{{KeyID: KeyID(pub), Ed25519: pub}}
}

func newGuard(t *testing.T, m *Manifest) (*Guard, []PublicKey) {
	t.Helper()
	env, keys := signed(t, m)
	parsed, err := ParseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := parsed.Verify(keys, testNow)
	if err != nil {
		t.Fatal(err)
	}
	g, err := NewGuard(verified, nil)
	if err != nil {
		t.Fatal(err)
	}
	g.Now = func() time.Time { return testNow }
	return g, keys
}

func check(t *testing.T, g *Guard, req Request) Decision {
	t.Helper()
	if req.Now.IsZero() {
		req.Now = testNow
	}
	return g.Check(context.Background(), req)
}

func TestNormalizeTargets(t *testing.T) {
	cases := []struct {
		raw  string
		kind string
		host string
		port int
	}{
		{"https://user:pass@Example.COM:8443/x?q=1", TargetDomain, "example.com", 8443},
		{"http://example.com", TargetDomain, "example.com", 80},
		{"2130706433", TargetIP, "127.0.0.1", 0},
		{"0x7f000001", TargetIP, "127.0.0.1", 0},
		{"0177.0.0.1", TargetIP, "127.0.0.1", 0},
		{"127.1", TargetIP, "127.0.0.1", 0},
		{"::ffff:10.0.0.1", TargetIP, "10.0.0.1", 0},
		{"[2001:db8::1]:443", TargetIP, "2001:db8::1", 443},
		{"10.1.2.7/24", TargetCIDR, "10.1.2.0/24", 0},
	}
	for _, tc := range cases {
		got, ok := Normalize(tc.raw)
		if !ok || got.Kind != tc.kind || got.Host != tc.host || got.Port != tc.port {
			t.Errorf("Normalize(%q) = %+v, %v; want %s %s %d", tc.raw, got, ok, tc.kind, tc.host, tc.port)
		}
	}
}

func TestSignatureAndSchema(t *testing.T) {
	m := baseManifest()
	env, keys := signed(t, m)

	t.Run("valid", func(t *testing.T) {
		parsed, err := ParseEnvelope(env)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parsed.Verify(keys, testNow); err != nil {
			t.Fatalf("verify: %v", err)
		}
	})
	t.Run("tampered manifest", func(t *testing.T) {
		parsed, _ := ParseEnvelope(env)
		var raw map[string]any
		_ = json.Unmarshal(parsed.Manifest, &raw)
		raw["mission_id"] = "forged"
		parsed.Manifest, _ = json.Marshal(raw)
		if _, err := parsed.Verify(keys, testNow); CodeOf(err) != CodeManifestInvalid {
			t.Fatalf("tampered manifest: %v", err)
		}
	})
	t.Run("unknown key", func(t *testing.T) {
		parsed, _ := ParseEnvelope(env)
		parsed.KeyID = "nope"
		if _, err := parsed.Verify(keys, testNow); CodeOf(err) != CodeManifestUnsigned {
			t.Fatalf("unknown key: %v", err)
		}
	})
	t.Run("wrong alg", func(t *testing.T) {
		parsed, _ := ParseEnvelope(env)
		parsed.Alg = "hmac"
		if _, err := parsed.Verify(keys, testNow); CodeOf(err) != CodeManifestUnsigned {
			t.Fatalf("wrong alg: %v", err)
		}
	})
	t.Run("budget split above total", func(t *testing.T) {
		bad := baseManifest()
		bad.Budgets = Budget{TotalOps: 10, PerServer: map[string]int{"nmap": 11}}
		badEnv, badKeys := signed(t, bad)
		parsed, _ := ParseEnvelope(badEnv)
		if _, err := parsed.Verify(badKeys, testNow); CodeOf(err) != CodeManifestInvalid {
			t.Fatalf("over-split budget: %v", err)
		}
	})
	t.Run("time window", func(t *testing.T) {
		parsed, _ := ParseEnvelope(env)
		if _, err := parsed.Verify(keys, testNow.Add(2*time.Hour)); CodeOf(err) != CodeManifestExpired {
			t.Fatalf("expired: %v", err)
		}
		if _, err := parsed.Verify(keys, testNow.Add(-2*time.Hour)); CodeOf(err) != CodeManifestExpired {
			t.Fatalf("not yet active: %v", err)
		}
	})
}

func TestOutOfScopeAndExclusions(t *testing.T) {
	g, _ := newGuard(t, baseManifest())

	if d := check(t, g, Request{Operation: "scan", Target: Target{Kind: TargetIP, Host: "192.168.1.1"}}); d.Allow || d.Code != CodeScopeDenied {
		t.Fatalf("out of scope: %+v", d)
	}
	if d := check(t, g, Request{Operation: "scan", Target: Target{Kind: TargetIP, Host: "10.1.2.7"}}); d.Allow || !d.Excluded || d.Code != CodeScopeDenied {
		t.Fatalf("excluded CIDR inside an allowed parent: %+v", d)
	}
	if d := check(t, g, Request{Operation: "scan", Target: Target{Kind: TargetIP, Host: "10.1.3.7"}}); !d.Allow {
		t.Fatalf("allowed sibling: %+v", d)
	}
	// A whole subnet overlapping an exclusion is refused: scanning it would reach
	// the excluded addresses.
	if d := check(t, g, Request{Operation: "scan", Target: Target{Kind: TargetCIDR, Host: "10.0.0.0/8"}}); d.Allow || !d.Excluded {
		t.Fatalf("subnet overlapping an exclusion: %+v", d)
	}
	if d := check(t, g, Request{Operation: "scan", Target: Target{Kind: TargetCIDR, Host: "10.2.0.0/16"}}); !d.Allow {
		t.Fatalf("subnet without an exclusion: %+v", d)
	}
}

func TestIPv6(t *testing.T) {
	m := baseManifest()
	m.Allowed = []Rule{{Kind: TargetCIDR, Value: "10.0.0.0/8"}}
	g, _ := newGuard(t, m)

	if d := check(t, g, Request{Operation: "scan", Target: Target{Kind: TargetIP, Host: "2001:db8::1"}}); d.Allow {
		t.Fatalf("IPv6 outside an IPv4-only scope: %+v", d)
	}
	m.Allowed = append(m.Allowed, Rule{Kind: TargetCIDR, Value: "2001:db8::/32"})
	g, _ = newGuard(t, m)
	if d := check(t, g, Request{Operation: "scan", Target: Target{Kind: TargetIP, Host: "2001:db8::1"}}); !d.Allow {
		t.Fatalf("IPv6 inside its prefix: %+v", d)
	}
	// IPv4-mapped IPv6 is evaluated as the IPv4 address, never as a separate host.
	if d := check(t, g, Request{Operation: "scan", Target: Target{Kind: TargetIP, Host: "::ffff:10.0.0.1"}}); !d.Allow {
		t.Fatalf("IPv4-mapped address: %+v", d)
	}
}

func TestDNSChangeAndResolution(t *testing.T) {
	m := baseManifest()
	m.Allowed = []Rule{{Kind: TargetCIDR, Value: "10.0.0.0/24"}} // no domain rule: DNS decides
	g, _ := newGuard(t, m)

	first := Request{Operation: "scan", Target: Target{Kind: TargetDomain, Host: "scan.example.net"},
		DNS: []netip.Addr{netip.MustParseAddr("10.0.0.5")}}
	if d := check(t, g, first); !d.Allow {
		t.Fatalf("first resolution inside scope: %+v", d)
	}
	second := first
	second.DNS = []netip.Addr{netip.MustParseAddr("10.9.9.9")}
	if d := check(t, g, second); d.Allow || d.Code != CodeDNSChanged {
		t.Fatalf("changed resolution must be refused: %+v", d)
	}
	third := first
	third.DNS = nil // no fresh answer: the pinned one is reused, not re-resolved
	if d := check(t, g, third); !d.Allow {
		t.Fatalf("pinned resolution: %+v", d)
	}
}

func TestRedirect(t *testing.T) {
	m := baseManifest()
	g, _ := newGuard(t, m)
	g.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
	}
	if d := g.CheckRedirect(context.Background(), "https://example.com/a", "https://evil.example.net/b", "scan"); d.Allow || d.Code != CodeScopeDenied {
		t.Fatalf("out-of-scope redirect: %+v", d)
	}
	if d := g.CheckRedirect(context.Background(), "https://example.com/a", "/local", "scan"); !d.Allow {
		t.Fatalf("same-origin relative redirect: %+v", d)
	}
}

func TestOperationsAudienceAndRunLimit(t *testing.T) {
	m := baseManifest()
	m.Operations["scan"] = OperationPolicy{Allowed: true, MaxPerRun: 1}
	g, _ := newGuard(t, m)

	if d := check(t, g, Request{Operation: "exploit", Target: Target{Kind: TargetIP, Host: "10.0.0.1"}}); d.Allow || d.Code != CodeOperationDenied {
		t.Fatalf("operation not granted: %+v", d)
	}
	if d := check(t, g, Request{Operation: "scan", Server: "other", Target: Target{Kind: TargetIP, Host: "10.0.0.1"}}); d.Allow || d.Code != CodeServerNotAudience {
		t.Fatalf("wrong audience: %+v", d)
	}
	req := Request{Operation: "scan", Target: Target{Kind: TargetIP, Host: "10.0.0.1"}}
	d := check(t, g, req)
	if !d.Allow {
		t.Fatal(d)
	}
	if d, err := g.Charge(context.Background(), req, d); err != nil || !d.Allow {
		t.Fatalf("charge: %+v %v", d, err)
	}
	if d := check(t, g, req); d.Allow || d.Code != CodeScopeDenied {
		t.Fatalf("max_per_run: %+v", d)
	}
}

func TestBudgetSplitAndConcurrency(t *testing.T) {
	ledger := NewMemoryLedger(5, map[string]int{"a": 2, "b": 3})
	if _, err := ledger.Reserve("m", "a", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Reserve("m", "a", 1); err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.Reserve("m", "a", 1); CodeOf(err) != CodeBudgetExhausted {
		t.Fatalf("a exceeded its own split: %v", err)
	}
	if left, err := ledger.Reserve("m", "b", 3); err != nil || left != 0 {
		t.Fatalf("b keeps its own split: %d %v", left, err)
	}
	if _, err := ledger.Reserve("m", "b", 1); CodeOf(err) != CodeBudgetExhausted {
		t.Fatalf("b over budget: %v", err)
	}

	// The whole mission cap also applies across servers.
	shared := NewMemoryLedger(2, map[string]int{"a": 2, "b": 2})
	if _, err := shared.Reserve("m", "a", 2); err != nil {
		t.Fatal(err)
	}
	if _, err := shared.Reserve("m", "b", 1); CodeOf(err) != CodeBudgetExhausted {
		t.Fatalf("mission total: %v", err)
	}

	// Concurrent reservations never exceed the signed allocation.
	m := baseManifest()
	m.Budgets = Budget{TotalOps: 10, PerServer: map[string]int{"nmap": 3}}
	g, _ := newGuard(t, m)
	req := Request{Operation: "scan", Target: Target{Kind: TargetIP, Host: "10.0.0.1"}}
	var ok atomic.Int32
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := g.Check(context.Background(), req)
			if !d.Allow {
				return
			}
			if d, _ := g.Charge(context.Background(), req, d); d.Allow {
				ok.Add(1)
			}
		}()
	}
	wg.Wait()
	if ok.Load() != 3 {
		t.Fatalf("concurrent charges = %d, want 3", ok.Load())
	}
}

func TestGuardTimeWindow(t *testing.T) {
	g, _ := newGuard(t, baseManifest())
	if d := check(t, g, Request{Operation: "scan", Target: Target{Kind: TargetIP, Host: "10.0.0.1"}, Now: testNow.Add(2 * time.Hour)}); d.Allow || d.Code != CodeManifestExpired {
		t.Fatalf("expired guard check: %+v", d)
	}
}

func TestScopeRulesCannotBeBypassedByWildcards(t *testing.T) {
	m := baseManifest()
	m.Allowed = []Rule{{Kind: TargetDomain, Value: "*.example.com"}}
	env, keys := signed(t, m)
	parsed, _ := ParseEnvelope(env)
	if _, err := parsed.Verify(keys, testNow); CodeOf(err) != CodeManifestInvalid {
		t.Fatalf("wildcard rule accepted: %v", err)
	}
}

func TestFromEnvFailsClosed(t *testing.T) {
	t.Setenv("ARTEX_SCOPE_MANIFEST", "")
	t.Setenv("ARTEX_SCOPE_PUBKEY", "")
	t.Setenv("ARTEX_SCOPE_ALLOW_UNSCOPED", "")
	if _, err := FromEnv(); err == nil || !strings.Contains(err.Error(), "ARTEX_SCOPE_MANIFEST") {
		t.Fatalf("unconfigured FromEnv: %v", err)
	}
	t.Setenv("ARTEX_SCOPE_ALLOW_UNSCOPED", "1")
	g, err := FromEnv()
	if err != nil || !g.Unscoped() {
		t.Fatalf("explicit unscoped mode: %v %v", g, err)
	}
	if d := check(t, g, Request{Operation: "scan", Target: Target{Kind: TargetIP, Host: "10.0.0.1"}}); d.Allow {
		t.Fatalf("unscoped guard allowed an operation: %+v", d)
	}
}
