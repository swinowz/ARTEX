package enum4linux

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/mcps/adcore"
	"github.com/Autumn-27/artex/scope"
)

const fixtureSecret = "S3cr3t!"

func testGuard(t *testing.T, allowed []scope.Rule, excluded ...scope.Rule) *scope.Guard {
	t.Helper()
	now := time.Now().UTC()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	m := &scope.Manifest{
		Version:    scope.ManifestVersion,
		MissionID:  "test-mission",
		Server:     "enum4linux",
		IssuedAt:   now,
		NotBefore:  now.Add(-time.Hour),
		NotAfter:   now.Add(time.Hour),
		Allowed:    allowed,
		Excluded:   excluded,
		Operations: map[string]scope.OperationPolicy{Operation: {Allowed: true}},
		Budgets:    scope.Budget{TotalOps: 10, PerServer: map[string]int{"enum4linux": 10}},
	}
	env, err := scope.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := scope.ParseEnvelope(env)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := parsed.Verify([]scope.PublicKey{{KeyID: scope.KeyID(pub), Ed25519: pub}}, now)
	if err != nil {
		t.Fatal(err)
	}
	g, err := scope.NewGuard(verified, nil)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// fakeRunner writes the JSON export where enum4linux-ng would, derived from -oJ.
type fakeRunner struct {
	calls   atomic.Int32
	args    []string
	env     []string
	fixture string
	runErr  error
}

func (f *fakeRunner) run(_ context.Context, name string, args []string, env []string) ([]byte, []byte, error) {
	f.calls.Add(1)
	f.args, f.env = append([]string(nil), args...), append([]string(nil), env...)
	if f.fixture != "" {
		base := argValue(args, "-oJ")
		if base == "" {
			panic("no -oJ in argv")
		}
		raw, err := os.ReadFile(filepath.Join("testdata", f.fixture))
		if err != nil {
			panic(err)
		}
		if err := os.WriteFile(base+".json", raw, 0o600); err != nil {
			panic(err)
		}
	}
	return []byte("[+] Enumerating users\n[-] Nothing on this host\n"), nil, f.runErr
}

func argValue(args []string, flag string) string {
	for i, a := range args {
		if a == flag && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

func testServer(t *testing.T, allowed []scope.Rule, runner *fakeRunner, creds ...adcore.Credential) *Server {
	t.Helper()
	s := New(testGuard(t, allowed), adcore.NewStore(creds), t.TempDir())
	s.Runner = runner.run
	s.Timeout = 5 * time.Second
	return s
}

func testCredential() adcore.Credential {
	return adcore.Credential{Ref: "12", Domain: "LAB.LOCAL", Username: "alice", Kind: adcore.KindPassword, Secret: fixtureSecret}
}

func TestEnumerateSuccessAndRedaction(t *testing.T) {
	runner := &fakeRunner{fixture: "success.json"}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetIP, Value: "10.20.30.10"}}, runner, testCredential())
	res, err := s.Enumerate(context.Background(), Request{TargetRef: "10.20.30.10", CredentialRef: "12"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Objects.Users) != 2 || res.Objects.Users[0].Name != "Administrator" {
		t.Fatalf("users = %+v", res.Objects.Users)
	}
	if len(res.Objects.Groups) != 1 || res.Objects.Groups[0].Name != "Domain Admins" {
		t.Fatalf("groups = %+v", res.Objects.Groups)
	}
	if len(res.Shares) != 2 || !res.Shares[0].Write {
		t.Fatalf("shares = %+v", res.Shares)
	}
	if len(res.Domains) == 0 || res.Domains[0].Name != "LAB.LOCAL" {
		t.Fatalf("domains = %+v", res.Domains)
	}
	if res.Auth.LockoutThreshold == nil || *res.Auth.LockoutThreshold != 5 {
		t.Fatalf("lockout = %v", res.Auth.LockoutThreshold)
	}
	for _, want := range []string{"shares", "users", "groups", "policy", "os_info"} {
		found := false
		for _, got := range res.Coverage.Collected {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s not collected: %+v", want, res.Coverage)
		}
	}

	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), fixtureSecret) {
		t.Fatalf("result leaks the secret: %s", raw)
	}
	artifact := res.Artifacts["raw_json"]
	if artifact == "" {
		t.Fatal("redacted JSON artifact missing")
	}
	blob, err := os.ReadFile(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), fixtureSecret) || strings.Contains(string(blob), "credentials") {
		t.Fatalf("artifact leaks the credential block: %s", blob)
	}
	st, _ := os.Stat(artifact)
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("artifact perm = %v", st.Mode().Perm())
	}
}

func TestEnumerateDeniedAndUnsupported(t *testing.T) {
	runner := &fakeRunner{fixture: "denied.json"}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetIP, Value: "10.20.30.11"}}, runner)
	res, err := s.Enumerate(context.Background(), Request{TargetRef: "10.20.30.11"})
	if err != nil {
		t.Fatal(err)
	}
	if !gapReason(res.Coverage.PermissionDenied, "shares", "ACCESS_DENIED") {
		t.Fatalf("shares should be permission_denied: %+v", res.Coverage)
	}
	if !gapReason(res.Coverage.Unsupported, "policy", "Unsupported") {
		t.Fatalf("policy should be unsupported: %+v", res.Coverage)
	}
	if !gapReason(res.Coverage.NotCollected, "sessions", "Skipping") {
		t.Fatalf("sessions should be not_collected: %+v", res.Coverage)
	}
}

func TestEnumerateScopeDeniedBeforeRunner(t *testing.T) {
	runner := &fakeRunner{fixture: "success.json"}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetCIDR, Value: "10.20.30.0/24"}}, runner, testCredential())
	_, err := s.Enumerate(context.Background(), Request{TargetRef: "10.99.0.5", CredentialRef: "12"})
	if scope.CodeOf(err) != scope.CodeScopeDenied {
		t.Fatalf("scope error = %v", err)
	}
	if runner.calls.Load() != 0 {
		t.Fatal("enum4linux-ng ran for an out-of-scope target")
	}
}

func TestEnumerateRejectsCIDRAndFreeForm(t *testing.T) {
	runner := &fakeRunner{}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetCIDR, Value: "10.20.30.0/24"}}, runner)
	if _, err := s.Enumerate(context.Background(), Request{TargetRef: "10.20.30.0/24"}); err == nil {
		t.Fatal("CIDR accepted")
	}
	if _, err := decodeRequest(json.RawMessage(`{"target_ref":"10.20.30.10","extra_args":"-R"}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if runner.calls.Load() != 0 {
		t.Fatal("enum4linux-ng ran for a rejected request")
	}
}

func TestEnumerateMissingExportIsHonest(t *testing.T) {
	runner := &fakeRunner{}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetIP, Value: "10.20.30.10"}}, runner, testCredential())
	res, err := s.Enumerate(context.Background(), Request{TargetRef: "10.20.30.10", CredentialRef: "12"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res.Note, "not observed") {
		t.Fatalf("note = %q", res.Note)
	}
	if len(res.Coverage.Collected) != 0 {
		t.Fatalf("missing export claims collected checks: %+v", res.Coverage)
	}
	if res.Stopped == nil {
		t.Fatal("missing export should be reported as stopped")
	}
}

func TestEnumerateChildEnvAndArgs(t *testing.T) {
	runner := &fakeRunner{fixture: "success.json"}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetIP, Value: "10.20.30.10"}}, runner, testCredential())
	if _, err := s.Enumerate(context.Background(), Request{TargetRef: "10.20.30.10", CredentialRef: "12", ProfileRef: ProfileDeep}); err != nil {
		t.Fatal(err)
	}
	args := strings.Join(runner.args, " ")
	for _, want := range []string{"-A", "-Gm", "-R", "-oJ"} {
		if !strings.Contains(args, want) {
			t.Errorf("args missing %q: %s", want, args)
		}
	}
	for _, kv := range runner.env {
		if strings.HasPrefix(kv, "ARTEX_") {
			t.Fatalf("child environment leaks %q", kv)
		}
	}
}

func TestServeExposesSingleTool(t *testing.T) {
	runner := &fakeRunner{fixture: "success.json"}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetIP, Value: "10.20.30.10"}}, runner, testCredential())
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"enumerate","arguments":{"target_ref":"10.20.30.10","credential_ref":"12"}}}`,
	}, "\n")
	var out strings.Builder
	if err := s.Serve(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("responses = %d: %q", len(lines), out.String())
	}
	if !strings.Contains(lines[1], `"name":"enumerate"`) {
		t.Fatalf("tools/list: %s", lines[1])
	}
	if strings.Contains(lines[2], fixtureSecret) {
		t.Fatalf("call result leaks the secret: %s", lines[2])
	}
}

func gapReason(gaps []adcore.Gap, check, reason string) bool {
	for _, g := range gaps {
		if g.Check == check && strings.Contains(g.Reason, reason) {
			return true
		}
	}
	return false
}
