package netexec

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/mcps/adcore"
	"github.com/Autumn-27/artex/scope"

	_ "modernc.org/sqlite"
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
		Server:     "netexec",
		IssuedAt:   now,
		NotBefore:  now.Add(-time.Hour),
		NotAfter:   now.Add(time.Hour),
		Allowed:    allowed,
		Excluded:   excluded,
		Operations: map[string]scope.OperationPolicy{Operation: {Allowed: true}},
		Budgets:    scope.Budget{TotalOps: 50, PerServer: map[string]int{"netexec": 50}},
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

// fakeRunner replays a fixture. prepare mimics what nxc writes: the workspace
// database and the users export, both derived from the argv.
type fakeRunner struct {
	calls      atomic.Int32
	name       string
	args       []string
	env        []string
	stdout     []byte
	stderr     []byte
	err        error
	prepare    func(args []string)
	confAtRun  string
	versionErr error
}

func (f *fakeRunner) run(_ context.Context, name string, args []string, env []string) ([]byte, []byte, error) {
	f.calls.Add(1)
	// First-run setup, as nxc does at import time: the layout and the default
	// config with an empty audit_mode.
	if len(args) == 1 && args[0] == "--version" {
		if f.versionErr != nil {
			return nil, []byte("nxc: not found"), f.versionErr
		}
		if dir := envValue(env, "NXC_PATH"); dir != "" {
			_ = os.MkdirAll(filepath.Join(dir, "workspaces", "default"), 0o700)
			_ = os.WriteFile(filepath.Join(dir, "nxc.conf"), []byte("[nxc]\nworkspace = default\naudit_mode = \n"), 0o600)
		}
		return []byte("1.4.0\n"), nil, nil
	}
	f.name, f.args, f.env = name, append([]string(nil), args...), append([]string(nil), env...)
	if dir := envValue(env, "NXC_PATH"); dir != "" {
		if raw, err := os.ReadFile(filepath.Join(dir, "nxc.conf")); err == nil {
			f.confAtRun = string(raw)
		}
	}
	if f.prepare != nil {
		f.prepare(args)
	}
	return f.stdout, f.stderr, f.err
}

func envValue(env []string, key string) string {
	for _, kv := range env {
		if k, v, ok := strings.Cut(kv, "="); ok && k == key {
			return v
		}
	}
	return ""
}

func mustFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// workspaceFor writes a fixture database where nxc would have written it.
func workspaceFor(t *testing.T, args []string, protocol, sqlFixture, usersFixture string) {
	t.Helper()
	export := argValue(args, "--users-export")
	if export == "" {
		return
	}
	work := filepath.Dir(export)
	if usersFixture != "" {
		if err := os.WriteFile(export, mustFixture(t, usersFixture), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if sqlFixture == "" {
		return
	}
	dir := filepath.Join(work, "nxc", "workspaces", "default")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", "file:"+filepath.Join(dir, protocol+".db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(string(mustFixture(t, sqlFixture))); err != nil {
		t.Fatal(err)
	}
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

func TestInventorySMBSuccess(t *testing.T) {
	runner := &fakeRunner{stdout: mustFixture(t, "smb_success.log")}
	runner.prepare = func(args []string) {
		workspaceFor(t, args, "smb", "smb_success.sql", "users.txt")
	}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetCIDR, Value: "10.20.30.0/24"}}, runner, testCredential())

	res, err := s.Inventory(context.Background(), Request{
		TargetRefs:    []string{"10.20.30.10", "10.20.30.11"},
		Protocol:      "smb",
		CredentialRef: "12",
	})
	if err != nil {
		t.Fatal(err)
	}

	if res.Auth.Outcome != "success" || res.Auth.Attempts != 1 {
		t.Fatalf("auth = %+v", res.Auth)
	}
	if len(res.Hosts) != 2 || res.Hosts[0].Domain != "LAB.LOCAL" {
		t.Fatalf("hosts = %+v", res.Hosts)
	}
	if len(res.Shares) != 2 || !res.Shares[0].Write {
		t.Fatalf("shares = %+v", res.Shares)
	}
	if len(res.Objects.Users) == 0 {
		t.Fatal("no users collected")
	}
	if len(res.Access) != 1 || res.Access[0].Kind != "admin" {
		t.Fatalf("access = %+v", res.Access)
	}
	for _, want := range []string{checkHosts, checkShares, checkUsers, checkPassPol} {
		if !contains(res.Coverage.Collected, want) {
			t.Errorf("%s not collected: %+v", want, res.Coverage)
		}
	}
	if res.Auth.LockoutThreshold == nil || *res.Auth.LockoutThreshold != 5 {
		t.Errorf("lockout threshold = %v", res.Auth.LockoutThreshold)
	}
	// signing:False on DC01 is a candidate, never a finding.
	found := false
	for _, c := range res.Candidates {
		if c.Kind == "smb_signing_not_required" && c.Target == "10.20.30.10" {
			found = true
		}
	}
	if !found {
		t.Fatalf("candidates = %+v", res.Candidates)
	}

	// No credential value in the result, in any form.
	raw, _ := json.Marshal(res)
	if strings.Contains(string(raw), fixtureSecret) {
		t.Fatalf("result leaks the secret: %s", raw)
	}
	if strings.Contains(string(raw), "alice") && res.Credential != nil && res.Credential.Ref != "12" {
		t.Fatal("credential ref lost")
	}

	if !strings.Contains(runner.confAtRun, "audit_mode = ********") {
		t.Fatalf("audit_mode not enabled in the run config: %q", runner.confAtRun)
	}

	// The secret reaches nxc through a file, never through argv.
	args := strings.Join(runner.args, " ")
	if strings.Contains(args, fixtureSecret) {
		t.Fatalf("secret in argv: %s", args)
	}
	if !strings.Contains(args, "--ufail-limit 1") || !strings.Contains(args, "-t 1") {
		t.Fatalf("auth is not bounded: %s", args)
	}
	if argValue(runner.args, "-p") == "" {
		t.Fatal("password file not passed to nxc")
	}
	for _, forbidden := range []string{"--sam", "--lsa", "--ntds", "--spider", "-x", "--gen-relay-list", "--bloodhound"} {
		if strings.Contains(args, forbidden) {
			t.Errorf("forbidden flag %q in argv: %s", forbidden, args)
		}
	}

	// The artifact is redacted and readable.
	path := res.Artifacts["log"]
	rawLog, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawLog), fixtureSecret) {
		t.Fatalf("artifact leaks the secret: %s", rawLog)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}

func TestInventoryAuthFailureAndLockout(t *testing.T) {
	t.Run("logon failure", func(t *testing.T) {
		runner := &fakeRunner{stdout: mustFixture(t, "smb_logon_failure.log")}
		s := testServer(t, []scope.Rule{{Kind: scope.TargetCIDR, Value: "10.20.30.0/24"}}, runner, testCredential())
		res, err := s.Inventory(context.Background(), Request{TargetRefs: []string{"10.20.30.10"}, Protocol: "smb", CredentialRef: "12"})
		if err != nil {
			t.Fatal(err)
		}
		if res.Auth.Outcome != "logon_failure" {
			t.Fatalf("auth = %+v", res.Auth)
		}
		if res.Stopped == nil || res.Stopped.Reason != "authentication_failed" {
			t.Fatalf("stopped = %+v", res.Stopped)
		}
		if !gapReason(res.Coverage.NotCollected, checkUsers, "authentication_failed") {
			t.Fatalf("users should be not_collected(authentication_failed): %+v", res.Coverage)
		}
		if !gapReason(res.Coverage.PermissionDenied, checkShares, "STATUS_ACCESS_DENIED") {
			t.Fatalf("shares should be permission_denied: %+v", res.Coverage)
		}
	})

	t.Run("account locked", func(t *testing.T) {
		runner := &fakeRunner{stdout: mustFixture(t, "smb_account_locked.log")}
		s := testServer(t, []scope.Rule{{Kind: scope.TargetCIDR, Value: "10.20.30.0/24"}}, runner, testCredential())
		res, err := s.Inventory(context.Background(), Request{TargetRefs: []string{"10.20.30.10"}, Protocol: "smb", CredentialRef: "12"})
		if err != nil {
			t.Fatal(err)
		}
		if res.Auth.Outcome != "account_locked_out" {
			t.Fatalf("auth = %+v", res.Auth)
		}
		if res.Stopped == nil || res.Stopped.Reason != "account_locked_out" {
			t.Fatalf("stopped = %+v", res.Stopped)
		}
	})
}

func TestInventoryLDAPSuccess(t *testing.T) {
	runner := &fakeRunner{stdout: mustFixture(t, "ldap_success.log")}
	runner.prepare = func(args []string) {
		workspaceFor(t, args, "ldap", "ldap_success.sql", "users.txt")
	}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetIP, Value: "10.20.30.10"}}, runner, testCredential())
	res, err := s.Inventory(context.Background(), Request{TargetRefs: []string{"10.20.30.10"}, Protocol: "ldap", CredentialRef: "12"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Objects.Computers) != 2 {
		t.Fatalf("computers = %+v", res.Objects.Computers)
	}
	if len(res.Objects.Groups) != 2 {
		t.Fatalf("groups = %+v", res.Objects.Groups)
	}
	if len(res.Domains) == 0 || len(res.Domains[0].DCs) != 1 {
		t.Fatalf("domains = %+v", res.Domains)
	}
	if res.Hosts[0].Signing == nil || !*res.Hosts[0].Signing {
		t.Fatalf("ldap signing = %+v", res.Hosts[0].Signing)
	}
	if !contains(res.Coverage.Collected, checkComputers) || !contains(res.Coverage.Collected, checkDCList) {
		t.Fatalf("coverage = %+v", res.Coverage)
	}
}

func TestInventoryUnsupportedCheck(t *testing.T) {
	runner := &fakeRunner{stdout: mustFixture(t, "ldap_unsupported.log")}
	runner.prepare = func(args []string) { workspaceFor(t, args, "ldap", "", "") }
	s := testServer(t, []scope.Rule{{Kind: scope.TargetIP, Value: "10.20.30.10"}}, runner, testCredential())
	res, err := s.Inventory(context.Background(), Request{TargetRefs: []string{"10.20.30.10"}, Protocol: "ldap", CredentialRef: "12"})
	if err != nil {
		t.Fatal(err)
	}
	if !gapReason(res.Coverage.Unsupported, checkPassPol, "STATUS_NOT_SUPPORTED") {
		t.Fatalf("pass_pol should be unsupported: %+v", res.Coverage)
	}
}

func TestInventoryScopeDeniedBeforeRunner(t *testing.T) {
	runner := &fakeRunner{stdout: mustFixture(t, "smb_success.log")}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetCIDR, Value: "10.20.30.0/24"}}, runner, testCredential())
	_, err := s.Inventory(context.Background(), Request{TargetRefs: []string{"10.20.30.10", "10.99.0.5"}, Protocol: "smb", CredentialRef: "12"})
	if scope.CodeOf(err) != scope.CodeScopeDenied {
		t.Fatalf("scope error = %v", err)
	}
	if runner.calls.Load() != 0 {
		t.Fatal("nxc ran although one target was out of scope")
	}
}

func TestInventoryDeepNeedsCredential(t *testing.T) {
	runner := &fakeRunner{}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetIP, Value: "10.20.30.10"}}, runner)
	if _, err := s.Inventory(context.Background(), Request{TargetRefs: []string{"10.20.30.10"}, ProfileRef: ProfileDeep}); err == nil {
		t.Fatal("deep profile accepted without a credential")
	}
	if runner.calls.Load() != 0 {
		t.Fatal("nxc ran for a rejected request")
	}
}

func TestInventoryUnknownCredentialListsRefs(t *testing.T) {
	runner := &fakeRunner{}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetIP, Value: "10.20.30.10"}}, runner, testCredential())
	_, err := s.Inventory(context.Background(), Request{TargetRefs: []string{"10.20.30.10"}, CredentialRef: "99"})
	if err == nil || !strings.Contains(err.Error(), "12") {
		t.Fatalf("error = %v", err)
	}
	if strings.Contains(err.Error(), fixtureSecret) || strings.Contains(err.Error(), "alice") {
		t.Fatalf("error leaks a credential: %v", err)
	}
	if runner.calls.Load() != 0 {
		t.Fatal("nxc ran for a rejected request")
	}
}

func TestInventoryChildEnvHasNoARTEX(t *testing.T) {
	runner := &fakeRunner{stdout: mustFixture(t, "smb_success.log")}
	runner.prepare = func(args []string) { workspaceFor(t, args, "smb", "", "") }
	s := testServer(t, []scope.Rule{{Kind: scope.TargetIP, Value: "10.20.30.10"}}, runner, testCredential())
	if _, err := s.Inventory(context.Background(), Request{TargetRefs: []string{"10.20.30.10"}, CredentialRef: "12"}); err != nil {
		t.Fatal(err)
	}
	for _, kv := range runner.env {
		if strings.HasPrefix(kv, "ARTEX_") {
			t.Fatalf("child environment leaks %q", kv)
		}
	}
	found := false
	for _, kv := range runner.env {
		if strings.HasPrefix(kv, "NXC_PATH=") {
			found = true
		}
	}
	if !found {
		t.Fatalf("NXC_PATH not isolated: %v", runner.env)
	}
}

func TestInventoryTimeoutAndEmpty(t *testing.T) {
	t.Run("time budget", func(t *testing.T) {
		runner := &fakeRunner{}
		s := testServer(t, []scope.Rule{{Kind: scope.TargetIP, Value: "10.20.30.10"}}, runner, testCredential())
		s.Timeout = time.Nanosecond
		runner.err = context.DeadlineExceeded
		res, err := s.Inventory(context.Background(), Request{TargetRefs: []string{"10.20.30.10"}, CredentialRef: "12"})
		if err != nil {
			t.Fatal(err)
		}
		if res.Stopped == nil || res.Stopped.Reason != adcore.ReasonTimeBudget {
			t.Fatalf("stopped = %+v", res.Stopped)
		}
	})
	t.Run("empty is not absence", func(t *testing.T) {
		runner := &fakeRunner{}
		s := testServer(t, []scope.Rule{{Kind: scope.TargetIP, Value: "10.20.30.10"}}, runner, testCredential())
		res, err := s.Inventory(context.Background(), Request{TargetRefs: []string{"10.20.30.10"}, CredentialRef: "12"})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(res.Note, "not observed") {
			t.Fatalf("note = %q", res.Note)
		}
		if len(res.Coverage.Collected) != 0 {
			t.Fatalf("empty run claims collected checks: %+v", res.Coverage)
		}
	})
}

func TestInventoryRejectsFreeFormAndUnknownFields(t *testing.T) {
	if _, err := decodeRequest(json.RawMessage(`{"target_refs":["10.0.0.1"],"extra_args":"--sam"}`)); err == nil {
		t.Fatal("unknown field accepted")
	}
	if _, err := decodeRequest(json.RawMessage(`{"target_refs":[]}`)); err == nil {
		t.Fatal("empty target list accepted")
	}
	runner := &fakeRunner{}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetCIDR, Value: "0.0.0.0/0"}}, runner)
	if _, err := s.Inventory(context.Background(), Request{TargetRefs: []string{"10.0.0.0/8"}}); err == nil {
		t.Fatal("oversized CIDR accepted")
	}
	if _, err := s.Inventory(context.Background(), Request{TargetRefs: []string{"10.0.0.1"}, Protocol: "ftp"}); err == nil {
		t.Fatal("unknown protocol accepted")
	}
	if runner.calls.Load() != 0 {
		t.Fatal("nxc ran for a rejected request")
	}
}

func TestServeExposesSingleTool(t *testing.T) {
	runner := &fakeRunner{stdout: mustFixture(t, "smb_success.log")}
	runner.prepare = func(args []string) { workspaceFor(t, args, "smb", "", "") }
	s := testServer(t, []scope.Rule{{Kind: scope.TargetIP, Value: "10.20.30.10"}}, runner, testCredential())
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"inventory","arguments":{"target_refs":["10.20.30.10"],"credential_ref":"12"}}}`,
	}, "\n")
	var out strings.Builder
	if err := s.Serve(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("responses = %d: %q", len(lines), out.String())
	}
	if !strings.Contains(lines[0], `"name":"netexec"`) {
		t.Fatalf("initialize: %s", lines[0])
	}
	if !strings.Contains(lines[1], `"name":"inventory"`) || strings.Contains(lines[1], "discover") {
		t.Fatalf("tools/list: %s", lines[1])
	}
	if !strings.Contains(lines[2], "LAB.LOCAL") || strings.Contains(lines[2], fixtureSecret) {
		t.Fatalf("call result: %s", lines[2])
	}
}

func contains(in []string, want string) bool {
	for _, v := range in {
		if v == want {
			return true
		}
	}
	return false
}

func gapReason(gaps []adcore.Gap, check, reason string) bool {
	for _, g := range gaps {
		if g.Check == check && strings.Contains(g.Reason, reason) {
			return true
		}
	}
	return false
}

func TestMaskPasswordsInConfig(t *testing.T) {
	in := "[nxc]\nworkspace = default\naudit_mode = \npwn3d_label = Pwn3d!\n"
	out := maskPasswordsInConfig(in)
	if !strings.Contains(out, "audit_mode = ********") || !strings.Contains(out, "pwn3d_label = Pwn3d!") {
		t.Fatalf("config = %q", out)
	}
	noAudit := "[nxc]\nworkspace = default\n"
	if out := maskPasswordsInConfig(noAudit); !strings.Contains(out, "audit_mode = ********") {
		t.Fatalf("missing audit_mode not added: %q", out)
	}
}

func TestInventoryFailsWhenToolMissing(t *testing.T) {
	runner := &fakeRunner{versionErr: context.Canceled}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetIP, Value: "10.20.30.10"}}, runner, testCredential())
	if _, err := s.Inventory(context.Background(), Request{TargetRefs: []string{"10.20.30.10"}, CredentialRef: "12"}); err == nil {
		t.Fatal("missing netexec accepted")
	}
	if runner.calls.Load() != 1 {
		t.Fatalf("calls = %d", runner.calls.Load())
	}
}
