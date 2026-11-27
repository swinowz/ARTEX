package nmap

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Autumn-27/artex/scope"
)

const successXML = `<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host>
    <status state="up" reason="user-set"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open" reason="syn-ack"/>
        <service name="microsoft-ds" product="Samba" version="4.15" extrainfo="workgroup: LAB"/>
      </port>
    </ports>
  </host>
  <runstats><finished exit="success"/></runstats>
</nmaprun>`

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
		Server:     "nmap",
		IssuedAt:   now,
		NotBefore:  now.Add(-time.Hour),
		NotAfter:   now.Add(time.Hour),
		Allowed:    allowed,
		Excluded:   excluded,
		Operations: map[string]scope.OperationPolicy{"discover": {Allowed: true}},
		Budgets:    scope.Budget{TotalOps: 10, PerServer: map[string]int{"nmap": 10}},
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

type fakeRunner struct {
	calls  atomic.Int32
	name   string
	args   []string
	stdout []byte
	stderr []byte
	err    error
}

func (f *fakeRunner) run(_ context.Context, name string, args ...string) ([]byte, []byte, error) {
	f.calls.Add(1)
	f.name = name
	f.args = append([]string(nil), args...)
	return f.stdout, f.stderr, f.err
}

func testServer(t *testing.T, allowed []scope.Rule, runner *fakeRunner, excluded ...scope.Rule) *Server {
	t.Helper()
	s := New(testGuard(t, allowed, excluded...), t.TempDir())
	s.Runner = runner.run
	s.Timeout = 5 * time.Second
	return s
}

func TestPortArguments(t *testing.T) {
	cases := []struct {
		in      string
		want    []string
		label   string
		wantErr bool
	}{
		{"", []string{"-p", joinInts(commonPorts, ",")}, "common", false},
		{"common", []string{"-p", joinInts(commonPorts, ",")}, "common", false},
		{"top100", []string{"--top-ports", "100"}, "top100", false},
		{"22,80,443", []string{"-p", "22,80,443"}, "22,80,443", false},
		{"22,80,443,80", []string{"-p", "22,80,443"}, "22,80,443", false},
		{"1-3", []string{"-p", "1,2,3"}, "1,2,3", false},
		{"0", nil, "", true},
		{"22,notaport", nil, "", true},
		{"1-5000", nil, "", true},
	}
	for _, tc := range cases {
		got, label, err := portArguments(tc.in)
		if tc.wantErr {
			if err == nil {
				t.Errorf("portArguments(%q) accepted invalid input", tc.in)
			}
			continue
		}
		if err != nil || strings.Join(got, " ") != strings.Join(tc.want, " ") || label != tc.label {
			t.Errorf("portArguments(%q) = %v %q %v; want %v %q", tc.in, got, label, err, tc.want, tc.label)
		}
	}
}

func TestParseXML(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		got, err := parseXML([]byte(successXML))
		if err != nil {
			t.Fatal(err)
		}
		if !got.Observed || len(got.Hosts) != 1 || got.Hosts[0].Address != "10.0.0.5" {
			t.Fatalf("parsed: %+v", got)
		}
		svc := got.Hosts[0].Services[0]
		if svc.Port != 445 || svc.Name != "microsoft-ds" || svc.State != "open" {
			t.Fatalf("service: %+v", svc)
		}
	})
	t.Run("empty", func(t *testing.T) {
		got, err := parseXML([]byte(`<nmaprun></nmaprun>`))
		if err != nil || got.Observed || len(got.Hosts) != 0 || got.Incomplete {
			t.Fatalf("empty scan: %+v %v", got, err)
		}
	})
	t.Run("interrupted", func(t *testing.T) {
		got, err := parseXML([]byte(`<nmaprun><runstats><finished exit="error" errormsg="caught SIGINT"/></runstats></nmaprun>`))
		if err != nil || !got.Incomplete || !strings.Contains(got.Warning, "SIGINT") {
			t.Fatalf("interrupted scan: %+v %v", got, err)
		}
	})
	t.Run("malformed", func(t *testing.T) {
		if _, err := parseXML([]byte(`<nmaprun><host>`)); err == nil {
			t.Fatal("truncated XML accepted")
		}
	})
	t.Run("empty output", func(t *testing.T) {
		if _, err := parseXML(nil); err == nil {
			t.Fatal("empty output accepted")
		}
	})
}

func TestDiscoverDeniedBeforeRunner(t *testing.T) {
	runner := &fakeRunner{stdout: []byte(successXML)}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetCIDR, Value: "10.0.0.0/24"}}, runner)
	_, err := s.Discover(context.Background(), DiscoverRequest{Target: "10.9.9.9"})
	if scope.CodeOf(err) != scope.CodeScopeDenied {
		t.Fatalf("scope error = %v", err)
	}
	if runner.calls.Load() != 0 {
		t.Fatal("nmap ran for an out-of-scope target")
	}
}

func TestDiscoverExclusionWins(t *testing.T) {
	runner := &fakeRunner{stdout: []byte(successXML)}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetCIDR, Value: "10.0.0.0/8"}}, runner,
		scope.Rule{Kind: scope.TargetCIDR, Value: "10.1.2.0/24"})
	_, err := s.Discover(context.Background(), DiscoverRequest{Target: "10.1.2.7"})
	if scope.CodeOf(err) != scope.CodeScopeDenied {
		t.Fatalf("excluded target: %v", err)
	}
	if runner.calls.Load() != 0 {
		t.Fatal("nmap ran for an excluded target")
	}
}

func TestDiscoverRunsBoundedArgsAndKeepsArtifact(t *testing.T) {
	runner := &fakeRunner{stdout: []byte(successXML)}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetCIDR, Value: "10.0.0.0/24"}}, runner)
	res, err := s.Discover(context.Background(), DiscoverRequest{Target: "10.0.0.5", Ports: "80,443"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Observed || len(res.Hosts) != 1 || res.Hosts[0].Services[0].Port != 445 {
		t.Fatalf("result: %+v", res)
	}
	args := strings.Join(runner.args, " ")
	for _, want := range []string{"-Pn", "-n", "-sT", "-oX", "-", "-p 80,443", "10.0.0.5"} {
		if !strings.Contains(args, want) {
			t.Errorf("nmap args missing %q: %s", want, args)
		}
	}
	for _, forbidden := range []string{"--script", "extra_args", "10.0.0.6"} {
		if strings.Contains(args, forbidden) {
			t.Errorf("nmap args contain %q: %s", forbidden, args)
		}
	}
	if res.RawArtifact == "" {
		t.Fatal("raw XML artifact path missing")
	}
	info, err := os.Stat(res.RawArtifact)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("artifact: %v %v", info, err)
	}
	raw, err := os.ReadFile(res.RawArtifact)
	if err != nil || !bytes.Equal(raw, runner.stdout) {
		t.Fatalf("artifact content: %v", err)
	}
}

func TestDiscoverResolvesAndScansPinnedIPs(t *testing.T) {
	runner := &fakeRunner{stdout: []byte(successXML)}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetDomain, Value: "example.test"}}, runner)
	s.Resolve = func(context.Context, string) ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
	}
	res, err := s.Discover(context.Background(), DiscoverRequest{Target: "example.test", Ports: "445"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Target != "example.test" {
		t.Fatalf("target: %q", res.Target)
	}
	args := strings.Join(runner.args, " ")
	if !strings.Contains(args, "10.0.0.5") || strings.Contains(args, "example.test") {
		t.Fatalf("nmap did not receive the pinned address: %s", args)
	}
}

func TestDiscoverEmptyIsNotAbsence(t *testing.T) {
	runner := &fakeRunner{stdout: []byte(`<nmaprun></nmaprun>`)}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetCIDR, Value: "10.0.0.0/24"}}, runner)
	res, err := s.Discover(context.Background(), DiscoverRequest{Target: "10.0.0.5"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Observed || !strings.Contains(res.Note, "not evidence") {
		t.Fatalf("empty result wording: %+v", res)
	}
}

func TestDiscoverRejectsOversizedAndFreeForm(t *testing.T) {
	runner := &fakeRunner{stdout: []byte(successXML)}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetCIDR, Value: "0.0.0.0/0"}}, runner)
	if _, err := s.Discover(context.Background(), DiscoverRequest{Target: "10.0.0.0/8"}); err == nil {
		t.Fatal("oversized CIDR accepted")
	}
	if _, err := decodeRequest(json.RawMessage(`{"target":"10.0.0.5","extra_args":"--script=x"}`)); err == nil {
		t.Fatal("extra_args accepted")
	}
	if runner.calls.Load() != 0 {
		t.Fatal("nmap ran for a rejected request")
	}
}

func TestServeProtocol(t *testing.T) {
	runner := &fakeRunner{stdout: []byte(successXML)}
	s := testServer(t, []scope.Rule{{Kind: scope.TargetCIDR, Value: "10.0.0.0/24"}}, runner)
	in := strings.Join([]string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"discover","arguments":{"target":"10.0.0.5","ports":"445"}}}`,
	}, "\n")
	var out bytes.Buffer
	if err := s.Serve(context.Background(), strings.NewReader(in), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 3 {
		t.Fatalf("responses = %d: %q", len(lines), out.String())
	}
	var init struct {
		Result struct {
			ProtocolVersion string `json:"protocolVersion"`
			ServerInfo      struct {
				Name string `json:"name"`
			} `json:"serverInfo"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[0]), &init); err != nil || init.Result.ProtocolVersion != "2025-11-25" || init.Result.ServerInfo.Name != "nmap" {
		t.Fatalf("initialize: %s (%v)", lines[0], err)
	}
	var list struct {
		Result struct {
			Tools []struct {
				Name        string         `json:"name"`
				InputSchema map[string]any `json:"inputSchema"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.Unmarshal([]byte(lines[1]), &list); err != nil || len(list.Result.Tools) != 1 || list.Result.Tools[0].Name != "discover" {
		t.Fatalf("tools/list: %s (%v)", lines[1], err)
	}
	if list.Result.Tools[0].InputSchema["additionalProperties"] != false {
		t.Fatalf("schema allows extra properties: %v", list.Result.Tools[0].InputSchema)
	}
	if !strings.Contains(lines[2], "microsoft-ds") {
		t.Fatalf("tools/call result: %s", lines[2])
	}
}

// TestDiscoverRealNmapLoopback runs the real binary against a local listener.
// It is skipped where nmap is unavailable or cannot open a connect scan.
func TestDiscoverRealNmapLoopback(t *testing.T) {
	if _, err := exec.LookPath("nmap"); err != nil {
		t.Skip("nmap is not installed")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("loopback listener: %v", err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	s := New(testGuard(t, []scope.Rule{{Kind: scope.TargetIP, Value: "127.0.0.1"}}), t.TempDir())
	s.Timeout = 30 * time.Second
	res, err := s.Discover(context.Background(), DiscoverRequest{Target: "127.0.0.1", Ports: strconv.Itoa(port)})
	if err != nil {
		t.Fatalf("real scan: %v", err)
	}
	if !res.Observed {
		t.Fatalf("no observation for an open loopback listener: %+v", res)
	}
	found := false
	for _, h := range res.Hosts {
		for _, svc := range h.Services {
			if svc.Port == port && svc.State == "open" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("open port %d not parsed: %+v", port, res)
	}
}
