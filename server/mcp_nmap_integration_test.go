package server

// Real end-to-end check for issue #15: build cmd/mcp-nmap, register it through
// the authenticated API with a signed mission manifest, let a real worker call
// discover against a local listener, and assert the parsed observation reached
// the model. Skipped where go, nmap or python-free execution is unavailable.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/scope"
)

func TestMCPNmapEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain is required to build the server")
	}
	if _, err := exec.LookPath("nmap"); err != nil {
		t.Skip("nmap is required")
	}
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(file))
	bin := filepath.Join(t.TempDir(), "mcp-nmap")
	build := exec.Command("go", "build", "-o", bin, "./cmd/mcp-nmap")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build mcp-nmap: %v\n%s", err, out)
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

	// Signed manifest for the nmap audience and a pinned public key.
	now := time.Now().UTC()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := &scope.Manifest{
		Version: scope.ManifestVersion, MissionID: "nmap-e2e", Server: "nmap",
		IssuedAt: now, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		Allowed:    []scope.Rule{{Kind: scope.TargetIP, Value: "127.0.0.1"}},
		Operations: map[string]scope.OperationPolicy{"discover": {Allowed: true}},
		Budgets:    scope.Budget{TotalOps: 5, PerServer: map[string]int{"nmap": 5}},
	}
	envelope, err := scope.Sign(m, priv)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	manifestPath := filepath.Join(dir, "mission.signed.json")
	pubPath := filepath.Join(dir, "mission.pub")
	if err := os.WriteFile(manifestPath, envelope, 0o600); err != nil {
		t.Fatal(err)
	}
	keys := []map[string]string{{"key_id": scope.KeyID(pub), "public_key": base64.RawURLEncoding.EncodeToString(pub)}}
	keyJSON, _ := json.Marshal(keys)
	if err := os.WriteFile(pubPath, keyJSON, 0o600); err != nil {
		t.Fatal(err)
	}

	g := newGateServer(t)
	const full = "mcp__nmap__discover"
	id := registerMCPContractServer(t, g, map[string]any{
		"name": "nmap", "transport": "stdio", "command": bin, "enabled": true,
		"env": map[string]string{
			"ARTEX_SCOPE_MANIFEST":        manifestPath,
			"ARTEX_SCOPE_PUBKEY":          pubPath,
			"ARTEX_MCP_NMAP_ARTIFACT_DIR": filepath.Join(dir, "artifacts"),
		},
	})
	assertMCPDiscovery(t, g, id, full)
	grantMCPVisibility(t, g, id)

	task := g.newTask(t, db.TaskCreateOptions{})
	factInput, _ := json.Marshal(map[string]any{"facts": []map[string]any{{
		"summary": "nmap loopback observation", "detail": "loopback service observed",
		"evidence": "loopback service observed", "confidence": "observed", "source": "tool_output",
	}}})
	p := &toolScript{
		calls: []scriptedCall{
			{"SearchExtraTools", `{"query":"select:` + full + `"}`},
			{"ExecuteExtraTool", `{"tool_name":"` + full + `","params":{"target":"127.0.0.1","ports":"` + strconv.Itoa(port) + `"}}`},
			{"record_fact", string(factInput)},
		},
		results: make(chan string, 8),
		hold:    map[int64]chan struct{}{},
	}
	done := runScriptedWorker(t, g, task, p)

	if r := p.next(t); !strings.Contains(r, full) || !strings.Contains(r, "params schema") {
		t.Fatalf("schema discovery: %q", r)
	}
	scan := p.next(t)
	if !strings.Contains(scan, `"observed": true`) || !strings.Contains(scan, `"port": `+strconv.Itoa(port)) {
		t.Fatalf("nmap observation did not reach the model: %q", scan)
	}
	if r := p.next(t); strings.Contains(r, "[error]") || !strings.Contains(r, `"ids":[`) {
		t.Fatalf("record_fact after the scan: %q", r)
	}
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("the worker run did not end")
	}
}

// The network-recon skill must load with the nmap server in its frontmatter, so
// loading the skill unlocks mcp__nmap__discover for the worker.
func TestNetworkReconSkillLoads(t *testing.T) {
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Dir(filepath.Dir(file))
	reg, err := loadSkillsConfined(filepath.Join(root, "skills"))
	if err != nil {
		t.Fatal(err)
	}
	sk, ok := reg.Get("network-recon")
	if !ok {
		t.Fatal("network-recon skill not found")
	}
	if len(sk.MCPs) != 1 || sk.MCPs[0] != "nmap" {
		t.Fatalf("network-recon mcps = %v, want [nmap]", sk.MCPs)
	}
	if !strings.Contains(sk.Instructions, "SCOPE_DENIED") || !strings.Contains(sk.Instructions, "not observed") {
		t.Fatalf("skill body lost its scope/empty-result rules")
	}
}
