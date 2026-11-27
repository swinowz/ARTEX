// Command artex-scope creates and signs mission manifests for the capability
// MCP servers that use package scope (issue #14).
//
//	artex-scope keygen -dir keys
//	artex-scope sign   -key keys/mission.key -in mission.json -out mission.signed.json
//	artex-scope verify -key keys/mission.pub  -in mission.signed.json
//
// The private key never belongs in the repository. keys/ is gitignored.
package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/Autumn-27/artex/scope"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = keygen(os.Args[2:])
	case "sign":
		err = sign(os.Args[2:])
	case "verify":
		err = verify(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "artex-scope:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  artex-scope keygen -dir keys
  artex-scope sign   -key keys/mission.key -in mission.json [-out mission.signed.json]
  artex-scope verify -key keys/mission.pub  -in mission.signed.json [-now RFC3339]`)
	os.Exit(2)
}

func keygen(args []string) error {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	dir := fs.String("dir", "keys", "directory for mission.key and mission.pub")
	if err := fs.Parse(args); err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*dir, 0o700); err != nil {
		return err
	}
	keyPath := *dir + "/mission.key"
	pubPath := *dir + "/mission.pub"
	if _, err := os.Stat(keyPath); err == nil {
		return fmt.Errorf("%s exists; refusing to overwrite a signing key", keyPath)
	}
	if err := os.WriteFile(keyPath, []byte(base64.RawURLEncoding.EncodeToString(priv)+"\n"), 0o600); err != nil {
		return err
	}
	keys := []map[string]string{{"key_id": scope.KeyID(pub), "public_key": base64.RawURLEncoding.EncodeToString(pub)}}
	raw, _ := json.MarshalIndent(keys, "", "  ")
	if err := os.WriteFile(pubPath, append(raw, '\n'), 0o644); err != nil {
		return err
	}
	fmt.Printf("key_id %s\nwrote %s (0600) and %s\n", scope.KeyID(pub), keyPath, pubPath)
	return nil
}

func sign(args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	keyPath := fs.String("key", "", "ed25519 private key file from keygen")
	in := fs.String("in", "", "manifest JSON")
	out := fs.String("out", "", "signed envelope (default stdout)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *in == "" {
		usage()
	}
	priv, err := readPrivateKey(*keyPath)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(*in)
	if err != nil {
		return err
	}
	var m scope.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		return fmt.Errorf("%s: %w", *in, err)
	}
	if err := m.Validate(); err != nil {
		return err
	}
	env, err := scope.Sign(&m, priv)
	if err != nil {
		return err
	}
	if *out == "" {
		fmt.Println(string(env))
		return nil
	}
	if err := os.WriteFile(*out, append(env, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Printf("signed %s -> %s (key_id %s)\n", *in, *out, scope.KeyID(priv.Public().(ed25519.PublicKey)))
	return nil
}

func verify(args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	keyPath := fs.String("key", "", "public key file from keygen")
	in := fs.String("in", "", "signed envelope")
	nowText := fs.String("now", "", "evaluation time (RFC3339, default now)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyPath == "" || *in == "" {
		usage()
	}
	keys, err := scope.LoadKeys(*keyPath)
	if err != nil {
		return err
	}
	now := time.Now()
	if *nowText != "" {
		if now, err = time.Parse(time.RFC3339, *nowText); err != nil {
			return err
		}
	}
	m, err := scope.LoadManifest(*in, keys, now)
	if err != nil {
		return err
	}
	fmt.Printf("valid: mission=%s server=%s window=%s..%s operations=%d allowed=%d excluded=%d budget=%d/%v\n",
		m.MissionID, m.Server, m.NotBefore.Format(time.RFC3339), m.NotAfter.Format(time.RFC3339),
		len(m.Operations), len(m.Allowed), len(m.Excluded), m.Budgets.TotalOps, m.Budgets.PerServer)
	return nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	key, err := base64.RawURLEncoding.DecodeString(string(trimSpace(raw)))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(key) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(key), nil
	}
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%s: expected a 32-byte seed or 64-byte ed25519 key", path)
	}
	return ed25519.PrivateKey(key), nil
}

func trimSpace(b []byte) []byte {
	start, end := 0, len(b)
	for start < end && (b[start] == ' ' || b[start] == '\n' || b[start] == '\r' || b[start] == '\t') {
		start++
	}
	for end > start && (b[end-1] == ' ' || b[end-1] == '\n' || b[end-1] == '\r' || b[end-1] == '\t') {
		end--
	}
	return b[start:end]
}
