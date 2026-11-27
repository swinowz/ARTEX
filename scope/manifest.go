package scope

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"
)

// ManifestVersion is the only manifest schema this package accepts.
const ManifestVersion = "artex.mission/v1"

// Decision codes. A caller should surface the code verbatim; capability
// servers render it in their tool error.
const (
	CodeScopeDenied       = "SCOPE_DENIED"
	CodeManifestInvalid   = "SCOPE_MANIFEST_INVALID"
	CodeManifestUnsigned  = "SCOPE_MANIFEST_UNSIGNED"
	CodeManifestExpired   = "SCOPE_MANIFEST_EXPIRED"
	CodeBudgetExhausted   = "SCOPE_BUDGET_EXHAUSTED"
	CodeServerNotAudience = "SCOPE_SERVER_NOT_AUDIENCE"
	CodeApprovalRequired  = "SCOPE_APPROVAL_REQUIRED"
	CodeOperationDenied   = "SCOPE_OPERATION_DENIED"
	CodeDNSChanged        = "SCOPE_DNS_CHANGED"
	CodeDNSFailed         = "SCOPE_DNS_FAILED"
)

// Rule is one allow or exclusion entry. Exclusion wins over every allow,
// regardless of specificity.
type Rule struct {
	Kind  string `json:"kind"`  // "domain" | "ip" | "cidr"
	Value string `json:"value"` // punycode name, canonical IP, masked prefix
	Ports []int  `json:"ports,omitempty"`
	Note  string `json:"note,omitempty"`
}

// OperationPolicy is the signed permission for one operation name.
type OperationPolicy struct {
	Allowed          bool `json:"allowed"`
	RequiresApproval bool `json:"requires_approval,omitempty"`
	MaxPerRun        int  `json:"max_per_run,omitempty"`
}

// Budget is fixed at signing time. A server may never spend another server's
// allocation, and no server may fall back to the mission total on its own.
type Budget struct {
	TotalOps  int            `json:"total_ops,omitempty"`
	PerServer map[string]int `json:"per_server,omitempty"`
}

// Manifest is the signed mission scope for exactly one MCP server audience.
type Manifest struct {
	Version    string                     `json:"version"`
	MissionID  string                     `json:"mission_id"`
	Server     string                     `json:"server"`
	IssuedAt   time.Time                  `json:"issued_at"`
	NotBefore  time.Time                  `json:"not_before"`
	NotAfter   time.Time                  `json:"not_after"`
	Allowed    []Rule                     `json:"allowed"`
	Excluded   []Rule                     `json:"excluded,omitempty"`
	Operations map[string]OperationPolicy `json:"operations"`
	Budgets    Budget                     `json:"budgets,omitempty"`
	Approval   string                     `json:"approval,omitempty"` // "none" | "operator" | "two-person"
	Cleanup    []string                   `json:"cleanup,omitempty"`
}

// Envelope is the wire form. The signature covers the exact Manifest bytes, so
// signers must use Sign (canonical JSON) or reproduce it byte for byte.
type Envelope struct {
	Manifest json.RawMessage `json:"manifest"`
	KeyID    string          `json:"key_id"`
	Alg      string          `json:"alg"`
	Sig      string          `json:"sig"`
}

// PublicKey is one pinned verification key; KeyID enables rotation.
type PublicKey struct {
	KeyID   string
	Ed25519 ed25519.PublicKey
}

// DeniedError carries a stable decision code through the error path.
type DeniedError struct {
	Code   string
	Reason string
}

func (e *DeniedError) Error() string {
	if e.Reason == "" {
		return e.Code
	}
	return e.Code + ": " + e.Reason
}

// Deny builds a decision for code.
func Deny(code, reason string) Decision {
	return Decision{Code: code, Reason: reason}
}

func denyErr(code, reason string) error { return &DeniedError{Code: code, Reason: reason} }

// ToolDeniedError is the operator-facing form of a deny, used in tool results.
// It keeps the stable code available to CodeOf while naming the layer.
type ToolDeniedError struct {
	Code   string
	Reason string
}

func (e *ToolDeniedError) Error() string {
	msg := "[ARTEX platform control, not target defense] " + e.Code
	if e.Reason != "" {
		msg += ": " + e.Reason
	}
	return msg
}

// CodeOf returns the decision code carried by err, or "" for other errors.
func CodeOf(err error) string {
	switch d := err.(type) {
	case *DeniedError:
		return d.Code
	case *ToolDeniedError:
		return d.Code
	}
	return ""
}

// Decision is the outcome of one scope check.
type Decision struct {
	Allow     bool
	Code      string
	Reason    string
	Excluded  bool
	Rule      string
	Remaining int
}

// Sign serialises m as canonical JSON (map keys sorted by encoding/json) and
// returns a signed envelope. The private key never belongs in the repository.
func Sign(m *Manifest, key ed25519.PrivateKey) ([]byte, error) {
	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("scope: ed25519 private key has length %d", len(key))
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	sig := ed25519.Sign(key, raw)
	env := Envelope{
		Manifest: raw,
		KeyID:    keyIDOf(key.Public().(ed25519.PublicKey)),
		Alg:      "ed25519",
		Sig:      base64.RawURLEncoding.EncodeToString(sig),
	}
	return json.Marshal(env)
}

// KeyID derives the stable identifier of a verification key.
func KeyID(pub ed25519.PublicKey) string { return keyIDOf(pub) }

func keyIDOf(pub ed25519.PublicKey) string {
	return base64.RawURLEncoding.EncodeToString(pub[:8])
}

// ParseEnvelope reads the wire form.
func ParseEnvelope(raw []byte) (Envelope, error) {
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		return Envelope{}, denyErr(CodeManifestInvalid, "envelope is not JSON: "+err.Error())
	}
	return env, nil
}

// Verify checks the detached signature, decodes the manifest and enforces its
// schema, audience-independent invariants and time window.
func (e Envelope) Verify(keys []PublicKey, now time.Time) (*Manifest, error) {
	if e.Alg != "ed25519" {
		return nil, denyErr(CodeManifestUnsigned, fmt.Sprintf("unsupported signature algorithm %q", e.Alg))
	}
	var key ed25519.PublicKey
	for _, k := range keys {
		if k.KeyID == e.KeyID {
			key = k.Ed25519
			break
		}
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, denyErr(CodeManifestUnsigned, fmt.Sprintf("unknown key id %q", e.KeyID))
	}
	sig, err := base64.RawURLEncoding.DecodeString(e.Sig)
	if err != nil {
		return nil, denyErr(CodeManifestUnsigned, "signature is not base64url: "+err.Error())
	}
	if len(e.Manifest) == 0 || !ed25519.Verify(key, e.Manifest, sig) {
		return nil, denyErr(CodeManifestInvalid, "manifest signature does not verify")
	}
	var m Manifest
	if err := json.Unmarshal(e.Manifest, &m); err != nil {
		return nil, denyErr(CodeManifestInvalid, "manifest is not JSON: "+err.Error())
	}
	if err := m.Validate(); err != nil {
		return nil, err
	}
	if now.Before(m.NotBefore) {
		return nil, denyErr(CodeManifestExpired, "mission is not active before "+m.NotBefore.Format(time.RFC3339))
	}
	if !now.Before(m.NotAfter) {
		return nil, denyErr(CodeManifestExpired, "mission expired at "+m.NotAfter.Format(time.RFC3339))
	}
	return &m, nil
}

// Validate normalises rule values and refuses an incoherent manifest. It is
// called after signature verification; it never changes the signed bytes.
func (m *Manifest) Validate() error {
	invalid := func(format string, args ...any) error {
		return denyErr(CodeManifestInvalid, fmt.Sprintf(format, args...))
	}
	if m.Version != ManifestVersion {
		return invalid("unsupported manifest version %q (want %q)", m.Version, ManifestVersion)
	}
	if strings.TrimSpace(m.MissionID) == "" {
		return invalid("mission_id is required")
	}
	if strings.TrimSpace(m.Server) == "" {
		return invalid("server (audience) is required")
	}
	if m.IssuedAt.IsZero() {
		return invalid("issued_at is required")
	}
	if m.NotBefore.IsZero() || m.NotAfter.IsZero() || !m.NotAfter.After(m.NotBefore) {
		return invalid("not_before/not_after must define a positive window")
	}
	if len(m.Operations) == 0 {
		return invalid("operations must grant at least one operation")
	}
	for name, op := range m.Operations {
		if strings.TrimSpace(name) == "" {
			return invalid("operation name is empty")
		}
		if op.MaxPerRun < 0 {
			return invalid("operation %q has a negative max_per_run", name)
		}
	}
	for i := range m.Allowed {
		if err := normalizeRule(&m.Allowed[i]); err != nil {
			return invalid("allowed[%d]: %v", i, err)
		}
	}
	for i := range m.Excluded {
		if err := normalizeRule(&m.Excluded[i]); err != nil {
			return invalid("excluded[%d]: %v", i, err)
		}
	}
	if m.Budgets.TotalOps < 0 || m.Budgets.TotalOps > 1<<30 {
		return invalid("budgets.total_ops is out of range")
	}
	sum := 0
	for server, n := range m.Budgets.PerServer {
		if n < 0 {
			return invalid("budgets.per_server[%q] is negative", server)
		}
		sum += n
	}
	if m.Budgets.TotalOps > 0 && sum > m.Budgets.TotalOps {
		return invalid("per-server budgets sum to %d, above total_ops %d", sum, m.Budgets.TotalOps)
	}
	return nil
}

func normalizeRule(r *Rule) error {
	switch r.Kind {
	case TargetDomain, TargetIP, TargetCIDR:
	default:
		return fmt.Errorf("unknown rule kind %q", r.Kind)
	}
	t, ok := Normalize(r.Value)
	if !ok {
		return fmt.Errorf("invalid rule value %q", r.Value)
	}
	if r.Kind == TargetDomain && t.Kind != TargetDomain {
		return fmt.Errorf("%q is not a domain", r.Value)
	}
	// A domain rule covers its subdomains already. A wildcard is refused rather
	// than interpreted, so no signer can believe it means something else.
	if strings.Contains(r.Value, "*") {
		return fmt.Errorf("wildcards are not supported; a domain rule covers its subdomains")
	}
	if r.Kind == TargetIP && t.Kind != TargetIP {
		return fmt.Errorf("%q is not an IP", r.Value)
	}
	if r.Kind == TargetCIDR && t.Kind != TargetCIDR {
		return fmt.Errorf("%q is not a CIDR", r.Value)
	}
	r.Value = t.Host
	for _, p := range r.Ports {
		if p < 1 || p > 65535 {
			return fmt.Errorf("port %d is out of range", p)
		}
	}
	return nil
}

// LoadKeys reads Ed25519 public keys from a JSON file: either an array of
// {"key_id","public_key"} objects, or an object {key_id: base64url}. A PEM
// PKIX file with one or more PUBLIC KEY blocks is also accepted.
func LoadKeys(path string) ([]PublicKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if block, _ := pem.Decode(raw); block != nil {
		var out []PublicKey
		for block != nil {
			if block.Type != "PUBLIC KEY" {
				return nil, fmt.Errorf("scope: unsupported PEM block %q", block.Type)
			}
			pub, err := parsePKIX(block.Bytes)
			if err != nil {
				return nil, err
			}
			out = append(out, PublicKey{KeyID: KeyID(pub), Ed25519: pub})
			block, raw = pem.Decode(raw)
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("scope: no public key in %s", path)
		}
		return out, nil
	}
	var list []struct {
		KeyID     string `json:"key_id"`
		PublicKey string `json:"public_key"`
	}
	if err := json.Unmarshal(raw, &list); err == nil && len(list) > 0 {
		return decodeKeyList(path, list)
	}
	var byID map[string]string
	if err := json.Unmarshal(raw, &byID); err == nil && len(byID) > 0 {
		list = list[:0]
		for id, key := range byID {
			list = append(list, struct {
				KeyID     string `json:"key_id"`
				PublicKey string `json:"public_key"`
			}{id, key})
		}
		return decodeKeyList(path, list)
	}
	// A single base64url raw key is accepted too.
	pub, err := decodePublicKey(string(raw))
	if err != nil {
		return nil, fmt.Errorf("scope: %s: %w", path, err)
	}
	return []PublicKey{{KeyID: KeyID(pub), Ed25519: pub}}, nil
}

func decodeKeyList(path string, list []struct {
	KeyID     string `json:"key_id"`
	PublicKey string `json:"public_key"`
}) ([]PublicKey, error) {
	out := make([]PublicKey, 0, len(list))
	for _, item := range list {
		pub, err := decodePublicKey(item.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("scope: %s key %q: %w", path, item.KeyID, err)
		}
		id := item.KeyID
		if id == "" {
			id = KeyID(pub)
		}
		out = append(out, PublicKey{KeyID: id, Ed25519: pub})
	}
	return out, nil
}

func decodePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	for _, dec := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.StdEncoding} {
		if raw, err := dec.DecodeString(s); err == nil && len(raw) == ed25519.PublicKeySize {
			return ed25519.PublicKey(raw), nil
		}
	}
	return nil, fmt.Errorf("expected a %d-byte base64 public key", ed25519.PublicKeySize)
}

func parsePKIX(der []byte) (ed25519.PublicKey, error) {
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	pub, ok := parsed.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("scope: PEM block is %T, not ed25519", parsed)
	}
	return pub, nil
}

// LoadManifest reads and verifies an envelope file.
func LoadManifest(path string, keys []PublicKey, now time.Time) (*Manifest, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	env, err := ParseEnvelope(raw)
	if err != nil {
		return nil, err
	}
	return env.Verify(keys, now)
}

// ruleMatches reports whether r covers t, given the addresses t resolved to
// (empty for an IP/CIDR target or when resolution was not performed).
func ruleMatches(r Rule, t Target, dns []netip.Addr) bool {
	if len(r.Ports) > 0 {
		if t.Port == 0 || !containsPort(r.Ports, t.Port) {
			return false
		}
	}
	switch r.Kind {
	case TargetDomain:
		return t.Kind == TargetDomain && domainCovers(r.Value, t.Host)
	case TargetIP:
		want, err := netip.ParseAddr(r.Value)
		if err != nil {
			return false
		}
		want = want.Unmap().WithZone("")
		if a, ok := addrOf(t); ok && sameFamily(a, want) && a == want {
			return true
		}
		for _, a := range dns {
			if sameFamily(a, want) && a == want {
				return true
			}
		}
		return false
	case TargetCIDR:
		p, err := netip.ParsePrefix(r.Value)
		if err != nil {
			return false
		}
		if a, ok := addrOf(t); ok {
			return sameFamily(a, p.Addr()) && p.Contains(a)
		}
		if tp, ok := targetPrefix(t); ok {
			return sameFamily(tp.Addr(), p.Addr()) && tp.Bits() >= p.Bits() && p.Masked().Contains(tp.Masked().Addr())
		}
		for _, a := range dns {
			if sameFamily(a, p.Addr()) && p.Contains(a) {
				return true
			}
		}
		return false
	}
	return false
}

// ruleExcludes is ruleMatches plus CIDR overlap: an exclusion covering any part
// of a target subnet excludes the whole subnet, because scanning it would reach
// the excluded addresses.
func ruleExcludes(r Rule, t Target, dns []netip.Addr) bool {
	if ruleMatches(r, t, dns) {
		return true
	}
	if r.Kind != TargetCIDR {
		return false
	}
	p, err := netip.ParsePrefix(r.Value)
	if err != nil {
		return false
	}
	if tp, ok := targetPrefix(t); ok {
		return p.Overlaps(tp)
	}
	return false
}

func containsPort(ports []int, p int) bool {
	for _, x := range ports {
		if x == p {
			return true
		}
	}
	return false
}
