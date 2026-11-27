package adcore

import (
	"os"
	"strings"
	"testing"
	"time"
)

func TestCredentialRoundTrip(t *testing.T) {
	in := []Credential{{Ref: "12", Domain: "LAB.LOCAL", Username: "alice", Kind: KindPassword, Secret: "S3cr3t!"}}
	raw, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	out, err := Decode(raw)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(out) != 1 || out[0] != in[0] {
		t.Fatalf("round trip = %+v, want %+v", out, in[0])
	}
	if strings.Contains(raw, "password\":\"") {
		// the envelope legitimately carries the secret; the tool results must not
		t.Log("envelope carries the secret by design")
	}
}

func TestDecodeFailsClosed(t *testing.T) {
	cases := map[string]string{
		"bad version": `{"version":9,"credentials":[]}`,
		"empty ref":   `{"version":1,"credentials":[{"ref":"","username":"a","secret":"b"}]}`,
		"no username": `{"version":1,"credentials":[{"ref":"1","secret":"b"}]}`,
		"no secret":   `{"version":1,"credentials":[{"ref":"1","username":"a"}]}`,
		"bad kind":    `{"version":1,"credentials":[{"ref":"1","username":"a","secret":"b","kind":"ticket"}]}`,
		"duplicate":   `{"version":1,"credentials":[{"ref":"1","username":"a","secret":"b"},{"ref":"1","username":"c","secret":"d"}]}`,
		"not json":    `{"version":1,`,
	}
	for name, raw := range cases {
		if _, err := Decode(raw); err == nil {
			t.Errorf("%s: accepted, want an error", name)
		}
	}
	if creds, err := Decode(""); err != nil || creds != nil {
		t.Errorf("empty env = %v, %v; want nil, nil", creds, err)
	}
}

func TestStoreNeverLeaksUsername(t *testing.T) {
	s := NewStore([]Credential{{Ref: "7", Domain: "LAB", Username: "alice", Kind: KindPassword, Secret: "pw"}})
	refs := s.Refs()
	if len(refs) != 1 || refs[0].Ref != "7" || refs[0].Domain != "LAB" {
		t.Fatalf("refs = %+v", refs)
	}
	msg := s.UnknownRefError("nope").Error()
	if strings.Contains(msg, "alice") || strings.Contains(msg, "pw") {
		t.Fatalf("error leaks a credential: %s", msg)
	}
	if _, ok := s.Get("7"); !ok {
		t.Fatal("GET(7) failed")
	}
	if _, ok := (*Store)(nil).Get("7"); ok {
		t.Fatal("nil store returned a credential")
	}
}

func TestClassifyMessage(t *testing.T) {
	cases := map[string]string{
		"STATUS_ACCESS_DENIED":     StatusPermissionDenied,
		"WERR_ACCESS_DENIED":       StatusPermissionDenied,
		"STATUS_NOT_SUPPORTED":     StatusUnsupported,
		"STATUS_INVALID_PARAMETER": StatusUnsupported,
		"RPC_S_UNKNOWN_IF":         StatusFailed,
		"":                         StatusFailed,
	}
	for msg, want := range cases {
		if got := ClassifyMessage(msg); got != want {
			t.Errorf("%q classified %q, want %q", msg, got, want)
		}
	}
}

func TestCoverageBuckets(t *testing.T) {
	var c Coverage
	c.Collect("hosts")
	c.Classify("hosts", "STATUS_ACCESS_DENIED") // already collected: not downgraded
	c.Skip("computers", ReasonNotInProfile)
	c.Classify("shares", "STATUS_ACCESS_DENIED")
	c.Classify("pass_pol", "STATUS_NOT_SUPPORTED")
	c.Classify("groups", "timeout")
	if len(c.Collected) != 1 {
		t.Fatalf("collected = %v", c.Collected)
	}
	if len(c.NotCollected) != 1 || len(c.PermissionDenied) != 1 || len(c.Unsupported) != 1 || len(c.Failed) != 1 {
		t.Fatalf("buckets = %+v", c)
	}
}

func TestRedactAndArtifact(t *testing.T) {
	if got := Redact("LAB\\alice:S3cr3t! ok", "S3cr3t!", ""); strings.Contains(got, "S3cr3t!") {
		t.Fatalf("secret survived: %s", got)
	}
	if got := Redact("keep", ""); got != "keep" {
		t.Fatalf("empty secret changed the text: %q", got)
	}
	dir := t.TempDir()
	path, err := WriteArtifact(dir+"/art", "nxc", ".log", []byte("x"), time.Unix(0, 0))
	if err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("artifact perm = %v", st.Mode().Perm())
	}
}
