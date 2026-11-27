package redact

import (
	"encoding/json"
	"strings"
	"testing"
)

const ntPair = "aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0"

func TestRedactHashPair(t *testing.T) {
	in := "Administrator:500:" + ntPair + ":::"
	out := Text(in)
	if strings.Contains(out, "31d6cfe0d16ae931b73c59d7e0c089c0") || !strings.Contains(out, PlaceholderHash) {
		t.Fatalf("hash survived: %s", out)
	}
	if !strings.HasPrefix(out, "Administrator:500:") {
		t.Fatalf("login/RID context lost: %s", out)
	}
}

func TestRedactPrivateKey(t *testing.T) {
	in := "key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\ndone"
	out := Text(in)
	if strings.Contains(out, "MIIEowIBAAKCAQEA") || !strings.Contains(out, PlaceholderPrivateKey) {
		t.Fatalf("key survived: %s", out)
	}
	if !strings.Contains(out, "done") {
		t.Fatalf("text around the key lost: %s", out)
	}
}

func TestRedactJSONSecretFields(t *testing.T) {
	in := `{"domain":"lab","username":"alice","password":"S3cr3t!","note":"x"}`
	out := Text(in)
	if strings.Contains(out, "S3cr3t!") {
		t.Fatalf("password survived: %s", out)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatalf("redaction broke JSON: %v (%s)", err, out)
	}
	if m["password"] != PlaceholderSecret || m["username"] != "alice" {
		t.Fatalf("unexpected fields: %+v", out)
	}
}

func TestRedactCredentialLine(t *testing.T) {
	for _, in := range []string{
		`SMB  10.20.30.10  445  DC01  [+] LAB\alice:S3cr3t! (Pwn3d!)`,
		`{"line":"LAB\\alice:S3cr3t! ok"}`, // JSON-escaped form (one literal backslash)
		`alice@lab.local:S3cr3t!`,
	} {
		out := Text(in)
		if strings.Contains(out, "S3cr3t!") {
			t.Errorf("credential survived: %s", out)
		}
	}
}

func TestRedactKeepsInnocuousText(t *testing.T) {
	for _, in := range []string{
		`SMB  10.20.30.10  445  DC01  [*] Windows Server 2022 (signing:False)`,
		`time 10:20:30 host 10.20.30.10:445 open`,
		`Minimum password length: 7`,
		`user@lab.local:8080 reachable`,
		`{"target_refs":["10.20.30.10"],"protocol":"smb"}`,
	} {
		if out := Text(in); out != in {
			t.Errorf("innocuous text changed:\n in: %s\nout: %s", in, out)
		}
	}
}

func TestRedactIsIdempotentAndJSONSafe(t *testing.T) {
	in := `{"a":"` + ntPair + `","b":"LAB\\alice:S3cr3t!","c":"` + strings.Repeat("QUJD", 200) + `"}`
	once := Text(in)
	twice := Text(once)
	if once != twice {
		t.Fatalf("not idempotent:\n%s\n%s", once, twice)
	}
	if strings.Contains(once, "S3cr3t!") {
		t.Fatalf("credential survived: %s", once)
	}
	var v any
	if err := json.Unmarshal([]byte(once), &v); err != nil {
		t.Fatalf("redaction broke JSON: %v (%s)", err, once)
	}
	if !Changed(in) || Changed(`{"ok":true}`) {
		t.Fatal("Changed disagrees with Text")
	}
}
