package agent

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// TestCredentialViewsCarryOnlyAReference is the #11 acceptance test for the
// worker context: the account surfaces as a ref, never as a value.
func TestCredentialViewsCarryOnlyAReference(t *testing.T) {
	c := db.TaskCredential{ID: 42, Domain: "LAB.LOCAL", Username: "alice", Password: "S3cr3t!", Source: "user", Note: "lab"}

	for name, view := range map[string]map[string]any{
		"list_task_credentials": credentialView(c),
		"graph_overview":        credentialOverviewEntry(c),
	} {
		raw, err := json.Marshal(view)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(raw), "S3cr3t!") || strings.Contains(string(raw), `"password"`) {
			t.Errorf("%s leaks the password: %s", name, raw)
		}
		if view["ref"] != "42" || view["domain"] != "LAB.LOCAL" || view["username"] != "alice" {
			t.Errorf("%s lost the reference: %v", name, view)
		}
	}

	empty := credentialOverviewEntry(db.TaskCredential{ID: 7, Domain: "LAB", Username: "bob"})
	if empty["has_password"] != false || !strings.Contains(empty["instruction"].(string), "save_task_credential") {
		t.Fatalf("empty-password entry lost its instruction: %v", empty)
	}
	if CredentialRef(42) != "42" {
		t.Fatalf("CredentialRef = %q", CredentialRef(42))
	}
}
