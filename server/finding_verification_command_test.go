package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// These DB-backed tests prove the non-HTTP verification path (ADR-0004, #8): a
// finding with no HTTP traffic bound reaches "verified" when a command/tool output
// is bound as proof and the evidence quote appears verbatim in it. They skip when
// no PostgreSQL is configured.

func TestVerificationCommandEvidenceOnlyVerified(t *testing.T) {
	skipWithoutDSN(t)
	s, f, _ := verificationFixture(t, "") // no HTTP traffic bound
	out := "Nmap scan report for dc01\n445/tcp open microsoft-ds\nSMB signing: disabled (required=no)"
	if _, err := s.m.pg.AddFindingCommandEvidence(f.FindingID, "verification", "nmap -p445 --script smb2-security-mode dc01", out, false); err != nil {
		t.Fatal(err)
	}
	msg, isErr := updateReport(t, s, f.NodeID, `,"poe_level":3,"evidence_quotes":["SMB signing: disabled (required=no)"]`)
	if isErr || !strings.Contains(msg, "verification: verified") {
		t.Fatalf("unexpected result: err=%v %q", isErr, msg)
	}
	status, poe, note, report := storedVerification(t, s, f.FindingID)
	if status != db.VerificationVerified || poe != 3 || note != "" || report == "" {
		t.Fatalf("stored: status=%s poe=%d note=%q report=%q", status, poe, note, report)
	}
}

func TestVerificationCommandEvidenceQuoteNotFoundUnverified(t *testing.T) {
	skipWithoutDSN(t)
	s, f, _ := verificationFixture(t, "")
	if _, err := s.m.pg.AddFindingCommandEvidence(f.FindingID, "proof", "cmd", "445/tcp open microsoft-ds", false); err != nil {
		t.Fatal(err)
	}
	msg, isErr := updateReport(t, s, f.NodeID, `,"poe_level":3,"evidence_quotes":["signing is disabled everywhere"]`)
	if isErr || !strings.Contains(msg, "unverified") {
		t.Fatalf("unexpected result: err=%v %q", isErr, msg)
	}
	status, _, note, _ := storedVerification(t, s, f.FindingID)
	if status != db.VerificationUnverified || !strings.HasPrefix(note, "quote not found in bound evidence") {
		t.Fatalf("stored: status=%s note=%q", status, note)
	}
}

// A "supporting" command evidence is not proof: the finding stays unverified with
// the same note as a finding with nothing bound at all.
func TestVerificationCommandEvidenceSupportingIsNotProof(t *testing.T) {
	skipWithoutDSN(t)
	s, f, _ := verificationFixture(t, "")
	if _, err := s.m.pg.AddFindingCommandEvidence(f.FindingID, "supporting", "cmd", "445/tcp open microsoft-ds", false); err != nil {
		t.Fatal(err)
	}
	msg, isErr := updateReport(t, s, f.NodeID, `,"poe_level":3,"evidence_quotes":["445/tcp open microsoft-ds"]`)
	if isErr || !strings.Contains(msg, "unverified - no proof traffic bound") {
		t.Fatalf("unexpected result: err=%v %q", isErr, msg)
	}
}

// End-to-end through the agent tool: update_finding_report carries command_evidence
// inline (no prior DB insert, no HTTP traffic) and the finding reaches verified.
func TestVerificationToolCommandEvidenceVerified(t *testing.T) {
	skipWithoutDSN(t)
	s, f, _ := verificationFixture(t, "")
	extra := `,"poe_level":3,"evidence_quotes":["Pre-Auth Not Required"],` +
		`"command_evidence":[{"role":"proof","command":"GetNPUsers.py",` +
		`"content":"[*] brandon.stark  Pre-Auth Not Required\n$krb5asrep$23$brandon.stark@NORTH..."}]`
	msg, isErr := updateReport(t, s, f.NodeID, extra)
	if isErr || !strings.Contains(msg, "verification: verified") {
		t.Fatalf("unexpected result: err=%v %q", isErr, msg)
	}
	status, _, note, _ := storedVerification(t, s, f.FindingID)
	if status != db.VerificationVerified || note != "" {
		t.Fatalf("stored: status=%s note=%q", status, note)
	}
}

func TestVerificationToolCommandEvidenceInvalidRole(t *testing.T) {
	skipWithoutDSN(t)
	s, f, _ := verificationFixture(t, "")
	extra := `,"poe_level":3,"evidence_quotes":["x7 long enough"],"command_evidence":[{"role":"bogus","content":"x7 long enough here"}]`
	msg, isErr := updateReport(t, s, f.NodeID, extra)
	if !isErr || !strings.Contains(msg, "invalid role") {
		t.Fatalf("expected invalid role error, got err=%v %q", isErr, msg)
	}
}

// Command evidence and HTTP evidence are unioned: a quote found only in the command
// output verifies even when an HTTP proof body is also bound but lacks the quote.
func TestVerificationCommandAndHTTPUnioned(t *testing.T) {
	skipWithoutDSN(t)
	s, f, _ := verificationFixture(t, "verification") // binds HTTP proof with verificationBody
	if _, err := s.m.pg.AddFindingCommandEvidence(f.FindingID, "proof", "secretsdump", "svc_sql:1001:aad3b435b51404ee:deadbeef::: (pwned)", false); err != nil {
		t.Fatal(err)
	}
	msg, isErr := updateReport(t, s, f.NodeID, `,"poe_level":4,"evidence_quotes":["deadbeef::: (pwned)"]`)
	if isErr || !strings.Contains(msg, "verification: verified") {
		t.Fatalf("unexpected result: err=%v %q", isErr, msg)
	}
}
