package server

import (
	"strings"
	"testing"

	"github.com/Autumn-27/artex/db"
)

// evaluateEvidence is the source-agnostic rule core extracted from
// assessFindingVerification (ADR-0004, #8). These tests pin its behaviour so the
// HTTP path stays identical and the future command-output path reuses the same rules.

func textBody(s string) boundBody { return boundBody{text: normalizeEvidenceText(s)} }

func TestEvaluateEvidencePOEBelowL3Unverified(t *testing.T) {
	st, note := evaluateEvidence(2, []string{"administrator hash dumped"}, []boundBody{textBody("administrator hash dumped")})
	if st != db.VerificationUnverified {
		t.Fatalf("status = %q, want %q", st, db.VerificationUnverified)
	}
	if !strings.Contains(note, "L2") {
		t.Fatalf("note %q should mention the POE level", note)
	}
}

func TestEvaluateEvidenceNoQuotesUnverified(t *testing.T) {
	st, _ := evaluateEvidence(4, nil, []boundBody{textBody("whatever")})
	if st != db.VerificationUnverified {
		t.Fatalf("status = %q, want unverified", st)
	}
}

func TestEvaluateEvidenceShortQuoteUnverified(t *testing.T) {
	st, note := evaluateEvidence(4, []string{"x7"}, []boundBody{textBody("x7 appears here")})
	if st != db.VerificationUnverified {
		t.Fatalf("status = %q, want unverified", st)
	}
	if !strings.Contains(note, "short") {
		t.Fatalf("note %q should say the quote is too short", note)
	}
}

func TestEvaluateEvidenceExactQuoteVerified(t *testing.T) {
	body := textBody("Nmap scan report\n445/tcp open microsoft-ds\nSMB signing: disabled")
	st, note := evaluateEvidence(3, []string{"SMB signing: disabled"}, []boundBody{body})
	if st != db.VerificationVerified {
		t.Fatalf("status = %q (note %q), want verified", st, note)
	}
}

func TestEvaluateEvidenceQuoteNotFoundUnverified(t *testing.T) {
	st, note := evaluateEvidence(4, []string{"RID 500 cracked offline"}, []boundBody{textBody("no such line in this output")})
	if st != db.VerificationUnverified {
		t.Fatalf("status = %q, want unverified", st)
	}
	if !strings.Contains(note, "not found") {
		t.Fatalf("note %q should say the quote was not found", note)
	}
}

func TestEvaluateEvidenceNonTextFailsClosed(t *testing.T) {
	st, _ := evaluateEvidence(4, []string{"something long enough"}, []boundBody{{nonText: true}})
	if st != db.VerificationNotAssessed {
		t.Fatalf("status = %q, want not_assessed (fail closed on non-text)", st)
	}
}

func TestEvaluateEvidenceTruncatedMissFailsClosed(t *testing.T) {
	st, _ := evaluateEvidence(4, []string{"quote beyond the read cap"}, []boundBody{{text: "partial body", truncated: true}})
	if st != db.VerificationNotAssessed {
		t.Fatalf("status = %q, want not_assessed when a miss may be past the cap", st)
	}
}

// A quote found in ONE of several bodies verifies, even if others are non-text.
// This matters for the union of HTTP + command-output evidence (ADR-0004 increment 3).
func TestEvaluateEvidenceFoundInOneOfSeveralBodies(t *testing.T) {
	bodies := []boundBody{{nonText: true}, textBody("ticket extracted for svc_mssql")}
	st, note := evaluateEvidence(3, []string{"ticket extracted for svc_mssql"}, bodies)
	if st != db.VerificationVerified {
		t.Fatalf("status = %q (note %q), want verified when the quote is in one readable body", st, note)
	}
}
