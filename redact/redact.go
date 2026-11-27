// Package redact removes authentication material from text before it reaches the
// model provider (issue #11).
//
// The filter runs on the outgoing request body, so it covers every source of
// model-visible text: tool results (including Bash output), graph facts,
// recorded evidence and the transcript itself. It works on raw JSON too: every
// pattern matches a span that contains no unescaped quote, so replacing it keeps
// the body valid.
//
// This is a safety net, not a classification system. A task that legitimately
// needs the material (pass-the-hash, ticket reuse) opts out with
// tasks.send_auth_material.
package redact

import "regexp"

// Placeholders replacing removed material. They contain no quote, backslash or
// base64 run, so the output is stable if the filter runs twice.
const (
	PlaceholderHash       = "[REDACTED:ntlm-hash]"
	PlaceholderPrivateKey = "[REDACTED:private-key]"
	PlaceholderSecret     = "[REDACTED]"
	PlaceholderBlob       = "[REDACTED:blob]"
	PlaceholderCredential = "[REDACTED:credential]"
)

// patterns run in order. The private-key and JSON-secret rules come before the
// generic base64 rule so a key block is labelled as a key, not as a blob.
var patterns = []struct {
	re   *regexp.Regexp
	repl string
}{
	// NT/LM hash pair, the shape secretsdump prints: lm:nt.
	{regexp.MustCompile(`\b[0-9a-fA-F]{32}:[0-9a-fA-F]{32}\b`), PlaceholderHash},
	// PEM private key block (plain text), also matched when JSON-escaped.
	{regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`), PlaceholderPrivateKey},
	// Password-like JSON fields: tool arguments (save_task_credential) and API
	// responses the agent may read. The value is unmarshalled by the provider as
	// an opaque string, so masking it changes nothing structurally.
	{regexp.MustCompile(`(?i)"(password|passwd|pwd|secret|nthash|ntlm_hash|hash)"\s*:\s*"[^"]*"`), `"$1":"` + PlaceholderSecret + `"`},
	// domain\user:password (nxc, impacket, smbclient), also in its JSON-escaped
	// form. The value must carry a letter so "host:8080" and timestamps survive.
	{regexp.MustCompile(`[A-Za-z0-9._$-]+(?:\\\\|\\|@)[A-Za-z0-9._$-]+:[^\s"\\]*[A-Za-z][^\s"\\]*`), PlaceholderCredential},
	// Kerberos tickets (kirbi/base64) and other long base64/url-base64 blobs.
	{regexp.MustCompile(`[A-Za-z0-9+/_-]{400,}={0,2}`), PlaceholderBlob},
}

// Text returns text with every authentication-material pattern replaced.
func Text(text string) string {
	if text == "" {
		return text
	}
	for _, p := range patterns {
		text = p.re.ReplaceAllString(text, p.repl)
	}
	return text
}

// Changed reports whether Text would modify text, without allocating a second
// copy when nothing matches.
func Changed(text string) bool {
	for _, p := range patterns {
		if p.re.MatchString(text) {
			return true
		}
	}
	return false
}
