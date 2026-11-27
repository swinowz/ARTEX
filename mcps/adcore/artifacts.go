package adcore

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WriteArtifact stores one raw tool output under dir (created 0700) as a 0600
// file and returns its path. The caller passes data already redacted: an
// artifact is evidence the model may read back.
func WriteArtifact(dir, prefix, ext string, data []byte, now time.Time) (string, error) {
	if strings.TrimSpace(dir) == "" {
		return "", fmt.Errorf("artifact directory is not configured")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	name := fmt.Sprintf("%s-%s%s", prefix, now.UTC().Format("20060102T150405.000000000Z"), ext)
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// Redact replaces every occurrence of each secret in text. Empty values are
// ignored so a missing secret cannot turn into a wildcard. The tool output is
// also expected to mask secrets on its own (NetExec audit_mode): this is the
// second line of defence.
func Redact(text string, secrets ...string) string {
	for _, s := range secrets {
		if s == "" {
			continue
		}
		text = strings.ReplaceAll(text, s, "***")
	}
	return text
}

// SecretString returns the secrets of the credentials, for Redact calls.
func SecretString(creds []Credential) []string {
	out := make([]string, 0, len(creds))
	for _, c := range creds {
		if c.Secret != "" {
			out = append(out, c.Secret)
		}
	}
	return out
}

// Tail keeps the last n bytes of a tool output for a warning field.
func Tail(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return "…" + s[len(s)-n:]
}
