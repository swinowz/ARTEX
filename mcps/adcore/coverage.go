package adcore

import "strings"

// Per-check statuses returned to the model. A check that was never run must
// never read like a negative result, so it is stored in its own bucket with a
// reason (issue #17).
const (
	StatusCollected        = "collected"
	StatusNotCollected     = "not_collected"
	StatusPermissionDenied = "permission_denied"
	StatusUnsupported      = "unsupported"
	StatusFailed           = "failed"
)

// Reason values used across the AD servers.
const (
	ReasonNotInProfile  = "not_in_profile"
	ReasonNotAttempted  = "not_attempted"
	ReasonAnonymous     = "no_credential"
	ReasonTimeBudget    = "time_budget"
	ReasonSchemaUnknown = "workspace_schema_unrecognized"
	ReasonUnknown       = "unknown_tool_error"
)

// Gap is one check that did not produce data, with the reason why.
type Gap struct {
	Check  string `json:"check"`
	Reason string `json:"reason,omitempty"`
}

// Coverage is the explicit separation of what was collected from what was not.
type Coverage struct {
	Collected        []string `json:"collected"`
	NotCollected     []Gap    `json:"not_collected,omitempty"`
	PermissionDenied []Gap    `json:"permission_denied,omitempty"`
	Unsupported      []Gap    `json:"unsupported,omitempty"`
	Failed           []Gap    `json:"failed,omitempty"`
}

// Collect records a check that returned data.
func (c *Coverage) Collect(check string) {
	if c == nil {
		return
	}
	c.Collected = append(c.Collected, check)
}

// Skip records a check that was not run.
func (c *Coverage) Skip(check, reason string) { c.add(StatusNotCollected, check, reason) }

// Deny records a check the target refused.
func (c *Coverage) Deny(check, reason string) { c.add(StatusPermissionDenied, check, reason) }

// Unsupported records a check the target or the protocol does not support.
func (c *Coverage) MarkUnsupported(check, reason string) { c.add(StatusUnsupported, check, reason) }

// Fail records a check that ran and did not produce a usable result.
func (c *Coverage) Fail(check, reason string) { c.add(StatusFailed, check, reason) }

// Classify records a check under the bucket its tool message implies.
func (c *Coverage) Classify(check, message string) {
	if c == nil {
		return
	}
	if c.isCollected(check) {
		return
	}
	switch ClassifyMessage(message) {
	case StatusPermissionDenied:
		c.Deny(check, firstLine(message))
	case StatusUnsupported:
		c.MarkUnsupported(check, firstLine(message))
	case StatusNotCollected:
		c.Skip(check, firstLine(message))
	default:
		c.Fail(check, firstLine(message))
	}
}

func (c *Coverage) add(status, check, reason string) {
	if c == nil || check == "" {
		return
	}
	g := Gap{Check: check, Reason: firstLine(reason)}
	switch status {
	case StatusNotCollected:
		c.NotCollected = append(c.NotCollected, g)
	case StatusPermissionDenied:
		c.PermissionDenied = append(c.PermissionDenied, g)
	case StatusUnsupported:
		c.Unsupported = append(c.Unsupported, g)
	default:
		c.Failed = append(c.Failed, g)
	}
}

func (c *Coverage) isCollected(check string) bool {
	for _, v := range c.Collected {
		if v == check {
			return true
		}
	}
	return false
}

// ClassifyMessage maps an SMB/RPC/LDAP status string to a coverage bucket. The
// order matters: an access-denied code sometimes carries a misleading generic
// error, so it is matched first.
func ClassifyMessage(msg string) string {
	u := strings.ToUpper(msg)
	switch {
	case strings.HasPrefix(u, "SKIPPING"):
		return StatusNotCollected
	case strings.Contains(u, "ACCESS_DENIED"),
		strings.Contains(u, "ERRACCESS"),
		strings.Contains(u, "PERMISSION DENIED"),
		strings.Contains(u, "AUTHENTICATION_FAILED"):
		return StatusPermissionDenied
	case strings.Contains(u, "NOT_SUPPORTED"),
		strings.Contains(u, "NOT_IMPLEMENTED"),
		strings.Contains(u, "STATUS_INVALID_PARAMETER"),
		strings.Contains(u, "UNSUPPORTED"),
		strings.Contains(u, "NOT POSSIBLE"):
		return StatusUnsupported
	default:
		return StatusFailed
	}
}

func firstLine(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	const max = 160
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
