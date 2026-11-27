package adcore

// The inventory wire format is shared by the AD capability servers (netexec,
// enum4linux) so a worker reads both results the same way.

// AuthResult is the authentication outcome of a run.
type AuthResult struct {
	Outcome          string `json:"outcome"` // anonymous|success|logon_failure|account_locked_out|password_expired|account_disabled
	Attempts         int    `json:"attempts"`
	LockoutThreshold *int   `json:"lockout_threshold,omitempty"`
}

// LockoutThresholdSeen records the domain policy observed with --pass-pol.
func (a *AuthResult) LockoutThresholdSeen(n int) {
	v := n
	a.LockoutThreshold = &v
}

// Domain is one domain observed or queried.
type Domain struct {
	Name           string          `json:"name,omitempty"`
	DCs            []string        `json:"dcs,omitempty"`
	PasswordPolicy *PasswordPolicy `json:"password_policy,omitempty"`
}

// PasswordPolicy is the password policy a target reported.
type PasswordPolicy struct {
	MinLength          *int   `json:"min_length,omitempty"`
	HistoryLength      *int   `json:"history_length,omitempty"`
	MaxAgeDays         *int   `json:"max_age_days,omitempty"`
	LockoutThreshold   *int   `json:"lockout_threshold,omitempty"`
	LockoutDurationMin *int   `json:"lockout_duration_min,omitempty"`
	Complexity         string `json:"complexity,omitempty"`
}

// Host is one target with its host info.
type Host struct {
	Target   string `json:"target"`
	Hostname string `json:"hostname,omitempty"`
	Domain   string `json:"domain,omitempty"`
	OS       string `json:"os,omitempty"`
	DC       *bool  `json:"dc,omitempty"`
	Signing  *bool  `json:"signing,omitempty"`
	SMBv1    *bool  `json:"smbv1,omitempty"`
}

// Share is one SMB share with the observing credential's access.
type Share struct {
	Host   string `json:"host"`
	Name   string `json:"name"`
	Remark string `json:"remark,omitempty"`
	Type   string `json:"type,omitempty"`
	Read   bool   `json:"read"`
	Write  bool   `json:"write"`
}

// Object is a user, group or computer.
type Object struct {
	Name   string `json:"name"`
	Domain string `json:"domain,omitempty"`
}

// Objects groups the directory objects by kind.
type Objects struct {
	Users     []Object `json:"users,omitempty"`
	Groups    []Object `json:"groups,omitempty"`
	Computers []Object `json:"computers,omitempty"`
}

// Access is one access result observed for the used credential.
type Access struct {
	Host   string `json:"host"`
	Kind   string `json:"kind"`
	Detail string `json:"detail,omitempty"`
}

// Candidate is a lead, explicitly not a confirmed finding.
type Candidate struct {
	Kind     string `json:"kind"`
	Target   string `json:"target,omitempty"`
	Evidence string `json:"evidence,omitempty"`
	Note     string `json:"note"`
}

// Stop explains why a run ended early.
type Stop struct {
	Reason string `json:"reason"`
	Detail string `json:"detail,omitempty"`
}
