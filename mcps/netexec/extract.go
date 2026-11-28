package netexec

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/mcps/adcore"
)

// Profiles: both are read-only; deep adds the noisier enumeration checks.
const (
	ProfileInventory = "inventory"
	ProfileDeep      = "deep"
)

// Check names used in coverage.
const (
	checkHosts         = "hosts"
	checkShares        = "shares"
	checkUsers         = "users"
	checkGroups        = "groups"
	checkComputers     = "computers"
	checkPassPol       = "pass_pol"
	checkDCList        = "dc_list"
	checkRIDBrute      = "rid_brute"
	checkLoggedOnUsers = "loggedon_users"
	checkDelegation    = "delegation"
	checkPSO           = "pso"
)

// checkArgs maps the closed profile to nxc flags. The export path is added by
// the caller; no argument here is model-controlled.
func checkArgs(protocol, profile string) []string {
	switch protocol {
	case "smb":
		args := []string{"--shares", "--pass-pol"}
		if profile == ProfileDeep {
			args = append(args, "--rid-brute", "8192", "--loggedon-users")
		}
		return args
	default: // ldap
		args := []string{"--groups", "--computers", "--pass-pol", "--dc-list"}
		if profile == ProfileDeep {
			args = append(args, "--find-delegation", "--pso")
		}
		return args
	}
}

// requestedChecks is the coverage checklist of a run, in report order.
func requestedChecks(protocol, profile string) []string {
	if protocol == "smb" {
		out := []string{checkHosts, checkShares, checkUsers, checkPassPol}
		if profile == ProfileDeep {
			out = append(out, checkRIDBrute, checkLoggedOnUsers)
		}
		return out
	}
	out := []string{checkHosts, checkUsers, checkGroups, checkComputers, checkPassPol, checkDCList}
	if profile == ProfileDeep {
		out = append(out, checkDelegation, checkPSO)
	}
	return out
}

type extractInput struct {
	Protocol string
	Profile  string
	Stdout   string
	WorkDir  string
	Export   string
}

type extracted struct {
	Auth       AuthResult
	Domains    []Domain
	Hosts      []Host
	Shares     []Share
	Objects    Objects
	Access     []Access
	Candidates []Candidate
	Evidence   []string
	Coverage   adcore.Coverage
	Warnings   []string
}

// logLine is one nxc output line with its target prefix removed.
type logLine struct {
	raw  string // ANSI-stripped, verbatim (usable as evidence)
	ip   string
	host string
	msg  string
}

var (
	ansiRE   = regexp.MustCompile("\x1b\\[[0-9;]*[a-zA-Z]")
	prefixRE = regexp.MustCompile(`^(SMB|LDAP|WINRM|MSSQL|SSH|WMI|RDP|VNC|NFS|FTP)\s+(\S+)\s+\d+\s+(\S+)\s+(.*)$`)
	parenRE  = regexp.MustCompile(`\(([a-zA-Z0-9_]+):([^)]*)\)`)
	ridRE    = regexp.MustCompile(`^\s*(\d+):\s+(?:([^\\\s]+)\\)?(\S+)\s+\(SidType(\w+)\)`)
	dcRE     = regexp.MustCompile(`^\[([^\]]+)\]\s+(\S+)\s+=\s+(\d+\.\d+\.\d+\.\d+)`)
	authRE   = regexp.MustCompile(`\[\+\]\s+(\S*)\\(\S+?):(\S*)`)
	delegRE  = regexp.MustCompile(`^(Unconstrained|Constrained|Resource-Based Constrained)`)
)

// parseLines strips ANSI codes and the target prefix of every line.
func parseLines(stdout string) []logLine {
	out := []logLine{}
	for _, raw := range strings.Split(stdout, "\n") {
		raw = strings.TrimRight(ansiRE.ReplaceAllString(raw, ""), "\r")
		if strings.TrimSpace(raw) == "" {
			continue
		}
		l := logLine{raw: raw}
		if m := prefixRE.FindStringSubmatch(strings.TrimSpace(raw)); m != nil {
			l.ip, l.host, l.msg = m[2], m[3], strings.TrimSpace(m[4])
		} else {
			l.msg = strings.TrimSpace(raw)
		}
		out = append(out, l)
	}
	return out
}

// body removes the nxc level marker ("[*] ", "[+] ", ...) from a message.
func (l logLine) body() string {
	for _, m := range []string{"[*] ", "[+] ", "[-] ", "[!] "} {
		if strings.HasPrefix(l.msg, m) {
			return strings.TrimSpace(strings.TrimPrefix(l.msg, m))
		}
	}
	return l.msg
}

// authOutcome classifies the authentication lines. One credential, one attempt:
// the first failure ends the authenticated part of the run.
func authOutcome(lines []logLine) AuthResult {
	res := AuthResult{Outcome: "anonymous"}
	for _, l := range lines {
		if strings.Contains(l.msg, "LOCKED_OUT") || strings.Contains(strings.ToUpper(l.msg), "ACCOUNT_LOCKED") {
			return AuthResult{Outcome: "account_locked_out", Attempts: 1}
		}
	}
	for _, l := range lines {
		switch {
		case strings.Contains(l.msg, "STATUS_PASSWORD_EXPIRED"):
			return AuthResult{Outcome: "password_expired", Attempts: 1}
		case strings.Contains(l.msg, "STATUS_ACCOUNT_DISABLED"):
			return AuthResult{Outcome: "account_disabled", Attempts: 1}
		case strings.Contains(l.msg, "STATUS_LOGON_FAILURE"):
			return AuthResult{Outcome: "logon_failure", Attempts: 1}
		}
	}
	for _, l := range lines {
		if authRE.MatchString(l.msg) || strings.Contains(l.msg, "Pwn3d!") {
			res.Outcome = "success"
			res.Attempts = 1
			return res
		}
	}
	return res
}

func parseHostLine(l logLine) (Host, bool) {
	if !strings.HasPrefix(l.msg, "[*]") {
		return Host{}, false
	}
	fields := map[string]string{}
	for _, m := range parenRE.FindAllStringSubmatch(l.msg, -1) {
		fields[strings.ToLower(m[1])] = m[2]
	}
	if len(fields) == 0 {
		return Host{}, false
	}
	h := Host{Target: l.ip, Hostname: fields["name"], Domain: fields["domain"]}
	if osText := strings.TrimSpace(strings.SplitN(strings.TrimPrefix(l.msg, "[*]"), "(", 2)[0]); osText != "" {
		h.OS = osText
	}
	h.Signing = parseTriBool(fields["signing"])
	h.SMBv1 = parseTriBool(fields["smbv1"])
	if strings.EqualFold(fields["dc"], "true") {
		v := true
		h.DC = &v
	}
	return h, true
}

// parseTriBool reads True/False/None into a tri-state.
func parseTriBool(v string) *bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true":
		b := true
		return &b
	case "false":
		b := false
		return &b
	}
	return nil
}

func atoiPtr(v string) *int {
	n, err := strconv.Atoi(strings.TrimSpace(v))
	if err != nil {
		return nil
	}
	return &n
}

// parsePolicy reads the --pass-pol block: the lockout threshold is what keeps a
// later skill from locking the account.
func parsePolicy(lines []logLine, x *extracted) {
	var cur *Domain
	for _, l := range lines {
		msg := l.body()
		if strings.HasPrefix(msg, "Dumping password info for domain:") {
			name := strings.TrimSpace(strings.TrimPrefix(msg, "Dumping password info for domain:"))
			x.Domains = append(x.Domains, Domain{Name: name})
			cur = &x.Domains[len(x.Domains)-1]
			if cur.PasswordPolicy == nil {
				cur.PasswordPolicy = &PasswordPolicy{}
			}
			continue
		}
		if cur == nil || cur.PasswordPolicy == nil {
			continue
		}
		p := cur.PasswordPolicy
		switch {
		case strings.HasPrefix(msg, "Minimum password length:"):
			p.MinLength = atoiPtr(strings.TrimSpace(strings.TrimPrefix(msg, "Minimum password length:")))
		case strings.HasPrefix(msg, "Password history length:"):
			p.HistoryLength = atoiPtr(strings.TrimSpace(strings.TrimPrefix(msg, "Password history length:")))
		case strings.HasPrefix(msg, "Maximum password age:"):
			p.MaxAgeDays = atoiPtr(strings.TrimSpace(strings.TrimPrefix(msg, "Maximum password age:")))
		case strings.HasPrefix(msg, "Account Lockout Threshold:"):
			p.LockoutThreshold = atoiPtr(strings.TrimSpace(strings.TrimPrefix(msg, "Account Lockout Threshold:")))
			if p.LockoutThreshold != nil {
				x.Auth.LockoutThresholdSeen(*p.LockoutThreshold)
			}
		case strings.HasPrefix(msg, "Locked Account Duration:"):
			p.LockoutDurationMin = atoiPtr(strings.TrimSpace(strings.TrimPrefix(msg, "Locked Account Duration:")))
		case strings.HasPrefix(msg, "Password Complexity Flags:"):
			p.Complexity = strings.TrimSpace(strings.TrimPrefix(msg, "Password Complexity Flags:"))
		}
	}
}
