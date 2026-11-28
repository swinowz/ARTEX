package netexec

import (
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/mcps/adcore"
)

// extract turns one nxc run into the structured, coverage-aware result.
func extract(in extractInput) extracted {
	var x extracted
	lines := parseLines(in.Stdout)
	x.Auth = authOutcome(lines)

	for _, l := range lines {
		if h, ok := parseHostLine(l); ok {
			x.Hosts = append(x.Hosts, h)
			x.addEvidence(l.raw)
			continue
		}
		msg := l.msg
		switch {
		case strings.HasPrefix(msg, "[+]") && (authRE.MatchString(msg) || strings.Contains(msg, "Pwn3d!")):
			x.addEvidence(l.raw)
		case strings.HasPrefix(msg, "[*]") && strings.Contains(msg, "Enumerated shares"):
			x.addEvidence(l.raw)
		}
	}

	parsePolicy(lines, &x)
	parseRIDBrute(lines, &x)
	parseLoggedOn(lines, &x)
	if in.Protocol == "ldap" {
		parseLDAPObjects(lines, &x)
		parseDelegation(lines, &x)
		parsePSO(lines, &x)
	}

	if users := readUsersExport(in.Export); len(users) > 0 {
		x.Objects.Users = users
	}

	ws, wsErr := readWorkspace(in.WorkDir, in.Protocol)
	if wsErr != nil {
		x.Warnings = append(x.Warnings, "workspace not read: "+wsErr.Error())
	} else {
		mergeWorkspace(&x, ws)
		x.Evidence = append(x.Evidence, fingerprintEvidence(ws.Hosts)...)
	}

	x.Candidates = signingCandidates(x.Hosts)
	x.Coverage = buildCoverage(in, &x, wsErr, lines)
	dedupeObjects(&x.Objects)
	sortShares(x.Shares)
	return x
}

func (x *extracted) addEvidence(line string) {
	const maxEvidence = 40
	if len(x.Evidence) < maxEvidence {
		x.Evidence = append(x.Evidence, line)
	}
}

// passwordPolicy returns the first parsed policy, if any.
func (x *extracted) passwordPolicy() bool {
	for _, d := range x.Domains {
		if d.PasswordPolicy != nil &&
			(d.PasswordPolicy.LockoutThreshold != nil || d.PasswordPolicy.MinLength != nil) {
			return true
		}
	}
	return false
}

func mergeWorkspace(x *extracted, ws workspace) {
	if len(x.Hosts) == 0 {
		x.Hosts = ws.Hosts
	} else {
		// Keep the parsed host info (os/domain/signing) and add hosts only the DB saw.
		seen := map[string]bool{}
		for _, h := range x.Hosts {
			seen[h.Target] = true
		}
		for _, h := range ws.Hosts {
			if !seen[h.Target] {
				x.Hosts = append(x.Hosts, h)
			}
		}
	}
	x.Shares = append(x.Shares, ws.Shares...)
	x.Access = append(x.Access, ws.Access...)
	if len(x.Objects.Users) == 0 {
		x.Objects.Users = ws.Users
	}
	if len(x.Objects.Groups) == 0 {
		x.Objects.Groups = ws.Groups
	}
}

// fingerprintEvidence adds one line per host the database reported (the log
// line may have been missed when the host line scrolled past).
func fingerprintEvidence(hosts []Host) []string {
	out := make([]string, 0, len(hosts))
	for _, h := range hosts {
		parts := []string{h.Target}
		if h.Hostname != "" {
			parts = append(parts, h.Hostname)
		}
		if h.Domain != "" {
			parts = append(parts, h.Domain)
		}
		out = append(out, strings.Join(parts, " "))
	}
	return out
}

func signingCandidates(hosts []Host) []Candidate {
	var out []Candidate
	for _, h := range hosts {
		if h.Signing != nil && !*h.Signing {
			out = append(out, Candidate{
				Kind:     "smb_signing_not_required",
				Target:   h.Target,
				Evidence: h.Target + " " + h.Hostname,
				Note:     "candidate for later review (relay is out of scope here); not a confirmed vulnerability",
			})
		}
		if h.SMBv1 != nil && *h.SMBv1 {
			out = append(out, Candidate{
				Kind:     "smb1_enabled",
				Target:   h.Target,
				Evidence: h.Target + " " + h.Hostname,
				Note:     "candidate only; not a confirmed vulnerability",
			})
		}
	}
	return out
}

// buildCoverage decides, per requested check, whether it produced data or why it
// did not. Every non-collected check carries a reason; nothing is inferred.
func buildCoverage(in extractInput, x *extracted, wsErr error, lines []logLine) adcore.Coverage {
	var c adcore.Coverage
	authBlocked := x.Auth.Outcome == "logon_failure" || x.Auth.Outcome == "account_locked_out" ||
		x.Auth.Outcome == "password_expired" || x.Auth.Outcome == "account_disabled"
	failures := failuresByCheck(lines)
	saw := func(substr string) bool {
		for _, l := range lines {
			if strings.Contains(l.msg, substr) {
				return true
			}
		}
		return false
	}
	mark := func(check string, ok bool, emptyOK bool) {
		switch {
		case ok:
			c.Collect(check)
		case failures[check] != "":
			c.Classify(check, failures[check])
		case authBlocked:
			c.Skip(check, "authentication_failed")
		case emptyOK:
			c.Collect(check)
		default:
			c.Skip(check, "no_output_for_check")
		}
	}

	if in.Protocol == "smb" {
		// NetExec enumerates groups and computers over LDAP only; say so instead
		// of leaving two silent holes in the SMB inventory.
		c.MarkUnsupported(checkGroups, "netexec enumerates groups over ldap only")
		c.MarkUnsupported(checkComputers, "netexec enumerates computers over ldap only")
	}
	for _, check := range requestedChecks(in.Protocol, in.Profile) {
		switch check {
		case checkHosts:
			if len(x.Hosts) == 0 && wsErr != nil {
				c.Fail(check, wsErr.Error())
				continue
			}
			mark(check, len(x.Hosts) > 0, false)
		case checkShares:
			mark(check, len(x.Shares) > 0 || saw("Enumerated shares"), saw("Enumerated shares"))
		case checkUsers:
			mark(check, len(x.Objects.Users) > 0 || fileExists(in.Export), false)
		case checkGroups:
			mark(check, len(x.Objects.Groups) > 0 || saw("-Group-") || saw("No entries found!"), saw("No entries found!"))
		case checkComputers:
			mark(check, len(x.Objects.Computers) > 0 || saw("Total records returned:"), false)
		case checkPassPol:
			mark(check, x.passwordPolicy(), x.passwordPolicy())
		case checkDCList:
			mark(check, len(x.Domains) > 0 && anyDC(x.Domains), false)
		case checkRIDBrute:
			mark(check, len(x.Objects.Users)+len(x.Objects.Groups) > 0, false)
		case checkLoggedOnUsers:
			mark(check, saw("logon_server:"), false)
		case checkDelegation:
			mark(check, saw("DelegationType") || saw("No entries found!"), saw("No entries found!"))
		case checkPSO:
			mark(check, saw("PSO Objects found") || saw("Attempting to enumerate policies"), false)
		}
	}
	return c
}

func anyDC(domains []Domain) bool {
	for _, d := range domains {
		if len(d.DCs) > 0 {
			return true
		}
	}
	return false
}

// failuresByCheck maps the first failure line to the check its wording names, so
// a denied share enumeration does not mark the users check as denied.
func failuresByCheck(lines []logLine) map[string]string {
	out := map[string]string{}
	keywords := []struct {
		check string
		words []string
	}{
		{checkShares, []string{"share"}},
		{checkPassPol, []string{"password policy", "pass-pol", "password info"}},
		{checkGroups, []string{"group"}},
		{checkComputers, []string{"computer"}},
		{checkDCList, []string{"domain controller", "dc list", "dc-list"}},
		{checkRIDBrute, []string{"rid"}},
		{checkLoggedOnUsers, []string{"logged on", "loggedon", "session"}},
		{checkDelegation, []string{"delegat"}},
		{checkPSO, []string{"pso", "password settings"}},
		{checkUsers, []string{"user"}},
	}
	for _, l := range lines {
		msg := l.msg
		if !strings.HasPrefix(msg, "[-]") && !strings.HasPrefix(msg, "Error ") && !strings.Contains(msg, "Error enumerating") {
			continue
		}
		low := strings.ToLower(msg)
		for _, k := range keywords {
			if out[k.check] != "" {
				continue
			}
			for _, w := range k.words {
				if strings.Contains(low, w) {
					out[k.check] = msg
					break
				}
			}
		}
	}
	return out
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && st.Size() > 0
}

// readUsersExport reads the one-username-per-line export nxc writes on success.
func readUsersExport(path string) []Object {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	var out []Object
	for _, line := range strings.Split(string(raw), "\n") {
		name := strings.TrimSpace(line)
		if name == "" {
			continue
		}
		out = append(out, Object{Name: name})
	}
	return out
}

// parseRIDBrute reads "--rid-brute" rows: "500: LAB\Administrator (SidTypeUser)".
func parseRIDBrute(lines []logLine, x *extracted) {
	for _, l := range lines {
		m := ridRE.FindStringSubmatch(l.msg)
		if m == nil {
			continue
		}
		domain, name, kind := m[2], m[3], strings.ToLower(m[4])
		obj := Object{Name: name, Domain: domain}
		x.addEvidence(l.raw)
		switch kind {
		case "user", "samuser":
			x.Objects.Users = append(x.Objects.Users, obj)
		case "group", "samgroup", "alias":
			x.Objects.Groups = append(x.Objects.Groups, obj)
		case "computer", "samcomputer", "machine":
			x.Objects.Computers = append(x.Objects.Computers, obj)
		}
	}
}

// parseLoggedOn reads the "--loggedon-users" rows.
func parseLoggedOn(lines []logLine, x *extracted) {
	for _, l := range lines {
		if !strings.Contains(l.msg, "logon_server:") {
			continue
		}
		entry := strings.TrimSpace(strings.SplitN(l.msg, " logon_server:", 2)[0])
		domain, name := "", entry
		if i := strings.Index(entry, `\`); i >= 0 {
			domain, name = entry[:i], entry[i+1:]
		}
		if name = strings.TrimSpace(name); name != "" {
			x.Objects.Users = append(x.Objects.Users, Object{Name: name, Domain: domain})
			x.addEvidence(l.raw)
		}
	}
}

// parseLDAPObjects reads the fixed-width tables the LDAP protocol prints: groups,
// computers and the DC list. A missing header is not an error: coverage reports
// that the check produced no output.
func parseLDAPObjects(lines []logLine, x *extracted) {
	groups := false
	computers := false
	for _, l := range lines {
		msg := l.body()
		switch {
		case strings.Contains(msg, "-Group-"):
			groups = true
			continue
		case strings.HasPrefix(msg, "Total records returned:"):
			computers = true
			continue
		}
		if m := dcRE.FindStringSubmatch(msg); m != nil {
			// "[LAB] DC01.LAB.LOCAL = 10.0.0.10"
			x.addDomain(m[1]).DCs = append(x.addDomain(m[1]).DCs, m[2])
			continue
		}
		if groups && len(msg) >= 40 {
			// Group rows are a 40-column name, then "members", then description;
			// the numeric second column keeps the pass-policy block out.
			name := strings.TrimSpace(msg[:40])
			rest := strings.Fields(msg[40:])
			if name != "" && !strings.HasPrefix(name, "-") && len(rest) > 0 {
				if _, err := strconv.Atoi(rest[0]); err == nil {
					x.Objects.Groups = append(x.Objects.Groups, Object{Name: name})
				}
			}
			continue
		}
		if computers && isComputerName(msg) {
			x.Objects.Computers = append(x.Objects.Computers, Object{Name: strings.TrimSpace(msg)})
		}
	}
}

// addDomain returns the domain entry with that name, creating it when needed.
func (x *extracted) addDomain(name string) *Domain {
	for i := range x.Domains {
		if sameDomain(x.Domains[i].Name, name) {
			if len(name) > len(x.Domains[i].Name) {
				x.Domains[i].Name = name // keep the FQDN over the NetBIOS name
			}
			return &x.Domains[i]
		}
	}
	x.Domains = append(x.Domains, Domain{Name: name})
	return &x.Domains[len(x.Domains)-1]
}

// sameDomain compares a NetBIOS name with its FQDN (LAB vs LAB.LOCAL).
func sameDomain(a, b string) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	if a == "" || b == "" {
		return false
	}
	return a == b || strings.HasPrefix(a, b+".") || strings.HasPrefix(b, a+".")
}

// isComputerName accepts a bare sAMAccountName line printed after the computers
// header, ignoring bracketed status lines.
func isComputerName(msg string) bool {
	msg = strings.TrimSpace(msg)
	if msg == "" || strings.HasPrefix(msg, "[") || strings.Contains(msg, " ") {
		return false
	}
	return strings.HasSuffix(msg, "$") || strings.Contains(msg, ".")
}

// parseDelegation reads the --find-delegation table rows.
func parseDelegation(lines []logLine, x *extracted) {
	for _, l := range lines {
		if !delegRE.MatchString(l.msg) {
			continue
		}
		fields := strings.Fields(l.msg)
		if len(fields) < 3 {
			continue
		}
		x.addEvidence(l.raw)
		x.Candidates = append(x.Candidates, Candidate{
			Kind:     "kerberos_delegation",
			Target:   fields[0],
			Evidence: l.msg,
			Note:     "delegation relationship observed; exploitation is out of scope here and this is not a confirmed vulnerability",
		})
	}
}

func parsePSO(lines []logLine, x *extracted) {
	for _, l := range lines {
		if strings.Contains(l.msg, "PSO Objects found") {
			x.addEvidence(l.raw)
		}
	}
}

func dedupeObjects(o *Objects) {
	o.Users = dedupeObjectsList(o.Users)
	o.Groups = dedupeObjectsList(o.Groups)
	o.Computers = dedupeObjectsList(o.Computers)
}

func dedupeObjectsList(in []Object) []Object {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := make([]Object, 0, len(in))
	for _, obj := range in {
		key := strings.ToLower(obj.Domain + `\` + obj.Name)
		if obj.Name == "" || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, obj)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		return out[i].Name < out[j].Name
	})
	return out
}

func sortShares(in []Share) {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Host != in[j].Host {
			return in[i].Host < in[j].Host
		}
		return in[i].Name < in[j].Name
	})
}
