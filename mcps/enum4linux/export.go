package enum4linux

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Autumn-27/artex/mcps/adcore"
)

// checks are the report entries of an enumeration, in report order.
var inventoryChecks = []string{"domain", "os_info", "sessions", "shares", "users", "groups", "policy", "printers"}

// sectionCheck maps a coverage check name to the export section it fills.
var sectionCheck = map[string]string{
	"domain":   "domain",
	"os_info":  "os_info",
	"sessions": "sessions",
	"shares":   "shares",
	"users":    "users",
	"groups":   "groups",
	"policy":   "policy",
	"printers": "printers",
	"machines": "machines",
}

type parsed struct {
	Domains          []adcore.Domain
	Hosts            []adcore.Host
	Shares           []adcore.Share
	Objects          adcore.Objects
	Coverage         adcore.Coverage
	Candidates       []adcore.Candidate
	LockoutThreshold *int
	authFailed       bool
	redactedJSON     []byte
}

// AuthOutcome keeps "anonymous" when no session could be established, and
// reports a failure when every session attempt was refused.
func (p parsed) AuthOutcome(current string) string {
	if p.authFailed {
		return "logon_failure"
	}
	return current
}

// parseExport decodes and redacts one enum4linux-ng export. It never returns a
// document that still contains the credential block.
func parseExport(raw []byte, target, profile string) (parsed, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return parsed{}, fmt.Errorf("empty JSON export")
	}
	var sections map[string]json.RawMessage
	if err := json.Unmarshal(raw, &sections); err != nil {
		return parsed{}, fmt.Errorf("invalid JSON export: %w", err)
	}
	// The export carries the credential in clear (Credentials.as_dict): drop it
	// before anything is stored or returned.
	delete(sections, "credentials")

	p := parsed{redactedJSON: nil}
	p.Coverage = adcore.Coverage{}
	p.Hosts = []adcore.Host{{Target: target}}
	p.Objects = adcore.Objects{}

	var errs map[string]map[string][]string
	if rawErrs, ok := sections["errors"]; ok {
		_ = json.Unmarshal(rawErrs, &errs)
	}
	delete(sections, "errors")

	// Domain and host info.
	if d, ok := decodeMap(sections["domain"]); ok {
		if name := firstString(d, "domain", "Domain", "NetBIOS domain name", "long_domain"); name != "" {
			p.Domains = appendDomain(p.Domains, name)
		}
		if h := firstString(d, "NetBIOS computer name", "host", "computer"); h != "" {
			p.Hosts[0].Hostname = h
		}
	}
	if d, ok := decodeMap(sections["os_info"]); ok {
		p.Hosts[0].OS = firstString(d, "OS", "os", "Operating system")
	}
	if d, ok := decodeMap(sections["smb_domain_info"]); ok {
		if name := firstString(d, "DNS domain name", "dns_domain", "NetBIOS domain name"); name != "" {
			p.Domains = appendDomain(p.Domains, name)
			p.Hosts[0].Domain = name
		}
	}
	if d, ok := decodeMap(sections["rpc_domain_info"]); ok {
		if name := firstString(d, "Domain Name", "domain", "NetBIOS domain name"); name != "" {
			p.Domains = appendDomain(p.Domains, name)
			if p.Hosts[0].Domain == "" {
				p.Hosts[0].Domain = name
			}
		}
	}

	// Policy: the same human labels NetExec prints.
	if d, ok := decodeMap(sections["policy"]); ok {
		info, _ := asMap(d["Domain password information"])
		pol := &adcore.PasswordPolicy{
			MinLength:          intField(info, "Minimum password length"),
			HistoryLength:      intField(info, "Password history length"),
			LockoutThreshold:   intField(info, "Account Lockout Threshold"),
			LockoutDurationMin: intField(info, "Locked Account Duration"),
			Complexity:         firstString(info, "Password Complexity Flags"),
		}
		domain := adcore.Domain{PasswordPolicy: pol}
		if len(p.Domains) > 0 {
			p.Domains[0].PasswordPolicy = pol
		} else {
			p.Domains = append(p.Domains, domain)
		}
		if pol.LockoutThreshold != nil {
			p.LockoutThreshold = pol.LockoutThreshold
		}
	}

	// Shares.
	if m, ok := decodeMap(sections["shares"]); ok {
		for name, v := range m {
			share := adcore.Share{Host: target, Name: name}
			if inner, ok := asMap(v); ok {
				if access, ok := asMap(inner["access"]); ok {
					share.Read = boolField(access, "read")
					share.Write = boolField(access, "write")
				}
				share.Remark = firstString(inner, "remark", "description", "comment")
			}
			p.Shares = append(p.Shares, share)
		}
		sort.Slice(p.Shares, func(i, j int) bool { return p.Shares[i].Name < p.Shares[j].Name })
	}

	// Users, groups, machines: {rid: {"username"/"groupname"/"machine": name}}.
	p.Objects.Users = objectField(sections["users"], "username")
	p.Objects.Groups = objectField(sections["groups"], "groupname")
	p.Objects.Computers = objectField(sections["machines"], "machine")

	// Coverage: one entry per check, from the section or its error.
	checks := inventoryChecks
	if profile == ProfileDeep {
		checks = append(append([]string{}, inventoryChecks...), "machines")
	}
	for _, check := range checks {
		section := sectionCheck[check]
		msg := firstError(errs, section)
		switch {
		case msg != "":
			p.Coverage.Classify(check, msg)
			if adcore.ClassifyMessage(msg) == adcore.StatusPermissionDenied &&
				strings.Contains(strings.ToLower(msg), "session") {
				p.authFailed = true
			}
		case hasContent(sections[section]) || (section == "machines" && profile == ProfileDeep):
			p.Coverage.Collect(check)
		default:
			p.Coverage.Skip(check, "no_output_for_check")
		}
	}
	redacted, err := json.MarshalIndent(sections, "", "  ")
	if err != nil {
		return parsed{}, err
	}
	if profile != ProfileDeep {
		p.Coverage.Skip("machines", adcore.ReasonNotInProfile)
	}
	p.redactedJSON = redacted
	return p, nil
}

// appendDomain merges NetBIOS and FQDN spellings of the same domain.
func appendDomain(in []adcore.Domain, name string) []adcore.Domain {
	name = strings.TrimSpace(name)
	if name == "" {
		return in
	}
	for i := range in {
		a, b := strings.ToLower(in[i].Name), strings.ToLower(name)
		if a == b || strings.HasPrefix(a, b+".") || strings.HasPrefix(b, a+".") {
			if len(name) > len(in[i].Name) {
				in[i].Name = name
			}
			return in
		}
	}
	return append(in, adcore.Domain{Name: name})
}

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok && m != nil
}

func decodeMap(raw json.RawMessage) (map[string]any, bool) {
	if len(raw) == 0 {
		return nil, false
	}
	var m map[string]any
	if json.Unmarshal(raw, &m) != nil || m == nil {
		return nil, false
	}
	return m, true
}

func hasContent(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return false
	}
	switch t := v.(type) {
	case nil:
		return false
	case map[string]any:
		return len(t) > 0
	case []any:
		return len(t) > 0
	case string:
		return strings.TrimSpace(t) != ""
	case bool:
		return t
	default:
		return true
	}
}

func firstString(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if m == nil {
			return ""
		}
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	return ""
}

func intField(m map[string]any, key string) *int {
	if m == nil {
		return nil
	}
	v, ok := m[key]
	if !ok {
		return nil
	}
	switch t := v.(type) {
	case float64:
		n := int(t)
		return &n
	case string:
		if n, err := strconv.Atoi(strings.TrimSpace(t)); err == nil {
			return &n
		}
	}
	return nil
}

func boolField(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	b, _ := m[key].(bool)
	return b
}

// objectField reads {rid: {name: value, ...}} maps into objects.
func objectField(raw json.RawMessage, nameKey string) []adcore.Object {
	m, ok := decodeMap(raw)
	if !ok {
		return nil
	}
	out := make([]adcore.Object, 0, len(m))
	for _, v := range m {
		inner, ok := asMap(v)
		if !ok {
			continue
		}
		if name := firstString(inner, nameKey); name != "" {
			out = append(out, adcore.Object{Name: name})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func firstError(errs map[string]map[string][]string, section string) string {
	byModule, ok := errs[section]
	if !ok {
		return ""
	}
	names := make([]string, 0, len(byModule))
	for name := range byModule {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		for _, msg := range byModule[name] {
			if strings.TrimSpace(msg) != "" {
				return msg
			}
		}
	}
	return ""
}
