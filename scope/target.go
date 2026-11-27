// Package scope implements the offline, signed mission manifest that capability
// MCP servers verify before performing an operation (issue #14).
//
// It deliberately has no dependency on ARTEX's database, interceptor or server
// packages: a standalone MCP server can import it (or vendor it) and validate a
// mission without a live control plane. It is not an egress firewall; it only
// constrains code that calls it. Native Bash, custom tools and servers that
// ignore this package are covered by the platform's hook and target gate, not
// here.
package scope

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// Target kinds.
const (
	TargetDomain = "domain"
	TargetIP     = "ip"
	TargetCIDR   = "cidr"
)

// Target is one normalised network target. Host is a lower-case punycode name,
// a canonical IP literal, or a masked CIDR.
type Target struct {
	Kind string
	Host string
	Port int
}

var schemePorts = map[string]int{"http": 80, "https": 443, "ws": 80, "wss": 443, "ftp": 21}

// hostProfile maps names the way a lookup does, without the strict rules that
// would reject an underscore label in a hostname.
var hostProfile = idna.New(idna.MapForLookup(), idna.BidiRule())

// Normalize parses a URL with a scheme, or a host, host:port, [IPv6]:port, IP
// literal or CIDR. Userinfo and URL path/query are dropped; IPv4-mapped IPv6 is
// unmapped; the numeric IPv4 forms a resolver accepts (2130706433, 0x7f000001,
// 0177.0.0.1, 127.1) are canonicalised.
func Normalize(raw string) (Target, bool) {
	raw = strings.TrimSpace(raw)
	defPort, isURL := 0, false
	if i := strings.Index(raw, "://"); i > 0 {
		isURL = true
		defPort = schemePorts[strings.ToLower(raw[:i])]
		raw = raw[i+3:]
		if end := strings.IndexAny(raw, "/?#"); end >= 0 {
			raw = raw[:end]
		}
		raw = raw[strings.LastIndexByte(raw, '@')+1:]
	}
	host, port := raw, ""
	switch {
	case strings.HasPrefix(raw, "["):
		end := strings.IndexByte(raw, ']')
		if end < 0 {
			return Target{}, false
		}
		host = raw[1:end]
		if rest := raw[end+1:]; rest != "" {
			if rest[0] != ':' {
				return Target{}, false
			}
			port = rest[1:]
		}
	case strings.Count(raw, ":") == 1:
		host, port, _ = strings.Cut(raw, ":")
	}
	if isURL {
		if decoded, err := url.PathUnescape(host); err == nil {
			host = decoded
		}
	}
	t := Target{Port: defPort}
	if port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return Target{}, false
		}
		t.Port = n
	}
	var ok bool
	t.Kind, t.Host, ok = normalizeHost(host)
	return t, ok
}

func normalizeHost(raw string) (kind, host string, ok bool) {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if h == "" || strings.HasPrefix(h, "-") {
		return "", "", false
	}
	// A host name never contains whitespace; refusing it here keeps a target from
	// being mistaken for several arguments by a downstream command.
	if strings.ContainsAny(h, " \t\r\n") {
		return "", "", false
	}
	if strings.Contains(h, "/") {
		p, err := netip.ParsePrefix(h)
		if err != nil {
			return "", "", false
		}
		return TargetCIDR, p.Masked().String(), true
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return TargetIP, a.Unmap().WithZone("").String(), true
	}
	if a, ok := parseIPv4Forms(h); ok {
		return TargetIP, a.String(), true
	}
	if name, err := hostProfile.ToASCII(h); err == nil && name != "" {
		h = name
	}
	return TargetDomain, h, true
}

// parseIPv4Forms accepts the non-dotted forms inet_aton and resolvers accept:
// one 32-bit part, a.b (b has 24 bits), a.b.c (c has 16 bits), or a.b.c.d. Each
// part may be decimal, hex (0x) or octal (leading 0).
func parseIPv4Forms(h string) (netip.Addr, bool) {
	parts := strings.Split(h, ".")
	if len(parts) < 1 || len(parts) > 4 {
		return netip.Addr{}, false
	}
	nums := make([]uint32, len(parts))
	for i, p := range parts {
		n, ok := parseIPv4Part(p)
		if !ok {
			return netip.Addr{}, false
		}
		nums[i] = n
	}
	var ip uint32
	switch len(nums) {
	case 1:
		ip = nums[0]
	case 2:
		if nums[0] > 0xff || nums[1] > 0xffffff {
			return netip.Addr{}, false
		}
		ip = nums[0]<<24 | nums[1]
	case 3:
		if nums[0] > 0xff || nums[1] > 0xff || nums[2] > 0xffff {
			return netip.Addr{}, false
		}
		ip = nums[0]<<24 | nums[1]<<16 | nums[2]
	case 4:
		for _, n := range nums {
			if n > 0xff {
				return netip.Addr{}, false
			}
		}
		ip = nums[0]<<24 | nums[1]<<16 | nums[2]<<8 | nums[3]
	}
	return netip.AddrFrom4([4]byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)}), true
}

func parseIPv4Part(p string) (uint32, bool) {
	if p == "" {
		return 0, false
	}
	base := 10
	switch {
	case strings.HasPrefix(p, "0x") || strings.HasPrefix(p, "0X"):
		base, p = 16, p[2:]
	case len(p) > 1 && p[0] == '0':
		base, p = 8, p[1:]
	}
	if p == "" {
		return 0, true // "0" and "0x" both mean zero
	}
	n, err := strconv.ParseUint(p, base, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

func (t Target) String() string {
	if t.Kind == TargetDomain && t.Port != 0 {
		return t.Host + ":" + strconv.Itoa(t.Port)
	}
	if t.Kind == TargetIP && t.Port != 0 {
		return netip.MustParseAddr(t.Host).String() + ":" + strconv.Itoa(t.Port)
	}
	return t.Host
}

// domainCovers reports whether rule covers name: the exact name or any
// subdomain, never a sibling that merely shares a suffix.
func domainCovers(rule, name string) bool {
	rule = strings.TrimSuffix(strings.ToLower(rule), ".")
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	return name == rule || strings.HasSuffix(name, "."+rule)
}

func targetPrefix(t Target) (netip.Prefix, bool) {
	if t.Kind != TargetCIDR {
		return netip.Prefix{}, false
	}
	p, err := netip.ParsePrefix(t.Host)
	if err != nil {
		return netip.Prefix{}, false
	}
	return p, true
}

func addrOf(t Target) (netip.Addr, bool) {
	if t.Kind != TargetIP {
		return netip.Addr{}, false
	}
	a, err := netip.ParseAddr(t.Host)
	if err != nil {
		return netip.Addr{}, false
	}
	return a.Unmap().WithZone(""), true
}

func sameFamily(a, b netip.Addr) bool { return a.Is4() == b.Is4() }
