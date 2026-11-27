package nmap

import (
	"encoding/xml"
	"fmt"
	"strings"
)

// xmlRun mirrors the subset of nmap's XML output this server needs. Only the
// declared fields are decoded; unknown elements are ignored. Go's encoding/xml
// never resolves external entities, so a hostile scan target cannot inject
// file/network entities through a banner.
type xmlRun struct {
	Hosts []xmlHost `xml:"host"`
	Stats struct {
		Finished struct {
			Exit     string `xml:"exit,attr"`
			ErrorMsg string `xml:"errormsg,attr"`
		} `xml:"finished"`
	} `xml:"runstats"`
}

type xmlHost struct {
	Status struct {
		State  string `xml:"state,attr"`
		Reason string `xml:"reason,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr     string `xml:"addr,attr"`
		AddrType string `xml:"addrtype,attr"`
	} `xml:"address"`
	Ports []struct {
		Protocol string `xml:"protocol,attr"`
		PortID   int    `xml:"portid,attr"`
		State    struct {
			State  string `xml:"state,attr"`
			Reason string `xml:"reason,attr"`
		} `xml:"state"`
		Service struct {
			Name      string `xml:"name,attr"`
			Product   string `xml:"product,attr"`
			Version   string `xml:"version,attr"`
			ExtraInfo string `xml:"extrainfo,attr"`
		} `xml:"service"`
	} `xml:"ports>port"`
}

type parsedXML struct {
	Hosts      []Host
	Observed   bool
	Incomplete bool
	Warning    string
}

// parseXML parses nmap XML. A truncated document is an error; a well-formed
// document that reports an aborted run is Incomplete, not a success.
func parseXML(raw []byte) (parsedXML, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return parsedXML{}, fmt.Errorf("empty output")
	}
	var run xmlRun
	if err := xml.Unmarshal(raw, &run); err != nil {
		return parsedXML{}, fmt.Errorf("malformed XML: %w", err)
	}
	out := parsedXML{}
	for _, h := range run.Hosts {
		host := Host{State: h.Status.State, Reason: h.Status.Reason}
		for _, a := range h.Addresses {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" || host.Address == "" {
				if host.Address == "" || a.AddrType == "ipv4" || a.AddrType == "ipv6" {
					host.Address = a.Addr
				}
			}
		}
		for _, p := range h.Ports {
			host.Services = append(host.Services, Service{
				Port: p.PortID, Protocol: p.Protocol, State: p.State.State,
				Name: p.Service.Name, Product: p.Service.Product,
				Version: p.Service.Version, Extra: p.Service.ExtraInfo,
			})
		}
		if host.State == "" {
			host.State = "unknown"
		}
		out.Hosts = append(out.Hosts, host)
		if host.State == "up" && len(host.Services) > 0 {
			out.Observed = true
		}
	}
	if exit := strings.ToLower(strings.TrimSpace(run.Stats.Finished.Exit)); exit != "" && exit != "success" {
		out.Incomplete = true
		if msg := strings.TrimSpace(run.Stats.Finished.ErrorMsg); msg != "" {
			out.Warning = "nmap reported " + exit + ": " + msg
		} else {
			out.Warning = "nmap reported an unsuccessful run (" + exit + ")"
		}
	}
	// A document with no runstats but at least one host is still useful; the
	// caller decides through Incomplete. A completely empty nmaprun is a valid
	// "nothing observed" answer, not malformed output.
	return out, nil
}
