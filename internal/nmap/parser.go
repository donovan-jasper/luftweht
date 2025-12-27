package nmap

import (
	"encoding/xml"
	"fmt"
	"time"

	"github.com/donovan-jasper/luftweht/internal/models"
)

// NmapRun represents the root element of nmap XML output
type NmapRun struct {
	XMLName          xml.Name `xml:"nmaprun"`
	Scanner          string   `xml:"scanner,attr"`
	Args             string   `xml:"args,attr"`
	Start            int64    `xml:"start,attr"`
	StartStr         string   `xml:"startstr,attr"`
	Version          string   `xml:"version,attr"`
	XMLOutputVersion string   `xml:"xmloutputversion,attr"`
	Hosts            []Host   `xml:"host"`
	RunStats         RunStats `xml:"runstats"`
}

// Host represents a host in nmap output
type Host struct {
	StartTime int64       `xml:"starttime,attr"`
	EndTime   int64       `xml:"endtime,attr"`
	Status    Status      `xml:"status"`
	Addresses []Address   `xml:"address"`
	Hostnames []Hostname  `xml:"hostnames>hostname"`
	Ports     Ports       `xml:"ports"`
	OS        OS          `xml:"os"`
	Times     Times       `xml:"times"`
}

// Status represents host status
type Status struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL int    `xml:"reason_ttl,attr"`
}

// Address represents an address (IP or MAC)
type Address struct {
	Addr     string `xml:"addr,attr"`
	AddrType string `xml:"addrtype,attr"`
	Vendor   string `xml:"vendor,attr"`
}

// Hostname represents a hostname
type Hostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

// Ports contains port information
type Ports struct {
	ExtraPorts []ExtraPort `xml:"extraports"`
	Ports      []Port      `xml:"port"`
}

// ExtraPort represents filtered/closed port counts
type ExtraPort struct {
	State string `xml:"state,attr"`
	Count int    `xml:"count,attr"`
}

// Port represents a single port
type Port struct {
	Protocol string  `xml:"protocol,attr"`
	PortID   int     `xml:"portid,attr"`
	State    State   `xml:"state"`
	Service  Service `xml:"service"`
	Scripts  []Script `xml:"script"`
}

// State represents port state
type State struct {
	State     string `xml:"state,attr"`
	Reason    string `xml:"reason,attr"`
	ReasonTTL int    `xml:"reason_ttl,attr"`
}

// Service represents service detection results
type Service struct {
	Name       string `xml:"name,attr"`
	Product    string `xml:"product,attr"`
	Version    string `xml:"version,attr"`
	ExtraInfo  string `xml:"extrainfo,attr"`
	Tunnel     string `xml:"tunnel,attr"`
	Method     string `xml:"method,attr"`
	Confidence int    `xml:"conf,attr"`
	CPE        string `xml:"cpe,attr"`
}

// Script represents NSE script output
type Script struct {
	ID     string `xml:"id,attr"`
	Output string `xml:"output,attr"`
}

// OS represents OS detection results
type OS struct {
	PortsUsed []PortUsed  `xml:"portused"`
	OSMatches []OSMatch   `xml:"osmatch"`
	OSClasses []OSClass   `xml:"osclass"`
}

// PortUsed represents a port used for OS detection
type PortUsed struct {
	State    string `xml:"state,attr"`
	Protocol string `xml:"proto,attr"`
	PortID   int    `xml:"portid,attr"`
}

// OSMatch represents an OS match
type OSMatch struct {
	Name     string `xml:"name,attr"`
	Accuracy int    `xml:"accuracy,attr"`
}

// OSClass represents an OS class
type OSClass struct {
	Type     string `xml:"type,attr"`
	Vendor   string `xml:"vendor,attr"`
	OSFamily string `xml:"osfamily,attr"`
	OSGen    string `xml:"osgen,attr"`
	Accuracy int    `xml:"accuracy,attr"`
}

// Times represents timing information
type Times struct {
	SRTT   int `xml:"srtt,attr"`
	RTTVar int `xml:"rttvar,attr"`
	To     int `xml:"to,attr"`
}

// RunStats represents scan statistics
type RunStats struct {
	Finished Finished `xml:"finished"`
	Hosts    HostStats `xml:"hosts"`
}

// Finished represents completion info
type Finished struct {
	Time    int64  `xml:"time,attr"`
	TimeStr string `xml:"timestr,attr"`
	Elapsed float64 `xml:"elapsed,attr"`
	Summary string `xml:"summary,attr"`
	Exit    string `xml:"exit,attr"`
}

// HostStats represents host statistics
type HostStats struct {
	Up    int `xml:"up,attr"`
	Down  int `xml:"down,attr"`
	Total int `xml:"total,attr"`
}

// ParseXML parses nmap XML output
func ParseXML(data []byte) (*NmapRun, error) {
	var result NmapRun
	if err := xml.Unmarshal(data, &result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ToModelHosts converts nmap hosts to model hosts
// Includes proxy ARP detection - if >50% of hosts share the same MAC, they're filtered out
func (n *NmapRun) ToModelHosts(subnet string) []models.Host {
	// First pass: collect all candidate hosts with their MACs
	type candidateHost struct {
		host models.Host
		mac  string
	}
	var candidates []candidateHost
	macCounts := make(map[string]int)

	for _, h := range n.Hosts {
		// Must be marked as "up"
		if h.Status.State != "up" {
			continue
		}

		reason := h.Status.Reason
		if reason == "" || reason == "no-response" || reason == "user-set" || reason == "localhost-response" {
			continue
		}

		host := models.Host{
			Subnet:       subnet,
			Status:       models.HostStatusDiscovered,
			DiscoveredAt: time.Now(),
		}

		// Get IP and MAC addresses
		var mac string
		for _, addr := range h.Addresses {
			switch addr.AddrType {
			case "ipv4", "ipv6":
				host.IP = addr.Addr
			case "mac":
				mac = addr.Addr
			}
		}

		// Get hostname if available
		for _, hn := range h.Hostnames {
			if hn.Name != "" {
				host.Hostname = hn.Name
				break
			}
		}

		if host.IP == "" {
			continue
		}

		// Only check for proxy ARP on arp-response discoveries
		// Other methods (ICMP, TCP) legitimately route through the gateway
		if reason == "arp-response" && mac != "" {
			candidates = append(candidates, candidateHost{host: host, mac: mac})
			macCounts[mac]++
		} else {
			// Non-ARP discovery or strong reason - don't filter by MAC
			candidates = append(candidates, candidateHost{host: host, mac: ""})
		}
	}

	// Detect proxy ARP: if any MAC appears on >50% of hosts, it's the firewall
	var proxyARPMac string
	threshold := len(candidates) / 2
	for mac, count := range macCounts {
		if count > threshold && count > 3 { // Also require at least 4 hosts to trigger
			proxyARPMac = mac
			break
		}
	}

	// Second pass: filter out proxy ARP hosts
	var hosts []models.Host
	for _, c := range candidates {
		// Keep if: no MAC (strong reason), different MAC than proxy, or no proxy detected
		if c.mac == "" || proxyARPMac == "" || c.mac != proxyARPMac {
			hosts = append(hosts, c.host)
		}
	}

	// Log if we filtered proxy ARP
	if proxyARPMac != "" {
		filtered := len(candidates) - len(hosts)
		if filtered > 0 {
			fmt.Printf("[Discovery] Proxy ARP detected (MAC %s) - filtered %d false hosts, kept %d\n",
				proxyARPMac, filtered, len(hosts))
		}
	}

	return hosts
}

// ToModelPorts converts nmap ports to model ports
func (h *Host) ToModelPorts(hostID int64) []models.Port {
	var ports []models.Port

	for _, p := range h.Ports.Ports {
		port := models.Port{
			HostID:       hostID,
			Port:         p.PortID,
			Protocol:     p.Protocol,
			State:        p.State.State,
			DiscoveredAt: time.Now(),
		}

		// Add service info if available
		if p.Service.Name != "" {
			port.Service = p.Service.Name
		}

		// Build version string
		var versionParts []string
		if p.Service.Product != "" {
			versionParts = append(versionParts, p.Service.Product)
		}
		if p.Service.Version != "" {
			versionParts = append(versionParts, p.Service.Version)
		}
		if p.Service.ExtraInfo != "" {
			versionParts = append(versionParts, "("+p.Service.ExtraInfo+")")
		}
		if len(versionParts) > 0 {
			port.Version = joinStrings(versionParts, " ")
		}

		ports = append(ports, port)
	}

	return ports
}

// GetOpenPortNumbers returns a slice of open port numbers
func (h *Host) GetOpenPortNumbers() []int {
	var ports []int
	for _, p := range h.Ports.Ports {
		if p.State.State == "open" {
			ports = append(ports, p.PortID)
		}
	}
	return ports
}

func joinStrings(parts []string, sep string) string {
	if len(parts) == 0 {
		return ""
	}
	result := parts[0]
	for _, p := range parts[1:] {
		result += sep + p
	}
	return result
}
