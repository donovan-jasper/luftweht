package models

import "time"

// Host represents a discovered host in the network
type Host struct {
	ID           int64      `json:"id"`
	IP           string     `json:"ip"`
	Hostname     string     `json:"hostname,omitempty"`
	Subnet       string     `json:"subnet"`
	Status       HostStatus `json:"status"`
	DiscoveredAt time.Time  `json:"discovered_at"`
	CompletedAt  *time.Time `json:"completed_at,omitempty"`
}

// HostStatus represents the current scan status of a host
type HostStatus string

const (
	HostStatusDiscovered  HostStatus = "discovered"
	HostStatusTCPScanning HostStatus = "tcp_scanning"
	HostStatusTCPDone     HostStatus = "tcp_done"
	HostStatusSVCScanning HostStatus = "svc_scanning"
	HostStatusSVCDone     HostStatus = "svc_done"
	HostStatusUDPScanning HostStatus = "udp_scanning"
	HostStatusComplete    HostStatus = "complete"
)

// Port represents a discovered port on a host
type Port struct {
	ID           int64     `json:"id"`
	HostID       int64     `json:"host_id"`
	Port         int       `json:"port"`
	Protocol     string    `json:"protocol"` // tcp or udp
	State        string    `json:"state"`    // open, closed, filtered
	Service      string    `json:"service,omitempty"`
	Version      string    `json:"version,omitempty"`
	DiscoveredAt time.Time `json:"discovered_at"`
}

// ScanProgress tracks the progress of scan chunks for resume capability
type ScanProgress struct {
	ID          int64          `json:"id"`
	HostID      *int64         `json:"host_id,omitempty"`
	Subnet      string         `json:"subnet,omitempty"`
	ScanType    ScanType       `json:"scan_type"`
	PortStart   int            `json:"port_start,omitempty"`
	PortEnd     int            `json:"port_end,omitempty"`
	Status      ProgressStatus `json:"status"`
	StartedAt   *time.Time     `json:"started_at,omitempty"`
	CompletedAt *time.Time     `json:"completed_at,omitempty"`
	Error       string         `json:"error,omitempty"`
}

// ScanType represents the type of scan being performed
type ScanType string

const (
	ScanTypeDiscovery ScanType = "discovery"
	ScanTypeTCP       ScanType = "tcp"
	ScanTypeSVC       ScanType = "svc"
	ScanTypeUDP       ScanType = "udp"
)

// ProgressStatus represents the status of a scan chunk
type ProgressStatus string

const (
	ProgressStatusPending  ProgressStatus = "pending"
	ProgressStatusRunning  ProgressStatus = "running"
	ProgressStatusComplete ProgressStatus = "complete"
	ProgressStatusFailed   ProgressStatus = "failed"
)

// ScanJob represents a unit of work for the scanner
type ScanJob struct {
	ID        int64
	HostID    *int64
	Host      *Host
	Subnet    string
	ScanType  ScanType
	PortStart int
	PortEnd   int
}

// ScanResult represents the result of a scan operation
type ScanResult struct {
	Job       *ScanJob
	Hosts     []Host  // For discovery scans
	Ports     []Port  // For port scans
	Error     error
	Timeout   bool
	StartTime time.Time
	EndTime   time.Time
}

// PortChunk defines a range of ports to scan
type PortChunk struct {
	Start int
	End   int
}

// DefaultTCPChunks returns the default port chunks for TCP scanning
func DefaultTCPChunks() []PortChunk {
	return []PortChunk{
		{1, 10000},
		{10001, 20000},
		{20001, 30000},
		{30001, 40000},
		{40001, 50000},
		{50001, 60000},
		{60001, 65535},
	}
}

// DefaultUDPChunks returns the default port chunks for UDP scanning
func DefaultUDPChunks() []PortChunk {
	return []PortChunk{
		{1, 10000},
		{10001, 20000},
		{20001, 30000},
		{30001, 40000},
		{40001, 50000},
		{50001, 60000},
		{60001, 65535},
	}
}
