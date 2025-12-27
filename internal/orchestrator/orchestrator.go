package orchestrator

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/donovan-jasper/luftweht/internal/config"
	"github.com/donovan-jasper/luftweht/internal/db"
	"github.com/donovan-jasper/luftweht/internal/models"
	"github.com/donovan-jasper/luftweht/internal/nmap"
)

// Orchestrator coordinates the scanning process
type Orchestrator struct {
	db     *db.DB
	nmap   *nmap.Runner
	config *config.Config

	// Pipeline channels
	tcpQueue  chan string // IPs to TCP scan
	deepQueue chan int64  // Host IDs to deep scan
	udpQueue  chan int64  // Host IDs to UDP scan

	// Channel close synchronization
	closeDeep sync.Once
	closeUDP  sync.Once

	// Cancellation
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Stats
	hostsDiscovered int32
	portsFound      int32
}

// NewOrchestrator creates a new scan orchestrator
func NewOrchestrator(database *db.DB, cfg *config.Config) *Orchestrator {
	ctx, cancel := context.WithCancel(context.Background())

	return &Orchestrator{
		db:        database,
		nmap:      nmap.NewRunner(cfg.Timing, cfg.Verbose),
		config:    cfg,
		tcpQueue:  make(chan string, 1000),
		deepQueue: make(chan int64, 1000),
		udpQueue:  make(chan int64, 1000),
		ctx:       ctx,
		cancel:    cancel,
	}
}

// Run executes the scan pipeline
func (o *Orchestrator) Run(subnets []string) error {
	maxWorkers := o.config.GetMaxWorkers()
	fmt.Printf("Starting pipeline scan of %d subnet(s) with %d workers\n", len(subnets), maxWorkers)

	if err := nmap.CheckNmapInstalled(); err != nil {
		return err
	}

	// Start worker pools for each phase
	// TCP scan workers
	for i := 0; i < maxWorkers; i++ {
		o.wg.Add(1)
		go o.tcpWorker()
	}

	// Deep scan workers (fewer, they're slower)
	deepWorkers := maxWorkers / 2
	if deepWorkers < 1 {
		deepWorkers = 1
	}
	if !o.config.SkipService {
		for i := 0; i < deepWorkers; i++ {
			o.wg.Add(1)
			go o.deepWorker()
		}
	}

	// UDP scan workers
	if !o.config.SkipUDP {
		for i := 0; i < deepWorkers; i++ {
			o.wg.Add(1)
			go o.udpWorker()
		}
	}

	// Either run discovery or queue all IPs directly
	if o.config.SkipDiscovery {
		fmt.Println("\n[Pipeline] Skipping discovery, scanning all IPs directly...")
		o.queueAllIPs(subnets)
	} else {
		fmt.Println("\n[Pipeline] Starting discovery + scans...")
		o.runDiscovery(subnets)
	}

	// Close TCP queue when discovery/queueing done
	close(o.tcpQueue)

	// Wait for all workers
	o.wg.Wait()

	o.printSummary()
	return nil
}

// runDiscovery runs parallel discovery and feeds hosts into TCP queue
func (o *Orchestrator) runDiscovery(subnets []string) {
	discovered := make(map[string]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, o.config.GetMaxWorkers())

	// Split into /24 chunks
	var chunks []string
	for _, subnet := range subnets {
		chunks = append(chunks, splitSubnet(subnet)...)
	}
	fmt.Printf("Discovery: %d chunks (4 methods each)\n", len(chunks))

	methods := []struct {
		name string
		flag string
	}{
		{"ICMP", ""},
		{"TCP-SYN", "-PS22,80,443,3389,8080,8443"},
		{"TCP-ACK", "-PA22,80,443,3389"},
		{"ARP", "-PR"},
	}

	for _, chunk := range chunks {
		for _, method := range methods {
			chunk := chunk
			method := method
			wg.Add(1)

			go func() {
				sem <- struct{}{}
				defer func() { <-sem }()
				defer wg.Done()

				args := []string{"-sn"}
				if method.flag != "" {
					args = append(args, method.flag)
				}
				args = append(args, chunk)

				result, err := o.nmap.RunRaw(o.ctx, args, 3*time.Minute)
				if err != nil {
					return
				}

				// Process discovered hosts immediately
				hosts := result.ToModelHosts(chunk)
				for _, h := range hosts {
					if h.IP == "" {
						continue
					}

					mu.Lock()
					isNew := !discovered[h.IP]
					if isNew {
						discovered[h.IP] = true
					}
					mu.Unlock()

					if isNew {
						// Insert to DB
						_, err := o.db.InsertHost(h.IP, h.Hostname, chunk)
						if err == nil {
							atomic.AddInt32(&o.hostsDiscovered, 1)
							// Immediately queue for TCP scan
							select {
							case o.tcpQueue <- h.IP:
							case <-o.ctx.Done():
								return
							}
						}
					}
				}
			}()
		}
	}

	wg.Wait()
	fmt.Printf("Discovery complete: %d hosts\n", atomic.LoadInt32(&o.hostsDiscovered))
}

// queueAllIPs generates all IPs from subnets and queues them directly for TCP scanning
// This bypasses discovery for firewall-heavy networks where probes get blocked or spoofed
func (o *Orchestrator) queueAllIPs(subnets []string) {
	// Split into /24 chunks first
	var chunks []string
	for _, subnet := range subnets {
		chunks = append(chunks, splitSubnet(subnet)...)
	}

	totalIPs := 0
	for _, chunk := range chunks {
		ips := expandSubnetToIPs(chunk)
		for _, ip := range ips {
			// Insert as discovered (we're assuming it might be live)
			_, err := o.db.InsertHost(ip, "", chunk)
			if err == nil {
				atomic.AddInt32(&o.hostsDiscovered, 1)
				totalIPs++

				// Queue for TCP scan
				select {
				case o.tcpQueue <- ip:
				case <-o.ctx.Done():
					return
				}
			}
		}
	}

	fmt.Printf("Queued %d IPs for direct TCP scanning\n", totalIPs)
}

// expandSubnetToIPs generates all host IPs in a /24 subnet (excluding .0 and .255)
func expandSubnetToIPs(cidr string) []string {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return nil
	}

	octets := strings.Split(parts[0], ".")
	if len(octets) != 4 {
		return nil
	}

	var o1, o2, o3 int
	fmt.Sscanf(octets[0], "%d", &o1)
	fmt.Sscanf(octets[1], "%d", &o2)
	fmt.Sscanf(octets[2], "%d", &o3)

	var ips []string
	// Generate .1 through .254 (skip network and broadcast)
	for i := 1; i < 255; i++ {
		ips = append(ips, fmt.Sprintf("%d.%d.%d.%d", o1, o2, o3, i))
	}

	return ips
}

// tcpWorker processes TCP scans
func (o *Orchestrator) tcpWorker() {
	defer o.wg.Done()

	for ip := range o.tcpQueue {
		select {
		case <-o.ctx.Done():
			return
		default:
		}

		host, err := o.db.GetHostByIP(ip)
		if err != nil {
			continue
		}

		o.db.UpdateHostStatus(host.ID, models.HostStatusTCPScanning)

		// Use -Pn in skip-discovery mode (we haven't verified hosts are up)
		result, err := o.nmap.ScanTCPFast(o.ctx, ip, o.config.SkipDiscovery)
		if err != nil {
			o.db.UpdateHostStatus(host.ID, models.HostStatusTCPDone)
			o.queueNextPhase(host.ID, false)
			continue
		}

		// Save ports
		hasOpenPorts := false
		if len(result.Hosts) > 0 {
			ports := result.Hosts[0].ToModelPorts(host.ID)
			if len(ports) > 0 {
				o.db.InsertPorts(ports)
				atomic.AddInt32(&o.portsFound, int32(len(ports)))
				hasOpenPorts = true
			}
		}

		o.db.UpdateHostStatus(host.ID, models.HostStatusTCPDone)
		o.queueNextPhase(host.ID, hasOpenPorts)
	}

	// When TCP queue closes, close next queue
	if o.config.SkipService {
		// No deep scan, close UDP queue directly
		o.closeUDP.Do(func() { close(o.udpQueue) })
	} else {
		o.closeDeep.Do(func() { close(o.deepQueue) })
	}
}

// queueNextPhase queues a host for the next scan phase
func (o *Orchestrator) queueNextPhase(hostID int64, hasOpenPorts bool) {
	// If deep scan enabled and has open ports, queue for deep scan
	if !o.config.SkipService && hasOpenPorts {
		select {
		case o.deepQueue <- hostID:
		case <-o.ctx.Done():
		}
		return
	}

	// Otherwise, if UDP enabled, queue for UDP
	if !o.config.SkipUDP {
		select {
		case o.udpQueue <- hostID:
		case <-o.ctx.Done():
		}
	}
}

// deepWorker processes deep scans
func (o *Orchestrator) deepWorker() {
	defer o.wg.Done()

	for hostID := range o.deepQueue {
		select {
		case <-o.ctx.Done():
			return
		default:
		}

		host, err := o.db.GetHostByID(hostID)
		if err != nil {
			continue
		}

		ports, err := o.db.GetOpenPorts(hostID, "tcp")
		if err != nil || len(ports) == 0 {
			o.db.UpdateHostStatus(hostID, models.HostStatusSVCDone)
			if !o.config.SkipUDP {
				select {
				case o.udpQueue <- hostID:
				case <-o.ctx.Done():
				}
			}
			continue
		}

		o.db.UpdateHostStatus(hostID, models.HostStatusSVCScanning)

		// Build port list (excluding brittle)
		var portNums []int
		for _, p := range ports {
			if !isBrittlePort(p.Port) {
				portNums = append(portNums, p.Port)
			}
		}

		if len(portNums) > 0 {
			result, err := o.nmap.ScanDeep(o.ctx, host.IP, portNums)
			if err == nil && len(result.Hosts) > 0 {
				updatedPorts := result.Hosts[0].ToModelPorts(hostID)
				if len(updatedPorts) > 0 {
					o.db.InsertPorts(updatedPorts)
				}
			}
		}

		o.db.UpdateHostStatus(hostID, models.HostStatusSVCDone)

		// Queue for UDP
		if !o.config.SkipUDP {
			select {
			case o.udpQueue <- hostID:
			case <-o.ctx.Done():
			}
		}
	}

	// When deep queue closes, close UDP queue (only once)
	o.closeUDP.Do(func() { close(o.udpQueue) })
}

// udpWorker processes UDP scans
func (o *Orchestrator) udpWorker() {
	defer o.wg.Done()

	for hostID := range o.udpQueue {
		select {
		case <-o.ctx.Done():
			return
		default:
		}

		host, err := o.db.GetHostByID(hostID)
		if err != nil {
			continue
		}

		o.db.UpdateHostStatus(hostID, models.HostStatusUDPScanning)

		result, err := o.nmap.ScanUDPFast(o.ctx, host.IP)
		if err == nil && len(result.Hosts) > 0 {
			ports := result.Hosts[0].ToModelPorts(hostID)
			if len(ports) > 0 {
				o.db.InsertPorts(ports)
				atomic.AddInt32(&o.portsFound, int32(len(ports)))
			}
		}

		o.db.UpdateHostStatus(hostID, models.HostStatusComplete)
	}
}

// printSummary prints final statistics
func (o *Orchestrator) printSummary() {
	stats, _ := o.db.GetScanStats()

	line := "══════════════════════════════════════════════════"
	fmt.Println("\n" + line)
	fmt.Println("SCAN COMPLETE")
	fmt.Println(line)
	fmt.Printf("Hosts discovered:  %d\n", atomic.LoadInt32(&o.hostsDiscovered))
	fmt.Printf("Open ports found:  %d\n", stats["open_ports"])
	fmt.Printf("Results saved to:  %s\n", o.config.DBPath)
	fmt.Println(line)
}

// Stop gracefully stops the orchestrator
func (o *Orchestrator) Stop() {
	o.cancel()
}

// splitSubnet splits a large subnet into /24 chunks
func splitSubnet(cidr string) []string {
	parts := strings.Split(cidr, "/")
	if len(parts) != 2 {
		return []string{cidr}
	}

	var mask int
	fmt.Sscanf(parts[1], "%d", &mask)

	if mask >= 24 {
		return []string{cidr}
	}

	octets := strings.Split(parts[0], ".")
	if len(octets) != 4 {
		return []string{cidr}
	}

	var o1, o2, o3, o4 int
	fmt.Sscanf(octets[0], "%d", &o1)
	fmt.Sscanf(octets[1], "%d", &o2)
	fmt.Sscanf(octets[2], "%d", &o3)
	fmt.Sscanf(octets[3], "%d", &o4)

	baseIP := uint32(o1)<<24 | uint32(o2)<<16 | uint32(o3)<<8 | uint32(o4)
	numChunks := 1 << (24 - mask)

	var chunks []string
	for i := 0; i < numChunks; i++ {
		chunkIP := baseIP + uint32(i)*256
		chunk := fmt.Sprintf("%d.%d.%d.0/24",
			(chunkIP>>24)&0xFF,
			(chunkIP>>16)&0xFF,
			(chunkIP>>8)&0xFF)
		chunks = append(chunks, chunk)
	}

	return chunks
}

// isBrittlePort returns true if aggressive scanning might cause issues
func isBrittlePort(port int) bool {
	brittle := map[int]bool{
		9100: true, // Printer
		515:  true, // LPD
		631:  true, // CUPS
	}
	return brittle[port]
}
