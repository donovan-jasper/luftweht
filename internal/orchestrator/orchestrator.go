package orchestrator

import (
	"context"
	"fmt"
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

	// Worker pool management
	workerSem    chan struct{}
	currentWorkers int32
	maxWorkers     int32

	// Adaptive concurrency
	adaptive *AdaptiveConcurrency

	// Progress tracking
	resultsChan chan *models.ScanResult
	errorsChan  chan error

	// Cancellation
	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	// Stats
	hostsDiscovered int32
	portsFound      int32
	scansCompleted  int32
	scansFailed     int32
}

// AdaptiveConcurrency manages dynamic worker scaling
type AdaptiveConcurrency struct {
	mu              sync.Mutex
	minWorkers      int
	maxWorkers      int
	currentWorkers  int
	targetUtil      float64
	recentTimeouts  int
	recentSuccesses int
	windowSize      int
}

// NewOrchestrator creates a new scan orchestrator
func NewOrchestrator(database *db.DB, cfg *config.Config) *Orchestrator {
	ctx, cancel := context.WithCancel(context.Background())

	maxWorkers := cfg.GetMaxWorkers()

	o := &Orchestrator{
		db:          database,
		nmap:        nmap.NewRunner(cfg.Timing, cfg.Verbose),
		config:      cfg,
		workerSem:   make(chan struct{}, maxWorkers),
		maxWorkers:  int32(maxWorkers),
		resultsChan: make(chan *models.ScanResult, 100),
		errorsChan:  make(chan error, 100),
		ctx:         ctx,
		cancel:      cancel,
		adaptive: &AdaptiveConcurrency{
			minWorkers:     cfg.MinWorkers,
			maxWorkers:     maxWorkers,
			currentWorkers: maxWorkers,
			targetUtil:     cfg.TargetUtilization,
			windowSize:     50,
		},
	}

	return o
}

// Run executes the full scan pipeline
func (o *Orchestrator) Run(subnets []string) error {
	fmt.Printf("Starting scan of %d subnet(s) with up to %d concurrent workers\n",
		len(subnets), o.maxWorkers)

	// Check for nmap
	if err := nmap.CheckNmapInstalled(); err != nil {
		return err
	}

	// Start results processor
	go o.processResults()

	// Phase 1: Host Discovery
	fmt.Println("\n[Phase 1] Host Discovery")
	if err := o.runDiscovery(subnets); err != nil {
		return fmt.Errorf("discovery phase failed: %w", err)
	}
	fmt.Printf("Discovered %d hosts\n", atomic.LoadInt32(&o.hostsDiscovered))

	// Phase 2: TCP Port Scan
	fmt.Println("\n[Phase 2] TCP Port Scan (1-65535)")
	if err := o.runTCPScans(); err != nil {
		return fmt.Errorf("TCP scan phase failed: %w", err)
	}

	// Phase 3: Service Version Detection
	if !o.config.SkipService {
		fmt.Println("\n[Phase 3] Service Version Detection")
		if err := o.runServiceScans(); err != nil {
			return fmt.Errorf("service scan phase failed: %w", err)
		}
	}

	// Phase 4: UDP Scan
	if !o.config.SkipUDP {
		fmt.Println("\n[Phase 4] UDP Port Scan (1-65535)")
		if err := o.runUDPScans(); err != nil {
			return fmt.Errorf("UDP scan phase failed: %w", err)
		}
	}

	// Wait for all workers to complete
	o.wg.Wait()
	close(o.resultsChan)

	// Print summary
	o.printSummary()

	return nil
}

// runDiscovery executes host discovery on all subnets
func (o *Orchestrator) runDiscovery(subnets []string) error {
	// Create discovery jobs for each subnet
	for _, subnet := range subnets {
		_, err := o.db.CreateScanProgress(nil, subnet, models.ScanTypeDiscovery, 0, 0)
		if err != nil {
			return err
		}
	}

	// Get pending discovery scans
	scans, err := o.db.GetPendingScansByType(models.ScanTypeDiscovery)
	if err != nil {
		return err
	}

	// Run discovery scans (parallel by subnet)
	var discoveryWg sync.WaitGroup
	for _, scan := range scans {
		scan := scan // capture
		discoveryWg.Add(1)

		o.workerSem <- struct{}{} // Acquire
		go func() {
			defer discoveryWg.Done()
			defer func() { <-o.workerSem }() // Release

			o.runSingleDiscovery(&scan)
		}()
	}

	discoveryWg.Wait()
	return nil
}

// runSingleDiscovery runs discovery on a single subnet
func (o *Orchestrator) runSingleDiscovery(scan *models.ScanProgress) {
	// Mark as running
	o.db.UpdateScanProgressStatus(scan.ID, models.ProgressStatusRunning, "")

	if o.config.Verbose {
		fmt.Printf("  Discovering hosts in %s...\n", scan.Subnet)
	}

	result, err := o.nmap.DiscoverHosts(o.ctx, scan.Subnet)
	if err != nil {
		o.db.UpdateScanProgressStatus(scan.ID, models.ProgressStatusFailed, err.Error())
		atomic.AddInt32(&o.scansFailed, 1)
		return
	}

	// Insert discovered hosts
	hosts := result.ToModelHosts(scan.Subnet)
	for _, h := range hosts {
		host, err := o.db.InsertHost(h.IP, h.Hostname, h.Subnet)
		if err != nil {
			fmt.Printf("  Warning: failed to insert host %s: %v\n", h.IP, err)
			continue
		}

		atomic.AddInt32(&o.hostsDiscovered, 1)

		// Create TCP scan jobs for this host (chunked)
		o.createPortScanJobs(host.ID, models.ScanTypeTCP)

		if o.config.Verbose {
			hostname := ""
			if h.Hostname != "" {
				hostname = fmt.Sprintf(" (%s)", h.Hostname)
			}
			fmt.Printf("  + %s%s\n", h.IP, hostname)
		}
	}

	o.db.UpdateScanProgressStatus(scan.ID, models.ProgressStatusComplete, "")
	atomic.AddInt32(&o.scansCompleted, 1)
}

// createPortScanJobs creates chunked port scan jobs for a host
func (o *Orchestrator) createPortScanJobs(hostID int64, scanType models.ScanType) {
	var chunks []models.PortChunk
	if scanType == models.ScanTypeTCP {
		chunks = models.DefaultTCPChunks()
	} else {
		chunks = models.DefaultUDPChunks()
	}

	for _, chunk := range chunks {
		o.db.CreateScanProgress(&hostID, "", scanType, chunk.Start, chunk.End)
	}
}

// runTCPScans runs TCP port scans on all discovered hosts
func (o *Orchestrator) runTCPScans() error {
	return o.runPortScans(models.ScanTypeTCP, models.HostStatusDiscovered, models.HostStatusTCPScanning, models.HostStatusTCPDone)
}

// runUDPScans runs UDP port scans on all hosts
func (o *Orchestrator) runUDPScans() error {
	// First create UDP scan jobs for all svc_done hosts
	hosts, err := o.db.GetHostsByStatus(models.HostStatusSVCDone)
	if err != nil {
		return err
	}

	for _, host := range hosts {
		o.createPortScanJobs(host.ID, models.ScanTypeUDP)
	}

	return o.runPortScans(models.ScanTypeUDP, models.HostStatusSVCDone, models.HostStatusUDPScanning, models.HostStatusComplete)
}

// runPortScans runs port scans of the specified type
func (o *Orchestrator) runPortScans(scanType models.ScanType, fromStatus, runningStatus, doneStatus models.HostStatus) error {
	for {
		// Check for cancellation
		select {
		case <-o.ctx.Done():
			return o.ctx.Err()
		default:
		}

		// Get next pending scan
		scan, err := o.db.GetNextPendingScan()
		if err != nil {
			return err
		}

		// No more scans of this type
		if scan == nil || scan.ScanType != scanType {
			break
		}

		// Skip if already running (from resume)
		if scan.Status == models.ProgressStatusRunning {
			o.db.UpdateScanProgressStatus(scan.ID, models.ProgressStatusPending, "")
		}

		o.wg.Add(1)
		o.workerSem <- struct{}{} // Acquire

		go func(s *models.ScanProgress) {
			defer o.wg.Done()
			defer func() { <-o.workerSem }() // Release

			o.runSinglePortScan(s, scanType, runningStatus, doneStatus)
		}(scan)
	}

	// Wait for current batch
	o.wg.Wait()
	return nil
}

// runSinglePortScan runs a single port scan chunk
func (o *Orchestrator) runSinglePortScan(scan *models.ScanProgress, scanType models.ScanType, runningStatus, doneStatus models.HostStatus) {
	if scan.HostID == nil {
		return
	}

	// Get host info
	host, err := o.db.GetHostByID(*scan.HostID)
	if err != nil {
		o.db.UpdateScanProgressStatus(scan.ID, models.ProgressStatusFailed, err.Error())
		return
	}

	// Update host status
	o.db.UpdateHostStatus(host.ID, runningStatus)

	// Mark scan as running
	o.db.UpdateScanProgressStatus(scan.ID, models.ProgressStatusRunning, "")

	if o.config.Verbose {
		fmt.Printf("  Scanning %s ports %d-%d on %s\n",
			scanType, scan.PortStart, scan.PortEnd, host.IP)
	}

	var result *nmap.NmapRun
	startTime := time.Now()

	if scanType == models.ScanTypeTCP {
		result, err = o.nmap.ScanTCPPorts(o.ctx, host.IP, scan.PortStart, scan.PortEnd)
	} else {
		result, err = o.nmap.ScanUDPPorts(o.ctx, host.IP, scan.PortStart, scan.PortEnd)
	}

	// Track for adaptive concurrency
	o.adaptive.recordResult(err != nil || time.Since(startTime) > 5*time.Minute)

	if err != nil {
		o.db.UpdateScanProgressStatus(scan.ID, models.ProgressStatusFailed, err.Error())
		atomic.AddInt32(&o.scansFailed, 1)
		return
	}

	// Save discovered ports
	if len(result.Hosts) > 0 {
		ports := result.Hosts[0].ToModelPorts(host.ID)
		if len(ports) > 0 {
			if err := o.db.InsertPorts(ports); err != nil {
				fmt.Printf("  Warning: failed to save ports for %s: %v\n", host.IP, err)
			}
			atomic.AddInt32(&o.portsFound, int32(len(ports)))

			if o.config.Verbose {
				for _, p := range ports {
					fmt.Printf("    %s:%d/%s %s\n", host.IP, p.Port, p.Protocol, p.State)
				}
			}
		}
	}

	o.db.UpdateScanProgressStatus(scan.ID, models.ProgressStatusComplete, "")
	atomic.AddInt32(&o.scansCompleted, 1)

	// Check if all chunks for this host are complete
	o.checkHostComplete(host, scanType, doneStatus)
}

// checkHostComplete checks if all scan chunks for a host are done
func (o *Orchestrator) checkHostComplete(host *models.Host, scanType models.ScanType, doneStatus models.HostStatus) {
	// Check if any chunks are still pending/running
	scans, err := o.db.GetPendingScansByType(scanType)
	if err != nil {
		return
	}

	for _, s := range scans {
		if s.HostID != nil && *s.HostID == host.ID {
			return // Still has pending scans
		}
	}

	// All chunks complete - update host status
	o.db.UpdateHostStatus(host.ID, doneStatus)

	// If TCP scan complete, create service scan job
	if scanType == models.ScanTypeTCP && !o.config.SkipService {
		o.db.CreateScanProgress(&host.ID, "", models.ScanTypeSVC, 0, 0)
	}
}

// runServiceScans runs service version detection
func (o *Orchestrator) runServiceScans() error {
	for {
		select {
		case <-o.ctx.Done():
			return o.ctx.Err()
		default:
		}

		scan, err := o.db.GetNextPendingScan()
		if err != nil {
			return err
		}

		if scan == nil || scan.ScanType != models.ScanTypeSVC {
			break
		}

		o.wg.Add(1)
		o.workerSem <- struct{}{}

		go func(s *models.ScanProgress) {
			defer o.wg.Done()
			defer func() { <-o.workerSem }()

			o.runSingleServiceScan(s)
		}(scan)
	}

	o.wg.Wait()
	return nil
}

// runSingleServiceScan runs service detection on a host
func (o *Orchestrator) runSingleServiceScan(scan *models.ScanProgress) {
	if scan.HostID == nil {
		return
	}

	host, err := o.db.GetHostByID(*scan.HostID)
	if err != nil {
		o.db.UpdateScanProgressStatus(scan.ID, models.ProgressStatusFailed, err.Error())
		return
	}

	// Get open TCP ports
	openPorts, err := o.db.GetOpenPorts(host.ID, "tcp")
	if err != nil {
		o.db.UpdateScanProgressStatus(scan.ID, models.ProgressStatusFailed, err.Error())
		return
	}

	if len(openPorts) == 0 {
		o.db.UpdateScanProgressStatus(scan.ID, models.ProgressStatusComplete, "no open ports")
		o.db.UpdateHostStatus(host.ID, models.HostStatusSVCDone)
		return
	}

	// Update status
	o.db.UpdateHostStatus(host.ID, models.HostStatusSVCScanning)
	o.db.UpdateScanProgressStatus(scan.ID, models.ProgressStatusRunning, "")

	// Get port numbers
	portNums := make([]int, len(openPorts))
	for i, p := range openPorts {
		portNums[i] = p.Port
	}

	if o.config.Verbose {
		fmt.Printf("  Running service detection on %s (%d ports)\n", host.IP, len(portNums))
	}

	result, err := o.nmap.ScanServiceVersion(o.ctx, host.IP, portNums)
	if err != nil {
		o.db.UpdateScanProgressStatus(scan.ID, models.ProgressStatusFailed, err.Error())
		atomic.AddInt32(&o.scansFailed, 1)
		return
	}

	// Update ports with service info
	if len(result.Hosts) > 0 {
		ports := result.Hosts[0].ToModelPorts(host.ID)
		if len(ports) > 0 {
			o.db.InsertPorts(ports)

			if o.config.Verbose {
				for _, p := range ports {
					if p.Service != "" || p.Version != "" {
						fmt.Printf("    %s:%d %s %s\n", host.IP, p.Port, p.Service, p.Version)
					}
				}
			}
		}
	}

	o.db.UpdateScanProgressStatus(scan.ID, models.ProgressStatusComplete, "")
	o.db.UpdateHostStatus(host.ID, models.HostStatusSVCDone)
	atomic.AddInt32(&o.scansCompleted, 1)
}

// processResults handles incoming scan results
func (o *Orchestrator) processResults() {
	for result := range o.resultsChan {
		if result.Error != nil {
			o.errorsChan <- result.Error
		}
	}
}

// recordResult records a scan result for adaptive concurrency
func (ac *AdaptiveConcurrency) recordResult(isTimeout bool) {
	ac.mu.Lock()
	defer ac.mu.Unlock()

	if isTimeout {
		ac.recentTimeouts++
	} else {
		ac.recentSuccesses++
	}

	total := ac.recentTimeouts + ac.recentSuccesses
	if total >= ac.windowSize {
		ac.adjust()
		ac.recentTimeouts = 0
		ac.recentSuccesses = 0
	}
}

// adjust adjusts worker count based on recent performance
func (ac *AdaptiveConcurrency) adjust() {
	errorRate := float64(ac.recentTimeouts) / float64(ac.windowSize)

	if errorRate > 0.10 {
		// Too many timeouts - reduce by 20%
		ac.currentWorkers = int(float64(ac.currentWorkers) * 0.80)
		if ac.currentWorkers < ac.minWorkers {
			ac.currentWorkers = ac.minWorkers
		}
		fmt.Printf("  [Adaptive] High error rate (%.1f%%), reducing workers to %d\n",
			errorRate*100, ac.currentWorkers)
	} else if errorRate < 0.02 && ac.currentWorkers < ac.maxWorkers {
		// Running smoothly - try increasing by 10%
		ac.currentWorkers = int(float64(ac.currentWorkers) * 1.10)
		if ac.currentWorkers > ac.maxWorkers {
			ac.currentWorkers = ac.maxWorkers
		}
		fmt.Printf("  [Adaptive] Low error rate (%.1f%%), increasing workers to %d\n",
			errorRate*100, ac.currentWorkers)
	}
}

// printSummary prints final scan statistics
func (o *Orchestrator) printSummary() {
	stats, _ := o.db.GetScanStats()

	line := "══════════════════════════════════════════════════"
	fmt.Println("\n" + line)
	fmt.Println("SCAN COMPLETE")
	fmt.Println(line)
	fmt.Printf("Hosts discovered:  %d\n", atomic.LoadInt32(&o.hostsDiscovered))
	fmt.Printf("Open ports found:  %d\n", stats["open_ports"])
	fmt.Printf("Scans completed:   %d\n", atomic.LoadInt32(&o.scansCompleted))
	fmt.Printf("Scans failed:      %d\n", atomic.LoadInt32(&o.scansFailed))
	fmt.Printf("Results saved to:  %s\n", o.config.DBPath)
	fmt.Println(line)
}

// Stop gracefully stops the orchestrator
func (o *Orchestrator) Stop() {
	o.cancel()
	o.wg.Wait()
}
