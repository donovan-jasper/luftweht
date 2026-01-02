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
	tcpQueue     chan string            // IPs to TCP scan
	deepQueue    chan int64             // Host IDs to deep scan
	fullTCPQueue chan models.ChunkJob   // TCP chunk jobs
	fullUDPQueue chan models.ChunkJob   // UDP chunk jobs
	svc2Queue    chan int64             // Host IDs for second service detection

	// Channel close synchronization
	closeDeep    sync.Once
	closeFullTCP sync.Once
	closeFullUDP sync.Once
	closeSVC2    sync.Once

	// Chunk progress tracking
	chunkProgress     map[int64]*models.HostChunkProgress
	chunkMutex        sync.RWMutex
	tcpChunksInFlight sync.WaitGroup // Tracks outstanding TCP chunk jobs
	udpChunksInFlight sync.WaitGroup // Tracks outstanding UDP chunk jobs

	// Timestamp tracking for SVC phase separation
	svc1CompleteTime map[int64]time.Time
	timeMutex        sync.RWMutex

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
		db:               database,
		nmap:             nmap.NewRunner(cfg.Timing, cfg.Verbose),
		config:           cfg,
		tcpQueue:         make(chan string, 1000),
		deepQueue:        make(chan int64, 1000),
		fullTCPQueue:     make(chan models.ChunkJob, 5000),
		fullUDPQueue:     make(chan models.ChunkJob, 5000),
		svc2Queue:        make(chan int64, 1000),
		chunkProgress:    make(map[int64]*models.HostChunkProgress),
		svc1CompleteTime: make(map[int64]time.Time),
		ctx:              ctx,
		cancel:           cancel,
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

	// Full TCP chunk workers
	for i := 0; i < maxWorkers; i++ {
		o.wg.Add(1)
		go o.fullTCPWorker()
	}

	// Full UDP chunk workers
	fullUDPWorkers := maxWorkers / 2
	if fullUDPWorkers < 1 {
		fullUDPWorkers = 1
	}
	if !o.config.SkipUDP {
		for i := 0; i < fullUDPWorkers; i++ {
			o.wg.Add(1)
			go o.fullUDPWorker()
		}
	}

	// Service detection round 2 workers
	if !o.config.SkipService {
		for i := 0; i < deepWorkers; i++ {
			o.wg.Add(1)
			go o.svc2Worker()
		}
	}

	// Add guard counts to prevent premature closure - will be decremented when pipeline setup complete
	o.tcpChunksInFlight.Add(1) // Guard for TCP
	o.udpChunksInFlight.Add(1) // Guard for UDP

	// Goroutine to close fullTCPQueue when all TCP chunk work is done
	go func() {
		if o.config.Verbose {
			fmt.Println("[DEBUG] TCP chunk closer goroutine started, waiting for chunks...")
		}
		o.tcpChunksInFlight.Wait() // Wait for all TCP chunks to complete
		if o.config.Verbose {
			fmt.Println("[DEBUG] All TCP chunks complete, closing fullTCPQueue and releasing UDP guard")
		}
		o.closeFullTCP.Do(func() { close(o.fullTCPQueue) })

		// Now that TCP is done, release the UDP guard
		// UDP chunks have been queued by fullTCPWorker, so the queue can now close when they finish
		o.udpChunksInFlight.Done() // Release UDP guard
	}()

	// Goroutine to close fullUDPQueue when all UDP chunk work is done
	go func() {
		if o.config.Verbose {
			fmt.Println("[DEBUG] UDP chunk closer goroutine started, waiting for chunks...")
		}
		o.udpChunksInFlight.Wait() // Wait for all UDP chunks to complete
		if o.config.Verbose {
			fmt.Println("[DEBUG] All UDP chunks complete, closing fullUDPQueue")
		}
		o.closeFullUDP.Do(func() { close(o.fullUDPQueue) })
	}()

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

	// Release TCP guard - pipeline setup is complete
	// Note: UDP guard is released when TCP completes (in the TCP closure goroutine)
	// because UDP chunks are only queued after TCP chunks finish
	o.tcpChunksInFlight.Done() // Release TCP guard

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
		// No deep scan, close fullTCP queue directly
		o.closeFullTCP.Do(func() { close(o.fullTCPQueue) })
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

	// If service detection is skipped, queue directly for full TCP
	if o.config.SkipService {
		o.queueFullTCPChunks(hostID)
		return
	}

	// Otherwise, queue for full TCP (no open ports in fast scan case)
	o.queueFullTCPChunks(hostID)
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

			// Record SVC1 completion time (even though no ports were found)
			o.timeMutex.Lock()
			o.svc1CompleteTime[hostID] = time.Now()
			o.timeMutex.Unlock()

			// Still queue for full TCP scan
			o.queueFullTCPChunks(hostID)
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

		// Record SVC1 completion time
		o.timeMutex.Lock()
		o.svc1CompleteTime[hostID] = time.Now()
		o.timeMutex.Unlock()

		// Queue full TCP scan chunks
		o.queueFullTCPChunks(hostID)
	}

	// Don't close fullTCPQueue here - it will be closed when all chunk work is done
}

// queueFullTCPChunks queues all TCP port chunks for a host
func (o *Orchestrator) queueFullTCPChunks(hostID int64) {
	chunks := models.DefaultTCPChunks()

	// Check for existing progress (resume support)
	progress, err := o.db.GetHostChunkProgress(hostID, models.ScanTypeFullTCP)
	if err != nil || progress.TotalChunks == 0 {
		// Create new chunk jobs
		_, err := o.db.CreateChunkJobs(hostID, models.ScanTypeFullTCP, chunks)
		if err != nil {
			fmt.Printf("[ERROR] Failed to create TCP chunk jobs for host %d: %v\n", hostID, err)
			return
		}

		// Initialize progress
		o.chunkMutex.Lock()
		o.chunkProgress[hostID] = &models.HostChunkProgress{
			HostID:          hostID,
			ScanType:        models.ScanTypeFullTCP,
			CompletedChunks: make(map[int]bool),
			TotalChunks:     len(chunks),
		}
		o.chunkMutex.Unlock()
	} else {
		// Restore progress for resume
		o.chunkMutex.Lock()
		o.chunkProgress[hostID] = progress
		o.chunkMutex.Unlock()
	}

	o.db.UpdateHostStatus(hostID, models.HostStatusFullTCPScanning)

	// Check if all chunks already complete (resume case)
	o.chunkMutex.RLock()
	allComplete := o.chunkProgress[hostID].IsComplete()
	o.chunkMutex.RUnlock()

	if allComplete {
		// Already done, advance to next phase
		o.db.UpdateHostStatus(hostID, models.HostStatusFullTCPDone)

		if !o.config.SkipUDP {
			o.queueFullUDPChunks(hostID)
		} else {
			select {
			case o.svc2Queue <- hostID:
			case <-o.ctx.Done():
			}
		}
		return
	}

	// Find first incomplete chunk
	nextChunkIndex := -1
	o.chunkMutex.RLock()
	for i := 0; i < len(chunks); i++ {
		if !o.chunkProgress[hostID].CompletedChunks[i] {
			nextChunkIndex = i
			break
		}
	}
	o.chunkMutex.RUnlock()

	// Queue only that chunk
	if nextChunkIndex >= 0 {
		o.queueNextTCPChunk(hostID, nextChunkIndex)
	}
}

// queueNextTCPChunk queues a specific TCP chunk for a host
func (o *Orchestrator) queueNextTCPChunk(hostID int64, chunkIndex int) {
	chunks := models.DefaultTCPChunks()

	if chunkIndex < 0 || chunkIndex >= len(chunks) {
		return
	}

	host, err := o.db.GetHostByID(hostID)
	if err != nil {
		return
	}

	chunk := chunks[chunkIndex]
	job := models.ChunkJob{
		HostID:     hostID,
		Host:       host,
		ChunkIndex: chunkIndex,
		PortStart:  chunk.Start,
		PortEnd:    chunk.End,
		Protocol:   "tcp",
	}

	// Track this chunk as in-flight work
	o.tcpChunksInFlight.Add(1)
	if o.config.Verbose {
		fmt.Printf("[DEBUG] queueNextTCPChunk: Adding TCP chunk %d for host %d (tcpChunksInFlight++)\n", chunkIndex, hostID)
	}

	// Safely send to channel (handle potential closed channel)
	defer func() {
		if r := recover(); r != nil {
			// Channel was closed - scan is shutting down
			if o.config.Verbose {
				fmt.Printf("[DEBUG] queueNextTCPChunk: PANIC caught! Channel closed for chunk %d host %d\n", chunkIndex, hostID)
			}
			o.tcpChunksInFlight.Done() // Still decrement counter
		}
	}()

	select {
	case o.fullTCPQueue <- job:
		if o.config.Verbose {
			fmt.Printf("[DEBUG] queueNextTCPChunk: Successfully queued TCP chunk %d for host %d\n", chunkIndex, hostID)
		}
	case <-o.ctx.Done():
		if o.config.Verbose {
			fmt.Printf("[DEBUG] queueNextTCPChunk: Context cancelled while queueing chunk %d for host %d\n", chunkIndex, hostID)
		}
		o.tcpChunksInFlight.Done() // Decrement if cancelled
		return
	}
}

// queueFullUDPChunks queues all UDP port chunks for a host
func (o *Orchestrator) queueFullUDPChunks(hostID int64) {
	chunks := models.DefaultUDPChunks()

	// Check for existing progress (resume support)
	progress, err := o.db.GetHostChunkProgress(hostID, models.ScanTypeFullUDP)
	if err != nil || progress.TotalChunks == 0 {
		// Create new chunk jobs
		_, err := o.db.CreateChunkJobs(hostID, models.ScanTypeFullUDP, chunks)
		if err != nil {
			fmt.Printf("[ERROR] Failed to create UDP chunk jobs for host %d: %v\n", hostID, err)
			return
		}

		// Initialize progress
		o.chunkMutex.Lock()
		o.chunkProgress[hostID] = &models.HostChunkProgress{
			HostID:          hostID,
			ScanType:        models.ScanTypeFullUDP,
			CompletedChunks: make(map[int]bool),
			TotalChunks:     len(chunks),
		}
		o.chunkMutex.Unlock()
	} else {
		// Restore progress for resume
		o.chunkMutex.Lock()
		o.chunkProgress[hostID] = progress
		o.chunkMutex.Unlock()
	}

	o.db.UpdateHostStatus(hostID, models.HostStatusFullUDPScanning)

	// Check if all chunks already complete (resume case)
	o.chunkMutex.RLock()
	allComplete := o.chunkProgress[hostID].IsComplete()
	o.chunkMutex.RUnlock()

	if allComplete {
		// Already done, advance to next phase
		o.db.UpdateHostStatus(hostID, models.HostStatusFullUDPDone)
		select {
		case o.svc2Queue <- hostID:
		case <-o.ctx.Done():
		}
		return
	}

	// Find first incomplete chunk
	nextChunkIndex := -1
	o.chunkMutex.RLock()
	for i := 0; i < len(chunks); i++ {
		if !o.chunkProgress[hostID].CompletedChunks[i] {
			nextChunkIndex = i
			break
		}
	}
	o.chunkMutex.RUnlock()

	// Queue only that chunk
	if nextChunkIndex >= 0 {
		o.queueNextUDPChunk(hostID, nextChunkIndex)
	}
}

// queueNextUDPChunk queues a specific UDP chunk for a host
func (o *Orchestrator) queueNextUDPChunk(hostID int64, chunkIndex int) {
	chunks := models.DefaultUDPChunks()

	if chunkIndex < 0 || chunkIndex >= len(chunks) {
		return
	}

	host, err := o.db.GetHostByID(hostID)
	if err != nil {
		return
	}

	chunk := chunks[chunkIndex]
	job := models.ChunkJob{
		HostID:     hostID,
		Host:       host,
		ChunkIndex: chunkIndex,
		PortStart:  chunk.Start,
		PortEnd:    chunk.End,
		Protocol:   "udp",
	}

	// Track this chunk as in-flight work
	o.udpChunksInFlight.Add(1)
	if o.config.Verbose {
		fmt.Printf("[DEBUG] queueNextUDPChunk: Adding UDP chunk %d for host %d (udpChunksInFlight++)\n", chunkIndex, hostID)
	}

	// Safely send to channel (handle potential closed channel)
	defer func() {
		if r := recover(); r != nil {
			// Channel was closed - scan is shutting down
			if o.config.Verbose {
				fmt.Printf("[DEBUG] queueNextUDPChunk: PANIC caught! Channel closed for chunk %d host %d\n", chunkIndex, hostID)
			}
			o.udpChunksInFlight.Done() // Still decrement counter
		}
	}()

	select {
	case o.fullUDPQueue <- job:
		if o.config.Verbose {
			fmt.Printf("[DEBUG] queueNextUDPChunk: Successfully queued UDP chunk %d for host %d\n", chunkIndex, hostID)
		}
	case <-o.ctx.Done():
		if o.config.Verbose {
			fmt.Printf("[DEBUG] queueNextUDPChunk: Context cancelled while queueing chunk %d for host %d\n", chunkIndex, hostID)
		}
		o.udpChunksInFlight.Done() // Decrement if cancelled
		return
	}
}

// fullTCPWorker processes full TCP chunk scans
func (o *Orchestrator) fullTCPWorker() {
	defer o.wg.Done()

	if o.config.Verbose {
		fmt.Println("[DEBUG] fullTCPWorker started, waiting for chunks...")
	}

	for job := range o.fullTCPQueue {
		select {
		case <-o.ctx.Done():
			return
		default:
		}

		if o.config.Verbose {
			fmt.Printf("[DEBUG] fullTCPWorker: Received chunk %d for host %d\n", job.ChunkIndex, job.HostID)
			fmt.Printf("[Full TCP] %s chunk %d/7 (ports %d-%d)\n",
				job.Host.IP, job.ChunkIndex+1, job.PortStart, job.PortEnd)
		}

		result, err := o.nmap.ScanTCPChunk(o.ctx, job.Host.IP, job.PortStart, job.PortEnd)

		if err == nil && len(result.Hosts) > 0 {
			ports := result.Hosts[0].ToModelPorts(job.HostID)
			if len(ports) > 0 {
				o.db.InsertPorts(ports)
				atomic.AddInt32(&o.portsFound, int32(len(ports)))
			}
		}

		// Mark chunk complete and determine next action
		o.chunkMutex.Lock()
		if progress, exists := o.chunkProgress[job.HostID]; exists {
			progress.CompletedChunks[job.ChunkIndex] = true

			if progress.IsComplete() {
				// All chunks done - advance to next phase
				o.chunkMutex.Unlock()

				o.db.UpdateHostStatus(job.HostID, models.HostStatusFullTCPDone)

				if !o.config.SkipUDP {
					o.queueFullUDPChunks(job.HostID)
				} else {
					select {
					case o.svc2Queue <- job.HostID:
					case <-o.ctx.Done():
					}
				}
			} else {
				// More chunks remain - queue next one
				nextChunkIndex := job.ChunkIndex + 1

				// Verify next chunk isn't already complete (safety check)
				shouldQueue := nextChunkIndex < progress.TotalChunks &&
					!progress.CompletedChunks[nextChunkIndex]

				o.chunkMutex.Unlock()

				if shouldQueue {
					o.queueNextTCPChunk(job.HostID, nextChunkIndex)
				}
			}
		} else {
			o.chunkMutex.Unlock()
		}

		// Mark this chunk as completed (decrement in-flight counter)
		if o.config.Verbose {
			fmt.Printf("[DEBUG] fullTCPWorker: Chunk %d for host %d complete (tcpChunksInFlight--)\n", job.ChunkIndex, job.HostID)
		}
		o.tcpChunksInFlight.Done()
	}

	if o.config.Verbose {
		fmt.Println("[DEBUG] fullTCPWorker: No more chunks, worker exiting")
	}

	// When fullTCP queue closes and SkipUDP is true, close SVC2 queue
	// (otherwise fullUDPWorker will close it after UDP chunks complete)
	if o.config.SkipUDP {
		o.closeSVC2.Do(func() { close(o.svc2Queue) })
	}
}

// fullUDPWorker processes full UDP chunk scans
func (o *Orchestrator) fullUDPWorker() {
	defer o.wg.Done()

	for job := range o.fullUDPQueue {
		select {
		case <-o.ctx.Done():
			return
		default:
		}

		if o.config.Verbose {
			fmt.Printf("[Full UDP] %s chunk %d/7 (ports %d-%d)\n",
				job.Host.IP, job.ChunkIndex+1, job.PortStart, job.PortEnd)
		}

		result, err := o.nmap.ScanUDPChunk(o.ctx, job.Host.IP, job.PortStart, job.PortEnd)

		if err == nil && len(result.Hosts) > 0 {
			ports := result.Hosts[0].ToModelPorts(job.HostID)
			if len(ports) > 0 {
				o.db.InsertPorts(ports)
				atomic.AddInt32(&o.portsFound, int32(len(ports)))
			}
		}

		// Mark chunk complete and determine next action
		o.chunkMutex.Lock()
		if progress, exists := o.chunkProgress[job.HostID]; exists {
			progress.CompletedChunks[job.ChunkIndex] = true

			if progress.IsComplete() {
				// All chunks done - advance to next phase
				o.chunkMutex.Unlock()

				o.db.UpdateHostStatus(job.HostID, models.HostStatusFullUDPDone)

				select {
				case o.svc2Queue <- job.HostID:
				case <-o.ctx.Done():
				}
			} else {
				// More chunks remain - queue next one
				nextChunkIndex := job.ChunkIndex + 1

				// Verify next chunk isn't already complete (safety check)
				shouldQueue := nextChunkIndex < progress.TotalChunks &&
					!progress.CompletedChunks[nextChunkIndex]

				o.chunkMutex.Unlock()

				if shouldQueue {
					o.queueNextUDPChunk(job.HostID, nextChunkIndex)
				}
			}
		} else {
			o.chunkMutex.Unlock()
		}

		// Mark this chunk as completed (decrement in-flight counter)
		o.udpChunksInFlight.Done()
	}

	// When fullUDP queue closes, close SVC2 queue
	o.closeSVC2.Do(func() { close(o.svc2Queue) })
}

// svc2Worker performs second service detection on newly discovered ports
func (o *Orchestrator) svc2Worker() {
	defer o.wg.Done()

	for hostID := range o.svc2Queue {
		select {
		case <-o.ctx.Done():
			return
		default:
		}

		host, err := o.db.GetHostByID(hostID)
		if err != nil {
			o.db.UpdateHostStatus(hostID, models.HostStatusComplete)
			continue
		}

		// Get SVC1 completion time
		o.timeMutex.RLock()
		svc1Time, hasSVC1Time := o.svc1CompleteTime[hostID]
		o.timeMutex.RUnlock()

		if !hasSVC1Time {
			// No SVC1 time means service detection was skipped
			o.db.UpdateHostStatus(hostID, models.HostStatusComplete)
			continue
		}

		// Get ONLY ports discovered after SVC1
		newPorts, err := o.db.GetNewPortsForServiceDetection(hostID, svc1Time)
		if err != nil || len(newPorts) == 0 {
			o.db.UpdateHostStatus(hostID, models.HostStatusComplete)
			continue
		}

		o.db.UpdateHostStatus(hostID, models.HostStatusSVC2Scanning)

		// Filter to TCP ports, exclude brittle
		var portNums []int
		for _, p := range newPorts {
			if p.Protocol == "tcp" && !isBrittlePort(p.Port) {
				portNums = append(portNums, p.Port)
			}
		}

		if len(portNums) > 0 {
			if o.config.Verbose {
				fmt.Printf("[SVC2] %s - scanning %d new ports\n",
					host.IP, len(portNums))
			}

			result, err := o.nmap.ScanDeep(o.ctx, host.IP, portNums)
			if err == nil && len(result.Hosts) > 0 {
				updatedPorts := result.Hosts[0].ToModelPorts(hostID)
				if len(updatedPorts) > 0 {
					o.db.InsertPorts(updatedPorts)
				}
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
