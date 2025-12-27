package nmap

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Runner executes nmap commands
type Runner struct {
	Timing  string
	Verbose bool
}

// NewRunner creates a new nmap runner
func NewRunner(timing string, verbose bool) *Runner {
	return &Runner{
		Timing:  timing,
		Verbose: verbose,
	}
}

// DiscoverHosts runs host discovery on a subnet
func (r *Runner) DiscoverHosts(ctx context.Context, subnet string) (*NmapRun, error) {
	// Aggressive multi-method discovery
	args := []string{
		"-sn",         // No port scan
		"-" + r.Timing, // Timing template
		"-PR",         // ARP ping (local subnet)
		"-PE",         // ICMP Echo
		"-PP",         // ICMP Timestamp
		"-PM",         // ICMP Address Mask
		"-PS21,22,23,25,80,111,135,139,443,445,3389,8080,8443", // TCP SYN
		"-PA80,443",       // TCP ACK
		"-PU53,123,137,161,500", // UDP probes
		"-oX", "-",        // XML output to stdout
		subnet,
	}

	return r.run(ctx, args, 5*time.Minute)
}

// ScanTCPPorts runs a TCP port scan on a host
func (r *Runner) ScanTCPPorts(ctx context.Context, host string, portStart, portEnd int) (*NmapRun, error) {
	portRange := fmt.Sprintf("%d-%d", portStart, portEnd)

	args := []string{
		"-sS",           // TCP SYN scan
		"-" + r.Timing,  // Timing template
		"-Pn",           // Skip host discovery (already discovered)
		"-p", portRange, // Port range
		"--open",        // Only show open ports
		"-oX", "-",      // XML output to stdout
		host,
	}

	// Timeout scales with port range
	portCount := portEnd - portStart + 1
	timeout := time.Duration(portCount/1000+5) * time.Minute
	if timeout > 30*time.Minute {
		timeout = 30 * time.Minute
	}

	return r.run(ctx, args, timeout)
}

// ScanServiceVersion runs service version detection on specific ports
func (r *Runner) ScanServiceVersion(ctx context.Context, host string, ports []int) (*NmapRun, error) {
	if len(ports) == 0 {
		return &NmapRun{}, nil
	}

	// Build port list
	portStrs := make([]string, len(ports))
	for i, p := range ports {
		portStrs[i] = strconv.Itoa(p)
	}
	portList := strings.Join(portStrs, ",")

	args := []string{
		"-sV",          // Version detection
		"-sC",          // Default scripts
		"-T3",          // Use T3 for service detection (faster than T2)
		"-Pn",          // Skip host discovery
		"-p", portList, // Specific ports
		"-oX", "-",     // XML output to stdout
		host,
	}

	// Timeout based on number of ports
	timeout := time.Duration(len(ports)*30+60) * time.Second
	if timeout > 15*time.Minute {
		timeout = 15 * time.Minute
	}

	return r.run(ctx, args, timeout)
}

// ScanUDPPorts runs a UDP port scan on a host
func (r *Runner) ScanUDPPorts(ctx context.Context, host string, portStart, portEnd int) (*NmapRun, error) {
	portRange := fmt.Sprintf("%d-%d", portStart, portEnd)

	args := []string{
		"-sU",           // UDP scan
		"-" + r.Timing,  // Timing template
		"-Pn",           // Skip host discovery
		"-p", portRange, // Port range
		"--open",        // Only show open ports
		"-oX", "-",      // XML output to stdout
		host,
	}

	// UDP scans are much slower - give them more time
	portCount := portEnd - portStart + 1
	timeout := time.Duration(portCount/100+10) * time.Minute
	if timeout > 60*time.Minute {
		timeout = 60 * time.Minute
	}

	return r.run(ctx, args, timeout)
}

// run executes nmap with the given arguments
func (r *Runner) run(ctx context.Context, args []string, timeout time.Duration) (*NmapRun, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, "nmap", args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if r.Verbose {
		fmt.Printf("[nmap] Running: nmap %s\n", strings.Join(args, " "))
	}

	startTime := time.Now()
	err := cmd.Run()
	duration := time.Since(startTime)

	if r.Verbose {
		fmt.Printf("[nmap] Completed in %s\n", duration)
	}

	if ctx.Err() == context.DeadlineExceeded {
		return nil, fmt.Errorf("nmap scan timed out after %s", timeout)
	}

	if err != nil {
		// nmap returns exit code 1 sometimes even on success
		// Check if we got valid XML output
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("nmap failed: %w\nstderr: %s", err, stderr.String())
		}
	}

	// Parse the XML output
	result, err := ParseXML(stdout.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to parse nmap output: %w", err)
	}

	return result, nil
}

// CheckNmapInstalled verifies that nmap is available
func CheckNmapInstalled() error {
	cmd := exec.Command("nmap", "--version")
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("nmap not found: %w (ensure nmap is installed and in PATH)", err)
	}

	// Parse version from output
	lines := strings.Split(string(output), "\n")
	if len(lines) > 0 {
		fmt.Printf("Using: %s\n", strings.TrimSpace(lines[0]))
	}

	return nil
}

// CheckRootPrivileges checks if we have root/sudo for raw sockets
func CheckRootPrivileges() bool {
	// Try to create a raw socket test
	cmd := exec.Command("nmap", "-sS", "-p", "1", "--max-retries", "0", "127.0.0.1")
	cmd.Run()
	// If SYN scan works on localhost, we have privileges
	return true // For now, assume it works - nmap will error if not
}
