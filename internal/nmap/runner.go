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

// RunRaw executes nmap with raw arguments
func (r *Runner) RunRaw(ctx context.Context, args []string, timeout time.Duration) (*NmapRun, error) {
	// Add XML output
	args = append(args, "-oX", "-")
	return r.run(ctx, args, timeout)
}

// ScanTCPFast runs a fast TCP scan (top 100 ports, no version detection)
// If skipPing is true, adds -Pn to skip nmap's host discovery (needed for Windows hosts or skip-discovery mode)
func (r *Runner) ScanTCPFast(ctx context.Context, host string, skipPing bool) (*NmapRun, error) {
	args := []string{}

	if skipPing {
		// Skip nmap's host discovery - scan even if host doesn't respond to probes
		// Required for: Windows hosts with firewall, skip-discovery mode
		args = append(args, "-Pn")
	}

	args = append(args,
		"-F",           // Fast mode (top 100 ports)
		"-R",           // Always resolve hostnames
		"-"+r.Timing,   // Timing template
		"-oX", "-",     // XML output
		host,
	)

	return r.run(ctx, args, 3*time.Minute)
}

// ScanDeep runs an aggressive scan on specific ports (-A -sVC)
func (r *Runner) ScanDeep(ctx context.Context, host string, ports []int) (*NmapRun, error) {
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
		"-Pn",          // Skip discovery
		"-p", portList, // Specific ports
		"-A",           // Aggressive (OS detection, version, scripts, traceroute)
		"-sV",          // Version detection
		"-sC",          // Default scripts
		"-oX", "-",     // XML output
		host,
	}

	// Timeout based on number of ports
	timeout := time.Duration(len(ports)*60+120) * time.Second
	if timeout > 30*time.Minute {
		timeout = 30 * time.Minute
	}

	return r.run(ctx, args, timeout)
}

// ScanUDPFast runs a fast UDP scan (top 100 ports)
func (r *Runner) ScanUDPFast(ctx context.Context, host string) (*NmapRun, error) {
	args := []string{
		"-Pn",          // Skip discovery
		"-sU",          // UDP scan
		"-F",           // Fast mode (top 100 ports)
		"-" + r.Timing, // Timing template
		"-oX", "-",     // XML output
		host,
	}

	return r.run(ctx, args, 15*time.Minute)
}

// ScanTCPChunk scans a specific range of TCP ports
func (r *Runner) ScanTCPChunk(ctx context.Context, host string, portStart, portEnd int) (*NmapRun, error) {
	portRange := fmt.Sprintf("%d-%d", portStart, portEnd)

	args := []string{
		"-Pn",          // Skip discovery
		"-sS",          // SYN scan
		"-p", portRange,
		"-" + r.Timing,
		"-oX", "-",
		host,
	}

	// Dynamic timeout based on range size
	rangeSize := portEnd - portStart + 1
	timeout := time.Duration(rangeSize/100+60) * time.Second
	if timeout > 10*time.Minute {
		timeout = 10 * time.Minute
	}

	return r.run(ctx, args, timeout)
}

// ScanUDPChunk scans a specific range of UDP ports
func (r *Runner) ScanUDPChunk(ctx context.Context, host string, portStart, portEnd int) (*NmapRun, error) {
	portRange := fmt.Sprintf("%d-%d", portStart, portEnd)

	args := []string{
		"-Pn",
		"-sU", // UDP scan
		"-p", portRange,
		"-" + r.Timing,
		"-oX", "-",
		host,
	}

	// UDP is slower - longer timeout
	rangeSize := portEnd - portStart + 1
	timeout := time.Duration(rangeSize/50+120) * time.Second
	if timeout > 20*time.Minute {
		timeout = 20 * time.Minute
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
