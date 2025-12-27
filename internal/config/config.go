package config

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
)

// Config holds all configuration for the scanner
type Config struct {
	// Input
	Subnets    []string
	TargetFile string

	// Output
	DBPath  string
	Verbose bool

	// Timing
	Timing string // T0-T5, default T2

	// Concurrency
	MinWorkers        int
	MaxWorkers        int
	TargetUtilization float64

	// Scan options
	TCPChunks   int
	SkipUDP     bool
	SkipService bool

	// Resume
	Resume       bool
	ForceRestart bool
}

// DefaultConfig returns a configuration with sensible defaults
func DefaultConfig() *Config {
	return &Config{
		DBPath:            "scan_results.db",
		Timing:            "T2",
		MinWorkers:        5,
		MaxWorkers:        0, // Will be auto-detected
		TargetUtilization: 0.80,
		TCPChunks:         7,
		SkipUDP:           false,
		SkipService:       false,
		Resume:            true,
		ForceRestart:      false,
	}
}

// DetectMaxWorkers determines the maximum number of concurrent workers
// based on system resources
func DetectMaxWorkers() int {
	// Factor 1: File descriptor limit
	fdLimit := getFileDescriptorLimit()
	// nmap uses roughly 5-10 FDs per scan
	fdBased := fdLimit / 10

	// Factor 2: Available memory
	// Estimate ~50MB per nmap process
	memBased := getAvailableMemoryMB() / 50

	// Factor 3: CPU cores (less important for I/O bound work)
	cpuBased := runtime.NumCPU() * 10

	// Take the minimum of all constraints
	maxPossible := min(fdBased, memBased, cpuBased)

	// Hard cap at 100 to be safe
	if maxPossible > 100 {
		maxPossible = 100
	}

	// Floor at 5
	if maxPossible < 5 {
		maxPossible = 5
	}

	return maxPossible
}

// getFileDescriptorLimit returns the soft limit on open file descriptors
func getFileDescriptorLimit() int {
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rLimit)
	if err != nil {
		return 256 // Conservative default
	}
	return int(rLimit.Cur)
}

// getAvailableMemoryMB returns available system memory in MB
func getAvailableMemoryMB() int {
	// This is platform-specific, using a conservative estimate
	// On macOS/Linux, we could parse /proc/meminfo or use sysctl

	// For now, use a heuristic based on total system memory
	// Most systems have at least 4GB, assume we can use 25% for scanning
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	// Use 25% of system memory as our budget
	// This is a rough estimate - m.Sys gives us Go's view of memory
	totalMB := int(m.Sys / 1024 / 1024)
	if totalMB < 1000 {
		totalMB = 4000 // Assume at least 4GB
	}

	return totalMB / 4
}

// Validate checks the configuration for errors
func (c *Config) Validate() error {
	if len(c.Subnets) == 0 && c.TargetFile == "" {
		return fmt.Errorf("no targets specified: provide subnets as arguments or use --file")
	}

	if c.TargetFile != "" {
		if _, err := os.Stat(c.TargetFile); os.IsNotExist(err) {
			return fmt.Errorf("target file not found: %s", c.TargetFile)
		}
	}

	validTimings := map[string]bool{
		"T0": true, "T1": true, "T2": true,
		"T3": true, "T4": true, "T5": true,
	}
	if !validTimings[c.Timing] {
		return fmt.Errorf("invalid timing: %s (must be T0-T5)", c.Timing)
	}

	if c.MinWorkers < 1 {
		return fmt.Errorf("min workers must be at least 1")
	}

	if c.MaxWorkers > 0 && c.MaxWorkers < c.MinWorkers {
		return fmt.Errorf("max workers must be >= min workers")
	}

	if c.TCPChunks < 1 || c.TCPChunks > 65 {
		return fmt.Errorf("tcp-chunks must be between 1 and 65")
	}

	return nil
}

// GetMaxWorkers returns the effective max workers, auto-detecting if not set
func (c *Config) GetMaxWorkers() int {
	if c.MaxWorkers > 0 {
		return c.MaxWorkers
	}

	detected := DetectMaxWorkers()
	return int(float64(detected) * c.TargetUtilization)
}

func min(nums ...int) int {
	if len(nums) == 0 {
		return 0
	}
	m := nums[0]
	for _, n := range nums[1:] {
		if n < m {
			m = n
		}
	}
	return m
}
