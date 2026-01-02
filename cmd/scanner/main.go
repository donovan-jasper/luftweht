package main

import (
	"bufio"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/donovan-jasper/luftweht/internal/config"
	"github.com/donovan-jasper/luftweht/internal/db"
	"github.com/donovan-jasper/luftweht/internal/orchestrator"
	"github.com/spf13/cobra"
)

var (
	cfg = config.DefaultConfig()
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "luftweht [subnets...]",
		Short: "Parallel nmap scanner with adaptive concurrency",
		Long: `Luftweht is a parallel network scanner that orchestrates nmap to scan
multiple subnets efficiently while maintaining per-host rate limiting.

Scan Pipeline:
  1. Host Discovery (ICMP, TCP SYN/ACK, UDP, ARP probes)
  2. TCP Port Scan (1-65535, chunked for progress)
  3. Service Version Detection (-sV on open ports)
  4. UDP Port Scan (1-65535, chunked for progress)

Examples:
  luftweht 10.0.0.0/24 192.168.1.0/24
  luftweht --file targets.txt
  luftweht --file targets.txt 10.10.0.0/16 --workers 50`,
		Args: cobra.ArbitraryArgs,
		RunE: runScan,
	}

	// Input flags
	rootCmd.Flags().StringVarP(&cfg.TargetFile, "file", "f", "", "File containing target subnets (one per line)")

	// Output flags
	rootCmd.Flags().StringVarP(&cfg.DBPath, "db", "d", cfg.DBPath, "SQLite database file for results")
	rootCmd.Flags().BoolVarP(&cfg.Verbose, "verbose", "v", false, "Verbose output")

	// Timing flags
	rootCmd.Flags().StringVarP(&cfg.Timing, "timing", "T", cfg.Timing, "Nmap timing template (T0-T5)")
	var fast bool
	rootCmd.Flags().BoolVar(&fast, "fast", false, "Use aggressive timing (T5) for faster scans")
	rootCmd.PreRun = func(cmd *cobra.Command, args []string) {
		if fast {
			cfg.Timing = "T5"
		}
	}

	// Concurrency flags
	rootCmd.Flags().IntVar(&cfg.MinWorkers, "min-workers", cfg.MinWorkers, "Minimum concurrent workers")
	rootCmd.Flags().IntVar(&cfg.MaxWorkers, "max-workers", cfg.MaxWorkers, "Maximum concurrent workers (0=auto-detect)")

	// Scan options
	rootCmd.Flags().IntVar(&cfg.TCPChunks, "tcp-chunks", cfg.TCPChunks, "Number of port chunks for TCP scan")
	rootCmd.Flags().BoolVar(&cfg.SkipUDP, "skip-udp", cfg.SkipUDP, "Skip UDP scanning")
	rootCmd.Flags().BoolVar(&cfg.SkipService, "skip-service", cfg.SkipService, "Skip service version detection")
	rootCmd.Flags().BoolVar(&cfg.SkipDiscovery, "skip-discovery", cfg.SkipDiscovery, "Skip host discovery, scan all IPs directly (for firewall-heavy networks)")

	// Resume flags
	rootCmd.Flags().BoolVar(&cfg.ForceRestart, "restart", false, "Force restart, ignoring any existing scan progress")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func runScan(cmd *cobra.Command, args []string) error {
	// Collect subnets from args
	cfg.Subnets = args

	// Load subnets from file if specified
	if cfg.TargetFile != "" {
		fileSubnets, err := loadSubnetsFromFile(cfg.TargetFile)
		if err != nil {
			return fmt.Errorf("failed to load targets: %w", err)
		}
		cfg.Subnets = append(cfg.Subnets, fileSubnets...)
	}

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return err
	}

	// Print banner
	printBanner()

	// Initialize database
	database, err := db.New(cfg.DBPath)
	if err != nil {
		return fmt.Errorf("failed to initialize database: %w", err)
	}
	defer database.Close()

	if err := database.Migrate(); err != nil {
		return fmt.Errorf("failed to migrate database: %w", err)
	}

	// Check for existing scan progress
	if !cfg.ForceRestart {
		hasIncomplete, count, err := database.HasIncompleteScans()
		if err != nil {
			return fmt.Errorf("failed to check scan progress: %w", err)
		}

		if hasIncomplete {
			fmt.Printf("\nFound incomplete scan with %d pending jobs.\n", count)
			if !promptYesNo("Resume previous scan?") {
				if promptYesNo("Clear previous data and start fresh?") {
					if err := database.ClearAllData(); err != nil {
						return fmt.Errorf("failed to clear data: %w", err)
					}
				} else {
					fmt.Println("Exiting. Use --restart to force a fresh scan.")
					return nil
				}
			} else {
				// Resume - reset any running scans to pending
				if err := database.ResetRunningScans(); err != nil {
					return fmt.Errorf("failed to reset running scans: %w", err)
				}
			}
		}
	} else {
		// Force restart - clear all data
		if err := database.ClearAllData(); err != nil {
			return fmt.Errorf("failed to clear data: %w", err)
		}
	}

	// Create orchestrator
	orch := orchestrator.NewOrchestrator(database, cfg)

	// Handle signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\n\nReceived interrupt signal, stopping gracefully...")
		fmt.Println("Progress has been saved. Run again to resume.")
		orch.Stop()
	}()

	// Run the scan
	return orch.Run(cfg.Subnets)
}

func loadSubnetsFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var subnets []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		subnets = append(subnets, line)
	}

	return subnets, scanner.Err()
}

func promptYesNo(prompt string) bool {
	fmt.Printf("%s [Y/n] ", prompt)
	reader := bufio.NewReader(os.Stdin)
	response, _ := reader.ReadString('\n')
	response = strings.TrimSpace(strings.ToLower(response))
	return response == "" || response == "y" || response == "yes"
}

func printBanner() {
	fmt.Println(`
 _         __ _                _   _
| |       / _| |              | | | |
| |_   _ | |_| |___      _____| |_| |_
| | | | ||  _| __\ \ /\ / / _ \ __| __|
| | |_| || | | |_ \ V  V /  __/ |_| |_
|_|\__,_||_|  \__| \_/\_/ \___|\__|\__|

    Parallel Nmap Scanner Orchestrator
`)

	fmt.Printf("Database:     %s\n", cfg.DBPath)
	fmt.Printf("Timing:       %s\n", cfg.Timing)
	fmt.Printf("Max Workers:  %d (auto-detected: %d)\n", cfg.GetMaxWorkers(), config.DetectMaxWorkers())
	fmt.Printf("Targets:      %d subnet(s)\n", len(cfg.Subnets))
	if cfg.SkipDiscovery {
		fmt.Printf("Mode:         Direct scan (skip discovery)\n")
	}
	fmt.Println()
}
