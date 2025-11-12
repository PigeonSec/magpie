package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/pigeonsec/magpie/internal/fetcher"
	"github.com/pigeonsec/magpie/internal/netutil"
	"github.com/pigeonsec/magpie/internal/stats"
	"github.com/pigeonsec/magpie/internal/ui"
	"github.com/pigeonsec/magpie/internal/validator"
	"golang.org/x/term"
)

const logo = `
🦅 Magpie - Blocklist Aggregation & Validation Tool
`

var (
	version = "1.0.0"

	// Input/Output
	sourceFile string
	outputFile string

	// Validation
	enableDNS    bool
	enableHTTP   bool
	workers      int
	dnsResolvers string

	// Performance
	fetchWorkers int
	enableCache  bool

	// Stats & Filtering
	dataDir    string
	noTracking bool

	// Options
	quiet     bool
	silent    bool
	showVer   bool
	showStats bool
)

func init() {
	// Input/Output flags
	flag.StringVar(&sourceFile, "source", "", "Source file containing URLs to fetch (one per line)")
	flag.StringVar(&sourceFile, "s", "", "Shorthand for -source")
	flag.StringVar(&outputFile, "output", "aggregated.txt", "Output file for aggregated domains")
	flag.StringVar(&outputFile, "o", "aggregated.txt", "Shorthand for -output")

	// Validation flags
	flag.BoolVar(&enableDNS, "dns", true, "Enable DNS validation (A, AAAA, CNAME)")
	flag.BoolVar(&enableDNS, "d", true, "Shorthand for -dns")
	flag.BoolVar(&enableHTTP, "http", false, "Enable HTTP validation (in addition to DNS)")
	flag.BoolVar(&enableHTTP, "H", false, "Shorthand for -http")
	flag.IntVar(&workers, "workers", 100, "Number of concurrent validation workers")
	flag.IntVar(&workers, "w", 100, "Shorthand for -workers")
	flag.StringVar(&dnsResolvers, "resolvers", "1.1.1.1:53,1.0.0.1:53,8.8.8.8:53,8.8.4.4:53,9.9.9.9:53,149.112.112.112:53", "Comma-separated DNS resolvers")
	flag.StringVar(&dnsResolvers, "r", "1.1.1.1:53,1.0.0.1:53,8.8.8.8:53,8.8.4.4:53,9.9.9.9:53,149.112.112.112:53", "Shorthand for -resolvers")

	// Performance flags
	flag.IntVar(&fetchWorkers, "fetch-workers", 5, "Number of concurrent URL fetchers")
	flag.IntVar(&fetchWorkers, "f", 5, "Shorthand for -fetch-workers")
	flag.BoolVar(&enableCache, "cache", true, "Enable DNS result caching (5min TTL)")
	flag.BoolVar(&enableCache, "c", true, "Shorthand for -cache")

	// Stats & Filtering flags
	flag.StringVar(&dataDir, "data-dir", "./data", "Directory for stats.json and persistent data")
	flag.BoolVar(&noTracking, "no-tracking", false, "Disable URL health tracking and filtering")

	// Options flags
	flag.BoolVar(&quiet, "quiet", false, "Quiet mode - minimal output")
	flag.BoolVar(&quiet, "q", false, "Shorthand for -quiet")
	flag.BoolVar(&silent, "silent", false, "Silent mode - no output (perfect for cronjobs)")
	flag.BoolVar(&showVer, "version", false, "Show version information")
	flag.BoolVar(&showVer, "v", false, "Shorthand for -version")
	flag.BoolVar(&showStats, "stats", false, "Display stats table and exit")

	// Custom usage message
	flag.Usage = printUsage
}

func printUsage() {
	// Beautiful styled help menu using lipgloss
	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("213")).
		Bold(true).
		Padding(0, 1).
		MarginBottom(1)

	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("99")).
		Bold(true).
		MarginTop(1).
		MarginBottom(0)

	sectionStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("86")).
		PaddingLeft(2)

	flagStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("117")).
		Bold(true)

	descStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("245"))

	exampleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("228")).
		Italic(true).
		PaddingLeft(2)

	commentStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240")).
		Italic(true).
		PaddingLeft(2)

	urlStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("212")).
		Underline(true)

	var b strings.Builder

	// Logo/Title
	b.WriteString(titleStyle.Render("🦅 MAGPIE - High-Performance Blocklist Aggregator"))
	b.WriteString("\n\n")
	b.WriteString(descStyle.Render("A beautiful, fast blocklist aggregator with smart filtering and DNS validation."))
	b.WriteString("\n\n")

	// Usage
	b.WriteString(headerStyle.Render("USAGE:"))
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render(flagStyle.Render("magpie") + " " + descStyle.Render("[OPTIONS]")))
	b.WriteString("\n")

	// Input/Output
	b.WriteString(headerStyle.Render("INPUT/OUTPUT:"))
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render(flagStyle.Render("-s, -source") + " " + descStyle.Render("<file>       Source file containing URLs (one per line) ") + lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Render("[REQUIRED]")))
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render(flagStyle.Render("-o, -output") + " " + descStyle.Render("<file>       Output file for aggregated domains (default: aggregated.txt)")))
	b.WriteString("\n")

	// Validation
	b.WriteString(headerStyle.Render("VALIDATION:"))
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render(flagStyle.Render("-d, -dns") + "                 " + descStyle.Render("Enable DNS validation - A, AAAA, CNAME (default: true)")))
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render(flagStyle.Render("-H, -http") + "                " + descStyle.Render("Enable HTTP validation in addition to DNS (default: false)")))
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render(flagStyle.Render("-w, -workers") + " " + descStyle.Render("<n>         Concurrent validation workers (default: 100)")))
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render(flagStyle.Render("-r, -resolvers") + " " + descStyle.Render("<list>    Comma-separated DNS resolvers (default: Cloudflare, Google, Quad9)")))
	b.WriteString("\n")

	// Performance
	b.WriteString(headerStyle.Render("PERFORMANCE:"))
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render(flagStyle.Render("-f, -fetch-workers") + " " + descStyle.Render("<n> Concurrent URL fetchers (default: 5)")))
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render(flagStyle.Render("-c, -cache") + "               " + descStyle.Render("Enable DNS caching with 5min TTL (default: true)")))
	b.WriteString("\n")

	// Stats & Filtering
	b.WriteString(headerStyle.Render("STATS & FILTERING:"))
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render(flagStyle.Render("--data-dir") + " " + descStyle.Render("<dir>        Directory for stats.json (default: ./data)")))
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render(flagStyle.Render("--no-tracking") + "            " + descStyle.Render("Disable URL health tracking and auto-filtering")))
	b.WriteString("\n")

	// Options
	b.WriteString(headerStyle.Render("OPTIONS:"))
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render(flagStyle.Render("-q, -quiet") + "               " + descStyle.Render("Quiet mode - minimal output")))
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render(flagStyle.Render("--silent") + "                 " + descStyle.Render("Silent mode - no output (perfect for cronjobs)")))
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render(flagStyle.Render("-v, -version") + "             " + descStyle.Render("Show version information")))
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render(flagStyle.Render("--stats") + "                  " + descStyle.Render("Display stats table and exit")))
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render(flagStyle.Render("-h, --help") + "               " + descStyle.Render("Show this help message")))
	b.WriteString("\n")

	// Examples
	b.WriteString(headerStyle.Render("EXAMPLES:"))
	b.WriteString("\n")
	b.WriteString(commentStyle.Render("# Basic aggregation with DNS validation"))
	b.WriteString("\n")
	b.WriteString(exampleStyle.Render("magpie -s sources.txt -o blocklist.txt"))
	b.WriteString("\n\n")
	b.WriteString(commentStyle.Render("# Fast mode - no validation"))
	b.WriteString("\n")
	b.WriteString(exampleStyle.Render("magpie -s sources.txt -o blocklist.txt -dns=false"))
	b.WriteString("\n\n")
	b.WriteString(commentStyle.Render("# Maximum filtering - DNS + HTTP validation"))
	b.WriteString("\n")
	b.WriteString(exampleStyle.Render("magpie -s sources.txt -o blocklist.txt -http -w 50"))
	b.WriteString("\n\n")
	b.WriteString(commentStyle.Render("# Silent mode for cronjobs"))
	b.WriteString("\n")
	b.WriteString(exampleStyle.Render("magpie -s sources.txt -o blocklist.txt --silent"))
	b.WriteString("\n\n")
	b.WriteString(commentStyle.Render("# View statistics"))
	b.WriteString("\n")
	b.WriteString(exampleStyle.Render("magpie --stats"))
	b.WriteString("\n")

	// Documentation
	b.WriteString(headerStyle.Render("DOCUMENTATION:"))
	b.WriteString("\n")
	b.WriteString(sectionStyle.Render(urlStyle.Render("https://github.com/pigeonsec/magpie")))
	b.WriteString("\n\n")

	fmt.Fprint(os.Stderr, b.String())
}

type AggregationStats struct {
	URLsFetched     int
	URLsFiltered    int
	DomainsFound    int
	DomainsValid    int
	DomainsInvalid  int
	DuplicatesFound int
	Errors          []string
	FilteredURLs    []string
}

func main() {
	flag.Parse()

	if showVer {
		fmt.Printf("Magpie version %s\n", version)
		return
	}

	// Show stats and exit if requested
	if showStats {
		dataPath, err := filepath.Abs(dataDir)
		if err != nil {
			log.Fatalf("Failed to resolve data directory: %v", err)
		}

		tracker, err := stats.NewTracker(dataPath)
		if err != nil {
			log.Fatalf("Failed to load stats: %v", err)
		}

		displayStatsTable(tracker)
		return
	}

	if sourceFile == "" {
		flag.Usage()
		fmt.Println("\nError: -source or -s is required")
		os.Exit(1)
	}

	// If silent mode, suppress all output
	if silent {
		// Redirect all output to /dev/null
		log.SetOutput(io.Discard)
		quiet = true
	}

	// Check if running in TTY (interactive terminal)
	isTTY := term.IsTerminal(int(os.Stdout.Fd()))

	// Use TUI for interactive terminals, fall back to logging for non-TTY
	if !quiet && !silent && isTTY {
		runWithTUI()
	} else {
		runWithLogs()
	}
}

func runWithTUI() {
	// Initialize and run the TUI
	model := ui.NewAppModel()
	program := tea.NewProgram(model, tea.WithAltScreen())

	// Run aggregation in background
	go func() {
		ctx := context.Background()

		// Check internet connection
		time.Sleep(500 * time.Millisecond) // Give UI time to render
		if err := netutil.CheckConnectionWithRetry(ctx, true); err != nil {
			log.Fatalf("No internet connection: %v", err)
		}
		program.Send(ui.ConnectionCheckedMsg{})

		// Load URLs
		time.Sleep(300 * time.Millisecond)
		allURLs, err := loadURLs(sourceFile)
		if err != nil {
			log.Fatalf("Failed to load source file: %v", err)
		}

		// Initialize stats tracker
		var tracker *stats.Tracker
		var urls []string
		var filteredURLs []string

		if !noTracking {
			dataPath, err := filepath.Abs(dataDir)
			if err != nil {
				log.Fatalf("Failed to resolve data directory: %v", err)
			}

			tracker, err = stats.NewTracker(dataPath)
			if err != nil {
				log.Fatalf("Failed to initialize stats tracker: %v", err)
			}

			urls, filteredURLs = tracker.FilterURLs(allURLs)
		} else {
			urls = allURLs
		}

		if len(urls) == 0 {
			log.Fatalf("No active URLs to process")
		}

		program.Send(ui.SourcesLoadedMsg{
			SourceFile:   sourceFile,
			TotalURLs:    len(allURLs),
			ActiveURLs:   len(urls),
			FilteredURLs: len(filteredURLs),
			FetchWorkers: fetchWorkers,
		})

		// Fetch domains
		time.Sleep(300 * time.Millisecond)
		allDomains, duplicates, errors := fetchDomainsWithTUI(ctx, program, urls, tracker)

		program.Send(ui.FetchCompleteMsg{
			TotalDomains:      len(allDomains),
			DuplicatesRemoved: duplicates,
			Errors:            errors,
		})

		time.Sleep(500 * time.Millisecond)

		// Validate domains
		if enableDNS || enableHTTP {
			program.Send(ui.ValidationStartMsg{
				Total:   len(allDomains),
				Workers: workers,
			})

			resolvers := strings.Split(dnsResolvers, ",")
			for i, r := range resolvers {
				resolvers[i] = strings.TrimSpace(r)
			}

			v := validator.NewValidatorWithResolvers(enableCache, resolvers)
			validDomains, validCount, invalidCount := validateDomainsWithTUI(ctx, program, v, allDomains)

			program.Send(ui.ValidationDoneMsg{})
			time.Sleep(300 * time.Millisecond)

			// Write output
			if err := writeOutput(outputFile, validDomains); err != nil {
				log.Fatalf("Failed to write output: %v", err)
			}

			// Save stats with global metrics
			if tracker != nil {
				validationMethod := "dns"
				if enableHTTP {
					validationMethod = "dns+http"
				}

				// Record global stats from this run
				tracker.RecordGlobalStats(
					len(urls),              // URLs fetched
					len(errors),            // URLs failed
					len(allDomains)+duplicates, // Raw domains (including duplicates)
					len(allDomains),        // Unique domains
					duplicates,             // Duplicates removed
					validCount,             // Valid domains
					invalidCount,           // Invalid domains
					validationMethod,
				)

				if err := tracker.Save(); err != nil {
					log.Printf("Warning: Failed to save stats: %v", err)
				}
			}

			program.Send(ui.CompletionMsg{
				OutputFile: outputFile,
				Valid:      validCount,
				Invalid:    invalidCount,
			})
		} else {
			// No validation - write all domains
			validDomains := make([]string, 0, len(allDomains))
			for domain := range allDomains {
				validDomains = append(validDomains, domain)
			}

			if err := writeOutput(outputFile, validDomains); err != nil {
				log.Fatalf("Failed to write output: %v", err)
			}

			if tracker != nil {
				// Record global stats from this run (no validation)
				tracker.RecordGlobalStats(
					len(urls),              // URLs fetched
					len(errors),            // URLs failed
					len(allDomains)+duplicates, // Raw domains (including duplicates)
					len(allDomains),        // Unique domains
					duplicates,             // Duplicates removed
					len(validDomains),      // Valid domains (all)
					0,                      // Invalid domains (none)
					"none",
				)

				if err := tracker.Save(); err != nil {
					log.Printf("Warning: Failed to save stats: %v", err)
				}
			}

			program.Send(ui.CompletionMsg{
				OutputFile: outputFile,
				Valid:      len(validDomains),
				Invalid:    0,
			})
		}

		time.Sleep(2 * time.Second)
	}()

	if _, err := program.Run(); err != nil {
		log.Fatalf("Error running TUI: %v", err)
	}
}

func runWithLogs() {
	ctx := context.Background()

	if !quiet {
		fmt.Print(logo)
		log.Printf("Starting aggregation from %s", sourceFile)
	}

	// Check internet connection before starting
	if !quiet {
		log.Printf("Checking internet connection...")
	}
	if err := netutil.CheckConnectionWithRetry(ctx, quiet); err != nil {
		log.Fatalf("No internet connection: %v", err)
	}
	if !quiet {
		log.Printf("✓ Internet connection verified")
	}

	// Load URLs
	allURLs, err := loadURLs(sourceFile)
	if err != nil {
		log.Fatalf("Failed to load source file: %v", err)
	}

	// Initialize stats tracker
	var tracker *stats.Tracker
	var urls []string
	var filteredURLs []string

	if !noTracking {
		// Expand data directory path
		dataPath, err := filepath.Abs(dataDir)
		if err != nil {
			log.Fatalf("Failed to resolve data directory: %v", err)
		}

		tracker, err = stats.NewTracker(dataPath)
		if err != nil {
			log.Fatalf("Failed to initialize stats tracker: %v", err)
		}

		// Filter out blacklisted URLs
		urls, filteredURLs = tracker.FilterURLs(allURLs)

		if !quiet {
			log.Printf("Loaded %d source URLs", len(allURLs))
			if len(filteredURLs) > 0 {
				log.Printf("⚠️  Filtered out %d blacklisted URLs (failed %d+ times)", len(filteredURLs), stats.MaxFailures)
				for _, url := range filteredURLs {
					if urlStats := tracker.GetStats(url); urlStats != nil {
						log.Printf("   - %s (failures: %d, last: %s)", url, urlStats.FailureCount, urlStats.LastError)
					}
				}
			}
			log.Printf("Processing %d active URLs with %d parallel fetchers", len(urls), fetchWorkers)
		}
	} else {
		urls = allURLs
		if !quiet {
			log.Printf("Loaded %d source URLs (tracking disabled)", len(urls))
			log.Printf("Using %d parallel fetchers", fetchWorkers)
		}
	}

	if len(urls) == 0 {
		log.Fatalf("No active URLs to process")
	}

	// Fetch domains with parallel workers and streaming
	aggregationStats := &AggregationStats{
		FilteredURLs: filteredURLs,
		URLsFiltered: len(filteredURLs),
	}
	allDomains := make(map[string]bool)
	domainChan := make(chan string, 10000) // Buffered channel for streaming
	errorChan := make(chan error, len(urls))

	f := fetcher.NewFetcher(30*time.Second, 3)

	// Start parallel fetchers
	var fetchWg sync.WaitGroup
	urlChan := make(chan string, len(urls))

	// Start fetch workers
	for i := 0; i < fetchWorkers; i++ {
		fetchWg.Add(1)
		go func(workerID int) {
			defer fetchWg.Done()
			for url := range urlChan {
				if !quiet {
					log.Printf("[Worker %d] Fetching %s", workerID, url)
				}

				domains, err := f.Fetch(ctx, url)
				if err != nil {
					// Check if it's a connection error and wait for internet
					if strings.Contains(err.Error(), "dial") || strings.Contains(err.Error(), "connection") || strings.Contains(err.Error(), "network") {
						if !quiet {
							log.Printf("[Worker %d] Connection error detected, checking internet...", workerID)
						}
						if connErr := netutil.CheckConnectionWithRetry(ctx, quiet); connErr != nil {
							errMsg := fmt.Errorf("failed to fetch %s: %w (connection lost)", url, err)
							errorChan <- errMsg
							if tracker != nil {
								tracker.RecordFailure(url, err.Error())
							}
							continue
						}
						// Connection restored, retry this URL
						if !quiet {
							log.Printf("[Worker %d] Connection restored, retrying %s", workerID, url)
						}
						domains, err = f.Fetch(ctx, url)
						if err != nil {
							errMsg := fmt.Errorf("failed to fetch %s after reconnection: %w", url, err)
							errorChan <- errMsg
							if tracker != nil {
								tracker.RecordFailure(url, err.Error())
							}
							continue
						}
					} else {
						errMsg := fmt.Errorf("failed to fetch %s: %w", url, err)
						errorChan <- errMsg
						if tracker != nil {
							tracker.RecordFailure(url, err.Error())
						}
						continue
					}
				}

				aggregationStats.URLsFetched++

				// Record success in stats tracker
				if tracker != nil {
					tracker.RecordSuccess(url)
				}

				if !quiet {
					log.Printf("[Worker %d] Found %d domains from %s", workerID, len(domains), url)
				}

				// Stream domains to channel
				for _, domain := range domains {
					domainChan <- domain
				}
			}
		}(i)
	}

	// Feed URLs to workers
	go func() {
		for _, url := range urls {
			urlChan <- url
		}
		close(urlChan)
	}()

	// Collect domains in background
	collectorDone := make(chan bool)
	go func() {
		for domain := range domainChan {
			if allDomains[domain] {
				aggregationStats.DuplicatesFound++
			} else {
				allDomains[domain] = true
			}
		}
		collectorDone <- true
	}()

	// Wait for all fetchers to complete
	fetchWg.Wait()
	close(domainChan)

	// Wait for collector to finish
	<-collectorDone
	close(errorChan)

	// Collect errors
	for err := range errorChan {
		log.Printf("ERROR: %s", err)
		aggregationStats.Errors = append(aggregationStats.Errors, err.Error())
	}

	aggregationStats.DomainsFound = len(allDomains)

	if !quiet {
		log.Printf("Found %d unique domains (removed %d duplicates)", aggregationStats.DomainsFound, aggregationStats.DuplicatesFound)
	}

	if aggregationStats.DomainsFound == 0 {
		log.Fatalf("No domains found from any source")
	}

	// Validate domains
	validDomains := []string{}

	if enableDNS || enableHTTP {
		if !quiet {
			log.Printf("Validating %d domains with %d workers (caching: %v)...", aggregationStats.DomainsFound, workers, enableCache)
		}

		// Parse DNS resolvers
		resolvers := strings.Split(dnsResolvers, ",")
		for i, r := range resolvers {
			resolvers[i] = strings.TrimSpace(r)
		}

		v := validator.NewValidatorWithResolvers(enableCache, resolvers)
		validDomains = validateDomains(ctx, v, allDomains, aggregationStats)

		if !quiet {
			log.Printf("Validation complete: %d valid, %d invalid", aggregationStats.DomainsValid, aggregationStats.DomainsInvalid)
		}

		// Record global stats
		if tracker != nil {
			validationMethod := "dns"
			if enableHTTP {
				validationMethod = "dns+http"
			}

			tracker.RecordGlobalStats(
				aggregationStats.URLsFetched,
				len(aggregationStats.Errors),
				aggregationStats.DomainsFound+aggregationStats.DuplicatesFound,
				aggregationStats.DomainsFound,
				aggregationStats.DuplicatesFound,
				aggregationStats.DomainsValid,
				aggregationStats.DomainsInvalid,
				validationMethod,
			)
		}
	} else {
		// No validation - all domains are valid
		validDomains = make([]string, 0, len(allDomains))
		for domain := range allDomains {
			validDomains = append(validDomains, domain)
		}
		aggregationStats.DomainsValid = len(validDomains)

		// Record global stats (no validation)
		if tracker != nil {
			tracker.RecordGlobalStats(
				aggregationStats.URLsFetched,
				len(aggregationStats.Errors),
				aggregationStats.DomainsFound+aggregationStats.DuplicatesFound,
				aggregationStats.DomainsFound,
				aggregationStats.DuplicatesFound,
				len(validDomains),
				0,
				"none",
			)
		}
	}

	// Write output
	if err := writeOutput(outputFile, validDomains); err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}

	// Save stats tracker
	if tracker != nil {
		if err := tracker.Save(); err != nil {
			log.Printf("Warning: Failed to save stats: %v", err)
		} else if !quiet {
			log.Printf("Stats saved to %s", filepath.Join(dataDir, stats.StatsFile))
		}
	}

	// Print results
	printResults(aggregationStats, len(validDomains))
}

func fetchDomainsWithTUI(ctx context.Context, program *tea.Program, urls []string, tracker *stats.Tracker) (map[string]bool, int, []string) {
	allDomains := make(map[string]bool)
	duplicates := 0
	var errors []string
	var mu sync.Mutex

	domainChan := make(chan string, 10000)
	errorChan := make(chan error, len(urls))

	f := fetcher.NewFetcher(30*time.Second, 3)

	var fetchWg sync.WaitGroup
	urlChan := make(chan string, len(urls))
	fetchedCount := atomic.Int32{}

	// Start fetch workers
	for i := 0; i < fetchWorkers; i++ {
		fetchWg.Add(1)
		go func(workerID int) {
			defer fetchWg.Done()
			for url := range urlChan {
				domains, err := f.Fetch(ctx, url)
				if err != nil {
					errorChan <- fmt.Errorf("failed to fetch %s: %w", url, err)
					if tracker != nil {
						tracker.RecordFailure(url, err.Error())
					}
					continue
				}

				if tracker != nil {
					tracker.RecordSuccess(url)
				}

				fetched := int(fetchedCount.Add(1))

				// Send update to TUI
				program.Send(ui.FetchProgressMsg{
					URL:          url,
					WorkerID:     workerID,
					DomainsFound: len(domains),
					TotalDomains: len(allDomains) + len(domains),
					FetchedCount: fetched,
				})

				// Stream domains to channel
				for _, domain := range domains {
					domainChan <- domain
				}
			}
		}(i)
	}

	// Collect domains in background
	collectorDone := make(chan bool)
	go func() {
		for domain := range domainChan {
			mu.Lock()
			if allDomains[domain] {
				duplicates++
			} else {
				allDomains[domain] = true
			}
			mu.Unlock()
		}
		collectorDone <- true
	}()

	// Feed URLs to workers
	go func() {
		for _, url := range urls {
			urlChan <- url
		}
		close(urlChan)
	}()

	// Wait for all fetchers
	fetchWg.Wait()
	close(domainChan)
	<-collectorDone
	close(errorChan)

	// Collect errors
	for err := range errorChan {
		errors = append(errors, err.Error())
	}

	return allDomains, duplicates, errors
}

func validateDomainsWithTUI(ctx context.Context, program *tea.Program, v *validator.Validator, domains map[string]bool) ([]string, int, int) {
	var (
		wg           sync.WaitGroup
		validMu      sync.Mutex
		validDomains []string
		total        = len(domains)
		processed    atomic.Int64
		validCount   atomic.Int64
		invalidCount atomic.Int64
	)

	validDomains = make([]string, 0, total*4/5)
	domainChan := make(chan string, workers*2)

	// Start workers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			localValid := make([]string, 0, total/workers)

			for domain := range domainChan {
				valid := false
				var err error

				if enableHTTP {
					valid, err = v.ValidateFull(ctx, domain)
				} else if enableDNS {
					valid, err = v.ValidateDNS(ctx, domain)
				}

				if err == nil && valid {
					localValid = append(localValid, domain)
					validCount.Add(1)
				} else {
					invalidCount.Add(1)
				}

				current := processed.Add(1)

				// Update TUI every 50 domains to reduce overhead
				if current%50 == 0 || current == int64(total) {
					program.Send(ui.ValidationProgressMsg{
						Current: int(current),
						Valid:   int(validCount.Load()),
						Invalid: int(invalidCount.Load()),
					})
				}
			}

			validMu.Lock()
			validDomains = append(validDomains, localValid...)
			validMu.Unlock()
		}(i)
	}

	// Feed domains to workers
	for domain := range domains {
		domainChan <- domain
	}
	close(domainChan)

	wg.Wait()

	return validDomains, int(validCount.Load()), int(invalidCount.Load())
}

func loadURLs(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Basic URL validation
		if !strings.HasPrefix(line, "http://") && !strings.HasPrefix(line, "https://") {
			return nil, fmt.Errorf("line %d: invalid URL (must start with http:// or https://): %s", lineNum, line)
		}

		urls = append(urls, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %w", err)
	}

	if len(urls) == 0 {
		return nil, fmt.Errorf("no valid URLs found in file")
	}

	return urls, nil
}

func validateDomains(ctx context.Context, v *validator.Validator, domains map[string]bool, aggStats *AggregationStats) []string {
	var (
		wg           sync.WaitGroup
		validMu      sync.Mutex
		validDomains []string
		total        = len(domains)
		processed    atomic.Int64
		validCount   atomic.Int64
		invalidCount atomic.Int64
	)

	// Pre-allocate with estimated capacity (assume ~80% valid)
	validDomains = make([]string, 0, total*4/5)

	// Create buffered channel for better throughput
	domainChan := make(chan string, workers*2)

	// Check if running in TTY (interactive terminal)
	isTTY := term.IsTerminal(int(os.Stdout.Fd()))

	// Setup progress tracking
	var program *tea.Program
	startTime := time.Now()

	if !quiet && isTTY {
		// Use Bubble Tea for interactive terminals
		model := ui.NewProgressModel(total)
		program = tea.NewProgram(model)

		// Run the program in a goroutine
		go func() {
			if _, err := program.Run(); err != nil {
				log.Printf("Error running progress UI: %v", err)
			}
		}()
	} else if !quiet {
		// Simple logging for non-TTY (pipes, files, cronjobs)
		log.Printf("Starting validation of %d domains with %d workers...", total, workers)
	}

	// Start workers first
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			localValid := make([]string, 0, total/(workers))
			localValidCount := 0
			localInvalidCount := 0

			for domain := range domainChan {
				valid := false
				var err error

				if enableHTTP {
					valid, err = v.ValidateFull(ctx, domain)
				} else if enableDNS {
					valid, err = v.ValidateDNS(ctx, domain)
				}

				if err == nil && valid {
					localValid = append(localValid, domain)
					localValidCount++
					validCount.Add(1)
				} else {
					localInvalidCount++
					invalidCount.Add(1)
				}

				// Update progress
				current := processed.Add(1)

				if !quiet {
					if program != nil && isTTY {
						// TTY: Update Bubble Tea UI
						program.Send(ui.UpdateProgress(
							int(current),
							int(validCount.Load()),
							int(invalidCount.Load()),
						))
					} else if !isTTY {
						// Non-TTY: Log every 10k domains
						if current%10000 == 0 || current == int64(total) {
							elapsed := time.Since(startTime)
							speed := float64(current) / elapsed.Seconds()
							log.Printf("Progress: %d/%d (%.1f%%) - %d valid, %d invalid - %.0f domains/s",
								current, total, float64(current)/float64(total)*100,
								validCount.Load(), invalidCount.Load(), speed)
						}
					}
				}
			}

			// Merge local results
			validMu.Lock()
			validDomains = append(validDomains, localValid...)
			aggStats.DomainsValid += localValidCount
			aggStats.DomainsInvalid += localInvalidCount
			validMu.Unlock()
		}(i)
	}

	// Feed domains to workers
	for domain := range domains {
		domainChan <- domain
	}
	close(domainChan)

	wg.Wait()

	if program != nil {
		program.Send(ui.SendDone())
		program.Wait()
	}

	return validDomains
}

func writeOutput(path string, domains []string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Use larger buffer for better write performance with large lists
	writer := bufio.NewWriterSize(file, 256*1024) // 256KB buffer
	for _, domain := range domains {
		fmt.Fprintln(writer, domain)
	}
	return writer.Flush()
}

func printResults(aggStats *AggregationStats, validCount int) {
	if quiet {
		return
	}

	// Color definitions
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	magenta := color.New(color.FgMagenta, color.Bold)
	white := color.New(color.FgWhite, color.Bold)

	// Box drawing characters
	topLine := "╔" + strings.Repeat("═", 78) + "╗"
	midLine := "╠" + strings.Repeat("═", 78) + "╣"
	botLine := "╚" + strings.Repeat("═", 78) + "╝"

	fmt.Println()
	cyan.Println(topLine)
	cyan.Print("║")
	fmt.Print(strings.Repeat(" ", 20))
	green.Print("🎉 AGGREGATION COMPLETE! 🎉")
	fmt.Print(strings.Repeat(" ", 20))
	cyan.Println("║")
	cyan.Println(midLine)

	// Source statistics
	cyan.Print("║  ")
	white.Print("📥 SOURCE STATISTICS")
	fmt.Print(strings.Repeat(" ", 56))
	cyan.Println("║")
	cyan.Println("║" + strings.Repeat(" ", 78) + "║")

	printColorLine(cyan, cyan, "    URLs fetched:", fmt.Sprintf("%d", aggStats.URLsFetched))
	if aggStats.URLsFiltered > 0 {
		printColorLine(cyan, yellow, "    URLs filtered:", fmt.Sprintf("%d (failed %d+ times)", aggStats.URLsFiltered, stats.MaxFailures))
	}
	printColorLine(cyan, cyan, "    Domains found:", formatSize(aggStats.DomainsFound))
	printColorLine(cyan, yellow, "    Duplicates removed:", formatSize(aggStats.DuplicatesFound))

	cyan.Println(midLine)

	// Validation statistics
	if enableDNS || enableHTTP {
		cyan.Print("║  ")
		white.Print("🔍 VALIDATION RESULTS")
		fmt.Print(strings.Repeat(" ", 55))
		cyan.Println("║")
		cyan.Println("║" + strings.Repeat(" ", 78) + "║")

		printColorLine(cyan, green, "    Valid domains:", formatSize(aggStats.DomainsValid))
		printColorLine(cyan, red, "    Invalid domains:", formatSize(aggStats.DomainsInvalid))

		// Calculate cleaning statistics
		if aggStats.DomainsFound > 0 {
			filteredCount := aggStats.DomainsInvalid
			cleaningRate := float64(filteredCount) / float64(aggStats.DomainsFound) * 100

			cyan.Println("║" + strings.Repeat(" ", 78) + "║")
			cyan.Print("║  ")
			magenta.Print("  🧹 Cleaning Power:")
			fmt.Print(strings.Repeat(" ", 56))
			cyan.Println("║")

			cleaningMsg := fmt.Sprintf("      Filtered out %s invalid domains (%.1f%% cleaning rate)",
				formatSize(filteredCount), cleaningRate)
			cyan.Print("║  ")
			magenta.Print(cleaningMsg)
			fmt.Print(strings.Repeat(" ", 78-len(cleaningMsg)-2))
			cyan.Println("║")
		}

		cyan.Println(midLine)
	}

	// Final output
	cyan.Print("║  ")
	white.Print("💾 OUTPUT")
	fmt.Print(strings.Repeat(" ", 66))
	cyan.Println("║")
	cyan.Println("║" + strings.Repeat(" ", 78) + "║")

	printColorLine(cyan, green, "    File:", outputFile)
	printColorLine(cyan, green, "    Total domains:", formatSize(validCount))

	// Error summary
	if len(aggStats.Errors) > 0 {
		cyan.Println(midLine)
		cyan.Print("║  ")
		red.Print("⚠️  ERRORS ENCOUNTERED")
		fmt.Print(strings.Repeat(" ", 55))
		cyan.Println("║")
		cyan.Println("║" + strings.Repeat(" ", 78) + "║")

		errorCountMsg := fmt.Sprintf("    Total errors: %d", len(aggStats.Errors))
		cyan.Print("║  ")
		red.Print(errorCountMsg)
		fmt.Print(strings.Repeat(" ", 78-len(errorCountMsg)-2))
		cyan.Println("║")

		for i, errMsg := range aggStats.Errors {
			if i < 3 {
				// Truncate long error messages
				if len(errMsg) > 72 {
					errMsg = errMsg[:69] + "..."
				}
				cyan.Print("║    ")
				red.Print("- ")
				fmt.Print(errMsg)
				fmt.Print(strings.Repeat(" ", 72-len(errMsg)))
				cyan.Println("║")
			}
		}
		if len(aggStats.Errors) > 3 {
			moreMsg := fmt.Sprintf("    ... and %d more errors", len(aggStats.Errors)-3)
			cyan.Print("║  ")
			red.Print(moreMsg)
			fmt.Print(strings.Repeat(" ", 78-len(moreMsg)-2))
			cyan.Println("║")
		}
	}

	cyan.Println(botLine)
	fmt.Println()
}

func printColorLine(borderColor, textColor *color.Color, label, value string) {
	borderColor.Print("║  ")
	fmt.Print(label)
	spaces := 76 - len(label) - len(value)
	fmt.Print(strings.Repeat(" ", spaces))
	textColor.Print(value)
	fmt.Print("  ")
	borderColor.Println("║")
}

func displayStatsTable(tracker *stats.Tracker) {
	if len(tracker.Stats) == 0 {
		noStatsStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("240")).
			Italic(true).
			Padding(1, 2)
		fmt.Println(noStatsStyle.Render("No stats available yet. Run an aggregation first."))
		return
	}

	// Style definitions
	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("213")).
		Bold(true).
		Padding(1, 2).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("99"))

	urlStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("86"))

	labelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240"))

	numberStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("228")).
		Bold(true)

	successStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("10")).
		Bold(true)

	failureStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("9")).
		Bold(true)

	activeStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("10")).
		Bold(true)

	filteredStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("9")).
		Bold(true)

	timeStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("245")).
		Italic(true)

	summaryLabelStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("117")).
		Bold(true).
		Width(18)

	summaryValueStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("86")).
		Bold(true)

	var b strings.Builder

	// Title
	b.WriteString("\n")
	b.WriteString(titleStyle.Render("📊 BLOCKLIST STATISTICS"))
	b.WriteString("\n\n")

	// Calculate summary first
	totalURLs := len(tracker.Stats)
	activeURLs := 0
	filteredURLs := 0
	totalSuccess := 0
	totalFailures := 0

	for _, stat := range tracker.Stats {
		if stat.Blacklisted || stat.FailureCount >= stats.MaxFailures {
			filteredURLs++
		} else {
			activeURLs++
		}
		totalSuccess += stat.SuccessCount
		totalFailures += stat.FailureCount
	}

	// Sort URLs for consistent output
	var urls []string
	for url := range tracker.Stats {
		urls = append(urls, url)
	}

	// Compact card-based layout for each URL
	for _, url := range urls {
		stat := tracker.Stats[url]

		// Truncate URL if too long (40 chars for smaller screens)
		displayURL := url
		if len(displayURL) > 40 {
			displayURL = displayURL[:37] + "..."
		}

		// Status indicator
		isFiltered := stat.Blacklisted || stat.FailureCount >= stats.MaxFailures
		var statusText string
		if isFiltered {
			statusText = filteredStyle.Render("✗ Filtered")
		} else {
			statusText = activeStyle.Render("✓ Active")
		}

		// Format last checked time
		lastChecked := "-"
		if !stat.LastChecked.IsZero() {
			lastChecked = formatTimeSince(stat.LastChecked)
		}

		// Build compact card
		cardStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("240")).
			Padding(0, 1)

		var card strings.Builder

		// URL line
		card.WriteString(urlStyle.Bold(true).Render(displayURL))
		card.WriteString("  ")
		card.WriteString(statusText)
		card.WriteString("\n")

		// Stats line
		card.WriteString(labelStyle.Render("Success: "))
		card.WriteString(successStyle.Render(fmt.Sprintf("%d", stat.SuccessCount)))
		card.WriteString(labelStyle.Render("  •  Failed: "))
		if stat.FailureCount > 0 {
			card.WriteString(failureStyle.Render(fmt.Sprintf("%d", stat.FailureCount)))
		} else {
			card.WriteString(labelStyle.Render("0"))
		}
		card.WriteString(labelStyle.Render("  •  "))
		card.WriteString(timeStyle.Render(lastChecked))
		if stat.ValidationMethod != "" {
			card.WriteString(labelStyle.Render("  •  "))
			card.WriteString(numberStyle.Render(stat.ValidationMethod))
		}

		b.WriteString(cardStyle.Render(card.String()))
		b.WriteString("\n")
	}

	// Summary box
	b.WriteString("\n")
	summaryStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("99")).
		Padding(1, 2).
		MarginTop(1)

	var summary strings.Builder
	summary.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("213")).Bold(true).Render("📈 Summary"))
	summary.WriteString("\n\n")

	summary.WriteString(summaryLabelStyle.Render("Total URLs:"))
	summary.WriteString(summaryValueStyle.Render(fmt.Sprintf("%d", totalURLs)))
	summary.WriteString("\n")

	summary.WriteString(summaryLabelStyle.Render("Active:"))
	summary.WriteString(activeStyle.Render(fmt.Sprintf("%d", activeURLs)))
	summary.WriteString("\n")

	summary.WriteString(summaryLabelStyle.Render("Filtered:"))
	if filteredURLs > 0 {
		summary.WriteString(filteredStyle.Render(fmt.Sprintf("%d", filteredURLs)))
	} else {
		summary.WriteString(summaryValueStyle.Render(fmt.Sprintf("%d", filteredURLs)))
	}
	summary.WriteString("\n")

	summary.WriteString(summaryLabelStyle.Render("Total Successes:"))
	summary.WriteString(successStyle.Render(fmt.Sprintf("%d", totalSuccess)))
	summary.WriteString("\n")

	summary.WriteString(summaryLabelStyle.Render("Total Failures:"))
	if totalFailures > 0 {
		summary.WriteString(failureStyle.Render(fmt.Sprintf("%d", totalFailures)))
	} else {
		summary.WriteString(summaryValueStyle.Render(fmt.Sprintf("%d", totalFailures)))
	}

	b.WriteString(summaryStyle.Render(summary.String()))
	b.WriteString("\n")

	// Global stats from last run (if available)
	if tracker.GlobalStats != nil {
		b.WriteString("\n")
		globalStyle := lipgloss.NewStyle().
			Border(lipgloss.RoundedBorder()).
			BorderForeground(lipgloss.Color("213")).
			Padding(1, 2).
			MarginTop(1)

		var globalSummary strings.Builder
		globalSummary.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("213")).Bold(true).Render("📊 Last Run Stats"))
		globalSummary.WriteString("\n\n")

		globalSummary.WriteString(summaryLabelStyle.Render("Run Time:"))
		globalSummary.WriteString(timeStyle.Render(formatTimeSince(tracker.GlobalStats.LastRun)))
		globalSummary.WriteString("\n")

		globalSummary.WriteString(summaryLabelStyle.Render("URLs Fetched:"))
		globalSummary.WriteString(successStyle.Render(fmt.Sprintf("%d", tracker.GlobalStats.TotalURLsFetched)))
		globalSummary.WriteString("\n")

		if tracker.GlobalStats.TotalURLsFailed > 0 {
			globalSummary.WriteString(summaryLabelStyle.Render("URLs Failed:"))
			globalSummary.WriteString(failureStyle.Render(fmt.Sprintf("%d", tracker.GlobalStats.TotalURLsFailed)))
			globalSummary.WriteString("\n")
		}

		globalSummary.WriteString(summaryLabelStyle.Render("Domains Raw:"))
		globalSummary.WriteString(numberStyle.Render(formatSize(tracker.GlobalStats.TotalDomainsRaw)))
		globalSummary.WriteString("\n")

		globalSummary.WriteString(summaryLabelStyle.Render("Domains Unique:"))
		globalSummary.WriteString(lipgloss.NewStyle().Foreground(lipgloss.Color("213")).Bold(true).Render(formatSize(tracker.GlobalStats.TotalDomainsUnique)))
		globalSummary.WriteString("\n")

		globalSummary.WriteString(summaryLabelStyle.Render("Duplicates:"))
		globalSummary.WriteString(labelStyle.Render(formatSize(tracker.GlobalStats.DuplicatesRemoved)))
		globalSummary.WriteString("\n")

		if tracker.GlobalStats.ValidationMethod != "none" {
			globalSummary.WriteString(summaryLabelStyle.Render("Valid Domains:"))
			globalSummary.WriteString(successStyle.Render(formatSize(tracker.GlobalStats.ValidDomains)))
			globalSummary.WriteString("\n")

			globalSummary.WriteString(summaryLabelStyle.Render("Invalid Domains:"))
			globalSummary.WriteString(failureStyle.Render(formatSize(tracker.GlobalStats.InvalidDomains)))
			globalSummary.WriteString("\n")
		}

		globalSummary.WriteString(summaryLabelStyle.Render("Validation:"))
		globalSummary.WriteString(numberStyle.Render(tracker.GlobalStats.ValidationMethod))

		b.WriteString(globalStyle.Render(globalSummary.String()))
	}

	b.WriteString("\n\n")

	fmt.Print(b.String())
}

func formatTimeSince(t time.Time) string {
	if t.IsZero() {
		return "-"
	}

	duration := time.Since(t)

	if duration < time.Minute {
		return "just now"
	} else if duration < time.Hour {
		mins := int(duration.Minutes())
		return fmt.Sprintf("%dm ago", mins)
	} else if duration < 24*time.Hour {
		hours := int(duration.Hours())
		return fmt.Sprintf("%dh ago", hours)
	} else {
		days := int(duration.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
}

func formatSize(count int) string {
	if count < 1000 {
		return fmt.Sprintf("%d", count)
	} else if count < 1000000 {
		return fmt.Sprintf("%.1fK", float64(count)/1000)
	} else {
		return fmt.Sprintf("%.1fM", float64(count)/1000000)
	}
}
