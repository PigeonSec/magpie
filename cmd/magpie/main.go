package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
	"github.com/schollz/progressbar/v3"
	"github.com/pigeonsec/magpie/internal/fetcher"
	"github.com/pigeonsec/magpie/internal/netutil"
	"github.com/pigeonsec/magpie/internal/stats"
	"github.com/pigeonsec/magpie/internal/validator"
	"golang.org/x/term"
)

const logo = `
🦅 Magpie - Blocklist Aggregation & Validation Tool
`

var (
	version = "1.0.0"

	// Input/Output
	sourceFile = flag.String("source-file", "", "File containing URLs to fetch (one per line)")
	outputFile = flag.String("output", "aggregated.txt", "Output file for aggregated domains")

	// Validation
	enableDNS    = flag.Bool("dns", true, "Enable DNS validation (A, AAAA, CNAME)")
	enableHTTP   = flag.Bool("http", false, "Enable HTTP validation (in addition to DNS)")
	workers      = flag.Int("workers", 100, "Number of concurrent validation workers")
	dnsResolvers = flag.String("dns-resolvers", "1.1.1.1:53,1.0.0.1:53,8.8.8.8:53,8.8.4.4:53,9.9.9.9:53,149.112.112.112:53", "Comma-separated DNS resolvers (bypasses Pi-hole)")

	// Performance
	fetchWorkers = flag.Int("fetch-workers", 5, "Number of concurrent URL fetchers")
	enableCache  = flag.Bool("cache", true, "Enable DNS result caching")

	// Stats & Filtering
	dataDir    = flag.String("data-dir", "./data", "Directory for stats.json and persistent data")
	noTracking = flag.Bool("no-tracking", false, "Disable URL health tracking and filtering")

	// Options
	quiet     = flag.Bool("quiet", false, "Quiet mode - minimal output")
	showVer   = flag.Bool("version", false, "Show version information")
	showStats = flag.Bool("show-stats", false, "Display stats table and exit")
)

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

	if *showVer {
		fmt.Printf("Magpie version %s\n", version)
		return
	}

	// Show stats and exit if requested
	if *showStats {
		dataPath, err := filepath.Abs(*dataDir)
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

	if *sourceFile == "" {
		flag.Usage()
		fmt.Println("\nError: -source-file is required")
		os.Exit(1)
	}

	if !*quiet {
		fmt.Print(logo)
		log.Printf("Starting aggregation from %s", *sourceFile)
	}

	// Check internet connection before starting
	ctx := context.Background()
	if !*quiet {
		log.Printf("Checking internet connection...")
	}
	if err := netutil.CheckConnectionWithRetry(ctx, *quiet); err != nil {
		log.Fatalf("No internet connection: %v", err)
	}
	if !*quiet {
		log.Printf("✓ Internet connection verified")
	}

	// Load URLs
	allURLs, err := loadURLs(*sourceFile)
	if err != nil {
		log.Fatalf("Failed to load source file: %v", err)
	}

	// Initialize stats tracker
	var tracker *stats.Tracker
	var urls []string
	var filteredURLs []string

	if !*noTracking {
		// Expand data directory path
		dataPath, err := filepath.Abs(*dataDir)
		if err != nil {
			log.Fatalf("Failed to resolve data directory: %v", err)
		}

		tracker, err = stats.NewTracker(dataPath)
		if err != nil {
			log.Fatalf("Failed to initialize stats tracker: %v", err)
		}

		// Filter out blacklisted URLs
		urls, filteredURLs = tracker.FilterURLs(allURLs)

		if !*quiet {
			log.Printf("Loaded %d source URLs", len(allURLs))
			if len(filteredURLs) > 0 {
				log.Printf("⚠️  Filtered out %d blacklisted URLs (failed %d+ times)", len(filteredURLs), stats.MaxFailures)
				for _, url := range filteredURLs {
					if urlStats := tracker.GetStats(url); urlStats != nil {
						log.Printf("   - %s (failures: %d, last: %s)", url, urlStats.FailureCount, urlStats.LastError)
					}
				}
			}
			log.Printf("Processing %d active URLs with %d parallel fetchers", len(urls), *fetchWorkers)
		}
	} else {
		urls = allURLs
		if !*quiet {
			log.Printf("Loaded %d source URLs (tracking disabled)", len(urls))
			log.Printf("Using %d parallel fetchers", *fetchWorkers)
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
	for i := 0; i < *fetchWorkers; i++ {
		fetchWg.Add(1)
		go func(workerID int) {
			defer fetchWg.Done()
			for url := range urlChan {
				if !*quiet {
					log.Printf("[Worker %d] Fetching %s", workerID, url)
				}

				domains, err := f.Fetch(ctx, url)
				if err != nil {
					// Check if it's a connection error and wait for internet
					if strings.Contains(err.Error(), "dial") || strings.Contains(err.Error(), "connection") || strings.Contains(err.Error(), "network") {
						if !*quiet {
							log.Printf("[Worker %d] Connection error detected, checking internet...", workerID)
						}
						if connErr := netutil.CheckConnectionWithRetry(ctx, *quiet); connErr != nil {
							errMsg := fmt.Errorf("failed to fetch %s: %w (connection lost)", url, err)
							errorChan <- errMsg
							if tracker != nil {
								tracker.RecordFailure(url, err.Error())
							}
							continue
						}
						// Connection restored, retry this URL
						if !*quiet {
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
					tracker.RecordSuccess(url, len(domains))
				}

				if !*quiet {
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

	if !*quiet {
		log.Printf("Found %d unique domains (removed %d duplicates)", aggregationStats.DomainsFound, aggregationStats.DuplicatesFound)
	}

	if aggregationStats.DomainsFound == 0 {
		log.Fatalf("No domains found from any source")
	}

	// Validate domains
	validDomains := []string{}

	if *enableDNS || *enableHTTP {
		if !*quiet {
			log.Printf("Validating %d domains with %d workers (caching: %v)...", aggregationStats.DomainsFound, *workers, *enableCache)
		}

		// Parse DNS resolvers
		resolvers := strings.Split(*dnsResolvers, ",")
		for i, r := range resolvers {
			resolvers[i] = strings.TrimSpace(r)
		}

		v := validator.NewValidatorWithResolvers(*enableCache, resolvers)
		validDomains = validateDomains(ctx, v, allDomains, aggregationStats)

		if !*quiet {
			log.Printf("Validation complete: %d valid, %d invalid", aggregationStats.DomainsValid, aggregationStats.DomainsInvalid)
		}

		// Record validation stats
		if tracker != nil {
			validationMethod := "dns"
			if *enableHTTP {
				validationMethod = "dns+http"
			}
			tracker.RecordOverallValidation(validationMethod, aggregationStats.DomainsValid, aggregationStats.DomainsInvalid)
		}
	} else {
		// No validation - all domains are valid
		validDomains = make([]string, 0, len(allDomains))
		for domain := range allDomains {
			validDomains = append(validDomains, domain)
		}
		aggregationStats.DomainsValid = len(validDomains)

		// Record that no validation was performed
		if tracker != nil {
			tracker.RecordOverallValidation("none", len(validDomains), 0)
		}
	}

	// Write output
	if err := writeOutput(*outputFile, validDomains); err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}

	// Save stats tracker
	if tracker != nil {
		if err := tracker.Save(); err != nil {
			log.Printf("Warning: Failed to save stats: %v", err)
		} else if !*quiet {
			log.Printf("Stats saved to %s", filepath.Join(*dataDir, stats.StatsFile))
		}
	}

	// Print results
	printResults(aggregationStats, len(validDomains))
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
	domainChan := make(chan string, *workers*2)

	// Check if running in TTY (interactive terminal)
	isTTY := term.IsTerminal(int(os.Stdout.Fd()))

	// Create progress bar or setup simple progress reporting
	var bar *progressbar.ProgressBar
	startTime := time.Now()

	if !*quiet && isTTY {
		// Beautiful progress bar for interactive terminals
		bar = progressbar.NewOptions(total,
			progressbar.OptionSetDescription(color.CyanString("🔍 Validating")),
			progressbar.OptionSetWidth(40),
			progressbar.OptionShowCount(),
			progressbar.OptionShowIts(),
			progressbar.OptionSetItsString("domains/s"),
			progressbar.OptionThrottle(100*time.Millisecond),
			progressbar.OptionShowElapsedTimeOnFinish(),
			progressbar.OptionSetTheme(progressbar.Theme{
				Saucer:        color.GreenString("█"),
				SaucerHead:    color.GreenString("█"),
				SaucerPadding: color.HiBlackString("░"),
				BarStart:      color.HiBlackString("["),
				BarEnd:        color.HiBlackString("]"),
			}),
			progressbar.OptionOnCompletion(func() {
				fmt.Fprintln(os.Stderr)
			}),
		)
	} else if !*quiet {
		// Simple logging for non-TTY (pipes, files, cronjobs)
		log.Printf("Starting validation of %d domains with %d workers...", total, *workers)
	}

	// Start workers first
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			localValid := make([]string, 0, total/(*workers))
			localValidCount := 0
			localInvalidCount := 0

			for domain := range domainChan {
				valid := false
				var err error

				if *enableHTTP {
					valid, err = v.ValidateFull(ctx, domain)
				} else if *enableDNS {
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

				if !*quiet {
					if bar != nil {
						// TTY: Update progress bar
						bar.Add(1)
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

	if bar != nil {
		bar.Finish()
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
	if *quiet {
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
	if *enableDNS || *enableHTTP {
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

	printColorLine(cyan, green, "    File:", *outputFile)
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
		fmt.Println("No stats available yet. Run an aggregation first.")
		return
	}

	// Color definitions
	green := color.New(color.FgGreen, color.Bold)
	red := color.New(color.FgRed, color.Bold)
	cyan := color.New(color.FgCyan, color.Bold)
	magenta := color.New(color.FgMagenta, color.Bold)

	fmt.Println()
	cyan.Println(strings.Repeat("=", 120))
	cyan.Print("📊 ")
	magenta.Print("URL Statistics")
	fmt.Println()
	cyan.Println(strings.Repeat("=", 120))

	// Table header
	fmt.Printf("%-50s | %8s | %8s | %10s | %12s | %20s | %8s\n",
		"URL", "Domains", "Success", "Failed", "Status", "Last Checked", "Size")
	cyan.Println(strings.Repeat("-", 120))

	// Sort URLs for consistent output
	var urls []string
	for url := range tracker.Stats {
		urls = append(urls, url)
	}

	// Display each URL's stats
	for _, url := range urls {
		stat := tracker.Stats[url]

		// Truncate URL if too long
		displayURL := url
		if len(displayURL) > 48 {
			displayURL = displayURL[:45] + "..."
		}

		// Status indicator
		isFiltered := stat.Blacklisted || stat.FailureCount >= stats.MaxFailures
		statusText := "✓ Active"
		if isFiltered {
			statusText = "✗ Filtered"
		}

		// Format last checked time
		lastChecked := "-"
		if !stat.LastChecked.IsZero() {
			lastChecked = formatTimeSince(stat.LastChecked)
		}

		// Human readable size
		humanSize := formatSize(stat.TotalDomains)

		// Print with colors
		fmt.Printf("%-50s | %8d | ", displayURL, stat.TotalDomains)
		green.Printf("%8d", stat.SuccessCount)
		fmt.Print(" | ")
		if stat.FailureCount > 0 {
			red.Printf("%8d", stat.FailureCount)
		} else {
			fmt.Printf("%8d", stat.FailureCount)
		}
		fmt.Print(" | ")
		if isFiltered {
			red.Printf("%12s", statusText)
		} else {
			green.Printf("%12s", statusText)
		}
		fmt.Printf(" | %20s | %8s\n", lastChecked, humanSize)
	}

	cyan.Println(strings.Repeat("=", 120))

	// Summary statistics
	totalURLs := len(tracker.Stats)
	activeURLs := 0
	filteredURLs := 0
	totalSuccess := 0
	totalFailures := 0
	totalDomains := 0

	for _, stat := range tracker.Stats {
		if stat.Blacklisted || stat.FailureCount >= stats.MaxFailures {
			filteredURLs++
		} else {
			activeURLs++
		}
		totalSuccess += stat.SuccessCount
		totalFailures += stat.FailureCount
		if stat.SuccessCount > 0 {
			totalDomains += stat.TotalDomains
		}
	}

	fmt.Println()
	magenta.Println("Summary:")
	fmt.Print("  Total URLs:      ")
	cyan.Println(totalURLs)
	fmt.Print("  Active:          ")
	green.Println(activeURLs)
	fmt.Print("  Filtered:        ")
	if filteredURLs > 0 {
		red.Println(filteredURLs)
	} else {
		fmt.Println(filteredURLs)
	}
	fmt.Print("  Total Successes: ")
	green.Println(totalSuccess)
	fmt.Print("  Total Failures:  ")
	if totalFailures > 0 {
		red.Println(totalFailures)
	} else {
		fmt.Println(totalFailures)
	}
	fmt.Print("  Total Domains:   ")
	magenta.Println(formatSize(totalDomains))
	fmt.Println()
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
