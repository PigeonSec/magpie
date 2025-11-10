package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pigeonsec/magpie/internal/fetcher"
	"github.com/pigeonsec/magpie/internal/validator"
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
	enableDNS  = flag.Bool("dns", true, "Enable DNS validation (A, AAAA, CNAME)")
	enableHTTP = flag.Bool("http", false, "Enable HTTP validation (in addition to DNS)")
	workers    = flag.Int("workers", 10, "Number of concurrent validation workers")

	// Performance
	fetchWorkers = flag.Int("fetch-workers", 5, "Number of concurrent URL fetchers")
	enableCache  = flag.Bool("cache", true, "Enable DNS result caching")

	// Options
	quiet   = flag.Bool("quiet", false, "Quiet mode - minimal output")
	showVer = flag.Bool("version", false, "Show version information")
)

type Stats struct {
	URLsFetched     int
	DomainsFound    int
	DomainsValid    int
	DomainsInvalid  int
	DuplicatesFound int
	Errors          []string
}

func main() {
	flag.Parse()

	if *showVer {
		fmt.Printf("Magpie version %s\n", version)
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

	// Load URLs
	urls, err := loadURLs(*sourceFile)
	if err != nil {
		log.Fatalf("Failed to load source file: %v", err)
	}

	if !*quiet {
		log.Printf("Loaded %d source URLs", len(urls))
		log.Printf("Using %d parallel fetchers", *fetchWorkers)
	}

	// Fetch domains with parallel workers and streaming
	stats := &Stats{}
	allDomains := make(map[string]bool)
	domainChan := make(chan string, 10000) // Buffered channel for streaming
	errorChan := make(chan error, len(urls))

	f := fetcher.NewFetcher(30*time.Second, 3)
	ctx := context.Background()

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
					errMsg := fmt.Errorf("failed to fetch %s: %w", url, err)
					errorChan <- errMsg
					continue
				}

				stats.URLsFetched++

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
				stats.DuplicatesFound++
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
		stats.Errors = append(stats.Errors, err.Error())
	}

	stats.DomainsFound = len(allDomains)

	if !*quiet {
		log.Printf("Found %d unique domains (removed %d duplicates)", stats.DomainsFound, stats.DuplicatesFound)
	}

	if stats.DomainsFound == 0 {
		log.Fatalf("No domains found from any source")
	}

	// Validate domains
	validDomains := []string{}

	if *enableDNS || *enableHTTP {
		if !*quiet {
			log.Printf("Validating %d domains with %d workers (caching: %v)...", stats.DomainsFound, *workers, *enableCache)
		}

		v := validator.NewValidator(*enableCache)
		validDomains = validateDomains(ctx, v, allDomains, stats)

		if !*quiet {
			log.Printf("Validation complete: %d valid, %d invalid", stats.DomainsValid, stats.DomainsInvalid)
		}
	} else {
		// No validation - all domains are valid
		validDomains = make([]string, 0, len(allDomains))
		for domain := range allDomains {
			validDomains = append(validDomains, domain)
		}
		stats.DomainsValid = len(validDomains)
	}

	// Write output
	if err := writeOutput(*outputFile, validDomains); err != nil {
		log.Fatalf("Failed to write output: %v", err)
	}

	// Print results
	printResults(stats, len(validDomains))
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

func validateDomains(ctx context.Context, v *validator.Validator, domains map[string]bool, stats *Stats) []string {
	var (
		wg           sync.WaitGroup
		validMu      sync.Mutex
		validDomains []string
		processed    int
		total        = len(domains)
	)

	// Pre-allocate with estimated capacity (assume ~80% valid)
	validDomains = make([]string, 0, total*4/5)

	// Create buffered channel for better throughput
	domainChan := make(chan string, *workers*2)

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
				} else {
					localInvalidCount++
				}

				// Progress reporting (every 1000 domains)
				if !*quiet && (localValidCount+localInvalidCount)%1000 == 0 {
					validMu.Lock()
					processed += 1000
					pct := float64(processed) / float64(total) * 100
					log.Printf("Progress: %d/%d (%.1f%%) - %d valid, %d invalid",
						processed, total, pct, stats.DomainsValid+localValidCount, stats.DomainsInvalid+localInvalidCount)
					validMu.Unlock()
				}
			}

			// Merge local results
			validMu.Lock()
			validDomains = append(validDomains, localValid...)
			stats.DomainsValid += localValidCount
			stats.DomainsInvalid += localInvalidCount
			validMu.Unlock()
		}(i)
	}

	// Feed domains to workers
	for domain := range domains {
		domainChan <- domain
	}
	close(domainChan)

	wg.Wait()
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

func printResults(stats *Stats, validCount int) {
	if *quiet {
		return
	}

	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("Aggregation Complete!")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("URLs fetched:        %d\n", stats.URLsFetched)
	fmt.Printf("Domains found:       %d\n", stats.DomainsFound)
	fmt.Printf("Duplicates removed:  %d\n", stats.DuplicatesFound)

	if *enableDNS || *enableHTTP {
		fmt.Printf("Domains validated:   %d valid, %d invalid\n", stats.DomainsValid, stats.DomainsInvalid)
	} else {
		fmt.Printf("Validation:          disabled\n")
	}

	fmt.Printf("Output file:         %s\n", *outputFile)
	fmt.Printf("Total domains:       %d\n", validCount)

	if len(stats.Errors) > 0 {
		fmt.Printf("\nErrors encountered:  %d\n", len(stats.Errors))
		for i, errMsg := range stats.Errors {
			if i < 5 {
				fmt.Printf("  - %s\n", errMsg)
			}
		}
		if len(stats.Errors) > 5 {
			fmt.Printf("  ... and %d more errors\n", len(stats.Errors)-5)
		}
	}

	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("")
}
