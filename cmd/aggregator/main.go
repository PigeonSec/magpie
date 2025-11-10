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
	}

	// Fetch domains
	stats := &Stats{}
	allDomains := make(map[string]bool)

	f := fetcher.NewFetcher(30*time.Second, 3)
	ctx := context.Background()

	for i, url := range urls {
		if !*quiet {
			log.Printf("[%d/%d] Fetching %s", i+1, len(urls), url)
		}

		domains, err := f.Fetch(ctx, url)
		if err != nil {
			errMsg := fmt.Sprintf("Failed to fetch %s: %v", url, err)
			log.Printf("ERROR: %s", errMsg)
			stats.Errors = append(stats.Errors, errMsg)
			continue
		}

		stats.URLsFetched++

		if !*quiet {
			log.Printf("  Found %d domains", len(domains))
		}

		// Deduplicate
		for _, domain := range domains {
			if allDomains[domain] {
				stats.DuplicatesFound++
			} else {
				allDomains[domain] = true
			}
		}
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
			log.Printf("Validating %d domains with %d workers...", stats.DomainsFound, *workers)
		}

		v := validator.NewValidator()
		validDomains = validateDomains(ctx, v, allDomains, stats)

		if !*quiet {
			log.Printf("Validation complete: %d valid, %d invalid", stats.DomainsValid, stats.DomainsInvalid)
		}
	} else {
		// No validation - all domains are valid
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
	)

	// Create channel
	domainChan := make(chan string, len(domains))
	for domain := range domains {
		domainChan <- domain
	}
	close(domainChan)

	// Start workers
	for i := 0; i < *workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for domain := range domainChan {
				valid := false
				var err error

				if *enableHTTP {
					valid, err = v.ValidateFull(ctx, domain)
				} else if *enableDNS {
					valid, err = v.ValidateDNS(ctx, domain)
				}

				if err == nil && valid {
					validMu.Lock()
					validDomains = append(validDomains, domain)
					stats.DomainsValid++
					validMu.Unlock()
				} else {
					validMu.Lock()
					stats.DomainsInvalid++
					validMu.Unlock()
				}
			}
		}()
	}

	wg.Wait()
	return validDomains
}

func writeOutput(path string, domains []string) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
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
