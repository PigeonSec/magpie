package fetcher

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	// Domain validation constants
	maxDomainLength = 253 // RFC 1035
	maxLabelLength  = 63  // RFC 1035
	minDomainLength = 3   // e.g., "a.b"

	// Scanner buffer size for large files
	maxScannerBuffer = 1024 * 1024 // 1MB
)

// Domain validation regex - matches valid domain names
var domainRegex = regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)

// Fetcher fetches and parses blocklists from URLs
type Fetcher struct {
	client        *http.Client
	retryAttempts int
}

// NewFetcher creates a new fetcher with optimized connection pooling
func NewFetcher(timeout time.Duration, retryAttempts int) *Fetcher {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if retryAttempts == 0 {
		retryAttempts = 3
	}

	// Optimize HTTP transport for fetching large blocklists
	transport := &http.Transport{
		MaxIdleConns:          500,                // High concurrent fetches
		MaxIdleConnsPerHost:   50,                 // Multiple connections per host
		MaxConnsPerHost:       50,                 // Limit per host
		IdleConnTimeout:       90 * time.Second,   // Keep alive longer
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,   // Wait for headers
		DisableCompression:    false,              // Enable compression for large files
		DisableKeepAlives:     false,              // Reuse connections
		ForceAttemptHTTP2:     true,               // HTTP/2 for better performance
		// Optimize read buffer
		ReadBufferSize:  64 * 1024,                // 64KB read buffer
		WriteBufferSize: 64 * 1024,                // 64KB write buffer
	}

	return &Fetcher{
		client: &http.Client{
			Timeout:   timeout,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		retryAttempts: retryAttempts,
	}
}

// Fetch downloads and parses domains from a URL with exponential backoff
func (f *Fetcher) Fetch(ctx context.Context, url string) ([]string, error) {
	var lastErr error

	for attempt := 1; attempt <= f.retryAttempts; attempt++ {
		domains, err := f.fetchAttempt(ctx, url)
		if err == nil {
			return domains, nil
		}

		lastErr = err

		// Don't sleep on last attempt
		if attempt < f.retryAttempts {
			// Exponential backoff: 1s, 2s, 4s, 8s, etc.
			backoff := time.Duration(1<<uint(attempt-1)) * time.Second

			// Add jitter (0-50% of backoff time)
			jitter := time.Duration(rand.Int63n(int64(backoff / 2)))
			sleepTime := backoff + jitter

			// Cap at 30 seconds
			if sleepTime > 30*time.Second {
				sleepTime = 30 * time.Second
			}

			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(sleepTime):
				// Continue to next attempt
			}
		}
	}

	return nil, fmt.Errorf("failed after %d attempts: %w", f.retryAttempts, lastErr)
}

func (f *Fetcher) fetchAttempt(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("User-Agent", "Magpie/1.0")
	req.Header.Set("Accept", "text/plain, */*")
	req.Header.Set("Accept-Encoding", "gzip, deflate")  // Enable compression

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch URL: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, http.StatusText(resp.StatusCode))
	}

	// Use map for deduplication during parsing
	// Pre-allocate for typical blocklist sizes (10k-100k domains)
	domainMap := make(map[string]bool, 50000)
	scanner := bufio.NewScanner(resp.Body)

	// Increase buffer size for large lines
	buf := make([]byte, maxScannerBuffer)
	scanner.Buffer(buf, maxScannerBuffer)

	lineNum := 0
	for scanner.Scan() {
		lineNum++

		// Check context cancellation periodically
		if lineNum%1000 == 0 {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			default:
			}
		}

		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") || strings.HasPrefix(line, ";") {
			continue
		}

		// Parse domain from line
		domain := ParseDomain(line)
		if domain != "" && IsValidDomain(domain) {
			domainMap[domain] = true
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading response (line %d): %w", lineNum, err)
	}

	// Convert map to slice
	domains := make([]string, 0, len(domainMap))
	for domain := range domainMap {
		domains = append(domains, domain)
	}

	return domains, nil
}

// ParseDomain extracts domain from various blocklist formats
func ParseDomain(line string) string {
	// Remove inline comments
	if idx := strings.Index(line, "#"); idx != -1 {
		line = line[:idx]
	}
	if idx := strings.Index(line, ";"); idx != -1 {
		line = line[:idx]
	}

	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}

	// Handle AdBlock/uBlock format: ||domain.com^ or ||domain.com^$third-party
	if strings.HasPrefix(line, "||") {
		line = strings.TrimPrefix(line, "||")
		if idx := strings.Index(line, "^"); idx != -1 {
			line = line[:idx]
		}
		return cleanDomain(line)
	}

	// Handle AdBlock exceptions: @@||domain.com^
	if strings.HasPrefix(line, "@@||") {
		return "" // Skip exceptions
	}

	// Handle IPv4 hosts file format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
	if strings.HasPrefix(line, "0.0.0.0 ") || strings.HasPrefix(line, "127.0.0.1 ") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			return cleanDomain(parts[1])
		}
	}

	// Handle IPv6 hosts file format: "::1 domain.com" or ":: domain.com"
	if strings.HasPrefix(line, "::") || strings.HasPrefix(line, "::1") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			return cleanDomain(parts[1])
		}
	}

	// Handle generic IP + domain format (IPv4 or IPv6)
	if strings.Contains(line, " ") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			firstPart := parts[0]
			// Check if first part looks like an IPv4 address
			if strings.Count(firstPart, ".") == 3 {
				return cleanDomain(parts[1])
			}
			// Check if first part looks like an IPv6 address
			if strings.Contains(firstPart, ":") {
				return cleanDomain(parts[1])
			}
		}
	}

	// Handle URL format: extract domain from URL
	if strings.HasPrefix(line, "http://") || strings.HasPrefix(line, "https://") {
		if parsed, err := url.Parse(line); err == nil && parsed.Host != "" {
			// Remove port if present
			host := parsed.Host
			if idx := strings.Index(host, ":"); idx != -1 {
				host = host[:idx]
			}
			return cleanDomain(host)
		}
	}

	// Plain domain format
	return cleanDomain(line)
}

// cleanDomain cleans and normalizes a domain string
func cleanDomain(domain string) string {
	domain = strings.TrimSpace(domain)
	domain = strings.ToLower(domain)

	// Remove protocol prefixes if present
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")

	// Remove trailing dot (FQDN format)
	domain = strings.TrimSuffix(domain, ".")

	// Remove path and query string if present
	if idx := strings.Index(domain, "/"); idx != -1 {
		domain = domain[:idx]
	}
	if idx := strings.Index(domain, "?"); idx != -1 {
		domain = domain[:idx]
	}

	// Remove port if present
	if idx := strings.Index(domain, ":"); idx != -1 {
		domain = domain[:idx]
	}

	// Handle wildcard domains - remove leading *. or *.
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimPrefix(domain, ".")

	domain = strings.TrimSpace(domain)

	// Must contain at least one dot and be non-empty
	if domain == "" || !strings.Contains(domain, ".") {
		return ""
	}

	return domain
}

// IsValidDomain validates a domain name according to RFC standards
func IsValidDomain(domain string) bool {
	if domain == "" {
		return false
	}

	// Check length constraints
	if len(domain) < minDomainLength || len(domain) > maxDomainLength {
		return false
	}

	// Domain must contain at least one dot
	if !strings.Contains(domain, ".") {
		return false
	}

	// Check for invalid characters
	if strings.Contains(domain, " ") || strings.Contains(domain, "\t") {
		return false
	}

	// Domain cannot start or end with a hyphen or dot
	if strings.HasPrefix(domain, "-") || strings.HasSuffix(domain, "-") ||
		strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}

	// Validate each label
	labels := strings.Split(domain, ".")
	if len(labels) < 2 {
		return false
	}

	for _, label := range labels {
		if len(label) == 0 || len(label) > maxLabelLength {
			return false
		}

		// Label cannot start or end with hyphen
		if strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return false
		}

		// Check for valid characters in label
		for _, char := range label {
			if !((char >= 'a' && char <= 'z') ||
				(char >= 'A' && char <= 'Z') ||
				(char >= '0' && char <= '9') ||
				char == '-') {
				return false
			}
		}
	}

	// TLD validation - last label should be at least 2 characters and alphabetic
	tld := labels[len(labels)-1]
	if len(tld) < 2 {
		return false
	}

	// Use regex for final validation
	return domainRegex.MatchString(domain)
}
