package fetcher

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Fetcher fetches and parses blocklists from URLs
type Fetcher struct {
	client        *http.Client
	retryAttempts int
}

// NewFetcher creates a new fetcher
func NewFetcher(timeout time.Duration, retryAttempts int) *Fetcher {
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	if retryAttempts == 0 {
		retryAttempts = 3
	}

	return &Fetcher{
		client: &http.Client{
			Timeout: timeout,
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

// Fetch downloads and parses domains from a URL
func (f *Fetcher) Fetch(ctx context.Context, url string) ([]string, error) {
	var lastErr error

	for attempt := 1; attempt <= f.retryAttempts; attempt++ {
		domains, err := f.fetchAttempt(ctx, url)
		if err == nil {
			return domains, nil
		}
		lastErr = err
		if attempt < f.retryAttempts {
			time.Sleep(time.Second * time.Duration(attempt))
		}
	}

	return nil, lastErr
}

func (f *Fetcher) fetchAttempt(ctx context.Context, url string) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("User-Agent", "Kestrel-Aggregator/1.0")

	resp, err := f.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	var domains []string
	scanner := bufio.NewScanner(resp.Body)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		// Parse domain from line
		domain := ParseDomain(line)
		if domain != "" {
			domains = append(domains, domain)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return domains, nil
}

// ParseDomain extracts domain from various blocklist formats
func ParseDomain(line string) string {
	// Remove inline comments
	if idx := strings.Index(line, "#"); idx != -1 {
		line = line[:idx]
	}

	line = strings.TrimSpace(line)

	// Handle hosts file format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
	if strings.HasPrefix(line, "0.0.0.0 ") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	if strings.HasPrefix(line, "127.0.0.1 ") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			return parts[1]
		}
	}

	// Handle generic IP + domain format
	if strings.Contains(line, " ") {
		parts := strings.Fields(line)
		if len(parts) >= 2 {
			// Check if first part looks like an IP
			if strings.Contains(parts[0], ".") && len(strings.Split(parts[0], ".")) == 4 {
				return parts[1]
			}
		}
	}

	// Plain domain format
	domain := strings.TrimSpace(line)

	// Basic validation - must contain a dot and no spaces
	if strings.Contains(domain, ".") && !strings.Contains(domain, " ") {
		// Remove trailing dot if present
		domain = strings.TrimSuffix(domain, ".")
		return domain
	}

	return ""
}
