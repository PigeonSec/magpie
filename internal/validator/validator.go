package validator

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

// dnsResult caches DNS lookup results
type dnsResult struct {
	valid     bool
	timestamp time.Time
}

// Validator validates domains via DNS and HTTP
type Validator struct {
	resolver   *net.Resolver
	httpClient *http.Client
	cache      map[string]*dnsResult
	cacheMu    sync.RWMutex
	cacheTTL   time.Duration
	useCache   bool
}

// NewValidator creates a new validator with optional caching
func NewValidator(enableCache bool) *Validator {
	// Optimize HTTP transport for high concurrency
	transport := &http.Transport{
		MaxIdleConns:        1000,              // Increased from default 100
		MaxIdleConnsPerHost: 100,               // Increased from default 2
		MaxConnsPerHost:     100,               // Limit connections per host
		IdleConnTimeout:     90 * time.Second,  // Keep connections alive longer
		TLSHandshakeTimeout: 5 * time.Second,   // Faster TLS timeout
		DisableCompression:  true,              // We don't need compression for HEAD requests
		DisableKeepAlives:   false,             // Keep connections alive
		ForceAttemptHTTP2:   true,              // Use HTTP/2 when possible
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,           // Skip cert validation for blocklists
			MinVersion:         tls.VersionTLS12,
		},
		// DNS cache settings
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}

	return &Validator{
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{
					Timeout:   3 * time.Second,    // Reduced from 5s
					KeepAlive: 30 * time.Second,
				}
				return d.DialContext(ctx, network, address)
			},
		},
		httpClient: &http.Client{
			Timeout:   8 * time.Second,            // Reduced from 10s
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {                 // Reduced from 10
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		cache:    make(map[string]*dnsResult, 100000),  // Pre-allocate for 100k domains
		cacheTTL: 5 * time.Minute,
		useCache: enableCache,
	}
}

// ValidateDNS checks if domain has A, AAAA, or CNAME records (with caching and parallel lookups)
func (v *Validator) ValidateDNS(ctx context.Context, domain string) (bool, error) {
	// Check cache first
	if v.useCache {
		v.cacheMu.RLock()
		if cached, ok := v.cache[domain]; ok {
			// Check if cache entry is still valid
			if time.Since(cached.timestamp) < v.cacheTTL {
				v.cacheMu.RUnlock()
				return cached.valid, nil
			}
		}
		v.cacheMu.RUnlock()
	}

	// Perform parallel DNS lookups for A, AAAA, and CNAME
	type lookupResult struct {
		hasRecord bool
		err       error
	}

	results := make(chan lookupResult, 3)
	lookupCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	// Check A records (IPv4)
	go func() {
		ips, err := v.resolver.LookupIP(lookupCtx, "ip4", domain)
		results <- lookupResult{hasRecord: err == nil && len(ips) > 0, err: err}
	}()

	// Check AAAA records (IPv6)
	go func() {
		ips, err := v.resolver.LookupIP(lookupCtx, "ip6", domain)
		results <- lookupResult{hasRecord: err == nil && len(ips) > 0, err: err}
	}()

	// Check CNAME records
	go func() {
		cname, err := v.resolver.LookupCNAME(lookupCtx, domain)
		hasRecord := err == nil && cname != "" && cname != domain && cname != domain+"."
		results <- lookupResult{hasRecord: hasRecord, err: err}
	}()

	// Wait for any successful result
	valid := false
	for i := 0; i < 3; i++ {
		result := <-results
		if result.hasRecord {
			valid = true
			break // Exit early on first success
		}
	}

	// Cache the result
	if v.useCache {
		v.cacheMu.Lock()
		v.cache[domain] = &dnsResult{
			valid:     valid,
			timestamp: time.Now(),
		}
		v.cacheMu.Unlock()
	}

	return valid, nil
}

// ValidateHTTP checks if domain is reachable via HTTP/HTTPS (tries both in parallel)
func (v *Validator) ValidateHTTP(ctx context.Context, domain string) (bool, error) {
	type httpResult struct {
		valid bool
		err   error
	}

	results := make(chan httpResult, 2)
	httpCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	// Try HTTPS
	go func() {
		req, err := http.NewRequestWithContext(httpCtx, "HEAD", "https://"+domain, nil)
		if err != nil {
			results <- httpResult{valid: false, err: err}
			return
		}
		req.Header.Set("User-Agent", "Magpie/1.0")

		resp, err := v.httpClient.Do(req)
		if err == nil {
			resp.Body.Close()
			results <- httpResult{valid: resp.StatusCode < 500, err: nil}
		} else {
			results <- httpResult{valid: false, err: err}
		}
	}()

	// Try HTTP
	go func() {
		req, err := http.NewRequestWithContext(httpCtx, "HEAD", "http://"+domain, nil)
		if err != nil {
			results <- httpResult{valid: false, err: err}
			return
		}
		req.Header.Set("User-Agent", "Magpie/1.0")

		resp, err := v.httpClient.Do(req)
		if err == nil {
			resp.Body.Close()
			results <- httpResult{valid: resp.StatusCode < 500, err: nil}
		} else {
			results <- httpResult{valid: false, err: err}
		}
	}()

	// Return true if either succeeds
	for i := 0; i < 2; i++ {
		result := <-results
		if result.valid {
			return true, nil
		}
	}

	return false, nil
}

// ValidateFull performs both DNS and HTTP validation
func (v *Validator) ValidateFull(ctx context.Context, domain string) (bool, error) {
	// DNS must pass first (it's faster)
	dnsValid, err := v.ValidateDNS(ctx, domain)
	if err != nil || !dnsValid {
		return false, err
	}

	// HTTP validation (parallel HTTP/HTTPS)
	httpValid, _ := v.ValidateHTTP(ctx, domain)
	return httpValid, nil
}
