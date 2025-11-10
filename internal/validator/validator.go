package validator

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

// dnsResult caches DNS lookup results
type dnsResult struct {
	valid     bool
	timestamp time.Time
}

// Validator validates domains via DNS and HTTP
type Validator struct {
	resolvers  []*net.Resolver
	httpClient *http.Client
	cache      map[string]*dnsResult
	cacheMu    sync.RWMutex
	cacheTTL   time.Duration
	useCache   bool
	nextResolver uint32  // atomic counter for round-robin
}

// NewValidator creates a new validator with system DNS resolver and optional caching
func NewValidator(enableCache bool) *Validator {
	// Use system DNS resolver by default
	return NewValidatorWithResolvers(enableCache, []string{})
}

// NewValidatorWithResolvers creates a new validator with custom DNS resolvers
func NewValidatorWithResolvers(enableCache bool, dnsServers []string) *Validator {
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

	// Create multiple resolvers (one per DNS server)
	var resolvers []*net.Resolver

	if len(dnsServers) == 0 {
		// Use system DNS resolver
		resolvers = []*net.Resolver{
			{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout:   3 * time.Second,
						KeepAlive: 30 * time.Second,
					}
					return d.DialContext(ctx, network, address)
				},
			},
		}
	} else {
		// Create a resolver for each DNS server
		for _, server := range dnsServers {
			if server == "" {
				continue
			}
			serverAddr := server
			resolvers = append(resolvers, &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
					d := net.Dialer{
						Timeout:   3 * time.Second,
						KeepAlive: 30 * time.Second,
					}
					// Use the custom DNS server
					return d.DialContext(ctx, "udp", serverAddr)
				},
			})
		}
	}

	return &Validator{
		resolvers: resolvers,
		httpClient: &http.Client{
			Timeout:   8 * time.Second,
			Transport: transport,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 5 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
		cache:    make(map[string]*dnsResult, 100000),
		cacheTTL: 5 * time.Minute,
		useCache: enableCache,
		nextResolver: 0,
	}
}

// getResolver returns a resolver using round-robin selection
func (v *Validator) getResolver() *net.Resolver {
	if len(v.resolvers) == 1 {
		return v.resolvers[0]
	}
	idx := atomic.AddUint32(&v.nextResolver, 1) % uint32(len(v.resolvers))
	return v.resolvers[idx]
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

	// Get a resolver in round-robin fashion
	resolver := v.getResolver()

	// Parallel DNS lookup with early exit - check all record types simultaneously
	// This is MUCH faster than sequential lookups (0.5s vs 3s for invalid domains)
	lookupCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
	defer cancel()

	type lookupResult struct {
		valid bool
		err   error
	}

	results := make(chan lookupResult, 3)

	// Check A record (IPv4) in parallel
	go func() {
		ips, err := resolver.LookupIP(lookupCtx, "ip4", domain)
		results <- lookupResult{valid: err == nil && len(ips) > 0, err: err}
	}()

	// Check AAAA record (IPv6) in parallel
	go func() {
		ips, err := resolver.LookupIP(lookupCtx, "ip6", domain)
		results <- lookupResult{valid: err == nil && len(ips) > 0, err: err}
	}()

	// Check CNAME record in parallel
	go func() {
		cname, err := resolver.LookupCNAME(lookupCtx, domain)
		valid := err == nil && cname != "" && cname != domain && cname != domain+"."
		results <- lookupResult{valid: valid, err: err}
	}()

	// Wait for results - early exit on first success
	valid := false
	for i := 0; i < 3; i++ {
		result := <-results
		if result.valid {
			valid = true
			break // Early exit - no need to wait for other lookups
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

	// Helper to properly drain and close response body
	drainAndClose := func(resp *http.Response) {
		if resp != nil && resp.Body != nil {
			// Drain up to 512 bytes to allow connection reuse
			io.CopyN(io.Discard, resp.Body, 512)
			resp.Body.Close()
		}
	}

	// Try HTTPS
	go func() {
		req, err := http.NewRequestWithContext(httpCtx, "HEAD", "https://"+domain, nil)
		if err != nil {
			results <- httpResult{valid: false, err: err}
			return
		}
		req.Header.Set("User-Agent", "Magpie/1.0")
		req.Close = true // Close connection after request to avoid connection pool issues

		resp, err := v.httpClient.Do(req)
		if err == nil {
			valid := resp.StatusCode < 500
			drainAndClose(resp)
			results <- httpResult{valid: valid, err: nil}
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
		req.Close = true // Close connection after request to avoid connection pool issues

		resp, err := v.httpClient.Do(req)
		if err == nil {
			valid := resp.StatusCode < 500
			drainAndClose(resp)
			results <- httpResult{valid: valid, err: nil}
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
