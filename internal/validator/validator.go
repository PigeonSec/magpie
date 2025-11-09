package validator

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Validator validates domains via DNS and HTTP
type Validator struct {
	resolver   *net.Resolver
	httpClient *http.Client
}

// NewValidator creates a new validator
func NewValidator() *Validator {
	return &Validator{
		resolver: &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 5 * time.Second}
				return d.DialContext(ctx, network, address)
			},
		},
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

// ValidateDNS checks if domain has A, AAAA, or CNAME records
func (v *Validator) ValidateDNS(ctx context.Context, domain string) (bool, error) {
	// Check A records
	ips, err := v.resolver.LookupIP(ctx, "ip4", domain)
	if err == nil && len(ips) > 0 {
		return true, nil
	}

	// Check AAAA records
	ips, err = v.resolver.LookupIP(ctx, "ip6", domain)
	if err == nil && len(ips) > 0 {
		return true, nil
	}

	// Check CNAME records
	cname, err := v.resolver.LookupCNAME(ctx, domain)
	if err == nil && cname != "" && cname != domain+"." {
		return true, nil
	}

	return false, nil
}

// ValidateHTTP checks if domain is reachable via HTTP/HTTPS
func (v *Validator) ValidateHTTP(ctx context.Context, domain string) (bool, error) {
	// Try HTTPS first
	req, err := http.NewRequestWithContext(ctx, "HEAD", "https://"+domain, nil)
	if err != nil {
		return false, err
	}

	resp, err := v.httpClient.Do(req)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode < 500 {
			return true, nil
		}
	}

	// Try HTTP as fallback
	req, err = http.NewRequestWithContext(ctx, "HEAD", "http://"+domain, nil)
	if err != nil {
		return false, err
	}

	resp, err = v.httpClient.Do(req)
	if err != nil {
		return false, nil
	}
	resp.Body.Close()

	return resp.StatusCode < 500, nil
}

// ValidateFull performs both DNS and HTTP validation
func (v *Validator) ValidateFull(ctx context.Context, domain string) (bool, error) {
	// DNS must pass
	dnsValid, err := v.ValidateDNS(ctx, domain)
	if err != nil || !dnsValid {
		return false, err
	}

	// HTTP should pass (but we don't fail on HTTP errors)
	httpValid, _ := v.ValidateHTTP(ctx, domain)
	return httpValid, nil
}
