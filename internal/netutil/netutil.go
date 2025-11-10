package netutil

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"
)

const (
	// MaxRetries for connection checks
	MaxRetries = 5
	// RetryDelay between connection attempts
	RetryDelay = 5 * time.Second
)

// CheckInternetConnection verifies internet connectivity by checking DNS resolution
func CheckInternetConnection(ctx context.Context) error {
	// Test multiple DNS servers to ensure we're not blocked by one
	testHosts := []string{
		"1.1.1.1:53",     // Cloudflare
		"8.8.8.8:53",     // Google
		"9.9.9.9:53",     // Quad9
	}

	for _, host := range testHosts {
		conn, err := net.DialTimeout("udp", host, 3*time.Second)
		if err == nil {
			conn.Close()
			return nil
		}
	}

	return fmt.Errorf("no internet connection detected")
}

// WaitForConnection waits for internet connection to be restored
func WaitForConnection(ctx context.Context, quiet bool) error {
	if !quiet {
		log.Printf("⚠️  Internet connection lost. Waiting for connection to be restored...")
	}

	for attempt := 1; attempt <= MaxRetries; attempt++ {
		if !quiet {
			log.Printf("Checking connection... (attempt %d/%d)", attempt, MaxRetries)
		}

		if err := CheckInternetConnection(ctx); err == nil {
			if !quiet {
				log.Printf("✓ Internet connection restored!")
			}
			return nil
		}

		if attempt < MaxRetries {
			if !quiet {
				log.Printf("Connection still down. Retrying in %v...", RetryDelay)
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(RetryDelay):
				// Continue to next attempt
			}
		}
	}

	return fmt.Errorf("failed to restore internet connection after %d attempts", MaxRetries)
}

// CheckConnectionWithRetry checks connection and waits if it fails
func CheckConnectionWithRetry(ctx context.Context, quiet bool) error {
	if err := CheckInternetConnection(ctx); err != nil {
		return WaitForConnection(ctx, quiet)
	}
	return nil
}
