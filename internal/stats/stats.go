package stats

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const (
	// MaxFailures before a URL is filtered out
	MaxFailures = 3
	// StatsFile name
	StatsFile = "stats.json"
)

// URLStats tracks statistics for a single URL
type URLStats struct {
	URL              string    `json:"url"`
	SuccessCount     int       `json:"success_count"`
	FailureCount     int       `json:"failure_count"`
	LastSuccess      time.Time `json:"last_success,omitempty"`
	LastFailure      time.Time `json:"last_failure,omitempty"`
	LastError        string    `json:"last_error,omitempty"`
	Blacklisted      bool      `json:"blacklisted"`
	BlacklistedAt    time.Time `json:"blacklisted_at,omitempty"`
	TotalDomains     int       `json:"total_domains"`       // Total domains fetched
	ValidDomains     int       `json:"valid_domains"`       // Domains that passed validation
	InvalidDomains   int       `json:"invalid_domains"`     // Domains that failed validation
	FilteredDomains  int       `json:"filtered_domains"`    // Domains removed (invalid)
	ValidationMethod string    `json:"validation_method"`   // "none", "dns", "http", "dns+http"
	LastChecked      time.Time `json:"last_checked"`
}

// Tracker manages URL statistics
type Tracker struct {
	DataDir string
	Stats   map[string]*URLStats
	mu      sync.RWMutex
}

// NewTracker creates a new stats tracker
func NewTracker(dataDir string) (*Tracker, error) {
	// Create data directory if it doesn't exist
	if err := os.MkdirAll(dataDir, 0755); err != nil {
		return nil, err
	}

	t := &Tracker{
		DataDir: dataDir,
		Stats:   make(map[string]*URLStats),
	}

	// Load existing stats
	if err := t.Load(); err != nil {
		// If file doesn't exist, that's okay - start fresh
		if !os.IsNotExist(err) {
			return nil, err
		}
	}

	return t, nil
}

// Load reads stats from disk
func (t *Tracker) Load() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	statsPath := filepath.Join(t.DataDir, StatsFile)
	data, err := os.ReadFile(statsPath)
	if err != nil {
		return err
	}

	var stats map[string]*URLStats
	if err := json.Unmarshal(data, &stats); err != nil {
		return err
	}

	t.Stats = stats
	return nil
}

// Save writes stats to disk
func (t *Tracker) Save() error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	statsPath := filepath.Join(t.DataDir, StatsFile)
	data, err := json.MarshalIndent(t.Stats, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(statsPath, data, 0644)
}

// IsBlacklisted checks if a URL should be filtered out
func (t *Tracker) IsBlacklisted(url string) bool {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if stat, ok := t.Stats[url]; ok {
		return stat.Blacklisted || stat.FailureCount >= MaxFailures
	}
	return false
}

// RecordSuccess updates stats for a successful fetch
func (t *Tracker) RecordSuccess(url string, domainCount int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	stat, ok := t.Stats[url]
	if !ok {
		stat = &URLStats{URL: url}
		t.Stats[url] = stat
	}

	stat.SuccessCount++
	stat.LastSuccess = time.Now()
	stat.LastChecked = time.Now()
	stat.TotalDomains = domainCount
	stat.LastError = ""

	// Reset blacklist if it was previously blacklisted but now works
	if stat.Blacklisted {
		stat.Blacklisted = false
		stat.BlacklistedAt = time.Time{}
		stat.FailureCount = 0 // Reset failures on recovery
	}
}

// RecordFailure updates stats for a failed fetch
func (t *Tracker) RecordFailure(url string, errorMsg string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	stat, ok := t.Stats[url]
	if !ok {
		stat = &URLStats{URL: url}
		t.Stats[url] = stat
	}

	stat.FailureCount++
	stat.LastFailure = time.Now()
	stat.LastChecked = time.Now()
	stat.LastError = errorMsg

	// Blacklist if failure count reaches threshold
	if stat.FailureCount >= MaxFailures && !stat.Blacklisted {
		stat.Blacklisted = true
		stat.BlacklistedAt = time.Now()
	}
}

// RecordValidation updates validation statistics for a URL
func (t *Tracker) RecordValidation(url string, validCount, invalidCount int, method string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	stat, ok := t.Stats[url]
	if !ok {
		stat = &URLStats{URL: url}
		t.Stats[url] = stat
	}

	stat.ValidDomains = validCount
	stat.InvalidDomains = invalidCount
	stat.FilteredDomains = invalidCount // Domains removed due to validation failure
	stat.ValidationMethod = method
}

// RecordOverallValidation updates validation method for all successfully fetched URLs
func (t *Tracker) RecordOverallValidation(method string, totalValid, totalInvalid int) {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Calculate proportional stats for each URL based on their domain count
	totalDomains := 0
	for _, stat := range t.Stats {
		if stat.SuccessCount > 0 {
			totalDomains += stat.TotalDomains
		}
	}

	if totalDomains == 0 {
		return
	}

	// Distribute validation results proportionally
	for _, stat := range t.Stats {
		if stat.SuccessCount > 0 {
			proportion := float64(stat.TotalDomains) / float64(totalDomains)
			stat.ValidDomains = int(float64(totalValid) * proportion)
			stat.InvalidDomains = int(float64(totalInvalid) * proportion)
			stat.FilteredDomains = stat.InvalidDomains
			stat.ValidationMethod = method
		}
	}
}

// GetBlacklistedURLs returns all blacklisted URLs
func (t *Tracker) GetBlacklistedURLs() []string {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var blacklisted []string
	for url, stat := range t.Stats {
		if stat.Blacklisted || stat.FailureCount >= MaxFailures {
			blacklisted = append(blacklisted, url)
		}
	}
	return blacklisted
}

// GetStats returns a copy of stats for a URL
func (t *Tracker) GetStats(url string) *URLStats {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if stat, ok := t.Stats[url]; ok {
		// Return a copy
		statCopy := *stat
		return &statCopy
	}
	return nil
}

// FilterURLs removes blacklisted URLs from the list
func (t *Tracker) FilterURLs(urls []string) ([]string, []string) {
	var active []string
	var filtered []string

	for _, url := range urls {
		if t.IsBlacklisted(url) {
			filtered = append(filtered, url)
		} else {
			active = append(active, url)
		}
	}

	return active, filtered
}

// ResetURL removes blacklist status for a URL (manual intervention)
func (t *Tracker) ResetURL(url string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if stat, ok := t.Stats[url]; ok {
		stat.Blacklisted = false
		stat.BlacklistedAt = time.Time{}
		stat.FailureCount = 0
	}
}
