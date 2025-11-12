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
	ValidationMethod string    `json:"validation_method,omitempty"` // "none", "dns", "http", "dns+http"
	LastChecked      time.Time `json:"last_checked"`
}

// GlobalStats tracks aggregate statistics from the last run
type GlobalStats struct {
	LastRun            time.Time `json:"last_run"`
	TotalURLsFetched   int       `json:"total_urls_fetched"`    // URLs successfully fetched
	TotalURLsFailed    int       `json:"total_urls_failed"`     // URLs that failed
	TotalDomainsRaw    int       `json:"total_domains_raw"`     // Total domains downloaded (with duplicates)
	TotalDomainsUnique int       `json:"total_domains_unique"`  // Unique domains after deduplication
	DuplicatesRemoved  int       `json:"duplicates_removed"`    // Domains removed as duplicates
	ValidDomains       int       `json:"valid_domains"`         // Domains that passed validation
	InvalidDomains     int       `json:"invalid_domains"`       // Domains that failed validation
	ValidationMethod   string    `json:"validation_method"`     // "none", "dns", "http", "dns+http"
}

// StatsData represents the complete stats file structure
type StatsData struct {
	Sources map[string]*URLStats `json:"sources"`
	Global  *GlobalStats         `json:"global,omitempty"`
}

// Tracker manages URL statistics
type Tracker struct {
	DataDir      string
	Stats        map[string]*URLStats
	GlobalStats  *GlobalStats
	mu           sync.RWMutex
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

	// Try new format first
	var statsData StatsData
	if err := json.Unmarshal(data, &statsData); err == nil && statsData.Sources != nil {
		// New format
		t.Stats = statsData.Sources
		t.GlobalStats = statsData.Global
		return nil
	}

	// Fall back to old format (map[string]*URLStats)
	var stats map[string]*URLStats
	if err := json.Unmarshal(data, &stats); err != nil {
		return err
	}

	t.Stats = stats
	t.GlobalStats = nil // No global stats in old format
	return nil
}

// Save writes stats to disk
func (t *Tracker) Save() error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	statsPath := filepath.Join(t.DataDir, StatsFile)

	// Use new format with sources and global stats
	statsData := StatsData{
		Sources: t.Stats,
		Global:  t.GlobalStats,
	}

	data, err := json.MarshalIndent(statsData, "", "  ")
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
func (t *Tracker) RecordSuccess(url string) {
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

// RecordValidation updates validation method for a URL
func (t *Tracker) RecordValidation(url string, method string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	stat, ok := t.Stats[url]
	if !ok {
		stat = &URLStats{URL: url}
		t.Stats[url] = stat
	}

	stat.ValidationMethod = method
}

// RecordGlobalStats updates the global statistics from the last run
func (t *Tracker) RecordGlobalStats(urlsFetched, urlsFailed, domainsRaw, domainsUnique, duplicates, valid, invalid int, method string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.GlobalStats = &GlobalStats{
		LastRun:            time.Now(),
		TotalURLsFetched:   urlsFetched,
		TotalURLsFailed:    urlsFailed,
		TotalDomainsRaw:    domainsRaw,
		TotalDomainsUnique: domainsUnique,
		DuplicatesRemoved:  duplicates,
		ValidDomains:       valid,
		InvalidDomains:     invalid,
		ValidationMethod:   method,
	}

	// Update validation method for all successfully fetched URLs
	for _, stat := range t.Stats {
		if stat.SuccessCount > 0 && stat.LastSuccess.After(time.Now().Add(-24*time.Hour)) {
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
