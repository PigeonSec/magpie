package ui

import (
	"fmt"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	"github.com/charmbracelet/bubbles/spinner"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type Stage int

const (
	StageInit Stage = iota
	StageCheckingConnection
	StageLoadingSources
	StageFetching
	StageValidating
	StageDone
)

type AppModel struct {
	stage            Stage
	spinner          spinner.Model
	progress         progress.Model
	width            int
	height           int

	// Connection check
	connectionChecked bool

	// Source loading
	sourceFile    string
	totalURLs     int
	activeURLs    int
	filteredURLs  int

	// Fetching
	fetchWorkers      int
	currentFetchURL   string
	fetchedURLs       int
	totalFetchURLs    int
	domainsFound      int
	duplicatesRemoved int
	fetchComplete     bool
	fetchErrors       []string

	// Validation
	validationTotal   int
	validationCurrent int
	validationValid   int
	validationInvalid int
	validationWorkers int
	validationStart   time.Time
	validationDone    bool

	// Results
	outputFile string
	done       bool
}

// Messages
type ConnectionCheckedMsg struct{}
type SourcesLoadedMsg struct {
	SourceFile   string
	TotalURLs    int
	ActiveURLs   int
	FilteredURLs int
	FetchWorkers int
}
type FetchStartMsg struct {
	TotalURLs int
}
type FetchProgressMsg struct {
	URL           string
	WorkerID      int
	DomainsFound  int
	TotalDomains  int
	FetchedCount  int
}
type FetchCompleteMsg struct {
	TotalDomains      int
	DuplicatesRemoved int
	Errors            []string
}
type ValidationStartMsg struct {
	Total   int
	Workers int
}
type ValidationProgressMsg struct {
	Current int
	Valid   int
	Invalid int
}
type ValidationDoneMsg struct{}
type CompletionMsg struct {
	OutputFile string
	Valid      int
	Invalid    int
}

func NewAppModel() AppModel {
	s := spinner.New()
	s.Spinner = spinner.Dot
	s.Style = lipgloss.NewStyle().Foreground(lipgloss.Color("205"))

	p := progress.New(
		progress.WithDefaultGradient(),
		progress.WithWidth(50),
		progress.WithoutPercentage(),
	)

	return AppModel{
		stage:    StageInit,
		spinner:  s,
		progress: p,
	}
}

func (m AppModel) Init() tea.Cmd {
	return m.spinner.Tick
}

func (m AppModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" || msg.String() == "q" {
			return m, tea.Quit
		}

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		m.progress.Width = min(msg.Width-20, 60)
		return m, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		m.spinner, cmd = m.spinner.Update(msg)
		return m, cmd

	case ConnectionCheckedMsg:
		m.stage = StageLoadingSources
		m.connectionChecked = true
		return m, m.spinner.Tick

	case SourcesLoadedMsg:
		m.stage = StageFetching
		m.sourceFile = msg.SourceFile
		m.totalURLs = msg.TotalURLs
		m.activeURLs = msg.ActiveURLs
		m.filteredURLs = msg.FilteredURLs
		m.fetchWorkers = msg.FetchWorkers
		m.totalFetchURLs = msg.ActiveURLs
		return m, m.spinner.Tick

	case FetchProgressMsg:
		m.currentFetchURL = msg.URL
		m.domainsFound = msg.TotalDomains
		m.fetchedURLs = msg.FetchedCount
		return m, nil

	case FetchCompleteMsg:
		m.fetchComplete = true
		m.domainsFound = msg.TotalDomains
		m.duplicatesRemoved = msg.DuplicatesRemoved
		m.fetchErrors = msg.Errors
		return m, nil

	case ValidationStartMsg:
		m.stage = StageValidating
		m.validationTotal = msg.Total
		m.validationWorkers = msg.Workers
		m.validationStart = time.Now()
		return m, m.spinner.Tick

	case ValidationProgressMsg:
		m.validationCurrent = msg.Current
		m.validationValid = msg.Valid
		m.validationInvalid = msg.Invalid
		return m, nil

	case ValidationDoneMsg:
		m.validationDone = true
		return m, nil

	case CompletionMsg:
		m.stage = StageDone
		m.outputFile = msg.OutputFile
		m.done = true
		return m, tea.Quit
	}

	return m, nil
}

func (m AppModel) View() string {
	if m.width == 0 {
		return ""
	}

	var s strings.Builder

	// Header with logo
	headerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("213")).
		Bold(true).
		Padding(1, 2).
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("99"))

	header := headerStyle.Render("🦅 MAGPIE - Blocklist Aggregator")
	s.WriteString(lipgloss.NewStyle().Width(m.width).Align(lipgloss.Center).Render(header))
	s.WriteString("\n\n")

	// Current stage content
	switch m.stage {
	case StageInit, StageCheckingConnection:
		s.WriteString(m.renderConnectionCheck())
	case StageLoadingSources:
		s.WriteString(m.renderSourceLoading())
	case StageFetching:
		s.WriteString(m.renderFetching())
	case StageValidating:
		s.WriteString(m.renderValidation())
	case StageDone:
		s.WriteString(m.renderCompletion())
	}

	// Footer
	s.WriteString("\n\n")
	footerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("241")).
		Italic(true)
	footer := footerStyle.Render("Press Ctrl+C to quit")
	s.WriteString(lipgloss.NewStyle().Width(m.width).Align(lipgloss.Center).Render(footer))

	return s.String()
}

func (m AppModel) renderConnectionCheck() string {
	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color("86")).
		Padding(1, 2)

	return style.Render(fmt.Sprintf("%s Checking internet connection...", m.spinner.View()))
}

func (m AppModel) renderSourceLoading() string {
	style := lipgloss.NewStyle().
		Foreground(lipgloss.Color("117")).
		Padding(1, 2)

	content := fmt.Sprintf("%s Loading sources from %s...", m.spinner.View(), m.sourceFile)
	return style.Render(content)
}

func (m AppModel) renderFetching() string {
	var s strings.Builder

	// Title
	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("212")).
		Bold(true).
		Padding(0, 2)
	s.WriteString(titleStyle.Render(fmt.Sprintf("%s Fetching Blocklists", m.spinner.View())))
	s.WriteString("\n\n")

	// Stats box
	statsStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("99")).
		Padding(0, 2)

	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	valueStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true)

	s.WriteString(statsStyle.Render(fmt.Sprintf("%s %s",
		labelStyle.Render("URLs to fetch:"),
		valueStyle.Render(fmt.Sprintf("%d/%d", m.fetchedURLs, m.totalFetchURLs)))))
	s.WriteString("\n")

	s.WriteString(statsStyle.Render(fmt.Sprintf("%s %s",
		labelStyle.Render("Domains found:"),
		valueStyle.Render(formatNumber(m.domainsFound)))))
	s.WriteString("\n")

	if m.fetchComplete {
		s.WriteString("\n")
		completeStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("10")).
			Bold(true).
			Padding(0, 2)
		s.WriteString(completeStyle.Render(fmt.Sprintf("✓ Fetch complete! %s unique domains (%s duplicates removed)",
			formatNumber(m.domainsFound), formatNumber(m.duplicatesRemoved))))
	} else if m.currentFetchURL != "" {
		s.WriteString("\n")
		currentStyle := lipgloss.NewStyle().
			Foreground(lipgloss.Color("245")).
			Italic(true).
			Padding(0, 2)
		truncatedURL := m.currentFetchURL
		if len(truncatedURL) > 60 {
			truncatedURL = truncatedURL[:57] + "..."
		}
		s.WriteString(currentStyle.Render(fmt.Sprintf("Current: %s", truncatedURL)))
	}

	return s.String()
}

func (m AppModel) renderValidation() string {
	var s strings.Builder

	// Title
	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("213")).
		Bold(true).
		Padding(0, 2)
	s.WriteString(titleStyle.Render("🔍 Validating Domains"))
	s.WriteString("\n\n")

	// Progress bar
	percentage := float64(m.validationCurrent) / float64(m.validationTotal)
	if percentage > 1 {
		percentage = 1
	}

	progressBar := m.progress.ViewAs(percentage)
	s.WriteString(lipgloss.NewStyle().Padding(0, 2).Render(progressBar))
	s.WriteString("\n\n")

	// Stats
	statsBoxStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("99")).
		Padding(1, 2).
		Width(60)

	var statsContent strings.Builder

	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Width(18)

	// Progress
	progressValue := lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true).
		Render(fmt.Sprintf("%s / %s (%.1f%%)",
			formatNumber(m.validationCurrent),
			formatNumber(m.validationTotal),
			percentage*100))
	statsContent.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Progress:"), progressValue))

	// Valid
	validValue := lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true).
		Render(formatNumber(m.validationValid))
	statsContent.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Valid domains:"), validValue))

	// Invalid
	invalidValue := lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true).
		Render(formatNumber(m.validationInvalid))
	statsContent.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Invalid domains:"), invalidValue))

	// Speed
	if m.validationCurrent > 0 && !m.validationStart.IsZero() {
		elapsed := time.Since(m.validationStart)
		speed := float64(m.validationCurrent) / elapsed.Seconds()
		speedValue := lipgloss.NewStyle().Foreground(lipgloss.Color("226")).Bold(true).
			Render(fmt.Sprintf("%.0f domains/s", speed))
		statsContent.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Speed:"), speedValue))

		// ETA
		if speed > 0 {
			remaining := m.validationTotal - m.validationCurrent
			eta := time.Duration(float64(remaining)/speed) * time.Second
			etaValue := lipgloss.NewStyle().Foreground(lipgloss.Color("117")).
				Render(formatDuration(eta))
			statsContent.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("ETA:"), etaValue))
		}

		// Elapsed
		elapsedValue := lipgloss.NewStyle().Foreground(lipgloss.Color("245")).
			Render(formatDuration(elapsed))
		statsContent.WriteString(fmt.Sprintf("%s %s", labelStyle.Render("Elapsed:"), elapsedValue))
	}

	s.WriteString(lipgloss.NewStyle().Padding(0, 2).Render(statsBoxStyle.Render(statsContent.String())))

	return s.String()
}

func (m AppModel) renderCompletion() string {
	var s strings.Builder

	// Success banner
	bannerStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("10")).
		Bold(true).
		Border(lipgloss.DoubleBorder()).
		BorderForeground(lipgloss.Color("10")).
		Padding(1, 4).
		Align(lipgloss.Center)

	banner := bannerStyle.Render("🎉 AGGREGATION COMPLETE! 🎉")
	s.WriteString(lipgloss.NewStyle().Width(m.width).Align(lipgloss.Center).Render(banner))
	s.WriteString("\n\n")

	// Summary box
	summaryStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("99")).
		Padding(1, 2).
		Width(60)

	var summary strings.Builder

	labelStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("240")).Width(20)

	// Output file
	fileValue := lipgloss.NewStyle().Foreground(lipgloss.Color("86")).Bold(true).
		Render(m.outputFile)
	summary.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Output file:"), fileValue))

	// Total valid domains
	validValue := lipgloss.NewStyle().Foreground(lipgloss.Color("10")).Bold(true).
		Render(formatNumber(m.validationValid))
	summary.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Valid domains:"), validValue))

	// Invalid filtered
	invalidValue := lipgloss.NewStyle().Foreground(lipgloss.Color("9")).Bold(true).
		Render(formatNumber(m.validationInvalid))
	summary.WriteString(fmt.Sprintf("%s %s\n", labelStyle.Render("Invalid filtered:"), invalidValue))

	// Cleaning rate
	if m.domainsFound > 0 {
		cleaningRate := float64(m.validationInvalid) / float64(m.domainsFound) * 100
		rateValue := lipgloss.NewStyle().Foreground(lipgloss.Color("213")).Bold(true).
			Render(fmt.Sprintf("%.1f%%", cleaningRate))
		summary.WriteString(fmt.Sprintf("%s %s", labelStyle.Render("Cleaning rate:"), rateValue))
	}

	s.WriteString(lipgloss.NewStyle().Padding(0, 2).Render(summaryStyle.Render(summary.String())))

	return s.String()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
