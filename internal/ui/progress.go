package ui

import (
	"fmt"
	"time"

	"github.com/charmbracelet/bubbles/progress"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type ProgressModel struct {
	progress   progress.Model
	total      int
	current    int
	valid      int
	invalid    int
	startTime  time.Time
	done       bool
}

type progressMsg struct {
	current int
	valid   int
	invalid int
}

type doneMsg struct{}

func NewProgressModel(total int) ProgressModel {
	prog := progress.New(
		progress.WithDefaultGradient(),
		progress.WithWidth(40),
	)

	return ProgressModel{
		progress:  prog,
		total:     total,
		startTime: time.Now(),
	}
}

func (m ProgressModel) Init() tea.Cmd {
	return nil
}

func (m ProgressModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
	case progressMsg:
		m.current = msg.current
		m.valid = msg.valid
		m.invalid = msg.invalid
		if m.current >= m.total {
			m.done = true
			return m, tea.Quit
		}
		return m, nil
	case doneMsg:
		m.done = true
		return m, tea.Quit
	case tea.WindowSizeMsg:
		return m, nil
	}

	return m, nil
}

func (m ProgressModel) View() string {
	if m.done {
		return ""
	}

	elapsed := time.Since(m.startTime)
	percentage := float64(m.current) / float64(m.total)

	// Calculate speed and ETA
	speed := float64(m.current) / elapsed.Seconds()
	remaining := m.total - m.current
	eta := time.Duration(float64(remaining)/speed) * time.Second

	// Format time durations
	elapsedStr := formatDuration(elapsed)
	etaStr := formatDuration(eta)

	// Style definitions
	titleStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("99")).
		Bold(true)

	statsStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("240"))

	validStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("10")).
		Bold(true)

	invalidStyle := lipgloss.NewStyle().
		Foreground(lipgloss.Color("9")).
		Bold(true)

	// Build the view
	title := titleStyle.Render("🔍 Validating Domains")

	progressBar := m.progress.ViewAs(percentage)

	stats := fmt.Sprintf("%s/%s (%.1f%%) | %s valid | %s invalid | %.0f domains/s",
		formatNumber(m.current),
		formatNumber(m.total),
		percentage*100,
		validStyle.Render(formatNumber(m.valid)),
		invalidStyle.Render(formatNumber(m.invalid)),
		speed,
	)

	timing := statsStyle.Render(fmt.Sprintf("[%s elapsed | %s remaining]", elapsedStr, etaStr))

	return fmt.Sprintf("\n%s\n%s\n%s\n%s\n", title, progressBar, stats, timing)
}

func UpdateProgress(current, valid, invalid int) tea.Msg {
	return progressMsg{current: current, valid: valid, invalid: invalid}
}

func SendDone() tea.Msg {
	return doneMsg{}
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		return "calculating..."
	}

	hours := int(d.Hours())
	minutes := int(d.Minutes()) % 60
	seconds := int(d.Seconds()) % 60

	if hours > 0 {
		return fmt.Sprintf("%dh%dm%ds", hours, minutes, seconds)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm%ds", minutes, seconds)
	}
	return fmt.Sprintf("%ds", seconds)
}

func formatNumber(n int) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	} else if n < 1000000 {
		return fmt.Sprintf("%.1fK", float64(n)/1000)
	}
	return fmt.Sprintf("%.1fM", float64(n)/1000000)
}
