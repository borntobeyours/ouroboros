package report

import (
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/fatih/color"
)

// Progress displays real-time scan progress in the terminal.
type Progress struct {
	mu        sync.Mutex
	startTime time.Time
	phase     string
	step      string
	findings  int
	loop      int
	maxLoops  int
	active    bool
	spinIdx   int
	doneCh    chan struct{}
}

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// PhaseMap maps logger keywords to friendly phase names.
var PhaseMap = map[string]string{
	"Crawling target":                    "Crawling",
	"Discovered":                         "Classifying",
	"Classifying":                        "Classifying endpoints",
	"Running technique-specific probers": "Probing vulnerabilities",
	"Probers found":                      "Analyzing probes",
	"AI-powered vulnerability":           "AI scanning",
	"AI-guided active exploitation":      "Active exploitation",
	"Filtered SPA":                       "Filtering false positives",
	"Confidence":                         "Scoring confidence",
	"Analyzing":                          "Blue AI defending",
	"Attempting authentication":          "Authenticating",
	"Authentication successful":          "Authenticated ✓",
}

// NewProgress creates a new progress display.
func NewProgress(maxLoops int) *Progress {
	return &Progress{
		startTime: time.Now(),
		maxLoops:  maxLoops,
		doneCh:    make(chan struct{}),
	}
}

// Start begins the progress animation.
func (p *Progress) Start() {
	p.active = true
	go func() {
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-p.doneCh:
				return
			case <-ticker.C:
				p.render()
			}
		}
	}()
}

// Stop ends the progress display.
func (p *Progress) Stop() {
	p.mu.Lock()
	if !p.active {
		p.mu.Unlock()
		return
	}
	p.active = false
	p.mu.Unlock()
	close(p.doneCh)
	// Clear the progress line
	fmt.Print("\r" + strings.Repeat(" ", 100) + "\r")
}

// SetPhase updates the current scan phase.
func (p *Progress) SetPhase(phase string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.phase = phase
	p.step = ""
}

// SetStep updates the current step within a phase.
func (p *Progress) SetStep(step string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.step = step
}

// SetLoop updates the current loop counter.
func (p *Progress) SetLoop(loop int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.loop = loop
}

// AddFindings increments the finding counter.
func (p *Progress) AddFindings(count int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.findings += count
}

// LogWriter implements io.Writer to intercept log messages and update progress.
type LogWriter struct {
	Progress *Progress
	Inner    *strings.Builder
}

func (w *LogWriter) Write(data []byte) (int, error) {
	msg := string(data)
	// Check for known phase keywords
	for keyword, phase := range PhaseMap {
		if strings.Contains(msg, keyword) {
			w.Progress.SetStep(phase)
			break
		}
	}
	return len(data), nil
}

func (p *Progress) render() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if !p.active {
		return
	}

	elapsed := time.Since(p.startTime).Round(time.Second)
	spin := spinFrames[p.spinIdx%len(spinFrames)]
	p.spinIdx++

	// Build progress line
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)

	var parts []string
	parts = append(parts, cyan.Sprintf("%s", spin))

	if p.loop > 0 {
		parts = append(parts, yellow.Sprintf("Loop %d/%d", p.loop, p.maxLoops))
	}

	if p.phase != "" {
		parts = append(parts, color.New(color.FgWhite, color.Bold).Sprintf("%s", p.phase))
	}

	if p.step != "" {
		parts = append(parts, color.New(color.FgWhite).Sprintf("→ %s", p.step))
	}

	if p.findings > 0 {
		parts = append(parts, color.New(color.FgGreen).Sprintf("[%d findings]", p.findings))
	}

	parts = append(parts, color.New(color.FgHiBlack).Sprintf("%s", elapsed))

	line := strings.Join(parts, " ")

	// Truncate if too long
	if len(line) > 120 {
		line = line[:117] + "..."
	}

	fmt.Printf("\r%-120s", line)
}
