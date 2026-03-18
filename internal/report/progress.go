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
	verbose   bool
	spinIdx   int
	doneCh    chan struct{}
}

var spinFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// tagColors maps event tags to colors for terminal output.
var tagColors = map[string]*color.Color{
	"RED":    color.New(color.FgRed, color.Bold),
	"BLUE":   color.New(color.FgCyan, color.Bold),
	"AUTH":   color.New(color.FgGreen, color.Bold),
	"RECON":  color.New(color.FgYellow, color.Bold),
	"ENGINE": color.New(color.FgWhite),
	"BOSS":   color.New(color.FgMagenta, color.Bold),
}

// validEventTags is the set of recognized log tags for event emission.
var validEventTags = map[string]bool{
	"RED": true, "BLUE": true, "AUTH": true,
	"RECON": true, "ENGINE": true, "BOSS": true,
}

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
func NewProgress(maxLoops int, verbose bool) *Progress {
	return &Progress{
		startTime: time.Now(),
		maxLoops:  maxLoops,
		verbose:   verbose,
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
	fmt.Print("\r" + strings.Repeat(" ", 120) + "\r")
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

// Emit prints an event inline below the spinner.
// important events are always shown; non-important events only in verbose mode.
func (p *Progress) Emit(tag, msg string, important bool) {
	if !important && !p.verbose {
		return
	}
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	if p.active {
		// Clear the spinner line and move to a new line so the event persists above it.
		fmt.Print("\r" + strings.Repeat(" ", 120) + "\r\n")
	}

	c, ok := tagColors[tag]
	if !ok {
		c = color.New(color.FgWhite)
	}
	label := c.Sprintf("[%s]", tag)
	fmt.Printf("  %s %s\n", label, msg)
}

// LogWriter implements io.Writer to intercept log messages and update progress.
type LogWriter struct {
	Progress *Progress
	Inner    *strings.Builder
}

func (w *LogWriter) Write(data []byte) (int, error) {
	msg := strings.TrimRight(string(data), "\n")

	// Update phase step from known keywords.
	for keyword, phase := range PhaseMap {
		if strings.Contains(msg, keyword) {
			w.Progress.SetStep(phase)
			break
		}
	}

	// Parse the innermost [TAG] from the log line.
	// Logger format: "[ouroboros] 2006/01/02 15:04:05 [TAG] content..."
	tag, content := extractTagContent(msg)
	if tag == "" || content == "" {
		return len(data), nil
	}

	// Decide importance: AUTH events and Confidence summaries are always shown.
	important := tag == "AUTH" ||
		(tag == "RED" && strings.Contains(content, "Confidence:")) ||
		(tag == "BLUE" && strings.Contains(content, "Generated"))

	w.Progress.Emit(tag, content, important)

	return len(data), nil
}

// extractTagContent finds the last [TAG] in a log line and returns the tag
// and the content after it, if TAG is a recognized event tag.
func extractTagContent(msg string) (tag, content string) {
	// Walk backwards to find the last bracket pair.
	lastOpen := strings.LastIndex(msg, "[")
	if lastOpen < 0 {
		return "", ""
	}
	closeIdx := strings.Index(msg[lastOpen:], "]")
	if closeIdx < 0 {
		return "", ""
	}
	candidate := msg[lastOpen+1 : lastOpen+closeIdx]
	if !validEventTags[candidate] {
		return "", ""
	}
	return candidate, strings.TrimSpace(msg[lastOpen+closeIdx+1:])
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
