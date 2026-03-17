package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/borntobeyours/ouroboros/pkg/types"
)

// LiveView provides real-time attack visualization in the terminal.
type LiveView struct {
	target     string
	startTime  time.Time
	findings   []types.Finding
	urlsTested int
	phase      string
}

// NewLiveView creates a new live attack display.
func NewLiveView(target string) *LiveView {
	return &LiveView{
		target:    target,
		startTime: time.Now(),
	}
}

// PrintAttackHeader shows the scan startup in style.
func (lv *LiveView) PrintAttackHeader(session string, maxLoops int, provider string) {
	red := color.New(color.FgRed, color.Bold)
	cyan := color.New(color.FgCyan)
	yellow := color.New(color.FgYellow)
	dim := color.New(color.FgHiBlack)

	fmt.Println()
	red.Print("  ╔══════════════════════════════════════════════════════╗\n")
	red.Print("  ║")
	color.New(color.FgWhite, color.Bold).Print("  🐍 OUROBOROS — ADVERSARIAL SECURITY SCAN          ")
	red.Print("║\n")
	red.Print("  ╚══════════════════════════════════════════════════════╝\n")
	fmt.Println()

	cyan.Print("  TARGET  ")
	fmt.Println(lv.target)
	dim.Print("  SESSION ")
	fmt.Println(session[:8])
	yellow.Print("  MODE    ")
	fmt.Printf("%d loops × Red/Blue AI (%s)\n", maxLoops, provider)
	dim.Print("  TIME    ")
	fmt.Println(time.Now().Format("2006-01-02 15:04:05"))
	fmt.Println()
	fmt.Println(dim.Sprint("  " + strings.Repeat("─", 54)))
}

// PrintPhase shows a phase transition with style.
func (lv *LiveView) PrintPhase(loop, maxLoops int, phase string) {
	lv.phase = phase
	elapsed := time.Since(lv.startTime).Round(time.Second)

	var icon string
	var phaseColor *color.Color
	switch phase {
	case "crawl":
		icon = "🕷️"
		phaseColor = color.New(color.FgCyan)
	case "probe":
		icon = "🔍"
		phaseColor = color.New(color.FgYellow)
	case "exploit":
		icon = "💉"
		phaseColor = color.New(color.FgRed)
	case "ai":
		icon = "🧠"
		phaseColor = color.New(color.FgMagenta)
	case "defend":
		icon = "🛡️"
		phaseColor = color.New(color.FgBlue)
	case "score":
		icon = "📊"
		phaseColor = color.New(color.FgGreen)
	case "boss":
		icon = "👹"
		phaseColor = color.New(color.FgRed, color.Bold)
	default:
		icon = "⚡"
		phaseColor = color.New(color.FgWhite)
	}

	dim := color.New(color.FgHiBlack)
	fmt.Printf("\n  %s ", icon)
	phaseColor.Printf("%-20s", strings.ToUpper(phase))
	dim.Printf("  [loop %d/%d • %s]\n", loop, maxLoops, elapsed)
}

// PrintEndpointDiscovery shows crawler results.
func (lv *LiveView) PrintEndpointDiscovery(total int, classified map[string]int) {
	dim := color.New(color.FgHiBlack)
	green := color.New(color.FgGreen)

	green.Printf("  → %d endpoints discovered\n", total)
	if len(classified) > 0 {
		parts := []string{}
		order := []string{"login", "api", "admin", "upload", "search", "redirect"}
		for _, k := range order {
			if v, ok := classified[k]; ok && v > 0 {
				parts = append(parts, fmt.Sprintf("%s:%d", k, v))
			}
		}
		if len(parts) > 0 {
			dim.Printf("    %s\n", strings.Join(parts, " • "))
		}
	}
}

// PrintProbeResult shows a probing result in real-time.
func (lv *LiveView) PrintProbeResult(prober string, found int) {
	if found == 0 {
		return
	}
	dim := color.New(color.FgHiBlack)
	yellow := color.New(color.FgYellow)
	yellow.Printf("  → %s", prober)
	dim.Printf(": %d findings\n", found)
}

// PrintFindingLive shows a finding as it's discovered (compact format).
func (lv *LiveView) PrintFindingLive(f types.Finding) {
	var sevColor *color.Color
	var sevIcon string
	sev := f.AdjustedSeverity
	if sev == 0 {
		sev = f.Severity
	}
	switch sev {
	case types.SeverityCritical:
		sevColor = color.New(color.FgRed, color.Bold)
		sevIcon = "🔴"
	case types.SeverityHigh:
		sevColor = color.New(color.FgRed)
		sevIcon = "🟠"
	case types.SeverityMedium:
		sevColor = color.New(color.FgYellow)
		sevIcon = "🟡"
	case types.SeverityLow:
		sevColor = color.New(color.FgBlue)
		sevIcon = "🔵"
	default:
		sevColor = color.New(color.FgHiBlack)
		sevIcon = "⚪"
	}

	dim := color.New(color.FgHiBlack)
	fmt.Printf("  %s ", sevIcon)
	sevColor.Printf("[%s] ", sev)

	// Truncate title
	title := f.Title
	if len(title) > 50 {
		title = title[:47] + "..."
	}
	fmt.Print(title)

	// CVSS
	if f.CVSS.Score > 0 {
		dim.Printf(" (%.1f)", f.CVSS.Score)
	}

	// Confidence badge
	switch {
	case f.Confidence >= 95:
		color.New(color.FgGreen, color.Bold).Print(" ✓PROVEN")
	case f.Confidence >= 75:
		color.New(color.FgGreen).Print(" ✓HIGH")
	case f.Confidence >= 50:
		dim.Print(" ~MED")
	}

	// Exfiltrated data indicator
	if f.ExfiltratedData != "" {
		color.New(color.FgRed, color.Bold).Print(" 💀DATA")
	}

	fmt.Println()
}

// PrintConvergenceLive shows convergence with style.
func (lv *LiveView) PrintConvergenceLive(loop, total int) {
	green := color.New(color.FgGreen, color.Bold)
	fmt.Println()
	green.Printf("  ✅ CONVERGED after %d loops — %d unique findings\n", loop, total)
}

// PrintSummaryBox shows the final summary in a box.
func (lv *LiveView) PrintSummaryBox(session *types.ScanSession, findings []types.Finding) {
	elapsed := session.FinishedAt.Sub(session.StartedAt).Round(time.Second)

	// Count stats
	proven, high, med, low := 0, 0, 0, 0
	crit, highSev, medSev, lowSev, info := 0, 0, 0, 0, 0
	maxCVSS := 0.0

	for _, f := range findings {
		switch {
		case f.Confidence >= 95:
			proven++
		case f.Confidence >= 75:
			high++
		case f.Confidence >= 50:
			med++
		default:
			low++
		}
		sev := f.AdjustedSeverity
		if sev == 0 {
			sev = f.Severity
		}
		switch sev {
		case types.SeverityCritical:
			crit++
		case types.SeverityHigh:
			highSev++
		case types.SeverityMedium:
			medSev++
		case types.SeverityLow:
			lowSev++
		default:
			info++
		}
		if f.CVSS.Score > maxCVSS {
			maxCVSS = f.CVSS.Score
		}
	}

	red := color.New(color.FgRed, color.Bold)
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)
	dim := color.New(color.FgHiBlack)

	fmt.Println()
	fmt.Println(dim.Sprint("  " + strings.Repeat("═", 54)))
	cyan.Println("  📋 SCAN COMPLETE")
	fmt.Println(dim.Sprint("  " + strings.Repeat("─", 54)))

	fmt.Printf("  Target:   %s\n", lv.target)
	fmt.Printf("  Duration: %s • %d loops", elapsed, len(session.Loops))
	if session.Converged {
		green.Print(" • converged ✓")
	}
	fmt.Println()
	fmt.Printf("  Session:  %s\n", session.ID[:8])
	fmt.Println()

	// Severity breakdown with bar
	total := len(findings)
	fmt.Print("  Severity: ")
	if crit > 0 {
		red.Printf("%d crit ", crit)
	}
	if highSev > 0 {
		color.New(color.FgRed).Printf("%d high ", highSev)
	}
	if medSev > 0 {
		yellow.Printf("%d med ", medSev)
	}
	if lowSev > 0 {
		color.New(color.FgBlue).Printf("%d low ", lowSev)
	}
	if info > 0 {
		dim.Printf("%d info ", info)
	}
	fmt.Printf("(%d total)\n", total)

	// Confidence bar
	fmt.Print("  Quality:  ")
	if proven > 0 {
		green.Printf("%d proven ", proven)
	}
	if high > 0 {
		green.Printf("%d high ", high)
	}
	if med > 0 {
		yellow.Printf("%d med ", med)
	}
	if low > 0 {
		dim.Printf("%d low", low)
	}
	fmt.Println()

	if maxCVSS > 0 {
		fmt.Printf("  Max CVSS: ")
		if maxCVSS >= 9.0 {
			red.Printf("%.1f", maxCVSS)
		} else if maxCVSS >= 7.0 {
			color.New(color.FgRed).Printf("%.1f", maxCVSS)
		} else {
			yellow.Printf("%.1f", maxCVSS)
		}
		fmt.Println()
	}

	fmt.Println()
	dim.Printf("  View:  ouroboros report --session %s\n", session.ID[:8])
	fmt.Println(dim.Sprint("  " + strings.Repeat("═", 54)))
	fmt.Println()
}
