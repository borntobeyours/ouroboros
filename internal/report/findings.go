package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/ouroboros-security/ouroboros/pkg/types"
)

// Reporter handles all output formatting.
type Reporter struct {
	colorEnabled bool
}

// NewReporter creates a new reporter.
func NewReporter(colorEnabled bool) *Reporter {
	if !colorEnabled {
		color.NoColor = true
	}
	return &Reporter{colorEnabled: colorEnabled}
}

func (r *Reporter) PrintBanner() {
	cyan := color.New(color.FgCyan, color.Bold)
	cyan.Print(`
   ____                  __
  / __ \__  ___________/ /_  ____  _________  _____
 / / / / / / / ___/ __ \/ __ \/ __ \/ ___/ __ \/ ___/
/ /_/ / /_/ / /  / /_/ / /_/ / /_/ / /  / /_/ (__  )
\____/\__,_/_/   \____/_.___/\____/_/   \____/____/
`)
	fmt.Println()
	fmt.Println("  Security that attacks itself until nothing can.")
	fmt.Println()
}

func (r *Reporter) PrintSessionStart(session *types.ScanSession) {
	bold := color.New(color.Bold)
	bold.Printf("Session: %s\n", session.ID)
	fmt.Printf("Target:  %s\n", session.Config.Target.URL)
	fmt.Printf("Provider: %s (%s)\n", session.Config.Provider, session.Config.Model)
	fmt.Printf("Max Loops: %d | Final Boss: %v\n", session.Config.MaxLoops, session.Config.FinalBoss)
	fmt.Println(strings.Repeat("=", 60))
}

func (r *Reporter) PrintLoopStart(loop, maxLoops int) {
	yellow := color.New(color.FgYellow, color.Bold)
	yellow.Printf("\n[Loop %d/%d] ", loop, maxLoops)
	fmt.Println("Starting attack cycle...")
	fmt.Println(strings.Repeat("-", 40))
}

func (r *Reporter) PrintFindings(findings []types.Finding, loop int) {
	if len(findings) == 0 {
		green := color.New(color.FgGreen)
		green.Printf("  No new vulnerabilities found in loop %d\n", loop)
		return
	}

	for _, f := range findings {
		r.printFinding(f)
	}
}

func (r *Reporter) printFinding(f types.Finding) {
	var sevColor *color.Color
	switch f.Severity {
	case types.SeverityCritical:
		sevColor = color.New(color.FgRed, color.Bold)
	case types.SeverityHigh:
		sevColor = color.New(color.FgRed)
	case types.SeverityMedium:
		sevColor = color.New(color.FgYellow)
	case types.SeverityLow:
		sevColor = color.New(color.FgBlue)
	default:
		sevColor = color.New(color.FgWhite)
	}

	sevColor.Printf("  [%s] ", f.Severity)
	fmt.Printf("%s", f.Title)

	// Show confirmation status
	if f.Confirmed {
		color.New(color.FgGreen, color.Bold).Print(" ✅ EXPLOITED")
	} else {
		color.New(color.FgYellow).Print(" ⚠️  unconfirmed")
	}
	fmt.Println()

	fmt.Printf("    Endpoint: %s %s\n", f.Method, f.Endpoint)
	if f.CWE != "" {
		fmt.Printf("    CWE: %s\n", f.CWE)
	}
	if f.Description != "" {
		desc := f.Description
		if len(desc) > 120 {
			desc = desc[:120] + "..."
		}
		fmt.Printf("    %s\n", desc)
	}
	if f.ExploitEvidence != "" {
		color.New(color.FgGreen).Printf("    Exploit: %s\n", f.ExploitEvidence)
	}
	if f.ExfiltratedData != "" {
		color.New(color.FgRed).Printf("    Data Exfiltrated: %s\n", truncateStr(f.ExfiltratedData, 200))
	}
}

func truncateStr(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "...[truncated]"
}

func (r *Reporter) PrintPatches(patches []types.Patch, loop int) {
	if len(patches) == 0 {
		return
	}
	blue := color.New(color.FgBlue, color.Bold)
	blue.Printf("  Blue AI generated %d patches:\n", len(patches))
	for _, p := range patches {
		fmt.Printf("    - %s (confidence: %s)\n", p.Description, p.Confidence)
	}
}

func (r *Reporter) PrintLoopEnd(loop, newFindings, patches int) {
	fmt.Printf("  Loop %d complete: %d new findings, %d patches\n", loop, newFindings, patches)
}

func (r *Reporter) PrintConvergence(loop, totalUnique int) {
	green := color.New(color.FgGreen, color.Bold)
	green.Printf("\nConverged after %d loops! ", loop)
	fmt.Printf("Total unique findings: %d\n", totalUnique)
}

func (r *Reporter) PrintBossStart() {
	red := color.New(color.FgRed, color.Bold)
	red.Println("\n[FINAL BOSS] Elite validation scan starting...")
	fmt.Println(strings.Repeat("=", 40))
}

func (r *Reporter) PrintBossResults(findings []types.Finding) {
	if len(findings) == 0 {
		green := color.New(color.FgGreen, color.Bold)
		green.Println("  Final Boss found no additional vulnerabilities!")
		return
	}
	red := color.New(color.FgRed, color.Bold)
	red.Printf("  Final Boss found %d additional vulnerabilities!\n", len(findings))
	for _, f := range findings {
		r.printFinding(f)
	}
}

func (r *Reporter) PrintError(msg string) {
	errColor := color.New(color.FgRed)
	errColor.Printf("  ERROR: %s\n", msg)
}

func (r *Reporter) PrintSummary(session *types.ScanSession, findings []types.Finding) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	bold := color.New(color.Bold)
	bold.Println("SCAN SUMMARY")
	fmt.Println(strings.Repeat("=", 60))

	fmt.Printf("Session:   %s\n", session.ID)
	fmt.Printf("Target:    %s\n", session.Config.Target.URL)
	fmt.Printf("Duration:  %s\n", session.FinishedAt.Sub(session.StartedAt).Round(time.Second))
	fmt.Printf("Loops:     %d\n", len(session.Loops))
	fmt.Printf("Converged: %v\n", session.Converged)
	fmt.Printf("Total Findings: %d\n", session.TotalFindings)

	// Count confirmed
	confirmedCount := 0
	for _, f := range findings {
		if f.Confirmed {
			confirmedCount++
		}
	}
	color.New(color.FgGreen, color.Bold).Printf("Confirmed (Exploited): %d/%d\n", confirmedCount, session.TotalFindings)

	// Count by severity
	counts := map[types.Severity]int{}
	for _, f := range findings {
		counts[f.Severity]++
	}
	fmt.Println()
	if c := counts[types.SeverityCritical]; c > 0 {
		color.New(color.FgRed, color.Bold).Printf("  Critical: %d\n", c)
	}
	if c := counts[types.SeverityHigh]; c > 0 {
		color.New(color.FgRed).Printf("  High:     %d\n", c)
	}
	if c := counts[types.SeverityMedium]; c > 0 {
		color.New(color.FgYellow).Printf("  Medium:   %d\n", c)
	}
	if c := counts[types.SeverityLow]; c > 0 {
		color.New(color.FgBlue).Printf("  Low:      %d\n", c)
	}
	if c := counts[types.SeverityInfo]; c > 0 {
		fmt.Printf("  Info:     %d\n", c)
	}

	fmt.Println()
	fmt.Printf("Full report: ouroboros report --session %s\n", session.ID)
}

// ExportJSON writes findings as JSON to a file.
func ExportJSON(findings []types.Finding, session *types.ScanSession, path string) error {
	data := map[string]interface{}{
		"session":  session,
		"findings": findings,
	}
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, jsonData, 0o644)
}

// ExportMarkdown writes findings as Markdown to a file.
func ExportMarkdown(findings []types.Finding, session *types.ScanSession, path string) error {
	var sb strings.Builder

	sb.WriteString("# Ouroboros Security Report\n\n")
	sb.WriteString(fmt.Sprintf("**Session:** %s\n\n", session.ID))
	sb.WriteString(fmt.Sprintf("**Target:** %s\n\n", session.Config.Target.URL))
	sb.WriteString(fmt.Sprintf("**Date:** %s\n\n", session.StartedAt.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Loops:** %d | **Converged:** %v | **Total Findings:** %d\n\n", len(session.Loops), session.Converged, session.TotalFindings))
	sb.WriteString("---\n\n")
	sb.WriteString("## Findings\n\n")

	for i, f := range findings {
		status := "⚠️ Unconfirmed"
		if f.Confirmed {
			status = "✅ EXPLOITED"
		}
		sb.WriteString(fmt.Sprintf("### %d. [%s] %s — %s\n\n", i+1, f.Severity, f.Title, status))
		sb.WriteString(fmt.Sprintf("- **Endpoint:** `%s %s`\n", f.Method, f.Endpoint))
		sb.WriteString(fmt.Sprintf("- **CWE:** %s\n", f.CWE))
		sb.WriteString(fmt.Sprintf("- **Technique:** %s\n", f.Technique))
		sb.WriteString(fmt.Sprintf("- **Found in Loop:** %d\n", f.Loop))
		sb.WriteString(fmt.Sprintf("- **Confirmed:** %v\n\n", f.Confirmed))
		sb.WriteString(fmt.Sprintf("**Description:** %s\n\n", f.Description))
		if f.PoC != "" {
			sb.WriteString(fmt.Sprintf("**PoC:**\n```\n%s\n```\n\n", f.PoC))
		}
		if f.ExploitEvidence != "" {
			sb.WriteString(fmt.Sprintf("**Exploit Evidence:** %s\n\n", f.ExploitEvidence))
		}
		if f.ExfiltratedData != "" {
			sb.WriteString(fmt.Sprintf("**Exfiltrated Data:**\n```\n%s\n```\n\n", f.ExfiltratedData))
		}
		if f.Remediation != "" {
			sb.WriteString(fmt.Sprintf("**Remediation:** %s\n\n", f.Remediation))
		}
		sb.WriteString("---\n\n")
	}

	return os.WriteFile(path, []byte(sb.String()), 0o644)
}
