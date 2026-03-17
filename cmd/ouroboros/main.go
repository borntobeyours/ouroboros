package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/borntobeyours/ouroboros/internal/ai"
	"github.com/borntobeyours/ouroboros/internal/blue"
	"github.com/borntobeyours/ouroboros/internal/boss"
	"github.com/borntobeyours/ouroboros/internal/engine"
	"github.com/borntobeyours/ouroboros/internal/memory"
	"github.com/borntobeyours/ouroboros/internal/red"
	"github.com/borntobeyours/ouroboros/internal/report"
	"github.com/borntobeyours/ouroboros/pkg/types"
)

var (
	version = "dev"
)

func main() {
	rootCmd := &cobra.Command{
		Use:     "ouroboros",
		Short:   "AI-powered security platform with self-learning adversarial loop",
		Long:    "Ouroboros - Security that attacks itself until nothing can.\nOpen-source AI security platform with Red AI → Blue AI → Re-attack loop.",
		Version: version,
	}

	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newReportCmd())
	rootCmd.AddCommand(newDiffCmd())
	rootCmd.AddCommand(newCICmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func newScanCmd() *cobra.Command {
	var (
		maxLoops      int
		finalBoss     bool
		provider      string
		model         string
		output        string
		minConfidence int
		minCVSS       float64
		sortBy        string
		profile       string
	)

	cmd := &cobra.Command{
		Use:   "scan [target-url]",
		Short: "Scan a target with the adversarial AI loop",
		Long: `Run the Red AI → Blue AI → Re-attack loop against a target URL until convergence.

Profiles:
  quick    - 1 loop, no AI analysis (fast recon)
  deep     - 3 loops with AI exploitation (default)
  paranoid - 5 loops + Final Boss validation (thorough)

Examples:
  ouroboros scan http://target.com --profile quick
  ouroboros scan http://target.com --profile deep --min-confidence 50
  ouroboros scan http://target.com --profile paranoid -o report.sarif`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			// Apply profile defaults (flags override profile)
			applyProfile(profile, cmd, &maxLoops, &finalBoss, &minConfidence, &minCVSS)
			return runScan(targetURL, maxLoops, finalBoss, provider, model, output, minConfidence, minCVSS, sortBy)
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "", "Scan profile: quick, deep, paranoid")
	cmd.Flags().IntVar(&maxLoops, "max-loops", 3, "Maximum number of attack-fix loops")
	cmd.Flags().BoolVar(&finalBoss, "final-boss", false, "Enable Final Boss validation after convergence")
	cmd.Flags().StringVar(&provider, "provider", "anthropic", "AI provider (anthropic, openai, ollama)")
	cmd.Flags().StringVar(&model, "model", "claude-sonnet-4-20250514", "AI model to use")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Export report to file (.json, .md, .sarif, .html)")
	cmd.Flags().IntVar(&minConfidence, "min-confidence", 0, "Minimum confidence score to include (0-100)")
	cmd.Flags().Float64Var(&minCVSS, "min-cvss", 0, "Minimum CVSS score to include (0.0-10.0)")
	cmd.Flags().StringVar(&sortBy, "sort", "cvss", "Sort findings by: cvss, confidence, severity")

	return cmd
}

// applyProfile sets defaults based on profile name. Explicit flags take precedence.
func applyProfile(profile string, cmd *cobra.Command, maxLoops *int, finalBoss *bool, minConf *int, minCVSS *float64) {
	if profile == "" {
		return
	}
	switch profile {
	case "quick":
		if !cmd.Flags().Changed("max-loops") {
			*maxLoops = 1
		}
		if !cmd.Flags().Changed("min-confidence") {
			*minConf = 0
		}
	case "deep":
		if !cmd.Flags().Changed("max-loops") {
			*maxLoops = 3
		}
		if !cmd.Flags().Changed("min-confidence") {
			*minConf = 50
		}
		if !cmd.Flags().Changed("min-cvss") {
			*minCVSS = 4.0
		}
	case "paranoid":
		if !cmd.Flags().Changed("max-loops") {
			*maxLoops = 5
		}
		if !cmd.Flags().Changed("final-boss") {
			*finalBoss = true
		}
		if !cmd.Flags().Changed("min-confidence") {
			*minConf = 25
		}
	default:
		fmt.Fprintf(os.Stderr, "Warning: unknown profile %q, using defaults\n", profile)
	}
}

func runScan(targetURL string, maxLoops int, finalBoss bool, providerName, model, output string, minConfidence int, minCVSS float64, sortBy string) error {
	logger := log.New(os.Stderr, "[ouroboros] ", log.LstdFlags)

	// Set up context with signal handling
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Println("Received interrupt signal, shutting down...")
		cancel()
	}()

	// Resolve API key
	apiKey := resolveAPIKey(providerName)
	if apiKey == "" && providerName != "ollama" {
		return fmt.Errorf("API key not found. Set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable")
	}

	// Initialize AI provider
	aiProvider, err := ai.NewProvider(providerName, model, apiKey)
	if err != nil {
		return fmt.Errorf("initialize AI provider: %w", err)
	}
	logger.Printf("Using AI provider: %s (%s)", aiProvider.Name(), model)

	// Initialize memory store
	store, err := memory.NewStore("")
	if err != nil {
		return fmt.Errorf("initialize memory store: %w", err)
	}
	defer store.Close()

	// Initialize agents
	redAgent := red.NewAgent(aiProvider, logger)
	blueAgent := blue.NewAgent(aiProvider, logger)

	var bossAgent *boss.Agent
	if finalBoss {
		bossAgent = boss.NewAgent(aiProvider, logger)
	}

	// Initialize reporter
	reporter := report.NewReporter(true)

	// Initialize engine
	eng := engine.NewEngine(redAgent, blueAgent, bossAgent, store, reporter, logger)

	// Build scan config
	config := types.ScanConfig{
		Target:    types.Target{URL: targetURL},
		MaxLoops:  maxLoops,
		FinalBoss: finalBoss,
		Provider:  providerName,
		Model:     model,
	}

	// Run the loop
	session, err := eng.Run(ctx, config)
	if err != nil {
		return fmt.Errorf("scan failed: %w", err)
	}

	// Export if requested
	if output != "" {
		findings, err := store.GetSessionFindings(session.ID)
		if err != nil {
			logger.Printf("Warning: could not load findings for export: %v", err)
		} else {
			// Apply filters
			findings = filterFindings(findings, minConfidence, minCVSS)
			// Sort
			sortFindings(findings, sortBy)

			if err := exportReport(output, findings, session); err != nil {
				return fmt.Errorf("export report: %w", err)
			}
			filtered := ""
			if minConfidence > 0 || minCVSS > 0 {
				filtered = fmt.Sprintf(" (filtered: min-confidence=%d, min-cvss=%.1f)", minConfidence, minCVSS)
			}
			fmt.Printf("\nReport exported to: %s%s\n", output, filtered)
		}
	}

	return nil
}

func newReportCmd() *cobra.Command {
	var (
		sessionID     string
		format        string
		output        string
		minConfidence int
		minCVSS       float64
		sortBy        string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "View findings from a scan session",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReport(sessionID, format, output, minConfidence, minCVSS, sortBy)
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "Session ID to view")
	cmd.Flags().StringVar(&format, "format", "terminal", "Output format (terminal, json, markdown)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Export report to file")
	cmd.Flags().IntVar(&minConfidence, "min-confidence", 0, "Minimum confidence score (0-100)")
	cmd.Flags().Float64Var(&minCVSS, "min-cvss", 0, "Minimum CVSS score (0.0-10.0)")
	cmd.Flags().StringVar(&sortBy, "sort", "cvss", "Sort by: cvss, confidence, severity")

	return cmd
}

func runReport(sessionID, format, output string, minConfidence int, minCVSS float64, sortBy string) error {
	store, err := memory.NewStore("")
	if err != nil {
		return fmt.Errorf("initialize store: %w", err)
	}
	defer store.Close()

	if sessionID == "" {
		// List recent sessions
		sessions, err := store.ListSessions(10)
		if err != nil {
			return fmt.Errorf("list sessions: %w", err)
		}
		if len(sessions) == 0 {
			fmt.Println("No scan sessions found. Run 'ouroboros scan <url>' to start.")
			return nil
		}
		fmt.Println("Recent scan sessions:")
		fmt.Println()
		for _, s := range sessions {
			status := "incomplete"
			if s.Converged {
				status = "converged"
			}
			fmt.Printf("  %s  %s  findings: %d  status: %s\n",
				s.ID[:8], s.Config.Target.URL, s.TotalFindings, status)
		}
		fmt.Println("\nUse --session <id> to view details.")
		return nil
	}

	session, err := store.GetSession(sessionID)
	if err != nil {
		return fmt.Errorf("load session: %w", err)
	}

	findings, err := store.GetSessionFindings(sessionID)
	if err != nil {
		return fmt.Errorf("load findings: %w", err)
	}

	// Apply filters and sort
	findings = filterFindings(findings, minConfidence, minCVSS)
	sortFindings(findings, sortBy)

	if output != "" {
		return exportReport(output, findings, session)
	}

	// Terminal output
	reporter := report.NewReporter(true)
	reporter.PrintSummary(session, findings)

	if len(findings) > 0 {
		fmt.Println("\nDetailed Findings:")
		fmt.Println()
		reporter.PrintFindings(findings, 0)
	}

	return nil
}

// filterFindings removes findings below minimum confidence or CVSS thresholds.
func filterFindings(findings []types.Finding, minConf int, minCVSS float64) []types.Finding {
	if minConf == 0 && minCVSS == 0 {
		return findings
	}
	filtered := make([]types.Finding, 0, len(findings))
	for _, f := range findings {
		if int(f.Confidence) < minConf {
			continue
		}
		if f.CVSS.Score < minCVSS {
			continue
		}
		filtered = append(filtered, f)
	}
	return filtered
}

// sortFindings sorts findings by the specified criteria (descending).
func sortFindings(findings []types.Finding, sortBy string) {
	switch sortBy {
	case "confidence":
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].Confidence > findings[j].Confidence
		})
	case "severity":
		sort.Slice(findings, func(i, j int) bool {
			si := findings[i].AdjustedSeverity
			if si == 0 {
				si = findings[i].Severity
			}
			sj := findings[j].AdjustedSeverity
			if sj == 0 {
				sj = findings[j].Severity
			}
			if si != sj {
				return si > sj
			}
			return findings[i].CVSS.Score > findings[j].CVSS.Score
		})
	default: // "cvss" or anything else
		sort.Slice(findings, func(i, j int) bool {
			if findings[i].CVSS.Score != findings[j].CVSS.Score {
				return findings[i].CVSS.Score > findings[j].CVSS.Score
			}
			return findings[i].Confidence > findings[j].Confidence
		})
	}
}

func exportReport(path string, findings []types.Finding, session *types.ScanSession) error {
	if strings.HasSuffix(path, ".sarif") {
		return report.ExportSARIF(findings, session, path)
	}
	if strings.HasSuffix(path, ".html") || strings.HasSuffix(path, ".htm") {
		return report.ExportHTML(findings, session, path)
	}
	if strings.HasSuffix(path, ".json") {
		return report.ExportJSON(findings, session, path)
	}
	if strings.HasSuffix(path, ".md") {
		return report.ExportMarkdown(findings, session, path)
	}
	// Default to JSON
	return report.ExportJSON(findings, session, path)
}

func resolveAPIKey(provider string) string {
	switch provider {
	case "anthropic":
		return os.Getenv("ANTHROPIC_API_KEY")
	case "openai":
		return os.Getenv("OPENAI_API_KEY")
	case "ollama":
		return "" // Ollama doesn't need an API key
	default:
		return os.Getenv("ANTHROPIC_API_KEY")
	}
}

// ============================================================
// DIFF COMMAND — Compare two scan sessions
// ============================================================

func newDiffCmd() *cobra.Command {
	var (
		before string
		after  string
		output string
	)

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two scan sessions to show fixed, persistent, and new findings",
		Long: `Compare a baseline scan with a newer scan to track remediation progress.

Examples:
  ouroboros diff --before da60 --after 7f3a
  ouroboros diff --before da60 --after 7f3a -o diff-report.html`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runDiff(before, after, output)
		},
	}

	cmd.Flags().StringVar(&before, "before", "", "Baseline session ID (or prefix)")
	cmd.Flags().StringVar(&after, "after", "", "New session ID (or prefix)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Export diff report (.md, .html)")
	_ = cmd.MarkFlagRequired("before")
	_ = cmd.MarkFlagRequired("after")

	return cmd
}

func runDiff(beforeID, afterID, output string) error {
	store, err := memory.NewStore("")
	if err != nil {
		return fmt.Errorf("initialize store: %w", err)
	}
	defer store.Close()

	beforeSession, err := store.GetSession(beforeID)
	if err != nil {
		return fmt.Errorf("load baseline session: %w", err)
	}
	afterSession, err := store.GetSession(afterID)
	if err != nil {
		return fmt.Errorf("load new session: %w", err)
	}

	beforeFindings, err := store.GetSessionFindings(beforeSession.ID)
	if err != nil {
		return fmt.Errorf("load baseline findings: %w", err)
	}
	afterFindings, err := store.GetSessionFindings(afterSession.ID)
	if err != nil {
		return fmt.Errorf("load new findings: %w", err)
	}

	diff := computeDiff(beforeFindings, afterFindings)

	if output != "" {
		if strings.HasSuffix(output, ".html") || strings.HasSuffix(output, ".htm") {
			return report.ExportDiffHTML(diff, beforeSession, afterSession, output)
		}
		return report.ExportDiffMarkdown(diff, beforeSession, afterSession, output)
	}

	// Terminal output
	printDiff(diff, beforeSession, afterSession)
	return nil
}

func computeDiff(before, after []types.Finding) report.DiffResult {
	beforeSigs := make(map[string]types.Finding)
	for _, f := range before {
		beforeSigs[f.Signature()] = f
	}
	afterSigs := make(map[string]types.Finding)
	for _, f := range after {
		afterSigs[f.Signature()] = f
	}

	var diff report.DiffResult

	for sig, f := range beforeSigs {
		if _, exists := afterSigs[sig]; !exists {
			diff.Fixed = append(diff.Fixed, f)
		}
	}
	for sig, f := range afterSigs {
		if _, exists := beforeSigs[sig]; exists {
			diff.Persistent = append(diff.Persistent, f)
		}
	}
	for sig, f := range afterSigs {
		if _, exists := beforeSigs[sig]; !exists {
			diff.New = append(diff.New, f)
		}
	}

	sortByCVSS := func(findings []types.Finding) {
		sort.Slice(findings, func(i, j int) bool {
			return findings[i].CVSS.Score > findings[j].CVSS.Score
		})
	}
	sortByCVSS(diff.Fixed)
	sortByCVSS(diff.Persistent)
	sortByCVSS(diff.New)

	return diff
}

func printDiff(diff report.DiffResult, before, after *types.ScanSession) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("SCAN DIFF")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Baseline: %s (%s)\n", before.ID[:8], before.Config.Target.URL)
	fmt.Printf("Current:  %s (%s)\n", after.ID[:8], after.Config.Target.URL)
	fmt.Println()

	// Summary
	fmt.Printf("✅ Fixed:      %d\n", len(diff.Fixed))
	fmt.Printf("⚠️  Persistent: %d\n", len(diff.Persistent))
	fmt.Printf("🆕 New:        %d\n", len(diff.New))
	fmt.Println()

	if len(diff.Fixed) > 0 {
		fmt.Println("── FIXED (Remediated) ──────────────────")
		for _, f := range diff.Fixed {
			sev := f.AdjustedSeverity
			if sev == 0 {
				sev = f.Severity
			}
			fmt.Printf("  ✅ [%s] %s", sev, f.Title)
			if f.CVSS.Score > 0 {
				fmt.Printf(" (CVSS:%.1f)", f.CVSS.Score)
			}
			fmt.Println()
		}
		fmt.Println()
	}

	if len(diff.New) > 0 {
		fmt.Println("── NEW (Regressions) ──────────────────")
		for _, f := range diff.New {
			sev := f.AdjustedSeverity
			if sev == 0 {
				sev = f.Severity
			}
			fmt.Printf("  🆕 [%s] %s", sev, f.Title)
			if f.CVSS.Score > 0 {
				fmt.Printf(" (CVSS:%.1f)", f.CVSS.Score)
			}
			fmt.Println()
		}
		fmt.Println()
	}

	if len(diff.Persistent) > 0 {
		fmt.Println("── PERSISTENT (Still Present) ─────────")
		for _, f := range diff.Persistent {
			sev := f.AdjustedSeverity
			if sev == 0 {
				sev = f.Severity
			}
			fmt.Printf("  ⚠️  [%s] %s", sev, f.Title)
			if f.CVSS.Score > 0 {
				fmt.Printf(" (CVSS:%.1f)", f.CVSS.Score)
			}
			fmt.Println()
		}
	}
}

// ============================================================
// CI COMMAND — Exit code based on findings
// ============================================================

func newCICmd() *cobra.Command {
	var (
		maxLoops      int
		provider      string
		model         string
		output        string
		failOn        string
		minConfidence int
		baseline      string
	)

	cmd := &cobra.Command{
		Use:   "ci [target-url]",
		Short: "CI/CD mode — scan and exit with code 1 if findings exceed threshold",
		Long: `Run a scan optimized for CI/CD pipelines.

Exit codes:
  0 - No findings above threshold (or all findings are below --fail-on level)
  1 - Findings found above threshold
  2 - Scan error

Examples:
  ouroboros ci http://staging.example.com --fail-on high
  ouroboros ci http://staging.example.com --fail-on critical -o results.sarif
  ouroboros ci http://staging.example.com --baseline abc123 --fail-on high`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			return runCI(targetURL, maxLoops, provider, model, output, failOn, minConfidence, baseline)
		},
	}

	cmd.Flags().IntVar(&maxLoops, "max-loops", 2, "Maximum loops (default 2 for speed)")
	cmd.Flags().StringVar(&provider, "provider", "anthropic", "AI provider")
	cmd.Flags().StringVar(&model, "model", "claude-sonnet-4-20250514", "AI model")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Export report file")
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Fail threshold: critical, high, medium, low, info")
	cmd.Flags().IntVar(&minConfidence, "min-confidence", 50, "Only count findings with this confidence+")
	cmd.Flags().StringVar(&baseline, "baseline", "", "Baseline session — only fail on NEW findings")

	return cmd
}

func runCI(targetURL string, maxLoops int, providerName, model, output, failOn string, minConf int, baselineID string) error {
	logger := log.New(os.Stderr, "[ouroboros] ", log.LstdFlags)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
	}()

	apiKey := resolveAPIKey(providerName)
	if apiKey == "" && providerName != "ollama" {
		return fmt.Errorf("API key not found")
	}

	aiProvider, err := ai.NewProvider(providerName, model, apiKey)
	if err != nil {
		return fmt.Errorf("initialize AI: %w", err)
	}

	store, err := memory.NewStore("")
	if err != nil {
		return fmt.Errorf("initialize store: %w", err)
	}
	defer store.Close()

	redAgent := red.NewAgent(aiProvider, logger)
	blueAgent := blue.NewAgent(aiProvider, logger)
	reporter := report.NewReporter(false) // No color in CI

	eng := engine.NewEngine(redAgent, blueAgent, nil, store, reporter, logger)

	config := types.ScanConfig{
		Target:    types.Target{URL: targetURL},
		MaxLoops:  maxLoops,
		Provider:  providerName,
		Model:     model,
	}

	session, err := eng.Run(ctx, config)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Scan failed: %v\n", err)
		os.Exit(2)
	}

	findings, err := store.GetSessionFindings(session.ID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Load findings failed: %v\n", err)
		os.Exit(2)
	}

	// Filter by confidence
	findings = filterFindings(findings, minConf, 0)
	sortFindings(findings, "cvss")

	// If baseline provided, only consider NEW findings
	if baselineID != "" {
		baselineFindings, err := store.GetSessionFindings(baselineID)
		if err != nil {
			logger.Printf("Warning: could not load baseline %s: %v", baselineID, err)
		} else {
			diff := computeDiff(baselineFindings, findings)
			findings = diff.New // Only new findings matter
			fmt.Printf("Baseline comparison: %d fixed, %d persistent, %d new\n",
				len(diff.Fixed), len(diff.Persistent), len(diff.New))
		}
	}

	// Export if requested
	if output != "" {
		if err := exportReport(output, findings, session); err != nil {
			logger.Printf("Warning: export failed: %v", err)
		}
	}

	// Determine threshold
	threshold, _ := types.ParseSeverity(failOn)

	// Count findings at or above threshold
	failCount := 0
	for _, f := range findings {
		sev := f.AdjustedSeverity
		if sev == 0 {
			sev = f.Severity
		}
		if sev >= threshold {
			failCount++
		}
	}

	// CI Summary
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("CI RESULT")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Target:    %s\n", targetURL)
	fmt.Printf("Findings:  %d (confidence >= %d%%)\n", len(findings), minConf)
	fmt.Printf("Threshold: %s\n", failOn)
	fmt.Printf("Failing:   %d findings at %s or above\n", failCount, failOn)

	if failCount > 0 {
		fmt.Printf("\n❌ FAILED — %d finding(s) at %s severity or above\n", failCount, failOn)
		for _, f := range findings {
			sev := f.AdjustedSeverity
			if sev == 0 {
				sev = f.Severity
			}
			if sev >= threshold {
				fmt.Printf("  [%s] %s (CVSS:%.1f, %d%%)\n", sev, f.Title, f.CVSS.Score, f.Confidence)
			}
		}
		os.Exit(1)
	}

	fmt.Println("\n✅ PASSED — no findings at or above threshold")
	return nil
}
