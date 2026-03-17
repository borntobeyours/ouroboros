package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sort"
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
	)

	cmd := &cobra.Command{
		Use:   "scan [target-url]",
		Short: "Scan a target with the adversarial AI loop",
		Long:  "Run the Red AI → Blue AI → Re-attack loop against a target URL until convergence.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			return runScan(targetURL, maxLoops, finalBoss, provider, model, output, minConfidence, minCVSS, sortBy)
		},
	}

	cmd.Flags().IntVar(&maxLoops, "max-loops", 5, "Maximum number of attack-fix loops")
	cmd.Flags().BoolVar(&finalBoss, "final-boss", false, "Enable Final Boss validation after convergence")
	cmd.Flags().StringVar(&provider, "provider", "anthropic", "AI provider (anthropic, openai, ollama)")
	cmd.Flags().StringVar(&model, "model", "claude-sonnet-4-20250514", "AI model to use")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Export report to file (supports .json, .md, .sarif)")
	cmd.Flags().IntVar(&minConfidence, "min-confidence", 0, "Minimum confidence score to include (0-100)")
	cmd.Flags().Float64Var(&minCVSS, "min-cvss", 0, "Minimum CVSS score to include (0.0-10.0)")
	cmd.Flags().StringVar(&sortBy, "sort", "cvss", "Sort findings by: cvss, confidence, severity")

	return cmd
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
	if len(path) > 6 && path[len(path)-6:] == ".sarif" {
		return report.ExportSARIF(findings, session, path)
	}
	if len(path) > 5 && path[len(path)-5:] == ".json" {
		return report.ExportJSON(findings, session, path)
	}
	if len(path) > 3 && path[len(path)-3:] == ".md" {
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
