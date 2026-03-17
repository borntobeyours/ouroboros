package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/ouroboros-security/ouroboros/internal/ai"
	"github.com/ouroboros-security/ouroboros/internal/blue"
	"github.com/ouroboros-security/ouroboros/internal/boss"
	"github.com/ouroboros-security/ouroboros/internal/engine"
	"github.com/ouroboros-security/ouroboros/internal/memory"
	"github.com/ouroboros-security/ouroboros/internal/red"
	"github.com/ouroboros-security/ouroboros/internal/report"
	"github.com/ouroboros-security/ouroboros/pkg/types"
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
		maxLoops  int
		finalBoss bool
		provider  string
		model     string
		output    string
	)

	cmd := &cobra.Command{
		Use:   "scan [target-url]",
		Short: "Scan a target with the adversarial AI loop",
		Long:  "Run the Red AI → Blue AI → Re-attack loop against a target URL until convergence.",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			return runScan(targetURL, maxLoops, finalBoss, provider, model, output)
		},
	}

	cmd.Flags().IntVar(&maxLoops, "max-loops", 10, "Maximum number of attack-fix loops")
	cmd.Flags().BoolVar(&finalBoss, "final-boss", false, "Enable Final Boss validation after convergence")
	cmd.Flags().StringVar(&provider, "provider", "anthropic", "AI provider (anthropic, openai, ollama)")
	cmd.Flags().StringVar(&model, "model", "claude-sonnet-4-20250514", "AI model to use")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Export report to file (supports .json, .md)")

	return cmd
}

func runScan(targetURL string, maxLoops int, finalBoss bool, providerName, model, output string) error {
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
			if err := exportReport(output, findings, session); err != nil {
				return fmt.Errorf("export report: %w", err)
			}
			fmt.Printf("\nReport exported to: %s\n", output)
		}
	}

	return nil
}

func newReportCmd() *cobra.Command {
	var (
		sessionID string
		format    string
		output    string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "View findings from a scan session",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReport(sessionID, format, output)
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "Session ID to view")
	cmd.Flags().StringVar(&format, "format", "terminal", "Output format (terminal, json, markdown)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Export report to file")

	return cmd
}

func runReport(sessionID, format, output string) error {
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

func exportReport(path string, findings []types.Finding, session *types.ScanSession) error {
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
