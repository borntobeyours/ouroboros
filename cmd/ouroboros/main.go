package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/borntobeyours/ouroboros/internal/ai"
	ourobapi "github.com/borntobeyours/ouroboros/internal/api"
	"github.com/borntobeyours/ouroboros/internal/blue"
	"github.com/borntobeyours/ouroboros/internal/boss"
	"github.com/borntobeyours/ouroboros/internal/compliance"
	"github.com/borntobeyours/ouroboros/internal/engine"
	"github.com/borntobeyours/ouroboros/internal/integrations"
	"github.com/borntobeyours/ouroboros/internal/memory"
	"github.com/borntobeyours/ouroboros/internal/notify"
	"github.com/borntobeyours/ouroboros/internal/plugin"
	"github.com/borntobeyours/ouroboros/internal/recon"
	"github.com/borntobeyours/ouroboros/internal/red"
	"github.com/borntobeyours/ouroboros/internal/red/probers"
	"github.com/borntobeyours/ouroboros/internal/report"
	"github.com/borntobeyours/ouroboros/internal/scheduler"
	"github.com/borntobeyours/ouroboros/internal/throttle"
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
	rootCmd.AddCommand(newReconCmd())
	rootCmd.AddCommand(newPluginsCmd())
	rootCmd.AddCommand(newScheduleCmd())
	rootCmd.AddCommand(newServeCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

// scanOpts carries the optional feature flags added in the second generation of CLI flags.
type scanOpts struct {
	webhook        string
	webhookFmt     string
	rateProfile    string
	rps            float64
	pluginsDir     string
	disablePlugins bool
	allTemplates   bool     // --all-templates: disable smart filtering
	templateTags   []string // --template-tags: manual tech tag override
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
		rateLimit     int
		reconEnabled  bool
		noRecon       bool
		reconModules  string
		verbose       bool
		// Auth flags
		authUser    string
		authPass    string
		authURL     string
		authMethod  string
		authToken   string
		authHeaders []string
		authCookies []string
		skipBlue    bool
		// Webhook flags
		webhookURL string
		webhookFmt string
		// Throttle flags
		rateLimitProfile string
		customRPS        float64
		// Plugin flags
		pluginsDir     string
		disablePlugins bool
		allTemplates   bool
		templateTags   string
		// Batch flags
		targetsFile string
		parallel    int
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
  ouroboros scan http://target.com --profile paranoid -o report.sarif
  ouroboros scan --targets urls.txt --profile quick --parallel 3 --provider claude-code`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if targetsFile == "" && len(args) == 0 {
				return fmt.Errorf("provide a target URL or --targets file")
			}
			applyProfile(profile, cmd, &maxLoops, &finalBoss, &minConfidence, &minCVSS)
			if rateLimit > 0 {
				probers.SetRate(rateLimit)
			}

			// Build AuthConfig from flags
			authCfg := types.AuthConfig{
				Username: authUser,
				Password: authPass,
				LoginURL: authURL,
				Method:   authMethod,
				Token:    authToken,
			}
			if len(authHeaders) > 0 {
				authCfg.Headers = make(map[string]string, len(authHeaders))
				for _, h := range authHeaders {
					parts := strings.SplitN(h, ":", 2)
					if len(parts) == 2 {
						authCfg.Headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
					}
				}
			}
			if len(authCookies) > 0 {
				authCfg.Cookies = make(map[string]string, len(authCookies))
				for _, c := range authCookies {
					parts := strings.SplitN(c, "=", 2)
					if len(parts) == 2 {
						authCfg.Cookies[parts[0]] = parts[1]
					}
				}
			}

			var parsedTemplateTags []string
			if templateTags != "" {
				for _, t := range strings.Split(templateTags, ",") {
					if t = strings.TrimSpace(t); t != "" {
						parsedTemplateTags = append(parsedTemplateTags, t)
					}
				}
			}
			opts := scanOpts{
				webhook:        webhookURL,
				webhookFmt:     webhookFmt,
				rateProfile:    rateLimitProfile,
				rps:            customRPS,
				pluginsDir:     pluginsDir,
				disablePlugins: disablePlugins,
				allTemplates:   allTemplates,
				templateTags:   parsedTemplateTags,
			}

			// Batch mode: --targets file provided
			if targetsFile != "" {
				targets, err := readTargetsFile(targetsFile)
				if err != nil {
					return err
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				sigCh := make(chan os.Signal, 1)
				signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
				go func() { <-sigCh; cancel() }()
				return runBatchScan(ctx, targets, parallel, maxLoops, finalBoss, skipBlue, verbose,
					provider, model, output, minConfidence, minCVSS, sortBy, authCfg, opts)
			}

			// Single target mode
			targetURL := args[0]
			rc := types.DefaultReconConfig()
			if noRecon {
				rc.Enabled = false
			} else if cmd.Flags().Changed("recon") {
				rc.Enabled = reconEnabled
			} else {
				rc.Enabled = shouldEnableRecon(targetURL)
			}
			if reconModules != "" {
				rc.Modules = strings.Split(reconModules, ",")
			}
			return runScan(targetURL, maxLoops, finalBoss, skipBlue, verbose, provider, model, output, minConfidence, minCVSS, sortBy, authCfg, opts, rc)
		},
	}

	cmd.Flags().StringVar(&profile, "profile", "", "Scan profile: quick, deep, paranoid")
	cmd.Flags().IntVar(&maxLoops, "max-loops", 3, "Maximum number of attack-fix loops")
	cmd.Flags().BoolVar(&finalBoss, "final-boss", false, "Enable Final Boss validation after convergence")
	cmd.Flags().BoolVar(&skipBlue, "skip-blue", false, "Skip Blue AI defense analysis (auto-enabled for claude-code provider)")
	cmd.Flags().StringVar(&provider, "provider", "anthropic", "AI provider (anthropic, openai, ollama)")
	cmd.Flags().StringVar(&model, "model", "claude-sonnet-4-20250514", "AI model to use")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Export report to file (.json, .md, .sarif, .html)")
	cmd.Flags().IntVar(&minConfidence, "min-confidence", 0, "Minimum confidence score to include (0-100)")
	cmd.Flags().Float64Var(&minCVSS, "min-cvss", 0, "Minimum CVSS score to include (0.0-10.0)")
	cmd.Flags().StringVar(&sortBy, "sort", "cvss", "Sort findings by: cvss, confidence, severity")
	cmd.Flags().IntVar(&rateLimit, "rate", 10, "Max requests per second (0 = unlimited)")
	cmd.Flags().BoolVar(&reconEnabled, "recon", false, "Enable recon phase before attack loop")
	cmd.Flags().BoolVar(&noRecon, "no-recon", false, "Disable recon phase")
	cmd.Flags().StringVar(&reconModules, "recon-modules", "", "Comma-separated recon modules: portscan,techfp,jsextract,wayback,params")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Show real-time AI reasoning and scan events")
	// Auth flags
	cmd.Flags().StringVar(&authUser, "auth-user", "", "Login username/email")
	cmd.Flags().StringVar(&authPass, "auth-pass", "", "Login password")
	cmd.Flags().StringVar(&authURL, "auth-url", "", "Custom login URL (auto-detect if empty)")
	cmd.Flags().StringVar(&authMethod, "auth-method", "", "Auth method: form/json/bearer/cookie/auto (default: auto)")
	cmd.Flags().StringVar(&authToken, "auth-token", "", "Direct bearer token")
	cmd.Flags().StringArrayVar(&authHeaders, "auth-header", nil, "Custom auth header 'Name: Value' (repeatable)")
	cmd.Flags().StringArrayVar(&authCookies, "auth-cookie", nil, "Custom cookie 'name=value' (repeatable)")
	// Webhook flags
	cmd.Flags().StringVar(&webhookURL, "webhook", "", "Webhook URL to notify on scan completion (Discord/Slack/generic)")
	cmd.Flags().StringVar(&webhookFmt, "webhook-format", "", "Webhook payload format: discord, slack, json (auto-detected from URL)")
	// Throttle flags
	cmd.Flags().StringVar(&rateLimitProfile, "rate-limit", "", "Throttle profile: aggressive, normal, stealth, paranoid-stealth")
	cmd.Flags().Float64Var(&customRPS, "rps", 0, "Custom requests per second (overrides --rate-limit)")
	// Plugin flags
	cmd.Flags().StringVar(&pluginsDir, "plugins-dir", "", "Directory to load custom YAML plugins from (default: ~/.ouroboros/plugins/)")
	cmd.Flags().BoolVar(&disablePlugins, "disable-plugins", false, "Skip loading custom plugins")
	cmd.Flags().BoolVar(&allTemplates, "all-templates", false, "Disable smart template filtering — run all 522 templates against every target")
	cmd.Flags().StringVar(&templateTags, "template-tags", "", "Comma-separated tech tags to run (e.g. nodejs,php,mysql) — overrides AI selection")
	// Batch flags
	cmd.Flags().StringVar(&targetsFile, "targets", "", "File with one URL per line for batch scanning")
	cmd.Flags().IntVar(&parallel, "parallel", 3, "Number of concurrent scans when using --targets")

	return cmd
}

// shouldEnableRecon returns true for domain targets, false for localhost/IP.
func shouldEnableRecon(targetURL string) bool {
	// Always enable recon — JS extraction and endpoint discovery are
	// critical for SPA targets (Angular, React, Vue) even on localhost.
	return true
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

func runScan(targetURL string, maxLoops int, finalBoss bool, skipBlue bool, verbose bool, providerName, model, output string, minConfidence int, minCVSS float64, sortBy string, authCfg types.AuthConfig, opts scanOpts, reconCfg ...types.ReconConfig) error {
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
	if apiKey == "" && providerName != "ollama" && providerName != "claude-code" && providerName != "claudecode" && providerName != "claude" {
		return fmt.Errorf("API key not found. Set ANTHROPIC_API_KEY or OPENAI_API_KEY environment variable, or use --provider claude-code")
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

	// Apply throttle / stealth profile
	if opts.rps > 0 {
		probers.SetThrottleRPS(opts.rps)
	} else if opts.rateProfile != "" {
		probers.SetThrottleProfile(throttle.ParseProfile(opts.rateProfile))
	}

	// Load custom plugins into PluginProbers (not yet registered).
	// The engine will filter and register them after the recon phase.
	var loadedPluginProbers []*plugin.PluginProber
	if !opts.disablePlugins {
		plugDir := opts.pluginsDir
		if plugDir == "" {
			plugDir = plugin.DefaultPluginsDir()
		}
		var plugErr error
		loadedPluginProbers, plugErr = plugin.LoadPluginProbers(plugDir)
		if plugErr != nil {
			logger.Printf("[PLUGINS] Warning: %v", plugErr)
		}
		if len(loadedPluginProbers) > 0 {
			logger.Printf("[PLUGINS] Loaded %d template(s) (filtering after recon)", len(loadedPluginProbers))
		}
	}

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

	// Wire AI provider and plugin probers for smart template filtering.
	eng.SetAIProvider(aiProvider)
	if len(loadedPluginProbers) > 0 {
		eng.SetPluginProbers(loadedPluginProbers)
	}

	// Attach webhook notifier if requested (non-fatal)
	if opts.webhook != "" {
		wfmt := notify.WebhookFormat(opts.webhookFmt)
		n := notify.NewNotifier(notify.WebhookConfig{
			URL:    opts.webhook,
			Format: wfmt,
		})
		eng.SetNotifier(n)
	}

	// Build scan config
	config := types.ScanConfig{
		Target:       types.Target{URL: targetURL},
		MaxLoops:     maxLoops,
		FinalBoss:    finalBoss,
		SkipBlue:     skipBlue,
		Verbose:      verbose,
		Provider:     providerName,
		Model:        model,
		AuthConfig:   authCfg,
		AllTemplates: opts.allTemplates,
		TemplateTags: opts.templateTags,
	}
	if len(reconCfg) > 0 {
		config.ReconConfig = reconCfg[0]
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

// readTargetsFile parses a targets file, skipping blank lines and # comments.
func readTargetsFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open targets file %q: %w", path, err)
	}
	defer f.Close()

	var targets []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		targets = append(targets, line)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read targets file: %w", err)
	}
	if len(targets) == 0 {
		return nil, fmt.Errorf("no targets found in %q", path)
	}
	return targets, nil
}

// batchResult holds the outcome of scanning a single target in batch mode.
type batchResult struct {
	url      string
	session  *types.ScanSession
	findings []types.Finding
	err      error
}

// runBatchScan scans multiple targets in parallel and prints an aggregate summary.
func runBatchScan(
	ctx context.Context,
	targets []string,
	parallel int,
	maxLoops int,
	finalBoss bool,
	skipBlue bool,
	verbose bool,
	providerName, model, output string,
	minConfidence int,
	minCVSS float64,
	sortBy string,
	authCfg types.AuthConfig,
	opts scanOpts,
) error {
	if parallel < 1 {
		parallel = 1
	}

	reporter := report.NewReporter(true)
	reporter.PrintBanner()
	fmt.Printf("Batch scanning %d targets (parallelism: %d)\n\n", len(targets), parallel)

	// Set up global throttle / plugins once before spawning goroutines to avoid
	// concurrent modification of shared prober state.
	if opts.rps > 0 {
		probers.SetThrottleRPS(opts.rps)
	} else if opts.rateProfile != "" {
		probers.SetThrottleProfile(throttle.ParseProfile(opts.rateProfile))
	}
	// Load plugin probers once for all batch targets (filtering happens per-target in the engine).
	var batchPluginProbers []*plugin.PluginProber
	if !opts.disablePlugins {
		plugDir := opts.pluginsDir
		if plugDir == "" {
			plugDir = plugin.DefaultPluginsDir()
		}
		batchPluginProbers, _ = plugin.LoadPluginProbers(plugDir)
	}

	results := make([]batchResult, len(targets))
	sem := make(chan struct{}, parallel)
	var wg sync.WaitGroup

	for i, target := range targets {
		wg.Add(1)
		i, target := i, target
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			fmt.Printf("[%d/%d] Scanning %s...\n", i+1, len(targets), target)

			apiKey := resolveAPIKey(providerName)
			aiProvider, err := ai.NewProvider(providerName, model, apiKey)
			if err != nil {
				results[i] = batchResult{url: target, err: err}
				return
			}

			store, err := memory.NewStore("")
			if err != nil {
				results[i] = batchResult{url: target, err: err}
				return
			}
			defer store.Close()

			logger := log.New(os.Stderr, fmt.Sprintf("[batch:%s] ", target), log.LstdFlags)
			redAgent := red.NewAgent(aiProvider, logger)
			blueAgent := blue.NewAgent(aiProvider, logger)
			var bossAgent *boss.Agent
			if finalBoss {
				bossAgent = boss.NewAgent(aiProvider, logger)
			}
			scanReporter := report.NewReporter(false)
			eng := engine.NewEngine(redAgent, blueAgent, bossAgent, store, scanReporter, logger)
			eng.SetAIProvider(aiProvider)
			if len(batchPluginProbers) > 0 {
				eng.SetPluginProbers(batchPluginProbers)
			}

			if opts.webhook != "" {
				wfmt := notify.WebhookFormat(opts.webhookFmt)
				n := notify.NewNotifier(notify.WebhookConfig{URL: opts.webhook, Format: wfmt})
				eng.SetNotifier(n)
			}

			config := types.ScanConfig{
				Target:       types.Target{URL: target},
				MaxLoops:     maxLoops,
				FinalBoss:    finalBoss,
				SkipBlue:     skipBlue,
				Verbose:      verbose,
				Provider:     providerName,
				Model:        model,
				AuthConfig:   authCfg,
				AllTemplates: opts.allTemplates,
				TemplateTags: opts.templateTags,
			}

			session, err := eng.Run(ctx, config)
			if err != nil {
				results[i] = batchResult{url: target, err: err}
				return
			}

			findings, err := store.GetSessionFindings(session.ID)
			if err != nil {
				results[i] = batchResult{url: target, session: session, err: err}
				return
			}
			findings = filterFindings(findings, minConfidence, minCVSS)
			sortFindings(findings, sortBy)

			results[i] = batchResult{url: target, session: session, findings: findings}
			fmt.Printf("[%d/%d] Done %s — %d finding(s)\n", i+1, len(targets), target, len(findings))

			// Per-target report export
			if output != "" {
				ext := filepath.Ext(output)
				base := strings.TrimSuffix(output, ext)
				slug := sanitizeURLForFilename(target)
				targetOutput := fmt.Sprintf("%s-%s%s", base, slug, ext)
				if err := exportReport(targetOutput, findings, session); err != nil {
					logger.Printf("Warning: export failed: %v", err)
				} else {
					fmt.Printf("  Report: %s\n", targetOutput)
				}
			}
		}()
	}

	wg.Wait()
	printBatchSummary(results, output)
	return nil
}

// sanitizeURLForFilename converts a URL into a safe filename component.
func sanitizeURLForFilename(rawURL string) string {
	s := strings.TrimPrefix(rawURL, "https://")
	s = strings.TrimPrefix(s, "http://")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, ":", "-")
	s = strings.ReplaceAll(s, ".", "-")
	// Remove any remaining unsafe characters
	var out []rune
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			out = append(out, r)
		}
	}
	if len(out) == 0 {
		return "target"
	}
	return string(out)
}

// printBatchSummary prints an aggregate table of all batch scan results.
func printBatchSummary(results []batchResult, output string) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 80))
	fmt.Println("BATCH SCAN SUMMARY")
	fmt.Println(strings.Repeat("=", 80))
	fmt.Printf("%-40s  %8s  %8s  %5s  %5s  %6s  %3s\n",
		"Target", "Findings", "Critical", "High", "Med", "Low", "Err")
	fmt.Println(strings.Repeat("-", 80))

	totalFindings := 0
	totalErrors := 0
	for _, r := range results {
		if r.err != nil {
			totalErrors++
			fmt.Printf("%-40s  %8s  ERROR: %v\n", truncateTo(r.url, 40), "-", r.err)
			continue
		}
		counts := map[types.Severity]int{}
		for _, f := range r.findings {
			sev := f.AdjustedSeverity
			if sev == 0 {
				sev = f.Severity
			}
			counts[sev]++
		}
		totalFindings += len(r.findings)
		fmt.Printf("%-40s  %8d  %8d  %5d  %5d  %6d  %3s\n",
			truncateTo(r.url, 40),
			len(r.findings),
			counts[types.SeverityCritical],
			counts[types.SeverityHigh],
			counts[types.SeverityMedium],
			counts[types.SeverityLow],
			"-",
		)
	}

	fmt.Println(strings.Repeat("-", 80))
	fmt.Printf("Totals: %d targets, %d findings, %d errors\n",
		len(results), totalFindings, totalErrors)

	if output != "" {
		ext := filepath.Ext(output)
		base := strings.TrimSuffix(output, ext)
		summaryPath := base + "-summary" + ext
		fmt.Printf("\nCombined summary report: %s\n", summaryPath)
		// Build combined findings list for export
		var all []types.Finding
		var firstSession *types.ScanSession
		for _, r := range results {
			if r.session != nil && firstSession == nil {
				firstSession = r.session
			}
			all = append(all, r.findings...)
		}
		if firstSession != nil {
			_ = exportReport(summaryPath, all, firstSession)
		}
	}
}

func truncateTo(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func newReportCmd() *cobra.Command {
	var (
		sessionID            string
		format               string
		output               string
		minConfidence        int
		minCVSS              float64
		sortBy               string
		complianceFrameworks string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "View findings from a scan session",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReport(sessionID, format, output, minConfidence, minCVSS, sortBy, complianceFrameworks)
		},
	}

	cmd.Flags().StringVar(&sessionID, "session", "", "Session ID to view")
	cmd.Flags().StringVar(&format, "format", "terminal", "Output format (terminal, json, markdown)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Export report to file")
	cmd.Flags().IntVar(&minConfidence, "min-confidence", 0, "Minimum confidence score (0-100)")
	cmd.Flags().Float64Var(&minCVSS, "min-cvss", 0, "Minimum CVSS score (0.0-10.0)")
	cmd.Flags().StringVar(&sortBy, "sort", "cvss", "Sort by: cvss, confidence, severity")
	cmd.Flags().StringVar(&complianceFrameworks, "compliance", "", "Map findings to compliance frameworks: owasp,pci,cis,nist (comma-separated)")

	return cmd
}

func runReport(sessionID, format, output string, minConfidence int, minCVSS float64, sortBy, complianceFrameworks string) error {
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

	// Apply compliance mappings if requested
	if complianceFrameworks != "" {
		frameworks := strings.Split(complianceFrameworks, ",")
		compliance.MapFindings(findings, frameworks)
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

	if complianceFrameworks != "" {
		reporter.PrintComplianceSummary(findings)
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
	case "openrouter":
		return os.Getenv("OPENROUTER_API_KEY")
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
		before         string
		after          string
		output         string
		latest         string
		severityChange bool
		regression     bool
	)

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare two scan sessions to show fixed, persistent, and new findings",
		Long: `Compare a baseline scan with a newer scan to track remediation progress.

Examples:
  ouroboros diff --before da60 --after 7f3a
  ouroboros diff --before da60 --after 7f3a -o diff-report.html
  ouroboros diff --latest                              # two most recent sessions
  ouroboros diff --latest http://target.com            # two most recent for target
  ouroboros diff --before da60 --after 7f3a --regression   # CI/CD gate`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// --latest takes an optional positional URL argument
			latestTarget := latest
			if latestTarget == "" && len(args) > 0 {
				latestTarget = args[0]
			}
			return runDiff(before, after, output, latestTarget, severityChange, regression)
		},
	}

	cmd.Flags().StringVar(&before, "before", "", "Baseline session ID (or prefix)")
	cmd.Flags().StringVar(&after, "after", "", "New session ID (or prefix)")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Export diff report (.md, .html)")
	cmd.Flags().StringVar(&latest, "latest", "", "Auto-pick two most recent sessions (optional: target URL to filter)")
	cmd.Flags().BoolVar(&severityChange, "severity-change", false, "Highlight findings that changed severity")
	cmd.Flags().BoolVar(&regression, "regression", false, "Exit code 1 if any new critical/high findings (CI/CD gate)")

	return cmd
}

func runDiff(beforeID, afterID, output, latestTarget string, severityChange, regression bool) error {
	store, err := memory.NewStore("")
	if err != nil {
		return fmt.Errorf("initialize store: %w", err)
	}
	defer store.Close()

	var beforeSession, afterSession *types.ScanSession

	if latestTarget != "" || (beforeID == "" && afterID == "") {
		// --latest mode: auto-pick the two most recent sessions
		beforeSession, afterSession, err = findLatestSessions(store, latestTarget)
		if err != nil {
			return fmt.Errorf("find latest sessions: %w", err)
		}
	} else {
		if beforeID == "" || afterID == "" {
			return fmt.Errorf("provide --before and --after session IDs, or use --latest")
		}
		beforeSession, err = store.GetSession(beforeID)
		if err != nil {
			return fmt.Errorf("load baseline session: %w", err)
		}
		afterSession, err = store.GetSession(afterID)
		if err != nil {
			return fmt.Errorf("load new session: %w", err)
		}
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
	printDiff(diff, beforeSession, afterSession, severityChange)

	// --regression gate: exit 1 if any new critical/high findings
	if regression {
		for _, f := range diff.New {
			sev := f.AdjustedSeverity
			if sev == 0 {
				sev = f.Severity
			}
			if sev >= types.SeverityHigh {
				return fmt.Errorf("REGRESSION: %d new critical/high finding(s) detected", countNewHighCrit(diff.New))
			}
		}
	}

	return nil
}

// findLatestSessions returns the two most recent sessions, optionally filtered by target URL.
func findLatestSessions(store *memory.Store, targetURL string) (before, after *types.ScanSession, err error) {
	sessions, err := store.ListSessions(100)
	if err != nil {
		return nil, nil, err
	}

	var filtered []types.ScanSession
	for _, s := range sessions {
		if targetURL == "" || s.Config.Target.URL == targetURL {
			filtered = append(filtered, s)
		}
	}

	if len(filtered) < 2 {
		if targetURL != "" {
			return nil, nil, fmt.Errorf("fewer than 2 sessions found for target %q", targetURL)
		}
		return nil, nil, fmt.Errorf("fewer than 2 sessions found")
	}

	// ListSessions returns DESC order: filtered[0] = newest, filtered[1] = second newest
	after = &filtered[0]
	before = &filtered[1]
	return before, after, nil
}

func countNewHighCrit(findings []types.Finding) int {
	n := 0
	for _, f := range findings {
		sev := f.AdjustedSeverity
		if sev == 0 {
			sev = f.Severity
		}
		if sev >= types.SeverityHigh {
			n++
		}
	}
	return n
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
	for sig, afterF := range afterSigs {
		if beforeF, exists := beforeSigs[sig]; exists {
			diff.Persistent = append(diff.Persistent, afterF)

			afterSev := afterF.AdjustedSeverity
			if afterSev == 0 {
				afterSev = afterF.Severity
			}
			beforeSev := beforeF.AdjustedSeverity
			if beforeSev == 0 {
				beforeSev = beforeF.Severity
			}
			if afterSev != beforeSev {
				diff.SeverityChanged = append(diff.SeverityChanged, report.SeverityChange{
					Finding:     afterF,
					OldSeverity: beforeSev,
					NewSeverity: afterSev,
				})
			}

			if afterF.Confidence != beforeF.Confidence {
				diff.ConfidenceChanged = append(diff.ConfidenceChanged, report.ConfidenceChange{
					Finding:       afterF,
					OldConfidence: beforeF.Confidence,
					NewConfidence: afterF.Confidence,
				})
			}
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

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBold   = "\033[1m"
)

func effectiveSev(f types.Finding) types.Severity {
	if f.AdjustedSeverity != 0 {
		return f.AdjustedSeverity
	}
	return f.Severity
}

func countBySev(findings []types.Finding) map[types.Severity]int {
	m := make(map[types.Severity]int)
	for _, f := range findings {
		m[effectiveSev(f)]++
	}
	return m
}

func formatSevBreakdown(counts map[types.Severity]int) string {
	var parts []string
	for _, sev := range []types.Severity{types.SeverityCritical, types.SeverityHigh, types.SeverityMedium, types.SeverityLow, types.SeverityInfo} {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, strings.ToLower(sev.String())))
		}
	}
	if len(parts) == 0 {
		return ""
	}
	return "(" + strings.Join(parts, ", ") + ")"
}

func printDiff(diff report.DiffResult, before, after *types.ScanSession, showSeverityChange bool) {
	fmt.Println()
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("%sSCAN DIFF%s\n", colorBold, colorReset)
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("Baseline: %s (%s)\n", before.ID[:8], before.Config.Target.URL)
	fmt.Printf("Current:  %s (%s)\n", after.ID[:8], after.Config.Target.URL)
	fmt.Println()

	// Summary with severity breakdown
	fixedBySev := countBySev(diff.Fixed)
	newBySev := countBySev(diff.New)
	persistBySev := countBySev(diff.Persistent)

	fixedBreak := formatSevBreakdown(fixedBySev)
	newBreak := formatSevBreakdown(newBySev)
	persistBreak := formatSevBreakdown(persistBySev)

	regressionNote := ""
	if countNewHighCrit(diff.New) > 0 {
		regressionNote = colorRed + " (REGRESSION!)" + colorReset
	}

	fmt.Printf("%s✅ Fixed:      %d%s  %s\n", colorGreen, len(diff.Fixed), colorReset, fixedBreak)
	fmt.Printf("%s⚠️  Persistent: %d%s  %s\n", colorYellow, len(diff.Persistent), colorReset, persistBreak)
	fmt.Printf("%s🆕 New:        %d%s  %s%s\n", colorRed, len(diff.New), colorReset, newBreak, regressionNote)
	fmt.Println()

	if len(diff.Fixed) > 0 {
		fmt.Printf("%s── FIXED (Remediated) ──────────────────%s\n", colorGreen, colorReset)
		for _, f := range diff.Fixed {
			sev := effectiveSev(f)
			fmt.Printf("%s  ✅ [%s] %s%s", colorGreen, sev, f.Title, colorReset)
			if f.CVSS.Score > 0 {
				fmt.Printf(" (CVSS:%.1f)", f.CVSS.Score)
			}
			fmt.Println()
		}
		fmt.Println()
	}

	if len(diff.New) > 0 {
		fmt.Printf("%s── NEW (Regressions) ──────────────────%s\n", colorRed, colorReset)
		for _, f := range diff.New {
			sev := effectiveSev(f)
			fmt.Printf("%s  🆕 [%s] %s%s", colorRed, sev, f.Title, colorReset)
			if f.CVSS.Score > 0 {
				fmt.Printf(" (CVSS:%.1f)", f.CVSS.Score)
			}
			fmt.Println()
		}
		fmt.Println()
	}

	if len(diff.Persistent) > 0 {
		fmt.Printf("%s── PERSISTENT (Still Present) ─────────%s\n", colorYellow, colorReset)
		for _, f := range diff.Persistent {
			sev := effectiveSev(f)
			fmt.Printf("%s  ⚠️  [%s] %s%s", colorYellow, sev, f.Title, colorReset)
			if f.CVSS.Score > 0 {
				fmt.Printf(" (CVSS:%.1f)", f.CVSS.Score)
			}
			fmt.Println()
		}
		fmt.Println()
	}

	if showSeverityChange && len(diff.SeverityChanged) > 0 {
		fmt.Println("── SEVERITY CHANGES ────────────────────")
		for _, sc := range diff.SeverityChanged {
			arrow := colorYellow
			if sc.NewSeverity > sc.OldSeverity {
				arrow = colorRed
			} else {
				arrow = colorGreen
			}
			fmt.Printf("  %s↕  [%s→%s] %s%s\n", arrow, sc.OldSeverity, sc.NewSeverity, sc.Finding.Title, colorReset)
		}
		fmt.Println()
	}

	if showSeverityChange && len(diff.ConfidenceChanged) > 0 {
		fmt.Println("── CONFIDENCE CHANGES ──────────────────")
		for _, cc := range diff.ConfidenceChanged {
			arrow := colorYellow
			if cc.NewConfidence > cc.OldConfidence {
				arrow = colorRed
			} else {
				arrow = colorGreen
			}
			fmt.Printf("  %s~  [%s→%s] %s%s\n", arrow, cc.OldConfidence, cc.NewConfidence, cc.Finding.Title, colorReset)
		}
		fmt.Println()
	}
}

// ============================================================
// CI COMMAND — Exit code based on findings
// ============================================================

func newReconCmd() *cobra.Command {
	var (
		output        string
		scanAll       bool
		workers       int
		scanProfile   string
		scanProvider  string
		scanModel     string
		scanOutput    string
		rateLimit     int
	)

	cmd := &cobra.Command{
		Use:   "recon [domain]",
		Short: "Subdomain enumeration & reconnaissance",
		Long: `Enumerate subdomains using certificate transparency (crt.sh) and DNS brute-force.

Each discovered subdomain is probed for:
  • DNS resolution (A records, CNAMEs)
  • HTTP/HTTPS availability + title
  • Subdomain takeover detection (30+ service signatures)

Pipeline mode (--scan):
  Recon first → automatically scan ALL alive subdomains → combined report.

Examples:
  ouroboros recon example.com                         # Enum only
  ouroboros recon example.com --scan                  # Enum → scan all alive
  ouroboros recon example.com --scan --profile deep   # Enum → deep scan
  ouroboros recon example.com --scan -o report.html   # Enum → scan → HTML report`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			domain := args[0]
			domain = strings.TrimPrefix(domain, "https://")
			domain = strings.TrimPrefix(domain, "http://")
			domain = strings.Split(domain, "/")[0]

			if rateLimit > 0 {
				probers.SetRate(rateLimit)
			}

			fmt.Printf("\n  \033[31m╔══════════════════════════════════════════════════════╗\033[0m\n")
			fmt.Printf("  \033[31m║\033[0m\033[1m  🔍 OUROBOROS — SUBDOMAIN RECONNAISSANCE            \033[31m║\033[0m\n")
			fmt.Printf("  \033[31m╚══════════════════════════════════════════════════════╝\033[0m\n\n")
			fmt.Printf("  \033[36mDOMAIN\033[0m  %s\n", domain)
			mode := "crt.sh + DNS wordlist"
			if scanAll {
				mode += " → AUTO-SCAN"
			}
			fmt.Printf("  \033[33mMODE\033[0m    %s (%d workers)\n\n", mode, workers)
			fmt.Printf("  \033[90m──────────────────────────────────────────────────────\033[0m\n")

			fmt.Printf("  🌐 \033[33mPhase 1:\033[0m Querying crt.sh (Certificate Transparency)...\n")

			enum := recon.NewSubdomainEnum(domain, func(sub recon.Subdomain) {
				if sub.Alive {
					icon := "🟢"
					scheme := "http"
					if sub.HTTPS {
						scheme = "https"
					}
					title := ""
					if sub.HTTPTitle != "" {
						title = fmt.Sprintf(" \033[90m— %s\033[0m", sub.HTTPTitle)
					}
					fmt.Printf("  %s \033[1m%s\033[0m \033[90m(%s://) [%d]\033[0m%s\n",
						icon, sub.Name, scheme, sub.HTTPCode, title)
				} else if sub.Takeover != "" {
					fmt.Printf("  ⚠️  \033[31m%s\033[0m \033[33m%s\033[0m\n", sub.Name, sub.Takeover)
				} else {
					fmt.Printf("  ⚫ \033[90m%s (no response)\033[0m\n", sub.Name)
				}
			})

			result := enum.Run()

			// Count takeover candidates
			takeovers := 0
			for _, s := range result.Subdomains {
				if s.Takeover != "" {
					takeovers++
				}
			}

			// Recon Summary
			fmt.Printf("\n  \033[90m══════════════════════════════════════════════════════\033[0m\n")
			fmt.Printf("  \033[36m📋 RECON COMPLETE\033[0m\n")
			fmt.Printf("  \033[90m──────────────────────────────────────────────────────\033[0m\n")
			fmt.Printf("  Domain:     %s\n", result.Domain)
			fmt.Printf("  Duration:   %s\n", result.Duration)
			fmt.Printf("  Subdomains: \033[1m%d\033[0m found, \033[32m%d alive\033[0m, \033[90m%d dead\033[0m\n",
				result.Total, result.Alive, result.Total-result.Alive)
			if takeovers > 0 {
				fmt.Printf("  Takeover:   \033[31m%d potential\033[0m\n", takeovers)
			}
			fmt.Printf("  \033[90m══════════════════════════════════════════════════════\033[0m\n\n")

			// Save recon report
			if output != "" && !scanAll {
				writeReconReport(output, result, takeovers)
				fmt.Printf("  Report saved: %s\n\n", output)
			}

			// AUTO-SCAN MODE: scan all alive subdomains
			if scanAll && result.Alive > 0 {
				fmt.Printf("  \033[31m╔══════════════════════════════════════════════════════╗\033[0m\n")
				fmt.Printf("  \033[31m║\033[0m\033[1m  🐍 OUROBOROS — SCANNING %d ALIVE SUBDOMAINS        \033[31m║\033[0m\n", result.Alive)
				fmt.Printf("  \033[31m╚══════════════════════════════════════════════════════╝\033[0m\n\n")

				// Determine scan params from profile
				maxLoops := 3
				finalBoss := false
				minConfidence := 0
				minCVSS := 0.0
				switch scanProfile {
				case "quick":
					maxLoops = 1
				case "deep":
					maxLoops = 3
					minConfidence = 25
					minCVSS = 3.0
				case "paranoid":
					maxLoops = 5
					finalBoss = true
					minConfidence = 25
					minCVSS = 3.0
				}

				var allFindings []types.Finding
				scannedCount := 0

				for _, sub := range result.Subdomains {
					if !sub.Alive {
						continue
					}

					scheme := "http"
					if sub.HTTPS {
						scheme = "https"
					}
					targetURL := fmt.Sprintf("%s://%s", scheme, sub.Name)

					scannedCount++
					fmt.Printf("  \033[33m━━━ [%d/%d] Scanning %s ━━━\033[0m\n\n",
						scannedCount, result.Alive, sub.Name)

					// Build per-subdomain output path if needed
					subOutput := ""
					if scanOutput != "" {
						ext := ".md"
						if strings.Contains(scanOutput, ".") {
							parts := strings.Split(scanOutput, ".")
							ext = "." + parts[len(parts)-1]
						}
						subOutput = fmt.Sprintf("%s-%s%s",
							strings.TrimSuffix(scanOutput, ext), sub.Name, ext)
					}

					err := runScan(targetURL, maxLoops, finalBoss, false, false, scanProvider, scanModel,
						subOutput, minConfidence, minCVSS, "cvss", types.AuthConfig{}, scanOpts{})
					if err != nil {
						fmt.Printf("  \033[31m✗ Error scanning %s: %v\033[0m\n\n", sub.Name, err)
						continue
					}

					// Collect findings from the session (read from DB)
					store, err := memory.NewStore("")
					if err == nil {
						sessions, _ := store.ListSessions(1)
						if len(sessions) > 0 {
							// Get most recent session findings
							latest := sessions[len(sessions)-1]
							findings, _ := store.GetSessionFindings(latest.ID)
							for i := range findings {
								findings[i].Endpoint = sub.Name + findings[i].Endpoint
							}
							allFindings = append(allFindings, findings...)
						}
						store.Close()
					}
				}

				// Combined summary
				fmt.Printf("\n  \033[31m╔══════════════════════════════════════════════════════╗\033[0m\n")
				fmt.Printf("  \033[31m║\033[0m\033[1m  📊 COMBINED RESULTS — %s\033[0m", domain)
				padding := 53 - 22 - len(domain)
				if padding > 0 {
					fmt.Printf("%s", strings.Repeat(" ", padding))
				}
				fmt.Printf("\033[31m║\033[0m\n")
				fmt.Printf("  \033[31m╚══════════════════════════════════════════════════════╝\033[0m\n\n")

				// Count by severity
				sevCount := map[string]int{}
				for _, f := range allFindings {
					sevCount[f.Severity.String()]++
				}
				fmt.Printf("  Subdomains scanned: %d\n", scannedCount)
				fmt.Printf("  Total findings:     %d\n", len(allFindings))
				fmt.Printf("  Severity: \033[31;1m%d crit\033[0m \033[31m%d high\033[0m \033[33m%d med\033[0m \033[34m%d low\033[0m \033[90m%d info\033[0m\n",
					sevCount["Critical"], sevCount["High"], sevCount["Medium"], sevCount["Low"], sevCount["Info"])

				if takeovers > 0 {
					fmt.Printf("\n  ⚠️  \033[31mSubdomain Takeover Candidates:\033[0m\n")
					for _, s := range result.Subdomains {
						if s.Takeover != "" {
							fmt.Printf("     \033[33m%s\033[0m → %s\n", s.Name, s.Takeover)
						}
					}
				}

				// Write combined report
				if output != "" {
					writeCombinedReport(output, domain, result, allFindings, takeovers)
					fmt.Printf("\n  Combined report saved: %s\n", output)
				}

				fmt.Printf("\n  \033[90m══════════════════════════════════════════════════════\033[0m\n\n")
			} else if scanAll && result.Alive == 0 {
				fmt.Printf("  \033[33mNo alive subdomains to scan.\033[0m\n\n")
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file (.json or .md/.html)")
	cmd.Flags().BoolVar(&scanAll, "scan", false, "Auto-scan all alive subdomains after recon")
	cmd.Flags().IntVar(&workers, "workers", 20, "Concurrent workers for DNS/HTTP probing")
	cmd.Flags().StringVar(&scanProfile, "profile", "quick", "Scan profile for --scan: quick, deep, paranoid")
	cmd.Flags().StringVar(&scanProvider, "provider", "openai", "AI provider for scanning")
	cmd.Flags().StringVar(&scanModel, "model", "gpt-4o", "AI model for scanning")
	cmd.Flags().StringVar(&scanOutput, "scan-output", "", "Per-subdomain scan report prefix")
	cmd.Flags().IntVar(&rateLimit, "rate", 10, "Max requests per second (0 = unlimited)")

	return cmd
}

// writeReconReport writes a recon-only report.
func writeReconReport(output string, result *recon.EnumResult, takeovers int) {
	if strings.HasSuffix(output, ".json") {
		data, _ := json.MarshalIndent(result, "", "  ")
		os.WriteFile(output, data, 0644)
		return
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# Subdomain Enumeration — %s\n\n", result.Domain))
	sb.WriteString(fmt.Sprintf("**Total:** %d | **Alive:** %d | **Duration:** %s\n\n", result.Total, result.Alive, result.Duration))

	sb.WriteString("## Alive Subdomains\n\n")
	sb.WriteString("| Subdomain | IPs | HTTP | Title | Source |\n")
	sb.WriteString("|-----------|-----|------|-------|--------|\n")
	for _, s := range result.Subdomains {
		if !s.Alive {
			continue
		}
		scheme := "http"
		if s.HTTPS {
			scheme = "https"
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s %d | %s | %s |\n",
			s.Name, strings.Join(s.IPs, ", "), scheme, s.HTTPCode, s.HTTPTitle, s.Source))
	}

	if takeovers > 0 {
		sb.WriteString("\n## ⚠️ Potential Subdomain Takeovers\n\n")
		for _, s := range result.Subdomains {
			if s.Takeover != "" {
				sb.WriteString(fmt.Sprintf("- **%s** — %s (CNAME: %s)\n",
					s.Name, s.Takeover, strings.Join(s.CNAMEs, ", ")))
			}
		}
	}

	sb.WriteString("\n## Dead Subdomains\n\n")
	for _, s := range result.Subdomains {
		if s.Alive || s.Takeover != "" {
			continue
		}
		sb.WriteString(fmt.Sprintf("- %s (%s)\n", s.Name, s.Source))
	}

	os.WriteFile(output, []byte(sb.String()), 0644)
}

// writeCombinedReport writes a combined recon + scan report.
func writeCombinedReport(output, domain string, reconResult *recon.EnumResult, findings []types.Finding, takeovers int) {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# 🐍 Ouroboros — Full Recon + Scan Report\n\n"))
	sb.WriteString(fmt.Sprintf("**Domain:** %s\n", domain))
	sb.WriteString(fmt.Sprintf("**Subdomains:** %d found, %d alive\n", reconResult.Total, reconResult.Alive))
	sb.WriteString(fmt.Sprintf("**Total Findings:** %d\n\n", len(findings)))

	// Recon section
	sb.WriteString("## 🔍 Subdomain Enumeration\n\n")
	sb.WriteString("| Subdomain | Status | Title | Source |\n")
	sb.WriteString("|-----------|--------|-------|--------|\n")
	for _, s := range reconResult.Subdomains {
		status := "⚫ Dead"
		title := "-"
		if s.Alive {
			status = fmt.Sprintf("🟢 %d", s.HTTPCode)
			title = s.HTTPTitle
		} else if s.Takeover != "" {
			status = "⚠️ Takeover?"
		}
		sb.WriteString(fmt.Sprintf("| %s | %s | %s | %s |\n", s.Name, status, title, s.Source))
	}

	if takeovers > 0 {
		sb.WriteString("\n### ⚠️ Subdomain Takeover Candidates\n\n")
		for _, s := range reconResult.Subdomains {
			if s.Takeover != "" {
				sb.WriteString(fmt.Sprintf("- **%s** — %s\n", s.Name, s.Takeover))
			}
		}
	}

	// Findings section grouped by severity
	sb.WriteString("\n## 🎯 Vulnerability Findings\n\n")
	sevOrder := []string{"Critical", "High", "Medium", "Low", "Info"}
	for _, sev := range sevOrder {
		var sevFindings []types.Finding
		for _, f := range findings {
			if f.Severity.String() == sev {
				sevFindings = append(sevFindings, f)
			}
		}
		if len(sevFindings) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("### %s (%d)\n\n", sev, len(sevFindings)))
		for _, f := range sevFindings {
			sb.WriteString(fmt.Sprintf("- **%s** — `%s %s` (CVSS %.1f, Confidence %d%%)\n",
				f.Title, f.Method, f.Endpoint, f.CVSS.Score, f.Confidence))
		}
		sb.WriteString("\n")
	}

	os.WriteFile(output, []byte(sb.String()), 0644)
}

func newCICmd() *cobra.Command {
	var (
		maxLoops      int
		provider      string
		model         string
		output        string
		failOn        string
		minConfidence int
		baseline      string
		githubPR      int
		githubRepo    string
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
  ouroboros ci http://staging.example.com --baseline abc123 --fail-on high
  ouroboros ci http://staging.example.com --github-pr 42 --github-repo owner/repo`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			targetURL := args[0]
			return runCI(targetURL, maxLoops, provider, model, output, failOn, minConfidence, baseline, githubPR, githubRepo)
		},
	}

	cmd.Flags().IntVar(&maxLoops, "max-loops", 2, "Maximum loops (default 2 for speed)")
	cmd.Flags().StringVar(&provider, "provider", "anthropic", "AI provider")
	cmd.Flags().StringVar(&model, "model", "claude-sonnet-4-20250514", "AI model")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Export report file")
	cmd.Flags().StringVar(&failOn, "fail-on", "high", "Fail threshold: critical, high, medium, low, info")
	cmd.Flags().IntVar(&minConfidence, "min-confidence", 50, "Only count findings with this confidence+")
	cmd.Flags().StringVar(&baseline, "baseline", "", "Baseline session — only fail on NEW findings")
	cmd.Flags().IntVar(&githubPR, "github-pr", 0, "GitHub PR number to post scan summary as a comment")
	cmd.Flags().StringVar(&githubRepo, "github-repo", "", "GitHub repository in owner/repo format for PR comments")

	return cmd
}

func runCI(targetURL string, maxLoops int, providerName, model, output, failOn string, minConf int, baselineID string, githubPR int, githubRepo string) error {
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
	if apiKey == "" && providerName != "ollama" && providerName != "claude-code" && providerName != "claudecode" && providerName != "claude" {
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

	// Post GitHub PR comment if configured
	if githubPR > 0 && githubRepo != "" {
		ghClient := integrations.NewGitHubClient(integrations.GitHubConfig{
			Repo:     githubRepo,
			PRNumber: githubPR,
		})
		if err := ghClient.PostPRComment(findings, session, threshold, failCount, nil); err != nil {
			logger.Printf("Warning: GitHub PR comment failed: %v", err)
		} else {
			fmt.Printf("📝 Posted scan summary to PR #%d\n", githubPR)
		}
	}

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

// ============================================================
// PLUGINS COMMAND — Manage custom YAML probers
// ============================================================

func newPluginsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugins",
		Short: "Manage custom YAML plugin probers",
	}
	cmd.AddCommand(newPluginsListCmd())
	cmd.AddCommand(newPluginsValidateCmd())
	return cmd
}

func newPluginsListCmd() *cobra.Command {
	var pluginsDir string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List loaded custom plugins",
		RunE: func(cmd *cobra.Command, args []string) error {
			dir := pluginsDir
			if dir == "" {
				dir = plugin.DefaultPluginsDir()
			}
			proberList, err := plugin.LoadPlugins(dir)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warning: %v\n", err)
			}
			if len(proberList) == 0 {
				fmt.Printf("No plugins found in %s\n", dir)
				fmt.Println("Create *.yaml files there to add custom probers.")
				fmt.Println("See examples/plugins/ for the file format.")
				return nil
			}
			fmt.Printf("Plugins loaded from %s:\n\n", dir)
			for _, p := range proberList {
				fmt.Printf("  %s\n", p.Name())
			}
			fmt.Printf("\n%d plugin(s) total\n", len(proberList))
			return nil
		},
	}
	cmd.Flags().StringVar(&pluginsDir, "plugins-dir", "", "Plugin directory (default: ~/.ouroboros/plugins/)")
	return cmd
}

func newPluginsValidateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "validate <file.yaml>",
		Short: "Validate a plugin YAML file",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("read file: %w", err)
			}
			def, err := plugin.ParsePluginFile(data)
			if err != nil {
				return fmt.Errorf("parse error: %w", err)
			}
			if err := plugin.ValidatePluginDef(def); err != nil {
				return fmt.Errorf("validation failed: %w", err)
			}
			fmt.Printf("✅ Plugin valid: %q\n", def.Name)
			fmt.Printf("   Description: %s\n", def.Description)
			fmt.Printf("   Severity:    %s\n", def.Severity)
			fmt.Printf("   CWE:         %s\n", def.CWE)
			fmt.Printf("   Requests:    %d\n", len(def.Requests))
			fmt.Printf("   Matchers:    %d\n", len(def.Matchers))
			fmt.Printf("   Extractors:  %d\n", len(def.Extractors))
			return nil
		},
	}
	return cmd
}

// ============================================================
// SCHEDULE COMMAND — Recurring scan scheduling
// ============================================================

func newScheduleCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "schedule",
		Short: "Manage recurring scan schedules",
		Long: `Schedule recurring scans using cron expressions.

Examples:
  ouroboros schedule add --target http://example.com --cron '@daily'
  ouroboros schedule add --target http://example.com --cron '0 */6 * * *' --webhook https://...
  ouroboros schedule list
  ouroboros schedule remove 1
  ouroboros schedule run`,
	}
	cmd.AddCommand(newScheduleAddCmd())
	cmd.AddCommand(newScheduleListCmd())
	cmd.AddCommand(newScheduleRemoveCmd())
	cmd.AddCommand(newScheduleRunCmd())
	return cmd
}

func newScheduleAddCmd() *cobra.Command {
	var (
		target   string
		profile  string
		provider string
		model    string
		cron     string
		webhook  string
	)

	cmd := &cobra.Command{
		Use:   "add",
		Short: "Add a recurring scan schedule",
		RunE: func(cmd *cobra.Command, args []string) error {
			if target == "" {
				return fmt.Errorf("--target is required")
			}
			if cron == "" {
				return fmt.Errorf("--cron is required")
			}
			if profile == "" {
				profile = "deep"
			}
			if provider == "" {
				provider = "anthropic"
			}
			if model == "" {
				model = "claude-sonnet-4-20250514"
			}

			store, err := memory.NewStore("")
			if err != nil {
				return fmt.Errorf("initialize store: %w", err)
			}
			defer store.Close()

			r := scheduler.NewRunner(store.DB(), nil)
			cfg := scheduler.ScheduleConfig{
				Target:   target,
				Profile:  profile,
				Provider: provider,
				Model:    model,
				Cron:     cron,
				Webhook:  webhook,
			}
			id, err := r.AddSchedule(context.Background(), cfg)
			if err != nil {
				return fmt.Errorf("add schedule: %w", err)
			}
			fmt.Printf("✅ Schedule #%d added\n", id)
			fmt.Printf("   Target:  %s\n", target)
			fmt.Printf("   Cron:    %s\n", cron)
			fmt.Printf("   Profile: %s\n", profile)
			if webhook != "" {
				fmt.Printf("   Webhook: %s\n", webhook)
			}
			fmt.Println("\nRun 'ouroboros schedule run' to start the scheduler daemon.")
			return nil
		},
	}

	cmd.Flags().StringVar(&target, "target", "", "Target URL to scan (required)")
	cmd.Flags().StringVar(&cron, "cron", "", "Cron expression: @daily, @hourly, or '0 * * * *' (required)")
	cmd.Flags().StringVar(&profile, "profile", "deep", "Scan profile: quick, deep, paranoid")
	cmd.Flags().StringVar(&provider, "provider", "anthropic", "AI provider")
	cmd.Flags().StringVar(&model, "model", "claude-sonnet-4-20250514", "AI model")
	cmd.Flags().StringVar(&webhook, "webhook", "", "Webhook URL for notifications")
	return cmd
}

func newScheduleListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all configured schedules",
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := memory.NewStore("")
			if err != nil {
				return fmt.Errorf("initialize store: %w", err)
			}
			defer store.Close()

			r := scheduler.NewRunner(store.DB(), nil)
			schedules, err := r.ListSchedules()
			if err != nil {
				return fmt.Errorf("list schedules: %w", err)
			}
			if len(schedules) == 0 {
				fmt.Println("No schedules configured.")
				fmt.Println("Use 'ouroboros schedule add' to create one.")
				return nil
			}
			fmt.Printf("%-4s  %-30s  %-20s  %-10s  %s\n", "ID", "Target", "Cron", "Profile", "Webhook")
			fmt.Println(strings.Repeat("-", 90))
			for _, s := range schedules {
				wh := s.Webhook
				if len(wh) > 30 {
					wh = wh[:27] + "..."
				}
				tgt := s.Target
				if len(tgt) > 28 {
					tgt = tgt[:25] + "..."
				}
				fmt.Printf("%-4d  %-30s  %-20s  %-10s  %s\n", s.ID, tgt, s.Cron, s.Profile, wh)
			}
			return nil
		},
	}
}

func newScheduleRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <id>",
		Short: "Remove a schedule by ID",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := strconv.ParseInt(args[0], 10, 64)
			if err != nil {
				return fmt.Errorf("invalid schedule ID %q: %w", args[0], err)
			}

			store, err := memory.NewStore("")
			if err != nil {
				return fmt.Errorf("initialize store: %w", err)
			}
			defer store.Close()

			r := scheduler.NewRunner(store.DB(), nil)
			if err := r.RemoveSchedule(id); err != nil {
				return fmt.Errorf("remove schedule: %w", err)
			}
			fmt.Printf("✅ Schedule #%d removed\n", id)
			return nil
		},
	}
}

func newScheduleRunCmd() *cobra.Command {
	var daemon bool

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start the scheduler daemon",
		Long: `Start the scheduler daemon and run configured schedules.

The daemon runs in the foreground by default. Use --daemon to background it.
Each scheduled scan creates a new session accessible via 'ouroboros report'.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := memory.NewStore("")
			if err != nil {
				return fmt.Errorf("initialize store: %w", err)
			}
			defer store.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
			go func() {
				<-sigCh
				fmt.Println("\nShutting down scheduler...")
				cancel()
			}()

			// scanFn is called by the scheduler for each fired job.
			scanFn := func(cfg scheduler.ScheduleConfig) (string, error) {
				logger := log.New(os.Stderr, fmt.Sprintf("[schedule#%d] ", cfg.ID), log.LstdFlags)
				logger.Printf("Starting scheduled scan: %s", cfg.Target)
				opts := scanOpts{}
				if cfg.Webhook != "" {
					opts.webhook = cfg.Webhook
				}
				err := runScan(cfg.Target, 3, false, false, false,
					cfg.Provider, cfg.Model, "", 0, 0, "cvss",
					types.AuthConfig{}, opts)
				if err != nil {
					logger.Printf("Scheduled scan failed: %v", err)
					return "", err
				}
				return "", nil
			}

			r := scheduler.NewRunner(store.DB(), scanFn)

			schedules, err := r.ListSchedules()
			if err != nil {
				return fmt.Errorf("load schedules: %w", err)
			}
			if len(schedules) == 0 {
				fmt.Println("No schedules configured. Use 'ouroboros schedule add' to create one.")
				return nil
			}

			fmt.Printf("Ouroboros scheduler started with %d job(s). Press Ctrl+C to stop.\n", len(schedules))
			for _, s := range schedules {
				fmt.Printf("  #%d  %s  [%s]\n", s.ID, s.Target, s.Cron)
			}
			fmt.Println()

			if daemon {
				// Background: hand off to Start and return immediately.
				go func() { _ = r.Start(ctx) }()
				fmt.Println("Scheduler running in background.")
				// In a real daemon you would detach the process; here we just run.
				<-ctx.Done()
				return nil
			}

			return r.Start(ctx)
		},
	}

	cmd.Flags().BoolVar(&daemon, "daemon", false, "Run scheduler in background")
	return cmd
}

// ============================================================
// SERVE COMMAND — REST API server mode
// ============================================================

func newServeCmd() *cobra.Command {
	var (
		port        int
		apiKey      string
		corsOrigins string
	)

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the Ouroboros REST API server",
		Long: `Start Ouroboros as a REST API server for integration with external platforms
(e.g. Bima Red ASM).

The server exposes a JSON REST API for managing scans, retrieving findings,
computing diffs, and streaming real-time progress via Server-Sent Events.

Examples:
  ouroboros serve --port 8080 --api-key secret
  ouroboros serve --port 8080 --cors-origins 'https://app.bimarted.com'
  OUROBOROS_API_KEY=secret ouroboros serve

Endpoints:
  POST   /api/v1/scans           Start a new scan
  GET    /api/v1/scans           List all scans
  GET    /api/v1/scans/:id       Scan details + progress
  GET    /api/v1/scans/:id/findings  Findings (filterable, paginated)
  DELETE /api/v1/scans/:id       Cancel a scan
  GET    /api/v1/scans/:id/report    Full JSON report
  GET    /api/v1/scans/:id/stream    SSE live progress stream
  POST   /api/v1/diff            Compare two scans
  GET    /api/v1/health          Health check
  GET    /api/v1/status          System status`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Allow API key from env if not passed as flag
			if apiKey == "" {
				apiKey = os.Getenv("OUROBOROS_API_KEY")
			}

			store, err := memory.NewStore("")
			if err != nil {
				return fmt.Errorf("initialize store: %w", err)
			}
			defer store.Close()

			srv := ourobapi.NewServer(store, port, apiKey, corsOrigins, version)
			return srv.ListenAndServe()
		},
	}

	cmd.Flags().IntVar(&port, "port", 8080, "Port to listen on")
	cmd.Flags().StringVar(&apiKey, "api-key", "", "API key for authentication (or set OUROBOROS_API_KEY env)")
	cmd.Flags().StringVar(&corsOrigins, "cors-origins", "*", "Allowed CORS origins (comma-separated, or '*' for all)")

	return cmd
}
