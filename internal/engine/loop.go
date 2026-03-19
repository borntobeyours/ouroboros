package engine

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/borntobeyours/ouroboros/internal/ai"
	"github.com/borntobeyours/ouroboros/internal/auth"
	"github.com/borntobeyours/ouroboros/internal/blue"
	"github.com/borntobeyours/ouroboros/internal/boss"
	"github.com/borntobeyours/ouroboros/internal/memory"
	"github.com/borntobeyours/ouroboros/internal/notify"
	"github.com/borntobeyours/ouroboros/internal/plugin"
	"github.com/borntobeyours/ouroboros/internal/recon"
	"github.com/borntobeyours/ouroboros/internal/red"
	"github.com/borntobeyours/ouroboros/internal/red/probers"
	"github.com/borntobeyours/ouroboros/internal/report"
	"github.com/borntobeyours/ouroboros/pkg/types"
)

// EventCallbackFn is called by the engine at key progress points.
// eventType is "progress" or "finding"; phase is the current scan phase;
// loop is the current iteration; findingsCount is the cumulative total.
type EventCallbackFn func(eventType, phase string, loop, findingsCount int)

// Engine orchestrates the Red → Blue → Re-attack loop.
type Engine struct {
	redAgent      *red.Agent
	blueAgent     *blue.Agent
	bossAgent     *boss.Agent
	store         *memory.Store
	reporter      *report.Reporter
	logger        *log.Logger
	notifier      *notify.Notifier // optional; nil means no webhook
	eventCallback EventCallbackFn  // optional; nil means no callback

	// Smart template filtering
	aiProvider   ai.Provider
	pluginProbers []*plugin.PluginProber
	aiFilter     *plugin.AIFilter
}

// NewEngine creates a new loop engine.
func NewEngine(redAgent *red.Agent, blueAgent *blue.Agent, bossAgent *boss.Agent, store *memory.Store, reporter *report.Reporter, logger *log.Logger) *Engine {
	return &Engine{
		redAgent:  redAgent,
		blueAgent: blueAgent,
		bossAgent: bossAgent,
		store:     store,
		reporter:  reporter,
		logger:    logger,
	}
}

// SetNotifier attaches a webhook notifier to the engine.
func (e *Engine) SetNotifier(n *notify.Notifier) {
	e.notifier = n
}

// SetEventCallback attaches an optional progress callback used by the API server
// to push real-time SSE events. Set to nil to disable (the default).
func (e *Engine) SetEventCallback(cb EventCallbackFn) {
	e.eventCallback = cb
}

// SetAIProvider stores the AI provider so the engine can use it for smart
// template filtering.  Call this before Run().
func (e *Engine) SetAIProvider(p ai.Provider) {
	e.aiProvider = p
}

// SetPluginProbers stores unregistered plugin probers for smart filtering.
// The engine will filter and register them after the recon phase.
// Do NOT call probers.RegisterProbers() in addition; the engine owns registration.
func (e *Engine) SetPluginProbers(ps []*plugin.PluginProber) {
	e.pluginProbers = ps
	e.aiFilter = plugin.NewAIFilter()
}

// emitEvent calls the event callback if one is set.
func (e *Engine) emitEvent(eventType, phase string, loop, findingsCount int) {
	if e.eventCallback != nil {
		e.eventCallback(eventType, phase, loop, findingsCount)
	}
}

// Run executes the full attack-fix-reattack loop.
func (e *Engine) Run(ctx context.Context, config types.ScanConfig) (*types.ScanSession, error) {
	session := types.NewScanSession(config)
	convergence := NewConvergenceChecker(3)

	// Live view for attack visualization
	lv := report.NewLiveView(config.Target.URL)
	lv.PrintAttackHeader(session.ID, config.MaxLoops, config.Provider)

	// Start progress spinner
	progress := report.NewProgress(config.MaxLoops, config.Verbose)
	progress.Start()
	defer progress.Stop()

	// Redirect logger through progress
	logWriter := &report.LogWriter{Progress: progress}
	e.logger.SetOutput(logWriter)

	var allFindings []types.Finding
	var allPatches []types.Patch

	// === RECON PHASE (Phase 0) ===
	var reconResult *types.ReconResult
	if config.ReconConfig.Enabled {
		progress.SetPhase("Recon")
		progress.SetStep("Running reconnaissance modules...")
		lv.PrintPhase(0, config.MaxLoops, "recon")

		orch := recon.NewOrchestrator(config.Target.URL, config.ReconConfig, config.Target.Headers, e.logger)
		orch.SetEventCallback(func(event string) {
			progress.SetStep(event)
			progress.Emit("RECON", event, false)
		})

		reconResult = orch.Run()

		// Display recon summary
		progress.Stop()
		printReconSummary(reconResult)
		progress = report.NewProgress(config.MaxLoops, config.Verbose)
		progress.Start()
	}

	// === PLUGIN FILTERING ===
	// Decide which templates are relevant based on the detected tech stack.
	// This step replaces the blanket "run everything" approach.
	if len(e.pluginProbers) > 0 {
		progress.SetPhase("Plugins")
		progress.SetStep("Filtering templates by tech stack...")

		var techs []types.TechFingerprint
		if reconResult != nil {
			techs = reconResult.Technologies
		}

		var filtered []*plugin.PluginProber

		switch {
		case config.AllTemplates:
			// --all-templates: skip filtering, run everything.
			filtered = e.pluginProbers

		case len(config.TemplateTags) > 0:
			// --template-tags: manual tech tag override.
			filtered = plugin.FilterByTags(e.pluginProbers, config.TemplateTags)

		case e.aiFilter != nil && e.aiProvider != nil:
			// AI-powered selection; falls back to tag-based internally.
			filtered = e.aiFilter.Filter(ctx, e.aiProvider, e.pluginProbers, techs)

		default:
			// Tag-based fallback (no AI provider configured).
			filtered = plugin.FilterByTechnology(e.pluginProbers, techs)
		}

		// Register the filtered set so the Red agent uses them during attack.
		probers.SetPluginProbers(plugin.ToProbers(filtered))

		// Log the result.
		techNames := make([]string, 0, len(techs))
		for _, t := range techs {
			techNames = append(techNames, t.Name)
		}
		techStr := "none detected"
		if len(techNames) > 0 {
			techStr = strings.Join(techNames, ", ")
		}
		e.logger.Printf("[PLUGINS] %d templates loaded, %d relevant for [%s]",
			len(e.pluginProbers), len(filtered), techStr)
	}

	// === AUTH PHASE ===
	ac := config.AuthConfig
	if !ac.NoAuth && (ac.Username != "" || ac.Token != "" || len(ac.Headers) > 0 || len(ac.Cookies) > 0 || ac.Method != "") {
		progress.SetPhase("Auth")
		progress.SetStep("Authenticating...")

		authenticator := auth.NewAuthenticator(ac, config.Target.URL, nil)
		authSession, authErr := authenticator.Authenticate(ctx)
		if authErr != nil {
			progress.Stop()
			e.reporter.PrintError(fmt.Sprintf("Auth failed (continuing unauthenticated): %v", authErr))
			progress = report.NewProgress(config.MaxLoops, config.Verbose)
			progress.Start()
		} else if authSession.IsValid() {
			e.logger.Printf("[AUTH] Authentication successful (method: %s)", authSession.Method)
			probers.SetAuthSession(authSession)
			e.redAgent.SetAuth(authSession)

			// Wire refresh so mid-scan re-auth is possible
			authSession.SetRefresh(func(rCtx context.Context) (*auth.AuthSession, error) {
				return auth.NewAuthenticator(ac, config.Target.URL, nil).Authenticate(rCtx)
			})
		}
	}

	for loop := 1; loop <= config.MaxLoops; loop++ {
		select {
		case <-ctx.Done():
			return session, ctx.Err()
		default:
		}

		loopResult := types.LoopResult{
			Iteration: loop,
			StartedAt: time.Now(),
		}

		// === CRAWL PHASE ===
		progress.SetLoop(loop)
		progress.SetPhase("Crawling")
		progress.SetStep("Discovering endpoints...")
		e.emitEvent("progress", "Crawling", loop, len(allFindings))

		// Feed recon-discovered URLs directly into attack target
		attackTarget := config.Target
		if reconResult != nil && len(reconResult.DiscoveredURLs) > 0 {
			attackTarget.ReconURLs = reconResult.DiscoveredURLs
			e.logger.Printf("[ENGINE] Feeding %d recon URLs to Red AI", len(reconResult.DiscoveredURLs))
		}

		// === ATTACK PHASE ===
		findings, err := e.redAgent.Attack(ctx, attackTarget, allFindings, allPatches, loop)
		if err != nil {
			progress.Stop()
			e.reporter.PrintError(fmt.Sprintf("Red AI error: %v", err))
			progress = report.NewProgress(config.MaxLoops, config.Verbose)
			progress.Start()
			loopResult.FinishedAt = time.Now()
			session.Loops = append(session.Loops, loopResult)
			continue
		}

		// Filter new findings
		newFindings := convergence.FilterNew(findings)
		loopResult.Findings = newFindings
		loopResult.NewFindings = len(newFindings)
		progress.AddFindings(len(newFindings))
		if len(newFindings) > 0 {
			e.emitEvent("finding", "Attack", loop, len(allFindings)+len(newFindings))
		}

		// === DISPLAY FINDINGS ===
		progress.Stop()

		lv.PrintPhase(loop, config.MaxLoops, "probe")
		if len(newFindings) > 0 {
			for _, f := range newFindings {
				lv.PrintFindingLive(f)
			}
		} else {
			fmt.Println("  → No new findings")
		}

		progress = report.NewProgress(config.MaxLoops, config.Verbose)
		progress.SetLoop(loop)
		progress.Start()

		// Record findings
		for _, f := range newFindings {
			if err := e.store.SaveFinding(session.ID, f); err != nil {
				// silently continue
			}
			if f.Technique != "" && f.PoC != "" {
				_ = e.store.RecordPlaybookEntry(f.Technique, "", f.PoC)
			}
		}

		allFindings = append(allFindings, newFindings...)

		// Check convergence
		if convergence.HasConverged(loop, len(newFindings)) {
			progress.Stop()
			lv.PrintConvergenceLive(loop, convergence.TotalUnique())
			session.Converged = true
			loopResult.FinishedAt = time.Now()
			session.Loops = append(session.Loops, loopResult)
			progress = report.NewProgress(config.MaxLoops, config.Verbose)
			progress.Start()
			break
		}

		// === DEFEND PHASE ===
		// Filter: only send non-template findings to Blue AI
		var aiFindings []types.Finding
		for _, f := range newFindings {
			if !strings.HasPrefix(f.Technique, "plugin:") {
				aiFindings = append(aiFindings, f)
			}
		}
		templateCount := len(newFindings) - len(aiFindings)
		if templateCount > 0 {
			e.logger.Printf("[ENGINE] %d findings from templates (skip Blue AI), %d from probers/AI (analyze)", templateCount, len(aiFindings))
		}
		e.emitEvent("progress", "Defending", loop, len(allFindings))
		if config.SkipBlue && len(aiFindings) > 0 {
			e.logger.Printf("[ENGINE] Blue AI skipped (--skip-blue)")
		}
		if len(aiFindings) > 0 && !config.SkipBlue {
			progress.SetPhase("Defending")
			progress.SetStep("Blue AI analyzing...")

			patches, err := e.blueAgent.Defend(ctx, aiFindings)
			if err != nil {
				progress.Stop()
				e.reporter.PrintError(fmt.Sprintf("Blue AI: %v", err))
				progress = report.NewProgress(config.MaxLoops, config.Verbose)
				progress.Start()
			} else {
				loopResult.Patches = patches
				allPatches = append(allPatches, patches...)
				for _, p := range patches {
					_ = e.store.SavePatch(session.ID, p)
				}
			}
		}

		loopResult.FinishedAt = time.Now()
		session.Loops = append(session.Loops, loopResult)
	}

	// === FINAL BOSS ===
	if config.FinalBoss && e.bossAgent != nil {
		progress.Stop()
		fmt.Println()
		lv.PrintPhase(0, 0, "boss")

		// Hook boss events into liveview
		e.bossAgent.SetEventCallback(func(event string) {
			fmt.Printf("  %s\n", event)
		})

		// Boss validates + finds new vulns + removes false positives
		bossFindings, err := e.bossAgent.Validate(ctx, config.Target, allFindings, allPatches)
		if err != nil {
			e.reporter.PrintError(fmt.Sprintf("Final Boss: %v", err))
		} else {
			// Get re-validated findings (false positives removed)
			validatedOld := e.bossAgent.GetValidatedFindings(ctx, config.Target, allFindings)
			removed := len(allFindings) - len(validatedOld)
			allFindings = validatedOld

			// Add new boss findings
			newBoss := convergence.FilterNew(bossFindings)
			for _, f := range newBoss {
				lv.PrintFindingLive(f)
			}
			allFindings = append(allFindings, newBoss...)

			if removed > 0 {
				fmt.Printf("  🗑️  Removed %d false positives\n", removed)
			}
			fmt.Printf("  ✅ %d validated findings + %d new from Final Boss\n", len(validatedOld), len(newBoss))
		}
	}

	// === SUMMARY ===
	progress.Stop()

	session.FinishedAt = time.Now()
	session.TotalFindings = len(allFindings)

	if err := e.store.SaveSession(session); err != nil {
		// silently continue
	}

	lv.PrintSummaryBox(session, allFindings)

	// === WEBHOOK NOTIFICATION ===
	if e.notifier != nil {
		e.notifier.NotifyScanComplete(session, allFindings)
	}

	return session, nil
}

// printReconSummary displays recon results in the terminal.
func printReconSummary(r *types.ReconResult) {
	if r == nil {
		return
	}
	fmt.Println()
	if len(r.Ports) > 0 {
		fmt.Printf("  📡 Open ports: %d", len(r.Ports))
		if len(r.Ports) <= 10 {
			parts := make([]string, len(r.Ports))
			for i, p := range r.Ports {
				parts[i] = fmt.Sprintf("%d/%s", p.Port, p.Service)
			}
			fmt.Printf(" (%s)", joinStrs(parts, ", "))
		}
		fmt.Println()
	}
	if len(r.Technologies) > 0 {
		parts := make([]string, 0, len(r.Technologies))
		for _, t := range r.Technologies {
			s := t.Name
			if t.Version != "" {
				s += "/" + t.Version
			}
			parts = append(parts, s)
		}
		fmt.Printf("  🔧 Technologies: %s\n", joinStrs(parts, ", "))
	}
	if len(r.JSEndpoints) > 0 {
		fmt.Printf("  📜 JS endpoints: %d\n", len(r.JSEndpoints))
	}
	if len(r.Secrets) > 0 {
		fmt.Printf("  🔑 Secrets found: %d\n", len(r.Secrets))
	}
	if len(r.WaybackURLs) > 0 {
		alive := 0
		for _, u := range r.WaybackURLs {
			if u.Alive {
				alive++
			}
		}
		fmt.Printf("  📚 Wayback URLs: %d (%d alive)\n", len(r.WaybackURLs), alive)
	}
	if len(r.Parameters) > 0 {
		reflected := 0
		for _, p := range r.Parameters {
			if p.Reflected {
				reflected++
			}
		}
		fmt.Printf("  🎯 Parameters: %d (%d reflected)\n", len(r.Parameters), reflected)
	}
	if len(r.DiscoveredURLs) > 0 {
		fmt.Printf("  🌐 New URLs for attack surface: %d\n", len(r.DiscoveredURLs))
	}
	fmt.Println()
}

// joinURLs joins up to max URLs with commas.
func joinURLs(urls []string, max int) string {
	if len(urls) > max {
		urls = urls[:max]
	}
	return joinStrs(urls, ",")
}

// joinStrs joins strings with a separator.
func joinStrs(items []string, sep string) string {
	result := ""
	for i, item := range items {
		if i > 0 {
			result += sep
		}
		result += item
	}
	return result
}
