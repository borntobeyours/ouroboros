package engine

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/borntobeyours/ouroboros/internal/blue"
	"github.com/borntobeyours/ouroboros/internal/boss"
	"github.com/borntobeyours/ouroboros/internal/memory"
	"github.com/borntobeyours/ouroboros/internal/red"
	"github.com/borntobeyours/ouroboros/internal/report"
	"github.com/borntobeyours/ouroboros/pkg/types"
)

// Engine orchestrates the Red → Blue → Re-attack loop.
type Engine struct {
	redAgent  *red.Agent
	blueAgent *blue.Agent
	bossAgent *boss.Agent
	store     *memory.Store
	reporter  *report.Reporter
	logger    *log.Logger
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

// Run executes the full attack-fix-reattack loop.
func (e *Engine) Run(ctx context.Context, config types.ScanConfig) (*types.ScanSession, error) {
	session := types.NewScanSession(config)
	convergence := NewConvergenceChecker(3)

	// Live view for attack visualization
	lv := report.NewLiveView(config.Target.URL)
	lv.PrintAttackHeader(session.ID, config.MaxLoops, config.Provider)

	// Start progress spinner
	progress := report.NewProgress(config.MaxLoops)
	progress.Start()
	defer progress.Stop()

	// Redirect logger through progress
	logWriter := &report.LogWriter{Progress: progress}
	e.logger.SetOutput(logWriter)

	var allFindings []types.Finding
	var allPatches []types.Patch

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

		// === ATTACK PHASE ===
		findings, err := e.redAgent.Attack(ctx, config.Target, allFindings, allPatches, loop)
		if err != nil {
			progress.Stop()
			e.reporter.PrintError(fmt.Sprintf("Red AI error: %v", err))
			progress = report.NewProgress(config.MaxLoops)
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

		progress = report.NewProgress(config.MaxLoops)
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
			progress = report.NewProgress(config.MaxLoops)
			progress.Start()
			break
		}

		// === DEFEND PHASE ===
		if len(newFindings) > 0 {
			progress.SetPhase("Defending")
			progress.SetStep("Blue AI analyzing...")

			patches, err := e.blueAgent.Defend(ctx, newFindings)
			if err != nil {
				progress.Stop()
				e.reporter.PrintError(fmt.Sprintf("Blue AI: %v", err))
				progress = report.NewProgress(config.MaxLoops)
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
		lv.PrintPhase(0, 0, "boss")
		progress = report.NewProgress(1)
		progress.SetPhase("Final Boss")
		progress.Start()

		bossFindings, err := e.bossAgent.Validate(ctx, config.Target, allFindings, allPatches)
		if err != nil {
			progress.Stop()
			e.reporter.PrintError(fmt.Sprintf("Final Boss: %v", err))
		} else {
			progress.Stop()
			newBoss := convergence.FilterNew(bossFindings)
			allFindings = append(allFindings, newBoss...)
			for _, f := range newBoss {
				lv.PrintFindingLive(f)
			}
		}
		progress = report.NewProgress(1)
		progress.Start()
	}

	// === SUMMARY ===
	progress.Stop()

	session.FinishedAt = time.Now()
	session.TotalFindings = len(allFindings)

	if err := e.store.SaveSession(session); err != nil {
		// silently continue
	}

	lv.PrintSummaryBox(session, allFindings)

	return session, nil
}
