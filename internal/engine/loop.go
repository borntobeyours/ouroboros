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
	redAgent   *red.Agent
	blueAgent  *blue.Agent
	bossAgent  *boss.Agent
	store      *memory.Store
	reporter   *report.Reporter
	logger     *log.Logger
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

	e.logger.Printf("Starting Ouroboros scan session %s", session.ID)
	e.logger.Printf("Target: %s | Max loops: %d | Final Boss: %v", config.Target.URL, config.MaxLoops, config.FinalBoss)

	e.reporter.PrintBanner()
	e.reporter.PrintSessionStart(session)

	// Start progress display
	progress := report.NewProgress(config.MaxLoops)
	progress.Start()
	defer progress.Stop()

	// Redirect logger output through progress
	logWriter := &report.LogWriter{Progress: progress}
	e.logger.SetOutput(logWriter)

	var allFindings []types.Finding
	var allPatches []types.Patch

	for loop := 1; loop <= config.MaxLoops; loop++ {
		select {
		case <-ctx.Done():
			e.logger.Printf("Scan cancelled")
			return session, ctx.Err()
		default:
		}

		loopResult := types.LoopResult{
			Iteration: loop,
			StartedAt: time.Now(),
		}

		progress.SetLoop(loop)
		progress.SetPhase("Attacking")
		e.reporter.PrintLoopStart(loop, config.MaxLoops)

		// Phase 1: Red AI attacks
		progress.SetStep("Crawling & probing endpoints...")
		findings, err := e.redAgent.Attack(ctx, config.Target, allFindings, allPatches, loop)
		if err != nil {
			e.logger.Printf("Red AI error in loop %d: %v", loop, err)
			e.reporter.PrintError(fmt.Sprintf("Red AI error: %v", err))
			loopResult.FinishedAt = time.Now()
			session.Loops = append(session.Loops, loopResult)
			continue
		}

		// Filter to only new findings
		newFindings := convergence.FilterNew(findings)
		loopResult.Findings = newFindings
		loopResult.NewFindings = len(newFindings)

		progress.AddFindings(len(newFindings))
		progress.SetPhase("Analyzing")
		progress.SetStep(fmt.Sprintf("%d new findings", len(newFindings)))

		// Pause progress for output
		progress.Stop()
		e.reporter.PrintFindings(newFindings, loop)
		progress = report.NewProgress(config.MaxLoops)
		progress.SetLoop(loop)
		progress.Start()

		// Record findings in memory
		for _, f := range newFindings {
			if err := e.store.SaveFinding(session.ID, f); err != nil {
				e.logger.Printf("Warning: failed to save finding: %v", err)
			}
			if f.Technique != "" && f.PoC != "" {
				_ = e.store.RecordPlaybookEntry(f.Technique, "", f.PoC)
			}
		}

		allFindings = append(allFindings, newFindings...)

		// Check convergence
		if convergence.HasConverged(loop, len(newFindings)) {
			e.logger.Printf("Converged after %d loops with %d unique findings", loop, convergence.TotalUnique())
			e.reporter.PrintConvergence(loop, convergence.TotalUnique())
			session.Converged = true
			loopResult.FinishedAt = time.Now()
			session.Loops = append(session.Loops, loopResult)
			break
		}

		// Phase 2: Blue AI defends
		if len(newFindings) > 0 {
			progress.SetPhase("Defending")
			progress.SetStep("Blue AI analyzing fixes...")
			patches, err := e.blueAgent.Defend(ctx, newFindings)
			if err != nil {
				e.logger.Printf("Blue AI error in loop %d: %v", loop, err)
				e.reporter.PrintError(fmt.Sprintf("Blue AI error: %v", err))
			} else {
				loopResult.Patches = patches
				allPatches = append(allPatches, patches...)
				e.reporter.PrintPatches(patches, loop)

				// Save patches
				for _, p := range patches {
					if err := e.store.SavePatch(session.ID, p); err != nil {
						e.logger.Printf("Warning: failed to save patch: %v", err)
					}
				}
			}
		}

		loopResult.FinishedAt = time.Now()
		session.Loops = append(session.Loops, loopResult)

		e.reporter.PrintLoopEnd(loop, len(newFindings), len(loopResult.Patches))
	}

	// Final Boss validation
	if config.FinalBoss && e.bossAgent != nil {
		progress.SetPhase("Final Boss")
		progress.SetStep("Elite validation scan...")
		progress.Stop()
		e.reporter.PrintBossStart()
		bossFindings, err := e.bossAgent.Validate(ctx, config.Target, allFindings, allPatches)
		if err != nil {
			e.logger.Printf("Final Boss error: %v", err)
			e.reporter.PrintError(fmt.Sprintf("Final Boss error: %v", err))
		} else {
			newBossFindings := convergence.FilterNew(bossFindings)
			allFindings = append(allFindings, newBossFindings...)
			e.reporter.PrintBossResults(newBossFindings)
		}
	}

	// Stop progress before final output
	progress.Stop()

	// Finalize session
	session.FinishedAt = time.Now()
	session.TotalFindings = len(allFindings)

	// Save session
	if err := e.store.SaveSession(session); err != nil {
		e.logger.Printf("Warning: failed to save session: %v", err)
	}

	// Print final report
	e.reporter.PrintSummary(session, allFindings)

	return session, nil
}
