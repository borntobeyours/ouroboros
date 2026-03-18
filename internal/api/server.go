// Package api provides a REST API server for Ouroboros scan engine integration.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/borntobeyours/ouroboros/internal/ai"
	"github.com/borntobeyours/ouroboros/internal/blue"
	"github.com/borntobeyours/ouroboros/internal/boss"
	"github.com/borntobeyours/ouroboros/internal/engine"
	"github.com/borntobeyours/ouroboros/internal/memory"
	"github.com/borntobeyours/ouroboros/internal/notify"
	"github.com/borntobeyours/ouroboros/internal/red"
	"github.com/borntobeyours/ouroboros/internal/report"
	"github.com/borntobeyours/ouroboros/pkg/types"
)

// ScanRecord tracks a single scan's lifecycle.
type ScanRecord struct {
	ID            string
	Target        string
	Config        types.ScanConfig
	Status        ScanStatus
	StartedAt     time.Time
	FinishedAt    time.Time
	FindingsCount int
	Loop          int
	Phase         string
	Converged     bool
	Err           string

	cancel context.CancelFunc
	broker *SSEBroker
	mu     sync.RWMutex
}

func (r *ScanRecord) setStatus(s ScanStatus) {
	r.mu.Lock()
	r.Status = s
	r.mu.Unlock()
}

// snapshot returns a point-in-time ScanDetail without holding the lock.
func (r *ScanRecord) snapshot() ScanDetail {
	r.mu.RLock()
	defer r.mu.RUnlock()

	d := ScanDetail{
		ScanID:        r.ID,
		Target:        r.Target,
		Status:        r.Status,
		FindingsCount: r.FindingsCount,
		StartedAt:     r.StartedAt,
		Progress: ScanProgress{
			Phase:      r.Phase,
			Loop:       r.Loop,
			TotalLoops: r.Config.MaxLoops,
		},
		Error: r.Err,
	}
	if r.Config.MaxLoops > 0 && r.Loop > 0 {
		d.Progress.Percent = r.Loop * 100 / r.Config.MaxLoops
	}
	if !r.FinishedAt.IsZero() {
		t := r.FinishedAt
		d.FinishedAt = &t
	}
	return d
}

// ScanManager manages concurrent scan execution.
type ScanManager struct {
	mu    sync.RWMutex
	scans map[string]*ScanRecord
	store *memory.Store
}

// NewScanManager creates a new ScanManager backed by the given store.
func NewScanManager(store *memory.Store) *ScanManager {
	return &ScanManager{
		scans: make(map[string]*ScanRecord),
		store: store,
	}
}

// StartScan validates the request, creates a ScanRecord, and launches the scan
// in a background goroutine. Returns the assigned scan ID.
func (m *ScanManager) StartScan(req StartScanRequest) (string, error) {
	if req.Target == "" {
		return "", fmt.Errorf("target is required")
	}

	scanID := uuid.New().String()

	// Apply profile defaults
	maxLoops := req.MaxLoops
	finalBoss := req.FinalBoss
	if maxLoops <= 0 {
		switch req.Profile {
		case "quick":
			maxLoops = 1
		case "paranoid":
			maxLoops = 5
			finalBoss = true
		default: // "deep" or ""
			maxLoops = 3
		}
	}

	provider := req.Provider
	if provider == "" {
		provider = "anthropic"
	}
	model := req.Model
	if model == "" {
		model = "claude-sonnet-4-20250514"
	}

	authCfg := types.AuthConfig{}
	if req.AuthConfig != nil {
		authCfg = *req.AuthConfig
	}

	cfg := types.ScanConfig{
		Target:     types.Target{URL: req.Target},
		MaxLoops:   maxLoops,
		FinalBoss:  finalBoss,
		SkipBlue:   req.SkipBlue,
		Provider:   provider,
		Model:      model,
		AuthConfig: authCfg,
	}

	record := &ScanRecord{
		ID:        scanID,
		Target:    req.Target,
		Config:    cfg,
		Status:    StatusQueued,
		StartedAt: time.Now(),
		broker:    NewSSEBroker(),
	}

	m.mu.Lock()
	m.scans[scanID] = record
	m.mu.Unlock()

	go m.runScan(record, req)
	return scanID, nil
}

// runScan executes the full scan lifecycle in a goroutine.
func (m *ScanManager) runScan(record *ScanRecord, req StartScanRequest) {
	record.setStatus(StatusRunning)

	ctx, cancel := context.WithCancel(context.Background())
	record.mu.Lock()
	record.cancel = cancel
	record.mu.Unlock()
	defer cancel()

	// Resolve API key from environment
	apiKey := resolveProviderAPIKey(record.Config.Provider)

	// Initialize AI provider
	aiProvider, err := ai.NewProvider(record.Config.Provider, record.Config.Model, apiKey)
	if err != nil {
		record.mu.Lock()
		record.Status = StatusFailed
		record.Err = fmt.Sprintf("initialize AI provider: %v", err)
		record.FinishedAt = time.Now()
		record.mu.Unlock()
		record.broker.Publish(SSEEvent{Type: "error", Data: map[string]string{"message": record.Err}})
		record.broker.Close()
		return
	}

	// Per-scan logger — writes to stderr; not shown in terminal during API mode
	logger := log.New(os.Stderr, fmt.Sprintf("[scan:%s] ", record.ID[:8]), log.LstdFlags)

	// Initialize agents
	redAgent := red.NewAgent(aiProvider, logger)
	blueAgent := blue.NewAgent(aiProvider, logger)

	var bossAgent *boss.Agent
	if record.Config.FinalBoss {
		bossAgent = boss.NewAgent(aiProvider, logger)
	}

	reporter := report.NewReporter(false)
	eng := engine.NewEngine(redAgent, blueAgent, bossAgent, m.store, reporter, logger)

	// Wire progress events to SSE
	eng.SetEventCallback(func(eventType, phase string, loop, findingsCount int) {
		record.mu.Lock()
		record.Phase = phase
		record.Loop = loop
		record.FindingsCount = findingsCount
		record.mu.Unlock()

		record.broker.Publish(SSEEvent{
			Type: eventType,
			Data: SSEProgressData{
				Phase:      phase,
				Loop:       loop,
				TotalLoops: record.Config.MaxLoops,
				Findings:   findingsCount,
			},
		})
	})

	// Attach webhook notifier if requested
	if req.WebhookURL != "" {
		n := notify.NewNotifier(notify.WebhookConfig{URL: req.WebhookURL})
		eng.SetNotifier(n)
	}

	session, err := eng.Run(ctx, record.Config)

	record.mu.Lock()
	record.FinishedAt = time.Now()
	if err != nil {
		if ctx.Err() != nil {
			record.Status = StatusCancelled
		} else {
			record.Status = StatusFailed
			record.Err = err.Error()
		}
	} else {
		record.Status = StatusCompleted
		record.FindingsCount = session.TotalFindings
		record.Converged = session.Converged
	}
	record.mu.Unlock()

	if err != nil {
		errMsg := record.Err
		if errMsg == "" {
			errMsg = "scan cancelled"
		}
		record.broker.Publish(SSEEvent{Type: "error", Data: map[string]string{"message": errMsg}})
	} else {
		record.broker.Publish(SSEEvent{
			Type: "complete",
			Data: SSECompleteData{
				ScanID:    record.ID,
				Findings:  record.FindingsCount,
				Converged: record.Converged,
			},
		})
	}
	record.broker.Close()
}

// GetScan returns a scan record by ID, or nil if not found.
func (m *ScanManager) GetScan(scanID string) *ScanRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.scans[scanID]
}

// ListScans returns all scans, optionally filtered by status and/or target.
func (m *ScanManager) ListScans(statusFilter, targetFilter string) []*ScanRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*ScanRecord, 0, len(m.scans))
	for _, r := range m.scans {
		r.mu.RLock()
		matchStatus := statusFilter == "" || string(r.Status) == statusFilter
		matchTarget := targetFilter == "" || r.Target == targetFilter
		r.mu.RUnlock()
		if matchStatus && matchTarget {
			result = append(result, r)
		}
	}
	return result
}

// CancelScan cancels a running scan. Returns false if the scan was not found.
func (m *ScanManager) CancelScan(scanID string) bool {
	m.mu.RLock()
	record, ok := m.scans[scanID]
	m.mu.RUnlock()
	if !ok {
		return false
	}

	record.mu.Lock()
	if record.cancel != nil {
		record.cancel()
	}
	record.mu.Unlock()
	return true
}

// resolveProviderAPIKey resolves the API key for a provider from environment.
func resolveProviderAPIKey(provider string) string {
	switch provider {
	case "anthropic":
		return os.Getenv("ANTHROPIC_API_KEY")
	case "openai":
		return os.Getenv("OPENAI_API_KEY")
	case "openrouter":
		return os.Getenv("OPENROUTER_API_KEY")
	default:
		return os.Getenv("ANTHROPIC_API_KEY")
	}
}

// ─── HTTP Server ────────────────────────────────────────────────────────────

// Server is the Ouroboros REST API server.
type Server struct {
	port         int
	apiKey       string
	corsOrigins  string
	manager      *ScanManager
	store        *memory.Store
	logger       *log.Logger
	version      string
}

// NewServer creates a new API server.
func NewServer(store *memory.Store, port int, apiKey, corsOrigins, version string) *Server {
	return &Server{
		port:        port,
		apiKey:      apiKey,
		corsOrigins: corsOrigins,
		manager:     NewScanManager(store),
		store:       store,
		logger:      log.New(os.Stderr, "[api] ", log.LstdFlags),
		version:     version,
	}
}

// ListenAndServe starts the HTTP server and blocks until it returns an error.
func (s *Server) ListenAndServe() error {
	mux := s.buildRouter()

	handler := chain(mux,
		withLogging(s.logger),
		withCORS(s.corsOrigins),
		withAuth(s.apiKey),
	)

	addr := fmt.Sprintf(":%d", s.port)
	s.logger.Printf("Ouroboros API server listening on %s", addr)
	if s.apiKey != "" {
		s.logger.Printf("API key authentication enabled")
	} else {
		s.logger.Printf("WARNING: no API key set — server is unauthenticated")
	}

	srv := &http.Server{
		Addr:         addr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 0, // SSE streams need long write timeouts
		IdleTimeout:  120 * time.Second,
	}
	return srv.ListenAndServe()
}

func (s *Server) buildRouter() *http.ServeMux {
	h := &Handlers{manager: s.manager, store: s.store, version: s.version}
	mux := http.NewServeMux()

	mux.HandleFunc("POST /api/v1/scans", h.StartScan)
	mux.HandleFunc("GET /api/v1/scans", h.ListScans)
	mux.HandleFunc("GET /api/v1/scans/{id}", h.GetScan)
	mux.HandleFunc("GET /api/v1/scans/{id}/findings", h.GetFindings)
	mux.HandleFunc("DELETE /api/v1/scans/{id}", h.CancelScan)
	mux.HandleFunc("GET /api/v1/scans/{id}/report", h.GetReport)
	mux.HandleFunc("GET /api/v1/scans/{id}/stream", h.StreamScan)
	mux.HandleFunc("POST /api/v1/diff", h.Diff)
	mux.HandleFunc("GET /api/v1/health", h.Health)
	mux.HandleFunc("GET /api/v1/status", h.Status)

	return mux
}

// writeJSON writes a JSON response with the given status code.
func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
