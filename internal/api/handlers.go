package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/borntobeyours/ouroboros/internal/memory"
	"github.com/borntobeyours/ouroboros/internal/report"
	"github.com/borntobeyours/ouroboros/pkg/types"
)

// Handlers holds dependencies for all HTTP handlers.
type Handlers struct {
	manager *ScanManager
	store   *memory.Store
	version string
}

// ─── Scan Management ────────────────────────────────────────────────────────

// StartScan handles POST /api/v1/scans
func (h *Handlers) StartScan(w http.ResponseWriter, r *http.Request) {
	var req StartScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid request body: " + err.Error()})
		return
	}

	scanID, err := h.manager.StartScan(req)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	writeJSON(w, http.StatusAccepted, StartScanResponse{
		ScanID: scanID,
		Status: StatusQueued,
	})
}

// ListScans handles GET /api/v1/scans
// Query params: status, target
func (h *Handlers) ListScans(w http.ResponseWriter, r *http.Request) {
	statusFilter := r.URL.Query().Get("status")
	targetFilter := r.URL.Query().Get("target")

	records := h.manager.ListScans(statusFilter, targetFilter)

	items := make([]ScanListItem, 0, len(records))
	for _, rec := range records {
		rec.mu.RLock()
		item := ScanListItem{
			ScanID:        rec.ID,
			Target:        rec.Target,
			Status:        rec.Status,
			StartedAt:     rec.StartedAt,
			FindingsCount: rec.FindingsCount,
		}
		if !rec.FinishedAt.IsZero() {
			t := rec.FinishedAt
			item.FinishedAt = &t
			item.Duration = rec.FinishedAt.Sub(rec.StartedAt).Round(1e9).String()
		}
		rec.mu.RUnlock()
		items = append(items, item)
	}

	writeJSON(w, http.StatusOK, items)
}

// GetScan handles GET /api/v1/scans/{id}
func (h *Handlers) GetScan(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	record := h.manager.GetScan(scanID)
	if record == nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "scan not found"})
		return
	}

	detail := record.snapshot()

	// Add severity breakdown from store if scan is done
	if detail.Status == StatusCompleted || detail.Status == StatusFailed {
		if findings, err := h.store.GetSessionFindings(scanID); err == nil {
			detail.SeverityBreakdown = buildSeverityBreakdown(findings)
			detail.FindingsCount = len(findings)
		}
	}

	writeJSON(w, http.StatusOK, detail)
}

// GetFindings handles GET /api/v1/scans/{id}/findings
// Query params: severity, confidence, proven_only, limit, offset
func (h *Handlers) GetFindings(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	if h.manager.GetScan(scanID) == nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "scan not found"})
		return
	}

	findings, err := h.store.GetSessionFindings(scanID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to load findings: " + err.Error()})
		return
	}

	q := r.URL.Query()

	// Filter by severity
	if sev := q.Get("severity"); sev != "" {
		wanted, parseErr := types.ParseSeverity(sev)
		if parseErr == nil {
			filtered := findings[:0]
			for _, f := range findings {
				if f.Severity == wanted || f.AdjustedSeverity == wanted {
					filtered = append(filtered, f)
				}
			}
			findings = filtered
		}
	}

	// Filter by minimum confidence
	if confStr := q.Get("confidence"); confStr != "" {
		if minConf, err := strconv.Atoi(confStr); err == nil {
			filtered := findings[:0]
			for _, f := range findings {
				if int(f.Confidence) >= minConf {
					filtered = append(filtered, f)
				}
			}
			findings = filtered
		}
	}

	// proven_only filter
	if q.Get("proven_only") == "true" {
		filtered := findings[:0]
		for _, f := range findings {
			if f.Confirmed || f.Confidence >= types.ConfProven {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	total := len(findings)

	// Pagination
	limit := 50
	if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
		limit = l
	}
	offset := 0
	if o, err := strconv.Atoi(q.Get("offset")); err == nil && o >= 0 {
		offset = o
	}

	page := 1
	if limit > 0 {
		page = offset/limit + 1
	}

	if offset >= len(findings) {
		findings = nil
	} else {
		findings = findings[offset:]
		if len(findings) > limit {
			findings = findings[:limit]
		}
	}

	if findings == nil {
		findings = []types.Finding{}
	}

	writeJSON(w, http.StatusOK, FindingsResponse{
		Findings: findings,
		Total:    total,
		Page:     page,
		Limit:    limit,
	})
}

// CancelScan handles DELETE /api/v1/scans/{id}
func (h *Handlers) CancelScan(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	if !h.manager.CancelScan(scanID) {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "scan not found"})
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// GetReport handles GET /api/v1/scans/{id}/report
func (h *Handlers) GetReport(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	record := h.manager.GetScan(scanID)
	if record == nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "scan not found"})
		return
	}

	findings, err := h.store.GetSessionFindings(scanID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to load findings: " + err.Error()})
		return
	}

	// Try to get the persisted session for full metadata
	session, _ := h.store.GetSession(scanID)

	record.mu.RLock()
	report := FullReport{
		ScanID:   record.ID,
		Target:   record.Target,
		Status:   record.Status,
		Session:  session,
		Findings: findings,
	}
	record.mu.RUnlock()

	writeJSON(w, http.StatusOK, report)
}

// StreamScan handles GET /api/v1/scans/{id}/stream — SSE live progress.
func (h *Handlers) StreamScan(w http.ResponseWriter, r *http.Request) {
	scanID := r.PathValue("id")
	record := h.manager.GetScan(scanID)
	if record == nil {
		writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "scan not found"})
		return
	}

	record.mu.RLock()
	broker := record.broker
	record.mu.RUnlock()

	ServeSSE(w, r, broker)
}

// ─── Diff ───────────────────────────────────────────────────────────────────

// Diff handles POST /api/v1/diff
func (h *Handlers) Diff(w http.ResponseWriter, r *http.Request) {
	var req DiffRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "invalid request body: " + err.Error()})
		return
	}

	var beforeSession, afterSession *types.ScanSession

	if req.Latest || (req.ScanIDBefore == "" && req.ScanIDAfter == "") {
		// Auto-pick two most recent sessions, optionally filtered by target
		sessions, err := h.store.ListSessions(100)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to list sessions: " + err.Error()})
			return
		}
		var filtered []types.ScanSession
		for _, s := range sessions {
			if req.Target == "" || s.Config.Target.URL == req.Target {
				filtered = append(filtered, s)
			}
		}
		if len(filtered) < 2 {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "fewer than 2 sessions found"})
			return
		}
		afterSession = &filtered[0]
		beforeSession = &filtered[1]
	} else {
		if req.ScanIDBefore == "" || req.ScanIDAfter == "" {
			writeJSON(w, http.StatusBadRequest, ErrorResponse{Error: "scan_id_before and scan_id_after are required"})
			return
		}
		var err error
		beforeSession, err = h.store.GetSession(req.ScanIDBefore)
		if err != nil {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "baseline scan not found"})
			return
		}
		afterSession, err = h.store.GetSession(req.ScanIDAfter)
		if err != nil {
			writeJSON(w, http.StatusNotFound, ErrorResponse{Error: "new scan not found"})
			return
		}
	}

	beforeFindings, err := h.store.GetSessionFindings(beforeSession.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to load baseline findings"})
		return
	}
	afterFindings, err := h.store.GetSessionFindings(afterSession.ID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, ErrorResponse{Error: "failed to load new findings"})
		return
	}

	diff := report.ComputeDiff(beforeFindings, afterFindings)

	newFindings := diff.New
	fixedFindings := diff.Fixed
	persistentFindings := diff.Persistent
	if newFindings == nil {
		newFindings = []types.Finding{}
	}
	if fixedFindings == nil {
		fixedFindings = []types.Finding{}
	}
	if persistentFindings == nil {
		persistentFindings = []types.Finding{}
	}

	writeJSON(w, http.StatusOK, DiffResponse{
		New:        newFindings,
		Fixed:      fixedFindings,
		Persistent: persistentFindings,
		Summary: DiffSummary{
			NewCount:        len(newFindings),
			FixedCount:      len(fixedFindings),
			PersistentCount: len(persistentFindings),
		},
	})
}

// ─── System ─────────────────────────────────────────────────────────────────

// Health handles GET /api/v1/health
func (h *Handlers) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, HealthResponse{
		Status:  "ok",
		Version: h.version,
	})
}

// Status handles GET /api/v1/status
func (h *Handlers) Status(w http.ResponseWriter, r *http.Request) {
	records := h.manager.ListScans("", "")

	var running, queued int
	for _, r := range records {
		r.mu.RLock()
		switch r.Status {
		case StatusRunning:
			running++
		case StatusQueued:
			queued++
		}
		r.mu.RUnlock()
	}

	writeJSON(w, http.StatusOK, StatusResponse{
		RunningScans: running,
		QueuedScans:  queued,
		TotalScans:   len(records),
		Providers:    []string{"anthropic", "openai", "openrouter", "ollama", "claude-code"},
	})
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

func buildSeverityBreakdown(findings []types.Finding) SeverityBreakdown {
	var bd SeverityBreakdown
	for _, f := range findings {
		sev := f.AdjustedSeverity
		if sev == 0 {
			sev = f.Severity
		}
		switch sev {
		case types.SeverityCritical:
			bd.Critical++
		case types.SeverityHigh:
			bd.High++
		case types.SeverityMedium:
			bd.Medium++
		case types.SeverityLow:
			bd.Low++
		default:
			bd.Info++
		}
	}
	return bd
}
