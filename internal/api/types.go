package api

import (
	"time"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// ScanStatus represents the state of a scan.
type ScanStatus string

const (
	StatusQueued    ScanStatus = "queued"
	StatusRunning   ScanStatus = "running"
	StatusCompleted ScanStatus = "completed"
	StatusFailed    ScanStatus = "failed"
	StatusCancelled ScanStatus = "cancelled"
)

// StartScanRequest is the body for POST /api/v1/scans.
type StartScanRequest struct {
	Target     string            `json:"target"`
	Profile    string            `json:"profile"`   // quick, deep, paranoid
	Provider   string            `json:"provider"`  // anthropic, openai, etc.
	Model      string            `json:"model"`
	MaxLoops   int               `json:"max_loops"`
	FinalBoss  bool              `json:"final_boss"`
	SkipBlue   bool              `json:"skip_blue"`
	AuthConfig *types.AuthConfig `json:"auth_config,omitempty"`
	RateLimit  float64           `json:"rate_limit"`
	WebhookURL string            `json:"webhook_url"`
}

// StartScanResponse is returned by POST /api/v1/scans.
type StartScanResponse struct {
	ScanID string     `json:"scan_id"`
	Status ScanStatus `json:"status"`
}

// ScanListItem is one entry in GET /api/v1/scans.
type ScanListItem struct {
	ScanID        string     `json:"scan_id"`
	Target        string     `json:"target"`
	Status        ScanStatus `json:"status"`
	StartedAt     time.Time  `json:"started_at"`
	FinishedAt    *time.Time `json:"finished_at,omitempty"`
	Duration      string     `json:"duration,omitempty"`
	FindingsCount int        `json:"findings_count"`
}

// ScanProgress shows where a running scan is.
type ScanProgress struct {
	Phase      string `json:"phase"`
	Loop       int    `json:"loop"`
	TotalLoops int    `json:"total_loops"`
	Percent    int    `json:"percent"`
}

// SeverityBreakdown groups findings by severity.
type SeverityBreakdown struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
}

// ScanDetail is returned by GET /api/v1/scans/:id.
type ScanDetail struct {
	ScanID            string            `json:"scan_id"`
	Target            string            `json:"target"`
	Status            ScanStatus        `json:"status"`
	Progress          ScanProgress      `json:"progress"`
	FindingsCount     int               `json:"findings_count"`
	SeverityBreakdown SeverityBreakdown `json:"severity_breakdown"`
	StartedAt         time.Time         `json:"started_at"`
	FinishedAt        *time.Time        `json:"finished_at,omitempty"`
	Error             string            `json:"error,omitempty"`
}

// FindingsResponse is returned by GET /api/v1/scans/:id/findings.
type FindingsResponse struct {
	Findings []types.Finding `json:"findings"`
	Total    int             `json:"total"`
	Page     int             `json:"page"`
	Limit    int             `json:"limit"`
}

// FullReport is returned by GET /api/v1/scans/:id/report.
type FullReport struct {
	ScanID   string          `json:"scan_id"`
	Target   string          `json:"target"`
	Status   ScanStatus      `json:"status"`
	Session  interface{}     `json:"session"`
	Findings []types.Finding `json:"findings"`
}

// DiffRequest is the body for POST /api/v1/diff.
type DiffRequest struct {
	ScanIDBefore string `json:"scan_id_before"`
	ScanIDAfter  string `json:"scan_id_after"`
	Target       string `json:"target"`
	Latest       bool   `json:"latest"`
}

// DiffSummary summarizes the diff.
type DiffSummary struct {
	NewCount        int `json:"new_count"`
	FixedCount      int `json:"fixed_count"`
	PersistentCount int `json:"persistent_count"`
}

// DiffResponse is returned by POST /api/v1/diff.
type DiffResponse struct {
	New        []types.Finding `json:"new"`
	Fixed      []types.Finding `json:"fixed"`
	Persistent []types.Finding `json:"persistent"`
	Summary    DiffSummary     `json:"summary"`
}

// HealthResponse is returned by GET /api/v1/health.
type HealthResponse struct {
	Status  string `json:"status"`
	Version string `json:"version"`
}

// StatusResponse is returned by GET /api/v1/status.
type StatusResponse struct {
	RunningScans int      `json:"running_scans"`
	QueuedScans  int      `json:"queued_scans"`
	TotalScans   int      `json:"total_scans"`
	Providers    []string `json:"providers"`
}

// ErrorResponse wraps an error message.
type ErrorResponse struct {
	Error string `json:"error"`
}

// SSEEvent is a server-sent event payload.
type SSEEvent struct {
	Type string      `json:"type"` // progress, finding, complete, error
	Data interface{} `json:"data"`
}

// SSEProgressData is the data for progress events.
type SSEProgressData struct {
	Phase      string `json:"phase"`
	Loop       int    `json:"loop"`
	TotalLoops int    `json:"total_loops"`
	Findings   int    `json:"findings"`
}

// SSECompleteData is the data for complete events.
type SSECompleteData struct {
	ScanID    string `json:"scan_id"`
	Findings  int    `json:"findings"`
	Converged bool   `json:"converged"`
}
