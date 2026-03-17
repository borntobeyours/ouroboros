package types

import (
	"time"

	"github.com/google/uuid"
)

// Target represents a scan target.
type Target struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	Cookies map[string]string `json:"cookies,omitempty"`
}

// Endpoint represents a discovered endpoint on the target.
type Endpoint struct {
	URL             string            `json:"url"`
	Method          string            `json:"method"`
	StatusCode      int               `json:"status_code,omitempty"`
	ContentType     string            `json:"content_type,omitempty"`
	Parameters      []string          `json:"parameters,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	ResponseHeaders map[string]string `json:"response_headers,omitempty"`
	Body            string            `json:"body,omitempty"`
}

// ScanConfig holds configuration for a scan session.
type ScanConfig struct {
	Target    Target `json:"target"`
	MaxLoops  int    `json:"max_loops"`
	FinalBoss bool   `json:"final_boss"`
	Provider  string `json:"provider"`
	Model     string `json:"model"`
}

// ScanSession represents an entire scan lifecycle.
type ScanSession struct {
	ID          string       `json:"id"`
	Config      ScanConfig   `json:"config"`
	Loops       []LoopResult `json:"loops"`
	Converged   bool         `json:"converged"`
	StartedAt   time.Time    `json:"started_at"`
	FinishedAt  time.Time    `json:"finished_at,omitempty"`
	TotalFindings int        `json:"total_findings"`
}

// NewScanSession creates a new scan session with defaults.
func NewScanSession(cfg ScanConfig) *ScanSession {
	return &ScanSession{
		ID:        uuid.New().String(),
		Config:    cfg,
		Loops:     make([]LoopResult, 0),
		StartedAt: time.Now(),
	}
}
