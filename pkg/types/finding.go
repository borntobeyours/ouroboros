package types

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

// Finding represents a discovered vulnerability.
type Finding struct {
	ID               string    `json:"id"`
	Title            string    `json:"title"`
	Description      string    `json:"description"`
	Severity         Severity  `json:"severity"`
	Endpoint         string    `json:"endpoint"`
	Method           string    `json:"method,omitempty"`
	CWE              string    `json:"cwe,omitempty"`
	PoC              string    `json:"poc,omitempty"`
	Evidence         string    `json:"evidence,omitempty"`
	Technique        string    `json:"technique,omitempty"`
	Remediation      string    `json:"remediation,omitempty"`
	Confirmed        bool      `json:"confirmed"`
	ExploitEvidence  string    `json:"exploit_evidence,omitempty"`
	ExfiltratedData  string    `json:"exfiltrated_data,omitempty"`
	FoundAt          time.Time `json:"found_at"`
	Loop             int       `json:"loop"`
}

// Signature returns a unique hash for deduplication.
func (f *Finding) Signature() string {
	// Normalize endpoint: strip query params and trailing slashes for consistent dedup
	ep := f.Endpoint
	if idx := strings.Index(ep, "?"); idx != -1 {
		ep = ep[:idx]
	}
	ep = strings.TrimRight(ep, "/")
	// Also include title for findings with same endpoint but different vulns
	data := fmt.Sprintf("%s|%s|%s|%s|%s", ep, f.Method, f.Technique, f.CWE, f.Title)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:8])
}

// Patch represents a fix suggestion from Blue AI.
type Patch struct {
	FindingID      string `json:"finding_id"`
	Description    string `json:"description"`
	Code           string `json:"code,omitempty"`
	ConfigChange   string `json:"config_change,omitempty"`
	Hardening      string `json:"hardening,omitempty"`
	Confidence     string `json:"confidence,omitempty"`
}

// LoopResult holds the outcome of a single attack-fix cycle.
type LoopResult struct {
	Iteration   int        `json:"iteration"`
	Findings    []Finding  `json:"findings"`
	Patches     []Patch    `json:"patches"`
	NewFindings int        `json:"new_findings"`
	StartedAt   time.Time  `json:"started_at"`
	FinishedAt  time.Time  `json:"finished_at"`
}
