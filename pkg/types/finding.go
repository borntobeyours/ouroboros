package types

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"time"
)

// Confidence represents how certain we are about a finding.
type Confidence int

const (
	ConfNone     Confidence = 0  // No evidence
	ConfLow      Confidence = 25 // Heuristic/pattern match only
	ConfMedium   Confidence = 50 // Behavioral indicator (error, status code change)
	ConfHigh     Confidence = 75 // Active probe confirmed (reflected input, status bypass)
	ConfProven   Confidence = 95 // Exploited with data extraction or state change
)

func (c Confidence) String() string {
	switch {
	case c >= 95:
		return "Proven"
	case c >= 75:
		return "High"
	case c >= 50:
		return "Medium"
	case c >= 25:
		return "Low"
	default:
		return "None"
	}
}

// Finding represents a discovered vulnerability.
type Finding struct {
	ID               string     `json:"id"`
	Title            string     `json:"title"`
	Description      string     `json:"description"`
	Severity         Severity   `json:"severity"`
	AdjustedSeverity Severity   `json:"adjusted_severity"` // After confidence adjustment
	Confidence       Confidence `json:"confidence"`
	CVSS             CVSS       `json:"cvss"`
	Endpoint         string     `json:"endpoint"`
	Method           string     `json:"method,omitempty"`
	CWE              string     `json:"cwe,omitempty"`
	PoC              string     `json:"poc,omitempty"`
	Evidence         string     `json:"evidence,omitempty"`
	Technique        string     `json:"technique,omitempty"`
	Remediation      string     `json:"remediation,omitempty"`
	Confirmed        bool       `json:"confirmed"`
	ExploitEvidence  string     `json:"exploit_evidence,omitempty"`
	ExfiltratedData  string     `json:"exfiltrated_data,omitempty"`
	FoundAt          time.Time         `json:"found_at"`
	Loop             int               `json:"loop"`
	Compliance       []ComplianceMapping `json:"compliance,omitempty"`
}

// AdjustSeverity recalculates severity based on confidence.
// Low-confidence findings get downgraded. Proven findings stay or get upgraded.
func (f *Finding) AdjustSeverity() {
	f.AdjustedSeverity = f.Severity

	switch {
	case f.Confidence >= 95:
		// Proven — keep original severity
		f.AdjustedSeverity = f.Severity
	case f.Confidence >= 75:
		// High confidence — keep severity
		f.AdjustedSeverity = f.Severity
	case f.Confidence >= 50:
		// Medium confidence — downgrade by 1 level
		if f.Severity > SeverityLow {
			f.AdjustedSeverity = f.Severity - 1
		}
	case f.Confidence >= 25:
		// Low confidence — downgrade by 2 levels, minimum Info
		downgraded := f.Severity
		if downgraded > SeverityInfo {
			downgraded--
		}
		if downgraded > SeverityInfo {
			downgraded--
		}
		f.AdjustedSeverity = downgraded
	default:
		// No confidence — force to Info
		f.AdjustedSeverity = SeverityInfo
	}
}

// Signature returns a unique hash for deduplication.
// It uses endpoint + method + technique + CWE + title keywords.
// Title keywords distinguish genuinely different vulnerabilities at the same
// endpoint (e.g., "error-based SQLi" vs "UNION SQLi") while still catching
// duplicates where probers/AI use slightly different wording.
func (f *Finding) Signature() string {
	// Normalize endpoint: strip query params and trailing slashes for consistent dedup
	ep := f.Endpoint
	if idx := strings.Index(ep, "?"); idx != -1 {
		ep = ep[:idx]
	}
	ep = strings.TrimRight(ep, "/")
	ep = strings.ToLower(ep)

	// Normalize technique
	technique := strings.ToLower(strings.TrimSpace(f.Technique))

	// Normalize CWE
	cwe := strings.ToUpper(strings.TrimSpace(f.CWE))

	// Extract distinguishing keywords from the title.
	// This preserves different attack variants (error-based vs UNION vs blind)
	// while still deduplicating same-vuln-different-wording reports.
	titleKey := extractTitleKey(f.Title)

	data := fmt.Sprintf("%s|%s|%s|%s|%s", ep, f.Method, technique, cwe, titleKey)
	hash := sha256.Sum256([]byte(data))
	return fmt.Sprintf("%x", hash[:8])
}

// extractTitleKey returns a normalized, dedup-friendly key from a finding title.
// It keeps attack-variant keywords (union, blind, error, time-based, etc.)
// while stripping noise words so similar titles still match.
func extractTitleKey(title string) string {
	title = strings.ToLower(title)

	// Keywords that distinguish attack variants — order matters for consistency
	variantKeywords := []string{
		"union", "blind", "time-based", "error-based", "boolean",
		"stacked", "out-of-band", "stored", "reflected", "dom",
		"open redirect", "ssrf", "file upload", "path traversal",
		"command injection", "prototype pollution", "deserialization",
		"algorithm confusion", "none algorithm", "jwt", "cors",
		"rate limit", "brute", "enumeration", "disclosure",
		"stack trace", "wildcard", "missing", "bypass",
	}

	var matched []string
	for _, kw := range variantKeywords {
		if strings.Contains(title, kw) {
			matched = append(matched, kw)
		}
	}

	if len(matched) == 0 {
		// Fallback: use first 3 significant words
		words := strings.Fields(title)
		noise := map[string]bool{
			"the": true, "a": true, "an": true, "in": true, "on": true,
			"at": true, "via": true, "with": true, "for": true, "of": true,
			"to": true, "-": true, "and": true, "or": true, "is": true,
		}
		for _, w := range words {
			if !noise[w] && len(w) > 2 {
				matched = append(matched, w)
				if len(matched) >= 3 {
					break
				}
			}
		}
	}

	return strings.Join(matched, "+")
}

// DeduplicateFindings removes duplicate findings based on their signature.
// When duplicates exist, the finding with the higher confidence is kept.
func DeduplicateFindings(findings []Finding) []Finding {
	seen := make(map[string]int) // signature -> index in result
	result := make([]Finding, 0, len(findings))

	for _, f := range findings {
		sig := f.Signature()
		if idx, exists := seen[sig]; exists {
			// Keep the one with higher confidence, or higher severity as tiebreaker
			existing := result[idx]
			if f.Confidence > existing.Confidence ||
				(f.Confidence == existing.Confidence && f.Severity > existing.Severity) {
				result[idx] = f
			}
		} else {
			seen[sig] = len(result)
			result = append(result, f)
		}
	}
	return result
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
