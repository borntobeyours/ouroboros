package red

import (
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// ScoreConfidence assigns a confidence score to each finding based on evidence quality.
func ScoreConfidence(findings []types.Finding) {
	for i := range findings {
		f := &findings[i]

		// Start with base confidence from confirmation status
		if f.ExfiltratedData != "" {
			f.Confidence = types.ConfProven
		} else if f.Confirmed && f.ExploitEvidence != "" {
			f.Confidence = types.ConfProven
		} else if f.Confirmed {
			f.Confidence = types.ConfHigh
		} else {
			f.Confidence = types.ConfMedium
		}

		// Apply technique-specific adjustments
		f.Confidence = adjustByTechnique(f)

		// Apply evidence quality adjustments
		f.Confidence = adjustByEvidence(f)

		// Downgrade known low-value findings
		f.Confidence = adjustByFindingType(f)

		// Clamp to valid range
		if f.Confidence > 100 {
			f.Confidence = 100
		}
		if f.Confidence < 0 {
			f.Confidence = 0
		}

		// Calculate CVSS
		f.CVSS = types.CalculateCVSS(f)

		// Recalculate adjusted severity
		f.AdjustSeverity()
	}
}

// adjustByTechnique modifies confidence based on the attack technique used.
func adjustByTechnique(f *types.Finding) types.Confidence {
	conf := f.Confidence
	tech := strings.ToLower(f.Technique)
	lower := strings.ToLower(f.Evidence + f.ExploitEvidence)

	switch {
	case tech == "sqli":
		// SQLi with actual data extraction = highest confidence
		if strings.Contains(lower, "sqlite_master") || strings.Contains(lower, "information_schema") ||
			strings.Contains(lower, "table_name") || strings.Contains(lower, "column_name") {
			conf = types.ConfProven + 5 // 100
		} else if strings.Contains(lower, "token") || strings.Contains(lower, "jwt") {
			conf = types.ConfProven
		} else if strings.Contains(lower, "sql") || strings.Contains(lower, "syntax error") {
			conf = types.ConfHigh
		}

	case tech == "xss":
		// XSS with payload reflected in response
		if strings.Contains(lower, "<script") || strings.Contains(lower, "<iframe") ||
			strings.Contains(lower, "javascript:") || strings.Contains(lower, "onerror") {
			conf = types.ConfProven
		} else if strings.Contains(lower, "reflected") {
			conf = types.ConfHigh
		}

	case tech == "idor":
		// IDOR with actual sensitive data
		if strings.Contains(lower, "password") || strings.Contains(lower, "token") ||
			strings.Contains(lower, "secret") || strings.Contains(lower, "card") {
			conf = types.ConfProven
		} else if strings.Contains(lower, "email") && strings.Contains(lower, "phone") {
			conf = types.ConfHigh
		} else if strings.Contains(lower, "200") {
			conf = types.ConfMedium // Just accessible, not necessarily sensitive
		}

	case tech == "xxe":
		if strings.Contains(lower, "root:") || strings.Contains(lower, "/etc/passwd") {
			conf = types.ConfProven + 5
		} else if f.Confirmed {
			conf = types.ConfHigh
		} else {
			conf = types.ConfMedium // XML accepted but no file read
		}

	case tech == "nosql_injection":
		if strings.Contains(lower, "token") || strings.Contains(lower, "bypass") {
			conf = types.ConfProven
		} else if strings.Contains(lower, "error") {
			conf = types.ConfMedium // Error response doesn't mean exploitable
		}

	case tech == "auth_bypass":
		if strings.Contains(lower, "admin") && strings.Contains(lower, "token") {
			conf = types.ConfProven
		} else if strings.Contains(lower, "role") {
			conf = types.ConfHigh
		}

	case tech == "path_traversal":
		if strings.Contains(lower, "root:") || strings.Contains(lower, "etc/passwd") ||
			strings.Contains(lower, "file content") {
			conf = types.ConfProven
		}
	}

	return conf
}

// adjustByEvidence modifies confidence based on evidence quality.
func adjustByEvidence(f *types.Finding) types.Confidence {
	conf := f.Confidence
	evidence := f.Evidence + f.ExploitEvidence

	// Boost: has actual HTTP response proof
	if strings.Contains(evidence, "HTTP") && strings.Contains(evidence, "status") {
		if conf < types.ConfHigh {
			conf = types.ConfHigh
		}
	}

	// Boost: multi-step exploit chain
	if strings.Contains(evidence, "chain") || strings.Contains(evidence, "Step") {
		conf += 5
	}

	// Penalty: empty or very short evidence
	if len(evidence) < 20 {
		conf -= 15
	}

	return conf
}

// adjustByFindingType downgrades known low-value finding categories.
func adjustByFindingType(f *types.Finding) types.Confidence {
	conf := f.Confidence
	title := strings.ToLower(f.Title)

	// Missing security headers — always low confidence (informational)
	if strings.Contains(title, "missing security header") ||
		strings.Contains(title, "missing rate limiting") ||
		strings.Contains(title, "insecure cookie") {
		if conf > types.ConfLow+10 {
			conf = types.ConfLow + 10 // Cap at 35
		}
		// Also force severity to Low/Info
		if f.Severity > types.SeverityLow {
			f.Severity = types.SeverityLow
		}
	}

	// Server header disclosure — always Info
	if strings.Contains(title, "server header") ||
		strings.Contains(title, "x-powered-by") ||
		strings.Contains(title, "information disclosure - robots") {
		conf = types.ConfLow
		f.Severity = types.SeverityInfo
	}

	// Input validation "no length limit" — barely a finding
	if strings.Contains(title, "no length limit") || strings.Contains(title, "length limit") {
		conf = types.ConfLow
		f.Severity = types.SeverityInfo
	}

	// Verbose error messages — only Medium at best unless stack trace contains secrets
	if strings.Contains(title, "verbose error") || strings.Contains(title, "stack trace") {
		evidence := strings.ToLower(f.Evidence + f.ExploitEvidence)
		if !strings.Contains(evidence, "password") && !strings.Contains(evidence, "secret") &&
			!strings.Contains(evidence, "key") {
			if conf > types.ConfMedium {
				conf = types.ConfMedium
			}
		}
	}

	// NoSQL injection "error response" without actual bypass — downgrade
	if strings.Contains(title, "nosql injection attempt") && strings.Contains(title, "error") {
		if conf > types.ConfLow+10 {
			conf = types.ConfLow + 10
		}
	}

	// JWT "none algorithm" needs actual proof of bypass working
	if strings.Contains(title, "jwt none algorithm") || strings.Contains(title, "none algorithm bypass") {
		evidence := strings.ToLower(f.Evidence + f.ExploitEvidence)
		if !strings.Contains(evidence, "200") || !strings.Contains(evidence, "data") {
			conf = types.ConfLow
		}
	}

	return conf
}
