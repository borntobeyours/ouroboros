package types

import (
	"fmt"
	"math"
	"strings"
)

// CVSS holds a CVSS v3.1 score and vector string.
type CVSS struct {
	Score  float64 `json:"score"`
	Vector string  `json:"vector"`
	Rating string  `json:"rating"` // None, Low, Medium, High, Critical
}

// CVSSMetrics holds the individual CVSS v3.1 base metrics.
type CVSSMetrics struct {
	// Base Score metrics
	AttackVector          string // N=Network, A=Adjacent, L=Local, P=Physical
	AttackComplexity      string // L=Low, H=High
	PrivilegesRequired    string // N=None, L=Low, H=High
	UserInteraction       string // N=None, R=Required
	Scope                 string // U=Unchanged, C=Changed
	ConfidentialityImpact string // N=None, L=Low, H=High
	IntegrityImpact       string // N=None, L=Low, H=High
	AvailabilityImpact    string // N=None, L=Low, H=High
}

// CalculateCVSS computes CVSS v3.1 score from a Finding's characteristics.
func CalculateCVSS(f *Finding) CVSS {
	m := inferMetrics(f)
	score := computeBaseScore(m)
	vector := formatVector(m)
	rating := scoreToRating(score)

	return CVSS{
		Score:  score,
		Vector: vector,
		Rating: rating,
	}
}

// inferMetrics determines CVSS metrics from finding properties.
func inferMetrics(f *Finding) CVSSMetrics {
	m := CVSSMetrics{
		AttackVector:          "N", // Default: Network (web scanner)
		AttackComplexity:      "L", // Default: Low
		PrivilegesRequired:    "N", // Default: None
		UserInteraction:       "N", // Default: None
		Scope:                 "U", // Default: Unchanged
		ConfidentialityImpact: "N",
		IntegrityImpact:       "N",
		AvailabilityImpact:    "N",
	}

	tech := strings.ToLower(f.Technique)
	title := strings.ToLower(f.Title)
	cwe := strings.ToLower(f.CWE)
	evidence := strings.ToLower(f.Evidence + f.ExploitEvidence)

	// === Attack Vector ===
	// Always Network for web findings (already default)

	// === Attack Complexity ===
	switch {
	case strings.Contains(tech, "sqli") || strings.Contains(tech, "xxe"):
		m.AttackComplexity = "L"
	case strings.Contains(tech, "xss") && strings.Contains(title, "stored"):
		m.AttackComplexity = "L"
	case strings.Contains(title, "race condition") || strings.Contains(title, "timing"):
		m.AttackComplexity = "H"
	case strings.Contains(title, "csrf"):
		m.AttackComplexity = "L"
	}

	// === Privileges Required ===
	switch {
	case strings.Contains(title, "without auth") || strings.Contains(title, "no auth") ||
		strings.Contains(tech, "auth_bypass") || strings.Contains(title, "login bypass"):
		m.PrivilegesRequired = "N"
	case strings.Contains(title, "missing authentication"):
		m.PrivilegesRequired = "N"
	case strings.Contains(tech, "idor"):
		m.PrivilegesRequired = "L" // Need to be authenticated to access other users' data
	case strings.Contains(title, "privilege escalation"):
		m.PrivilegesRequired = "L"
	case strings.Contains(title, "admin"):
		m.PrivilegesRequired = "N" // Accessing admin without auth = no privs needed
	}

	// === User Interaction ===
	switch {
	case strings.Contains(tech, "xss") && strings.Contains(title, "reflected"):
		m.UserInteraction = "R" // Victim must click link
	case strings.Contains(title, "csrf"):
		m.UserInteraction = "R"
	case strings.Contains(tech, "xss") && strings.Contains(title, "stored"):
		m.UserInteraction = "R" // Victim must view page
	case strings.Contains(title, "open redirect"):
		m.UserInteraction = "R"
	default:
		m.UserInteraction = "N"
	}

	// === Scope ===
	switch {
	case strings.Contains(tech, "xss"):
		m.Scope = "C" // XSS affects the user's browser (different component)
	case strings.Contains(tech, "ssrf"):
		m.Scope = "C" // SSRF affects internal services
	case strings.Contains(tech, "xxe") && strings.Contains(evidence, "root:"):
		m.Scope = "C" // XXE with file read affects the OS
	}

	// === Impact (CIA) ===
	switch {
	case tech == "sqli":
		m.ConfidentialityImpact = "H"
		m.IntegrityImpact = "H"
		if strings.Contains(evidence, "drop") || strings.Contains(evidence, "delete") {
			m.AvailabilityImpact = "H"
		}

	case tech == "xss":
		m.ConfidentialityImpact = "L"
		m.IntegrityImpact = "L"
		if strings.Contains(title, "stored") {
			m.ConfidentialityImpact = "L"
			m.IntegrityImpact = "L"
		}

	case tech == "xxe":
		m.ConfidentialityImpact = "H"
		if strings.Contains(evidence, "root:") {
			m.IntegrityImpact = "N"
			m.AvailabilityImpact = "L" // DoS via entity expansion
		}

	case tech == "idor":
		m.ConfidentialityImpact = "H"
		if strings.Contains(evidence, "modify") || strings.Contains(evidence, "put") ||
			strings.Contains(evidence, "delete") {
			m.IntegrityImpact = "H"
		} else {
			m.IntegrityImpact = "N"
		}

	case tech == "path_traversal":
		m.ConfidentialityImpact = "H"
		m.IntegrityImpact = "N"

	case tech == "auth_bypass":
		m.ConfidentialityImpact = "H"
		m.IntegrityImpact = "H"
		m.AvailabilityImpact = "N"

	case strings.Contains(tech, "nosql"):
		m.ConfidentialityImpact = "H"
		m.IntegrityImpact = "L"

	case tech == "ssrf":
		m.ConfidentialityImpact = "L"
		m.IntegrityImpact = "N"
		if strings.Contains(evidence, "internal") || strings.Contains(evidence, "localhost") {
			m.ConfidentialityImpact = "H"
		}

	case strings.Contains(tech, "file_upload"):
		m.ConfidentialityImpact = "H"
		m.IntegrityImpact = "H"
		m.AvailabilityImpact = "H"

	case tech == "misconfig":
		// Missing headers, cookies, etc
		m.ConfidentialityImpact = "N"
		m.IntegrityImpact = "N"
		m.AvailabilityImpact = "N"

	case tech == "info_leak":
		m.ConfidentialityImpact = "L"
		if strings.Contains(evidence, "password") || strings.Contains(evidence, "token") ||
			strings.Contains(evidence, "key") {
			m.ConfidentialityImpact = "H"
		}
		m.IntegrityImpact = "N"
		m.AvailabilityImpact = "N"
	}

	// === Override by specific CWE ===
	switch {
	case cwe == "cwe-89": // SQLi
		if m.ConfidentialityImpact == "N" {
			m.ConfidentialityImpact = "H"
		}
	case cwe == "cwe-79": // XSS
		m.Scope = "C"
	case cwe == "cwe-611": // XXE
		if m.ConfidentialityImpact == "N" {
			m.ConfidentialityImpact = "H"
		}
	case cwe == "cwe-918": // SSRF
		m.Scope = "C"
	case cwe == "cwe-352": // CSRF
		m.UserInteraction = "R"
	case cwe == "cwe-306": // Missing auth
		m.PrivilegesRequired = "N"
	}

	// === Override for header/cookie findings ===
	if strings.Contains(title, "missing security header") ||
		strings.Contains(title, "insecure cookie") ||
		strings.Contains(title, "server header") ||
		strings.Contains(title, "x-powered-by") {
		m.ConfidentialityImpact = "N"
		m.IntegrityImpact = "N"
		m.AvailabilityImpact = "N"
	}

	return m
}

// computeBaseScore implements CVSS v3.1 base score calculation.
func computeBaseScore(m CVSSMetrics) float64 {
	av := map[string]float64{"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
	ac := map[string]float64{"L": 0.77, "H": 0.44}
	pr := map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	prChanged := map[string]float64{"N": 0.85, "L": 0.68, "H": 0.50}
	ui := map[string]float64{"N": 0.85, "R": 0.62}
	impact := map[string]float64{"H": 0.56, "L": 0.22, "N": 0.0}

	// ISS (Impact Sub-Score)
	iss := 1.0 - (1.0-impact[m.ConfidentialityImpact])*(1.0-impact[m.IntegrityImpact])*(1.0-impact[m.AvailabilityImpact])

	if iss == 0 {
		return 0.0 // No impact = score 0
	}

	// Impact
	var impactScore float64
	if m.Scope == "U" {
		impactScore = 6.42 * iss
	} else {
		impactScore = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	}

	// Exploitability
	privReq := pr[m.PrivilegesRequired]
	if m.Scope == "C" {
		privReq = prChanged[m.PrivilegesRequired]
	}
	exploitability := 8.22 * av[m.AttackVector] * ac[m.AttackComplexity] * privReq * ui[m.UserInteraction]

	// Base Score
	if impactScore <= 0 {
		return 0.0
	}

	var baseScore float64
	if m.Scope == "U" {
		baseScore = math.Min(impactScore+exploitability, 10.0)
	} else {
		baseScore = math.Min(1.08*(impactScore+exploitability), 10.0)
	}

	// Round up to 1 decimal
	return math.Ceil(baseScore*10) / 10
}

func formatVector(m CVSSMetrics) string {
	return fmt.Sprintf("CVSS:3.1/AV:%s/AC:%s/PR:%s/UI:%s/S:%s/C:%s/I:%s/A:%s",
		m.AttackVector, m.AttackComplexity, m.PrivilegesRequired,
		m.UserInteraction, m.Scope, m.ConfidentialityImpact,
		m.IntegrityImpact, m.AvailabilityImpact)
}

func scoreToRating(score float64) string {
	switch {
	case score >= 9.0:
		return "Critical"
	case score >= 7.0:
		return "High"
	case score >= 4.0:
		return "Medium"
	case score > 0.0:
		return "Low"
	default:
		return "None"
	}
}
