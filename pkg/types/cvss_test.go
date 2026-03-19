package types

import (
	"math"
	"testing"
)

func TestCalculateCVSS_SQLi(t *testing.T) {
	f := &Finding{
		Title:           "SQL Injection - Login Bypass",
		Technique:       "sqli",
		CWE:             "CWE-89",
		Evidence:        "Database dump via UNION injection",
		ExploitEvidence: "Retrieved admin token",
		Severity:        SeverityCritical,
	}

	cvss := CalculateCVSS(f)

	if cvss.Score < 8.0 {
		t.Errorf("SQLi CVSS score should be >= 8.0, got %.1f", cvss.Score)
	}
	if cvss.Rating != "Critical" && cvss.Rating != "High" {
		t.Errorf("SQLi should be Critical or High, got %s", cvss.Rating)
	}
	if cvss.Vector == "" {
		t.Error("CVSS vector string should not be empty")
	}
	// Verify vector format
	if len(cvss.Vector) < 40 {
		t.Errorf("CVSS vector too short: %s", cvss.Vector)
	}
}

func TestCalculateCVSS_ReflectedXSS(t *testing.T) {
	f := &Finding{
		Title:     "Reflected XSS - Search Endpoint",
		Technique: "xss",
		CWE:       "CWE-79",
		Evidence:  "Payload reflected in response",
		Severity:  SeverityHigh,
	}

	cvss := CalculateCVSS(f)

	// Reflected XSS requires user interaction, scope is changed
	if cvss.Score < 4.0 || cvss.Score > 7.0 {
		t.Errorf("Reflected XSS CVSS should be 4.0-7.0, got %.1f", cvss.Score)
	}
}

func TestCalculateCVSS_StoredXSS(t *testing.T) {
	f := &Finding{
		Title:     "Stored XSS - Comment Field",
		Technique: "xss",
		CWE:       "CWE-79",
		Evidence:  "Stored payload rendered on page",
		Severity:  SeverityHigh,
	}

	cvss := CalculateCVSS(f)

	if cvss.Score < 4.0 {
		t.Errorf("Stored XSS CVSS should be >= 4.0, got %.1f", cvss.Score)
	}
}

func TestCalculateCVSS_MissingHeader(t *testing.T) {
	f := &Finding{
		Title:     "Missing Security Header - X-Frame-Options",
		Technique: "misconfig",
		CWE:       "CWE-1021",
		Evidence:  "Header missing from response",
		Severity:  SeverityMedium,
	}

	cvss := CalculateCVSS(f)

	// Missing headers have no direct impact
	if cvss.Score != 0.0 {
		t.Errorf("Missing header CVSS should be 0.0 (no impact), got %.1f", cvss.Score)
	}
	if cvss.Rating != "None" {
		t.Errorf("Missing header rating should be None, got %s", cvss.Rating)
	}
}

func TestCalculateCVSS_SSRF(t *testing.T) {
	f := &Finding{
		Title:     "SSRF - Internal Service Access",
		Technique: "ssrf",
		CWE:       "CWE-918",
		Evidence:  "Fetched internal localhost service",
		Severity:  SeverityHigh,
	}

	cvss := CalculateCVSS(f)

	if cvss.Score < 7.0 {
		t.Errorf("SSRF with internal access CVSS should be >= 7.0, got %.1f", cvss.Score)
	}
}

func TestCalculateCVSS_FileUploadRCE(t *testing.T) {
	f := &Finding{
		Title:     "Unrestricted File Upload - RCE",
		Technique: "file_upload",
		CWE:       "CWE-434",
		Evidence:  "Uploaded PHP webshell executed",
		Severity:  SeverityCritical,
	}

	cvss := CalculateCVSS(f)

	if cvss.Score < 9.0 {
		t.Errorf("File upload RCE CVSS should be >= 9.0, got %.1f", cvss.Score)
	}
	if cvss.Rating != "Critical" {
		t.Errorf("File upload RCE should be Critical, got %s", cvss.Rating)
	}
}

func TestCalculateCVSS_IDOR(t *testing.T) {
	f := &Finding{
		Title:     "IDOR - Access Other User's Data",
		Technique: "idor",
		CWE:       "CWE-639",
		Evidence:  "Accessed user 42 profile",
		Severity:  SeverityHigh,
	}

	cvss := CalculateCVSS(f)

	if cvss.Score < 5.0 {
		t.Errorf("IDOR CVSS should be >= 5.0, got %.1f", cvss.Score)
	}
}

func TestCalculateCVSS_InfoLeak_GitRepo(t *testing.T) {
	f := &Finding{
		Title:     "Git Repository Exposed — Source Code Extractable",
		Technique: "info_leak",
		CWE:       "CWE-200",
		Evidence:  "Branch: master, commit hash: abc123",
		Severity:  SeverityCritical,
	}

	cvss := CalculateCVSS(f)

	if cvss.Score < 7.0 {
		t.Errorf("Git repo exposure CVSS should be >= 7.0, got %.1f", cvss.Score)
	}
}

func TestScoreToRating(t *testing.T) {
	tests := []struct {
		score    float64
		expected string
	}{
		{10.0, "Critical"},
		{9.0, "Critical"},
		{8.5, "High"},
		{7.0, "High"},
		{6.9, "Medium"},
		{4.0, "Medium"},
		{3.9, "Low"},
		{0.1, "Low"},
		{0.0, "None"},
	}

	for _, tt := range tests {
		result := scoreToRating(tt.score)
		if result != tt.expected {
			t.Errorf("scoreToRating(%.1f) = %s, want %s", tt.score, result, tt.expected)
		}
	}
}

func TestFormatVector(t *testing.T) {
	m := CVSSMetrics{
		AttackVector:          "N",
		AttackComplexity:      "L",
		PrivilegesRequired:    "N",
		UserInteraction:       "N",
		Scope:                 "U",
		ConfidentialityImpact: "H",
		IntegrityImpact:       "H",
		AvailabilityImpact:    "N",
	}

	vector := formatVector(m)
	expected := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
	if vector != expected {
		t.Errorf("formatVector = %s, want %s", vector, expected)
	}
}

func TestComputeBaseScore_NoImpact(t *testing.T) {
	m := CVSSMetrics{
		AttackVector:          "N",
		AttackComplexity:      "L",
		PrivilegesRequired:    "N",
		UserInteraction:       "N",
		Scope:                 "U",
		ConfidentialityImpact: "N",
		IntegrityImpact:       "N",
		AvailabilityImpact:    "N",
	}

	score := computeBaseScore(m)
	if score != 0.0 {
		t.Errorf("No impact metrics should produce score 0.0, got %.1f", score)
	}
}

func TestComputeBaseScore_MaxScore(t *testing.T) {
	m := CVSSMetrics{
		AttackVector:          "N",
		AttackComplexity:      "L",
		PrivilegesRequired:    "N",
		UserInteraction:       "N",
		Scope:                 "C",
		ConfidentialityImpact: "H",
		IntegrityImpact:       "H",
		AvailabilityImpact:    "H",
	}

	score := computeBaseScore(m)
	if score != 10.0 {
		t.Errorf("Max impact metrics should produce score 10.0, got %.1f", score)
	}
}

func TestComputeBaseScore_Deterministic(t *testing.T) {
	m := CVSSMetrics{
		AttackVector:          "N",
		AttackComplexity:      "L",
		PrivilegesRequired:    "L",
		UserInteraction:       "R",
		Scope:                 "U",
		ConfidentialityImpact: "H",
		IntegrityImpact:       "N",
		AvailabilityImpact:    "N",
	}

	score1 := computeBaseScore(m)
	score2 := computeBaseScore(m)

	if math.Abs(score1-score2) > 0.001 {
		t.Errorf("CVSS calculation should be deterministic: %.1f != %.1f", score1, score2)
	}
}
