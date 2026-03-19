package red

import (
	"testing"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

func TestScoreConfidence_SQLiWithDataExtraction(t *testing.T) {
	findings := []types.Finding{
		{
			Title:           "SQL Injection - Login Bypass",
			Technique:       "sqli",
			Confirmed:       true,
			ExploitEvidence: "Retrieved sqlite_master table names: users, orders, products",
			Severity:        types.SeverityCritical,
		},
	}

	ScoreConfidence(findings)

	if findings[0].Confidence < 95 {
		t.Errorf("SQLi with data extraction should be Proven (95+), got %d", findings[0].Confidence)
	}
	if findings[0].CVSS.Score == 0 {
		t.Error("CVSS score should be calculated (non-zero)")
	}
}

func TestScoreConfidence_SQLiWithTokenExtraction(t *testing.T) {
	findings := []types.Finding{
		{
			Title:           "SQL Injection - Login Bypass",
			Technique:       "sqli",
			Confirmed:       true,
			ExploitEvidence: "Extracted admin JWT token: eyJhbG...",
			Severity:        types.SeverityCritical,
		},
	}

	ScoreConfidence(findings)

	if findings[0].Confidence < 95 {
		t.Errorf("SQLi with token extraction should be Proven, got %d", findings[0].Confidence)
	}
}

func TestScoreConfidence_XSSReflected(t *testing.T) {
	findings := []types.Finding{
		{
			Title:     "Reflected XSS - Search Endpoint",
			Technique: "xss",
			Confirmed: true,
			Evidence:  "Payload <script>alert('xss')</script> reflected in HTTP 200 response",
			Severity:  types.SeverityHigh,
		},
	}

	ScoreConfidence(findings)

	if findings[0].Confidence < 95 {
		t.Errorf("XSS with reflected script tag should be Proven, got %d", findings[0].Confidence)
	}
}

func TestScoreConfidence_MissingHeaderDowngrade(t *testing.T) {
	findings := []types.Finding{
		{
			Title:     "Missing Security Header - Content-Security-Policy",
			Technique: "misconfig",
			Confirmed: true,
			Evidence:  "HTTP 200 - Header 'Content-Security-Policy' is missing from response",
			Severity:  types.SeverityMedium,
		},
	}

	ScoreConfidence(findings)

	if findings[0].Confidence > 35 {
		t.Errorf("Missing header should be capped at Low+10 (35), got %d", findings[0].Confidence)
	}
	if findings[0].Severity > types.SeverityLow {
		t.Errorf("Missing header severity should be downgraded to Low, got %s", findings[0].Severity)
	}
}

func TestScoreConfidence_ServerHeaderDisclosure(t *testing.T) {
	findings := []types.Finding{
		{
			Title:     "Server Header Information Disclosure",
			Technique: "info_leak",
			Confirmed: true,
			Evidence:  "Server: Apache/2.4.51 (Ubuntu)",
			Severity:  types.SeverityLow,
		},
	}

	ScoreConfidence(findings)

	if findings[0].Severity != types.SeverityInfo {
		t.Errorf("Server header disclosure should be Info, got %s", findings[0].Severity)
	}
	if findings[0].Confidence != types.ConfLow {
		t.Errorf("Server header disclosure should be Low confidence, got %d", findings[0].Confidence)
	}
}

func TestScoreConfidence_IDORWithSensitiveData(t *testing.T) {
	findings := []types.Finding{
		{
			Title:           "IDOR - Access Other User's Data",
			Technique:       "idor",
			Confirmed:       true,
			ExploitEvidence: "Retrieved password hash and token for user ID 42",
			Severity:        types.SeverityHigh,
		},
	}

	ScoreConfidence(findings)

	if findings[0].Confidence < 95 {
		t.Errorf("IDOR with password/token extraction should be Proven, got %d", findings[0].Confidence)
	}
}

func TestScoreConfidence_GitRepoExposed(t *testing.T) {
	findings := []types.Finding{
		{
			Title:           "Git Repository Exposed — Source Code Extractable",
			Technique:       "info_leak",
			Confirmed:       true,
			ExploitEvidence: "Branch: master, Commit hash: e7188b26, git-dumper PoC validated",
			Severity:        types.SeverityCritical,
		},
	}

	ScoreConfidence(findings)

	if findings[0].Confidence < 95 {
		t.Errorf("Git repo exposed with commit hash should be Proven, got %d", findings[0].Confidence)
	}
}

func TestScoreConfidence_SSRFCloudMetadata(t *testing.T) {
	findings := []types.Finding{
		{
			Title:           "SSRF - Cloud Metadata Extraction",
			Technique:       "ssrf",
			Confirmed:       true,
			ExploitEvidence: "Retrieved AWS ami-id: ami-0abcdef1234567890, instance-id: i-0123456789abcdef0",
			Severity:        types.SeverityCritical,
		},
	}

	ScoreConfidence(findings)

	if findings[0].Confidence < 95 {
		t.Errorf("SSRF with cloud metadata should be Proven, got %d", findings[0].Confidence)
	}
}

func TestScoreConfidence_EmptyEvidence(t *testing.T) {
	findings := []types.Finding{
		{
			Title:     "Possible SQLi",
			Technique: "sqli",
			Confirmed: false,
			Evidence:  "maybe",
			Severity:  types.SeverityMedium,
		},
	}

	ScoreConfidence(findings)

	// Short evidence should result in penalty
	if findings[0].Confidence >= types.ConfHigh {
		t.Errorf("Finding with short evidence should not be High confidence, got %d", findings[0].Confidence)
	}
}

func TestScoreConfidence_BatchProcessing(t *testing.T) {
	findings := []types.Finding{
		{
			Title:     "SQLi Critical",
			Technique: "sqli",
			Confirmed: true,
			Evidence:  "Retrieved sqlite_master table with full database dump via UNION injection",
			Severity:  types.SeverityCritical,
		},
		{
			Title:     "Missing Security Header - X-Frame-Options",
			Technique: "misconfig",
			Confirmed: true,
			Evidence:  "HTTP 200 - Header missing",
			Severity:  types.SeverityMedium,
		},
		{
			Title:     "XSS Stored",
			Technique: "xss",
			Confirmed: true,
			Evidence:  "Payload <iframe src='javascript:alert(1)'> reflected in stored response",
			Severity:  types.SeverityHigh,
		},
	}

	ScoreConfidence(findings)

	// SQLi should be highest confidence
	if findings[0].Confidence < findings[1].Confidence {
		t.Error("SQLi with data extraction should have higher confidence than missing header")
	}

	// Missing header should be lowest
	if findings[1].Confidence > findings[2].Confidence {
		t.Error("Missing header should have lower confidence than stored XSS")
	}

	// All should have CVSS calculated
	for i, f := range findings {
		if f.CVSS.Vector == "" {
			t.Errorf("Finding %d (%s) should have CVSS vector calculated", i, f.Title)
		}
	}
}
