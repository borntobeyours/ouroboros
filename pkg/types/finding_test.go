package types

import (
	"testing"
	"time"
)

func TestSignature_BasicDedup(t *testing.T) {
	f1 := Finding{
		Title:     "SQL Injection in Login",
		Endpoint:  "/api/login",
		Method:    "POST",
		Technique: "sqli",
		CWE:       "CWE-89",
	}
	f2 := Finding{
		Title:     "SQLi - Authentication Bypass", // Different title
		Endpoint:  "/api/login",
		Method:    "POST",
		Technique: "sqli",
		CWE:       "CWE-89",
	}

	if f1.Signature() != f2.Signature() {
		t.Error("same endpoint+method+technique+CWE should produce same signature regardless of title")
	}
}

func TestSignature_NormalizesEndpoint(t *testing.T) {
	f1 := Finding{Endpoint: "/api/users?id=1", Method: "GET", Technique: "idor", CWE: "CWE-639"}
	f2 := Finding{Endpoint: "/api/users?id=2", Method: "GET", Technique: "idor", CWE: "CWE-639"}
	f3 := Finding{Endpoint: "/api/users/", Method: "GET", Technique: "idor", CWE: "CWE-639"}

	if f1.Signature() != f2.Signature() {
		t.Error("query params should be stripped for dedup")
	}
	if f1.Signature() != f3.Signature() {
		t.Error("trailing slashes should be stripped for dedup")
	}
}

func TestSignature_CaseInsensitive(t *testing.T) {
	f1 := Finding{Endpoint: "/API/Login", Method: "POST", Technique: "SQLi", CWE: "cwe-89"}
	f2 := Finding{Endpoint: "/api/login", Method: "POST", Technique: "sqli", CWE: "CWE-89"}

	if f1.Signature() != f2.Signature() {
		t.Error("signature should be case-insensitive for endpoint, technique, and CWE")
	}
}

func TestSignature_DifferentTechniques(t *testing.T) {
	f1 := Finding{Endpoint: "/api/search", Method: "GET", Technique: "sqli", CWE: "CWE-89"}
	f2 := Finding{Endpoint: "/api/search", Method: "GET", Technique: "xss", CWE: "CWE-79"}

	if f1.Signature() == f2.Signature() {
		t.Error("different techniques on same endpoint should have different signatures")
	}
}

func TestSignature_DifferentMethods(t *testing.T) {
	f1 := Finding{Endpoint: "/api/users", Method: "GET", Technique: "idor", CWE: "CWE-639"}
	f2 := Finding{Endpoint: "/api/users", Method: "POST", Technique: "idor", CWE: "CWE-639"}

	if f1.Signature() == f2.Signature() {
		t.Error("different HTTP methods should have different signatures")
	}
}

func TestDeduplicateFindings_RemovesDuplicates(t *testing.T) {
	findings := []Finding{
		{Title: "SQLi in login (prober)", Endpoint: "/login", Method: "POST", Technique: "sqli", CWE: "CWE-89", Confidence: 95},
		{Title: "SQL Injection - Login", Endpoint: "/login", Method: "POST", Technique: "sqli", CWE: "CWE-89", Confidence: 50},
		{Title: "XSS in search", Endpoint: "/search", Method: "GET", Technique: "xss", CWE: "CWE-79", Confidence: 75},
	}

	result := DeduplicateFindings(findings)

	if len(result) != 2 {
		t.Errorf("expected 2 unique findings, got %d", len(result))
	}

	// The SQLi finding should keep the higher-confidence one
	for _, f := range result {
		if f.Technique == "sqli" && f.Confidence != 95 {
			t.Error("dedup should keep the finding with higher confidence")
		}
	}
}

func TestDeduplicateFindings_KeepsHigherSeverityOnTie(t *testing.T) {
	findings := []Finding{
		{Title: "Low confidence SQLi", Endpoint: "/login", Method: "POST", Technique: "sqli", CWE: "CWE-89", Confidence: 50, Severity: SeverityMedium},
		{Title: "Also low confidence SQLi", Endpoint: "/login", Method: "POST", Technique: "sqli", CWE: "CWE-89", Confidence: 50, Severity: SeverityCritical},
	}

	result := DeduplicateFindings(findings)

	if len(result) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(result))
	}
	if result[0].Severity != SeverityCritical {
		t.Error("on confidence tie, should keep higher severity")
	}
}

func TestDeduplicateFindings_EmptyInput(t *testing.T) {
	result := DeduplicateFindings(nil)
	if len(result) != 0 {
		t.Errorf("expected 0 findings for nil input, got %d", len(result))
	}

	result = DeduplicateFindings([]Finding{})
	if len(result) != 0 {
		t.Errorf("expected 0 findings for empty input, got %d", len(result))
	}
}

func TestDeduplicateFindings_AllUnique(t *testing.T) {
	findings := []Finding{
		{Title: "SQLi", Endpoint: "/login", Method: "POST", Technique: "sqli", CWE: "CWE-89"},
		{Title: "XSS", Endpoint: "/search", Method: "GET", Technique: "xss", CWE: "CWE-79"},
		{Title: "IDOR", Endpoint: "/api/users/1", Method: "GET", Technique: "idor", CWE: "CWE-639"},
	}

	result := DeduplicateFindings(findings)
	if len(result) != 3 {
		t.Errorf("expected 3 unique findings preserved, got %d", len(result))
	}
}

func TestAdjustSeverity(t *testing.T) {
	tests := []struct {
		name       string
		severity   Severity
		confidence Confidence
		expected   Severity
	}{
		{"proven critical stays critical", SeverityCritical, 95, SeverityCritical},
		{"high conf keeps severity", SeverityHigh, 75, SeverityHigh},
		{"medium conf downgrades by 1", SeverityCritical, 50, SeverityHigh},
		{"medium conf low stays low", SeverityLow, 50, SeverityLow}, // SeverityLow - 1 still = SeverityInfo? No, Low(1) > Low check fails so stays Low
		{"low conf downgrades by 2", SeverityCritical, 25, SeverityMedium},
		{"no confidence becomes info", SeverityCritical, 0, SeverityInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := Finding{
				Severity:   tt.severity,
				Confidence: tt.confidence,
			}
			f.AdjustSeverity()
			if f.AdjustedSeverity != tt.expected {
				t.Errorf("AdjustSeverity(%s, %d) = %s, want %s",
					tt.severity, tt.confidence, f.AdjustedSeverity, tt.expected)
			}
		})
	}
}

func TestConfidence_String(t *testing.T) {
	tests := []struct {
		confidence Confidence
		expected   string
	}{
		{95, "Proven"},
		{100, "Proven"},
		{75, "High"},
		{94, "High"},
		{50, "Medium"},
		{74, "Medium"},
		{25, "Low"},
		{49, "Low"},
		{0, "None"},
		{24, "None"},
	}

	for _, tt := range tests {
		result := tt.confidence.String()
		if result != tt.expected {
			t.Errorf("Confidence(%d).String() = %s, want %s", tt.confidence, result, tt.expected)
		}
	}
}

func TestFinding_SignatureStability(t *testing.T) {
	f := Finding{
		Title:     "Test Finding",
		Endpoint:  "/api/test",
		Method:    "GET",
		Technique: "xss",
		CWE:       "CWE-79",
		FoundAt:   time.Now(),
	}

	sig1 := f.Signature()
	sig2 := f.Signature()

	if sig1 != sig2 {
		t.Error("signature should be deterministic")
	}

	if len(sig1) != 16 { // 8 bytes = 16 hex chars
		t.Errorf("expected 16 char hex signature, got %d chars: %s", len(sig1), sig1)
	}
}
