package probers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

func TestContainsSQLError(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"MySQL error", "You have an error in your SQL syntax; check the manual", true},
		{"SQLite error", "unrecognized token: \"'\"", true},
		{"PostgreSQL error", "ERROR: syntax error at or near \"'\"", true}, // "syntax error" matches
		{"Sequelize error", "SequelizeDatabaseError: SQLITE_ERROR", true},
		{"JDBC error", "java.sql.SQLException: JDBC connection failed", true},
		{"No error", "<html><body>Hello World</body></html>", false},
		{"Empty body", "", false},
		{"Case insensitive", "MYSQL_ERROR in query", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsSQLError(tt.body)
			if result != tt.expected {
				t.Errorf("containsSQLError(%q) = %v, want %v", tt.body[:min(len(tt.body), 50)], result, tt.expected)
			}
		})
	}
}

func TestSQLiProber_Name(t *testing.T) {
	p := &SQLiProber{}
	if p.Name() != "sqli" {
		t.Errorf("expected prober name 'sqli', got '%s'", p.Name())
	}
}

func TestSQLiProber_DetectsLoginSQLi(t *testing.T) {
	// Mock server that returns a token when given SQLi payload
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/login" && r.Method == "POST" {
			body := make([]byte, 1024)
			n, _ := r.Body.Read(body)
			bodyStr := string(body[:n])
			if strings.Contains(bodyStr, "OR 1=1") || strings.Contains(bodyStr, "admin'--") {
				w.WriteHeader(200)
				w.Write([]byte(`{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test.sig"}`))
				return
			}
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"Invalid credentials"}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer server.Close()

	// Set up classified endpoints
	classified := &types.ClassifiedEndpoints{
		Login: []types.Endpoint{
			{URL: server.URL + "/login", Method: "POST"},
		},
	}
	currentClassified = classified
	defer func() { currentClassified = nil }()

	target := types.Target{URL: server.URL}
	p := &SQLiProber{}
	findings := p.Probe(context.Background(), target, nil)

	if len(findings) == 0 {
		t.Fatal("expected SQLi finding for vulnerable login endpoint")
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "SQL Injection") && strings.Contains(f.Title, "Login Bypass") {
			found = true
			if f.Severity != types.SeverityCritical {
				t.Errorf("login SQLi bypass should be Critical, got %s", f.Severity)
			}
			if f.CWE != "CWE-89" {
				t.Errorf("expected CWE-89, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Error("expected a 'SQL Injection - Login Bypass' finding")
	}
}

func TestSQLiProber_DetectsSQLErrorDisclosure(t *testing.T) {
	// Mock server that leaks SQL errors
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		if strings.Contains(q, "'") {
			w.WriteHeader(500)
			w.Write([]byte(`{"error":"SequelizeDatabaseError: SQLITE_ERROR: unrecognized token"}`))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"results":[]}`))
	}))
	defer server.Close()

	classified := &types.ClassifiedEndpoints{
		Search: []types.Endpoint{
			{URL: server.URL + "/search?q=test", Method: "GET", Parameters: []string{"q"}},
		},
	}
	currentClassified = classified
	defer func() { currentClassified = nil }()

	target := types.Target{URL: server.URL}
	p := &SQLiProber{}
	findings := p.Probe(context.Background(), target, nil)

	if len(findings) == 0 {
		t.Fatal("expected SQLi finding for search endpoint with SQL error disclosure")
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "SQL Injection") && strings.Contains(f.Title, "Search") {
			found = true
			if f.CWE != "CWE-89" {
				t.Errorf("expected CWE-89, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Error("expected a SQL Injection finding for the search endpoint")
	}
}

func TestSQLiProber_NoFalsePositivesOnSafeServer(t *testing.T) {
	// Mock server that handles everything safely
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`{"status":"ok","data":[]}`))
	}))
	defer server.Close()

	classified := &types.ClassifiedEndpoints{
		Login:  []types.Endpoint{{URL: server.URL + "/login", Method: "POST"}},
		Search: []types.Endpoint{{URL: server.URL + "/search?q=test", Method: "GET", Parameters: []string{"q"}}},
	}
	currentClassified = classified
	defer func() { currentClassified = nil }()

	target := types.Target{URL: server.URL}
	p := &SQLiProber{}
	findings := p.Probe(context.Background(), target, nil)

	// A safe server returning generic 200 with "data" might trigger the UNION check
	// but should not produce critical/high findings for error-based
	for _, f := range findings {
		if strings.Contains(f.Title, "Error Disclosure") {
			t.Errorf("safe server should not trigger SQL error disclosure finding: %s", f.Title)
		}
	}
}

func TestSQLiProber_ParameterInjection(t *testing.T) {
	// Mock server that leaks SQL errors on parameter injection
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.URL.Query().Get("id")
		if strings.Contains(id, "'") {
			w.WriteHeader(500)
			w.Write([]byte(`Error: SQLSTATE[42000]: Syntax error`))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"user":{"id":1,"name":"test"}}`))
	}))
	defer server.Close()

	currentClassified = &types.ClassifiedEndpoints{}
	defer func() { currentClassified = nil }()

	target := types.Target{URL: server.URL}
	endpoints := []types.Endpoint{
		{URL: server.URL + "/api/user?id=1", Method: "GET", Parameters: []string{"id"}},
	}

	p := &SQLiProber{}
	findings := p.Probe(context.Background(), target, endpoints)

	if len(findings) == 0 {
		t.Fatal("expected SQLi finding for parameter injection")
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Parameter 'id'") {
			found = true
		}
	}
	if !found {
		t.Error("expected finding mentioning parameter 'id'")
	}
}

func TestIsReadOnlyParam(t *testing.T) {
	readOnly := []string{"ver", "v", "version", "cache", "cb", "t", "ts", "_", "nocache"}
	for _, p := range readOnly {
		if !IsReadOnlyParam(p) {
			t.Errorf("expected %q to be read-only param", p)
		}
	}

	attackable := []string{"id", "q", "search", "email", "name", "url"}
	for _, p := range attackable {
		if IsReadOnlyParam(p) {
			t.Errorf("expected %q to NOT be read-only param", p)
		}
	}
}

func TestIsStaticAssetURL(t *testing.T) {
	static := []string{
		"http://example.com/app.js",
		"http://example.com/style.css",
		"http://example.com/logo.png",
		"http://example.com/font.woff2",
		"http://example.com/app.js?v=123",
	}
	for _, u := range static {
		if !IsStaticAssetURL(u) {
			t.Errorf("expected %q to be detected as static asset", u)
		}
	}

	dynamic := []string{
		"http://example.com/api/users",
		"http://example.com/login",
		"http://example.com/search?q=test",
	}
	for _, u := range dynamic {
		if IsStaticAssetURL(u) {
			t.Errorf("expected %q to NOT be detected as static asset", u)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
