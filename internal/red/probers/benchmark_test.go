package probers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// mockVulnServer creates a realistic vulnerable web app mock for benchmarking.
func mockVulnServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		q := r.URL.Query()

		switch {
		// Login endpoint (SQLi vulnerable)
		case path == "/login" || path == "/api/login":
			if r.Method == "POST" {
				body := make([]byte, 4096)
				n, _ := r.Body.Read(body)
				bodyStr := string(body[:n])
				if strings.Contains(bodyStr, "OR 1=1") {
					w.WriteHeader(200)
					w.Write([]byte(`{"token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.fake"}`))
					return
				}
				w.WriteHeader(401)
				w.Write([]byte(`{"error":"Invalid credentials"}`))
				return
			}
			w.WriteHeader(200)
			w.Write([]byte(`<form><input name="email"><input name="password" type="password"></form>`))

		// Search endpoint (SQL error disclosure)
		case path == "/search":
			query := q.Get("q")
			if strings.Contains(query, "'") {
				w.WriteHeader(500)
				w.Write([]byte(`{"error":"SequelizeDatabaseError: SQLITE_ERROR: unrecognized token"}`))
				return
			}
			w.WriteHeader(200)
			w.Write([]byte(`{"results":[]}`))

		// Admin panel
		case strings.HasPrefix(path, "/admin"):
			w.WriteHeader(200)
			w.Write([]byte(`<html><head><title>Admin Panel</title></head><body>Dashboard</body></html>`))

		// User profile (IDOR candidate)
		case strings.HasPrefix(path, "/api/users/"):
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(200)
			w.Write([]byte(`{"id":1,"email":"admin@test.com","role":"admin"}`))

		// File upload
		case path == "/upload":
			w.WriteHeader(200)
			w.Write([]byte(`<form enctype="multipart/form-data"><input type="file" name="avatar"></form>`))

		// Redirect endpoint
		case path == "/redirect":
			target := q.Get("url")
			if target != "" {
				w.Header().Set("Location", target)
				w.WriteHeader(302)
				return
			}
			w.WriteHeader(200)

		// API endpoint with missing security headers
		case strings.HasPrefix(path, "/api/"):
			w.Header().Set("Content-Type", "application/json")
			// Intentionally missing: X-Frame-Options, CSP, etc.
			w.WriteHeader(200)
			w.Write([]byte(`{"data":"test"}`))

		// Reflected XSS candidate
		case path == "/error":
			msg := q.Get("msg")
			w.WriteHeader(200)
			w.Write([]byte(fmt.Sprintf(`<html><body><h1>Error: %s</h1></body></html>`, msg)))

		// .env file exposure
		case path == "/.env":
			w.WriteHeader(200)
			w.Write([]byte("DB_HOST=localhost\nDB_PASSWORD=secret123\nAPI_KEY=sk-test-12345"))

		// Git exposure
		case path == "/.git/config":
			w.WriteHeader(200)
			w.Write([]byte("[core]\n\trepositoryformatversion = 0"))

		// Default
		default:
			w.WriteHeader(200)
			w.Write([]byte(`<html><head><title>Test App</title></head><body>Welcome</body></html>`))
		}
	}))
}

func buildTestEndpoints(baseURL string) []types.Endpoint {
	return []types.Endpoint{
		{URL: baseURL + "/", Method: "GET", StatusCode: 200, ContentType: "text/html"},
		{URL: baseURL + "/login", Method: "GET", StatusCode: 200, ContentType: "text/html",
			Body: `<form><input name="email"><input name="password" type="password"></form>`},
		{URL: baseURL + "/api/login", Method: "POST", StatusCode: 200, ContentType: "application/json"},
		{URL: baseURL + "/search?q=test", Method: "GET", StatusCode: 200, ContentType: "application/json",
			Parameters: []string{"q"}},
		{URL: baseURL + "/admin/dashboard", Method: "GET", StatusCode: 200, ContentType: "text/html"},
		{URL: baseURL + "/api/users/1", Method: "GET", StatusCode: 200, ContentType: "application/json"},
		{URL: baseURL + "/upload", Method: "GET", StatusCode: 200, ContentType: "text/html",
			Body: `<form enctype="multipart/form-data"><input type="file" name="avatar"></form>`},
		{URL: baseURL + "/redirect?url=http://example.com", Method: "GET", StatusCode: 302,
			Parameters: []string{"url"}},
		{URL: baseURL + "/api/products", Method: "GET", StatusCode: 200, ContentType: "application/json",
			Parameters: []string{"page", "limit"}},
		{URL: baseURL + "/error?msg=test", Method: "GET", StatusCode: 200, ContentType: "text/html",
			Parameters: []string{"msg"}},
		{URL: baseURL + "/profile", Method: "GET", StatusCode: 200, ContentType: "text/html"},
		{URL: baseURL + "/settings", Method: "GET", StatusCode: 200, ContentType: "text/html"},
	}
}

func BenchmarkAllProbers(b *testing.B) {
	server := mockVulnServer()
	defer server.Close()

	// Disable rate limiting for benchmark
	SetRate(0)
	defer SetRate(10)

	endpoints := buildTestEndpoints(server.URL)
	target := types.Target{URL: server.URL}

	// Classify once
	classified := classifyForBenchmark(endpoints)
	currentClassified = classified
	defer func() { currentClassified = nil }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		RunAllProbers(context.Background(), target, endpoints, classified, 1)
	}
}

func BenchmarkSQLiProber(b *testing.B) {
	server := mockVulnServer()
	defer server.Close()

	SetRate(0)
	defer SetRate(10)

	endpoints := buildTestEndpoints(server.URL)
	target := types.Target{URL: server.URL}

	classified := classifyForBenchmark(endpoints)
	currentClassified = classified
	defer func() { currentClassified = nil }()

	prober := &SQLiProber{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prober.Probe(context.Background(), target, endpoints)
	}
}

func BenchmarkXSSProber(b *testing.B) {
	server := mockVulnServer()
	defer server.Close()

	SetRate(0)
	defer SetRate(10)

	endpoints := buildTestEndpoints(server.URL)
	target := types.Target{URL: server.URL}

	classified := classifyForBenchmark(endpoints)
	currentClassified = classified
	defer func() { currentClassified = nil }()

	prober := &XSSProber{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		prober.Probe(context.Background(), target, endpoints)
	}
}

// classifyForBenchmark classifies endpoints (imported from red package indirectly).
func classifyForBenchmark(endpoints []types.Endpoint) *types.ClassifiedEndpoints {
	ce := &types.ClassifiedEndpoints{All: endpoints}
	for _, ep := range endpoints {
		lp := strings.ToLower(ep.URL)
		lb := strings.ToLower(ep.Body)
		if strings.Contains(lp, "/login") || strings.Contains(lp, "/signin") ||
			(strings.Contains(lb, "password") && strings.Contains(lb, "email")) {
			ce.Login = append(ce.Login, ep)
		}
		if strings.Contains(lp, "/api/") || strings.Contains(ep.ContentType, "json") {
			ce.API = append(ce.API, ep)
		}
		if strings.Contains(lp, "/search") {
			for _, p := range ep.Parameters {
				if strings.EqualFold(p, "q") || strings.EqualFold(p, "query") {
					ce.Search = append(ce.Search, ep)
					break
				}
			}
		}
		if strings.Contains(lp, "/admin") || strings.Contains(lp, "/dashboard") {
			ce.Admin = append(ce.Admin, ep)
		}
		if strings.Contains(lp, "/upload") || strings.Contains(lb, "type=\"file\"") {
			ce.FileUpload = append(ce.FileUpload, ep)
		}
		if strings.Contains(lp, "/profile") || strings.Contains(lp, "/settings") || strings.Contains(lp, "/me") {
			ce.UserData = append(ce.UserData, ep)
		}
		for _, p := range ep.Parameters {
			if strings.EqualFold(p, "url") || strings.EqualFold(p, "redirect") {
				ce.Redirect = append(ce.Redirect, ep)
				break
			}
		}
	}
	return ce
}

// TestPerformanceAudit_LiveTargets runs a performance audit against live Docker targets.
// This is not a unit test — it measures real scan performance.
// Run with: go test -run TestPerformanceAudit_LiveTargets -v -timeout 300s
func TestPerformanceAudit_LiveTargets(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live target benchmark in short mode")
	}

	targets := []struct {
		name string
		url  string
	}{
		{"JuiceShop", "http://localhost:3000"},
		{"DVWA", "http://localhost:4280"},
		{"WebGoat", "http://localhost:18080"},
	}

	// Disable rate limiting for benchmarks
	SetRate(0)
	defer SetRate(10)

	fmt.Println("\n═══════════════════════════════════════════════════")
	fmt.Println("  OUROBOROS PERFORMANCE AUDIT — Live Targets")
	fmt.Println("═══════════════════════════════════════════════════")

	for _, tgt := range targets {
		// Check if target is reachable
		client := &http.Client{Timeout: 3 * time.Second}
		resp, err := client.Get(tgt.url)
		if err != nil {
			fmt.Printf("\n  ⚫ %s (%s) — UNREACHABLE\n", tgt.name, tgt.url)
			continue
		}
		resp.Body.Close()

		fmt.Printf("\n  🎯 %s (%s)\n", tgt.name, tgt.url)
		fmt.Printf("  ─────────────────────────────────\n")

		target := types.Target{URL: tgt.url}

		// Measure crawl time (via prober endpoint setup)
		start := time.Now()

		// Run all probers
		endpoints := buildLiveEndpoints(tgt.url)
		classified := classifyForBenchmark(endpoints)
		currentClassified = classified

		findings := RunAllProbers(context.Background(), target, endpoints, classified, 1)
		elapsed := time.Since(start)
		reqCount := GetRequestCount()

		fmt.Printf("  Time:      %s\n", elapsed.Round(time.Millisecond))
		fmt.Printf("  Endpoints: %d\n", len(endpoints))
		fmt.Printf("  Findings:  %d\n", len(findings))
		fmt.Printf("  Requests:  %d\n", reqCount)
		if elapsed.Seconds() > 0 {
			fmt.Printf("  Req/sec:   %.1f\n", float64(reqCount)/elapsed.Seconds())
		}

		// Show findings breakdown
		sevCount := map[string]int{}
		for _, f := range findings {
			sevCount[f.Severity.String()]++
		}
		fmt.Printf("  Severity:  %d crit, %d high, %d med, %d low\n",
			sevCount["Critical"], sevCount["High"], sevCount["Medium"], sevCount["Low"])

		currentClassified = nil
	}

	fmt.Println("\n═══════════════════════════════════════════════════")
}

func buildLiveEndpoints(baseURL string) []types.Endpoint {
	// Quick probe common paths to build endpoint list
	client := &http.Client{Timeout: 5 * time.Second}
	paths := []string{"/", "/login", "/api/login", "/admin", "/search?q=test",
		"/api/users/1", "/upload", "/profile", "/settings", "/api/products",
		"/.env", "/.git/config", "/robots.txt", "/sitemap.xml"}

	var endpoints []types.Endpoint
	for _, path := range paths {
		url := strings.TrimRight(baseURL, "/") + path
		resp, err := client.Get(url)
		if err != nil {
			continue
		}
		body := make([]byte, 8192)
		n, _ := resp.Body.Read(body)
		resp.Body.Close()

		ep := types.Endpoint{
			URL:         url,
			Method:      "GET",
			StatusCode:  resp.StatusCode,
			ContentType: resp.Header.Get("Content-Type"),
			Body:        string(body[:n]),
		}

		// Extract params from URL
		if idx := strings.Index(path, "?"); idx >= 0 {
			paramStr := path[idx+1:]
			for _, p := range strings.Split(paramStr, "&") {
				parts := strings.SplitN(p, "=", 2)
				ep.Parameters = append(ep.Parameters, parts[0])
			}
		}

		endpoints = append(endpoints, ep)
	}
	return endpoints
}
