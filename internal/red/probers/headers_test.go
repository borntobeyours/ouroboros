package probers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

func TestHeadersProber_Name(t *testing.T) {
	p := &HeadersProber{}
	if p.Name() != "headers" {
		t.Errorf("expected prober name 'headers', got '%s'", p.Name())
	}
}

func TestHeadersProber_DetectsMissingSecurityHeaders(t *testing.T) {
	// Mock server with no security headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>Hello</body></html>`))
	}))
	defer server.Close()

	currentClassified = &types.ClassifiedEndpoints{}
	defer func() { currentClassified = nil }()

	target := types.Target{URL: server.URL}
	p := &HeadersProber{}
	findings := p.Probe(context.Background(), target, nil)

	// Should detect missing CSP, HSTS, X-Frame-Options, etc.
	headerFindings := 0
	for _, f := range findings {
		if strings.Contains(f.Title, "Missing Security Header") {
			headerFindings++
		}
	}

	if headerFindings < 3 {
		t.Errorf("expected at least 3 missing security header findings, got %d", headerFindings)
	}
}

func TestHeadersProber_NoFindingsOnSecureServer(t *testing.T) {
	// Mock server with all security headers
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=()")
		w.WriteHeader(200)
		w.Write([]byte(`<html><body>Secure</body></html>`))
	}))
	defer server.Close()

	currentClassified = &types.ClassifiedEndpoints{}
	defer func() { currentClassified = nil }()

	target := types.Target{URL: server.URL}
	p := &HeadersProber{}
	findings := p.Probe(context.Background(), target, nil)

	for _, f := range findings {
		if strings.Contains(f.Title, "Missing Security Header") {
			t.Errorf("secure server should not have missing header findings: %s", f.Title)
		}
	}
}

func TestHeadersProber_DetectsWeakCSP(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self' 'unsafe-inline' 'unsafe-eval'")
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin")
		w.Header().Set("Permissions-Policy", "camera=()")
		w.WriteHeader(200)
		w.Write([]byte(`OK`))
	}))
	defer server.Close()

	currentClassified = &types.ClassifiedEndpoints{}
	defer func() { currentClassified = nil }()

	target := types.Target{URL: server.URL}
	p := &HeadersProber{}
	findings := p.Probe(context.Background(), target, nil)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "Weak Content Security Policy") {
			found = true
		}
	}
	if !found {
		t.Error("expected 'Weak Content Security Policy' finding for unsafe-inline CSP")
	}
}

func TestHeadersProber_DetectsCORSMisconfiguration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reflect any Origin — classic CORS misconfiguration
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"data":"secret"}`))
	}))
	defer server.Close()

	currentClassified = &types.ClassifiedEndpoints{}
	defer func() { currentClassified = nil }()

	target := types.Target{URL: server.URL}
	p := &HeadersProber{}
	findings := p.Probe(context.Background(), target, nil)

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "CORS") {
			found = true
		}
	}
	if !found {
		t.Error("expected CORS misconfiguration finding for origin-reflecting server")
	}
}
