package probers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

func TestXSSProber_Name(t *testing.T) {
	p := &XSSProber{}
	if p.Name() != "xss" {
		t.Errorf("expected prober name 'xss', got '%s'", p.Name())
	}
}

func TestXSSProber_DetectsReflectedXSS(t *testing.T) {
	// Mock server that reflects input without sanitization
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		// Vulnerable: reflects query parameter directly in HTML
		w.Write([]byte(`<html><body><h1>Search results for: ` + q + `</h1></body></html>`))
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
	p := &XSSProber{}
	findings := p.Probe(context.Background(), target, nil)

	if len(findings) == 0 {
		t.Fatal("expected XSS finding for vulnerable search endpoint")
	}

	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "XSS") && strings.Contains(f.Title, "Search") {
			found = true
			if f.CWE != "CWE-79" {
				t.Errorf("expected CWE-79, got %s", f.CWE)
			}
		}
	}
	if !found {
		t.Error("expected a Reflected XSS finding for search endpoint")
	}
}

func TestXSSProber_NoFalsePositiveOnSafeServer(t *testing.T) {
	// Mock server that properly sanitizes output
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"results":[],"query":"sanitized"}`))
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
	p := &XSSProber{}
	findings := p.Probe(context.Background(), target, nil)

	for _, f := range findings {
		if strings.Contains(f.Title, "Reflected XSS") && strings.Contains(f.Title, "Search") {
			t.Errorf("safe server should not trigger Reflected XSS finding: %s", f.Title)
		}
	}
}

func TestXSSProber_DetectsParameterXSS(t *testing.T) {
	// Mock server that reflects a named parameter
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := r.URL.Query().Get("name")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(200)
		w.Write([]byte(`<html><body><p>Hello ` + name + `</p></body></html>`))
	}))
	defer server.Close()

	currentClassified = &types.ClassifiedEndpoints{}
	defer func() { currentClassified = nil }()

	target := types.Target{URL: server.URL}
	endpoints := []types.Endpoint{
		{URL: server.URL + "/greet?name=user", Method: "GET", Parameters: []string{"name"}},
	}

	p := &XSSProber{}
	findings := p.Probe(context.Background(), target, endpoints)

	if len(findings) == 0 {
		t.Fatal("expected XSS finding for parameter injection on /greet")
	}
}
