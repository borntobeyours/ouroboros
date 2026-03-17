package probers

import (
	"context"
	"fmt"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// InfoLeakProber tests for information disclosure and sensitive data exposure.
type InfoLeakProber struct{}

func (p *InfoLeakProber) Name() string { return "infoleaks" }

func (p *InfoLeakProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	if currentClassified != nil {
		cfg.Classified = currentClassified
	}
	var findings []types.Finding

	findings = append(findings, p.testSensitiveFiles(cfg)...)
	findings = append(findings, p.testMetrics(cfg)...)
	findings = append(findings, p.testAPIDocExposure(cfg)...)
	findings = append(findings, p.testAPIDataExposure(cfg)...)
	findings = append(findings, p.testErrorDisclosure(cfg, endpoints)...)
	findings = append(findings, p.testSecurityTxt(cfg)...)
	findings = append(findings, p.testRobotsTxt(cfg)...)

	return findings
}

func (p *InfoLeakProber) testSensitiveFiles(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	sensitivePaths := []struct {
		path     string
		desc     string
		severity string
		cwe      string
		content  []string // expected content indicators
	}{
		{"/.git/config", "Git configuration exposed", "High", "CWE-538", []string{"[core]", "[remote", "ref:"}},
		{"/.git/HEAD", "Git HEAD reference exposed", "Medium", "CWE-538", []string{"ref:", "commit"}},
		{"/.env", "Environment file exposed", "Critical", "CWE-538", []string{"=", "DB_", "API_", "SECRET", "KEY", "PASSWORD"}},
		{"/backup", "Backup directory accessible", "High", "CWE-538", nil},
		{"/dump", "Database dump accessible", "Critical", "CWE-538", nil},
		{"/.htaccess", "Apache configuration exposed", "Medium", "CWE-538", []string{"rewrite", "deny", "allow"}},
		{"/web.config", "IIS configuration exposed", "Medium", "CWE-538", []string{"configuration", "system.web"}},
		{"/.DS_Store", "macOS directory metadata exposed", "Low", "CWE-538", nil},
		{"/package.json", "Node.js package manifest exposed", "Low", "CWE-538", []string{"name", "version", "dependencies"}},
		{"/composer.json", "PHP Composer manifest exposed", "Low", "CWE-538", []string{"name", "require"}},
		{"/Gemfile", "Ruby Gemfile exposed", "Low", "CWE-538", []string{"source", "gem"}},
	}

	for _, sp := range sensitivePaths {
		url := cfg.BaseURL + sp.path
		status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
		if err != nil || status != 200 || len(respBody) <= 10 {
			continue
		}

		// SPA detection
		if cfg.IsSPAResponse(url) {
			continue
		}

		// Skip if response is generic HTML without expected file content
		if strings.Contains(respBody, "<!doctype html>") || strings.Contains(respBody, "<!DOCTYPE html>") {
			if sp.content != nil {
				hasExpected := false
				lower := strings.ToLower(respBody)
				for _, c := range sp.content {
					if strings.Contains(lower, strings.ToLower(c)) {
						hasExpected = true
						break
					}
				}
				if !hasExpected {
					continue
				}
			} else {
				continue
			}
		}

		findings = append(findings, MakeFinding(
			fmt.Sprintf("Sensitive File Exposure - %s", sp.desc),
			sp.severity,
			fmt.Sprintf("Sensitive file/directory accessible at %s: %s", sp.path, sp.desc),
			sp.path,
			"GET",
			sp.cwe,
			fmt.Sprintf(`curl %s`, url),
			fmt.Sprintf("HTTP %d - Content: %s", status, truncate(respBody, 200)),
			"info_leak",
			0,
		))
	}

	return findings
}

func (p *InfoLeakProber) testMetrics(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	metricsPaths := []struct {
		path      string
		desc      string
		indicators []string
	}{
		{"/metrics", "Prometheus metrics", []string{"process_", "http_", "nodejs_", "go_", "python_"}},
		{"/actuator", "Spring Boot Actuator", []string{"_links", "health", "beans"}},
		{"/actuator/env", "Spring Boot environment", []string{"property", "value", "source"}},
		{"/actuator/health", "Spring Boot health", []string{"status", "UP", "DOWN"}},
		{"/health", "Health check endpoint", []string{"status", "healthy", "ok"}},
		{"/debug/vars", "Go debug variables", []string{"memstats", "cmdline"}},
		{"/debug/pprof", "Go profiling endpoint", []string{"goroutine", "heap", "profile"}},
	}

	for _, mp := range metricsPaths {
		url := cfg.BaseURL + mp.path
		status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
		if err != nil || status != 200 {
			continue
		}

		lowerBody := strings.ToLower(respBody)
		for _, indicator := range mp.indicators {
			if strings.Contains(lowerBody, strings.ToLower(indicator)) {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("Information Disclosure - %s Exposed", mp.desc),
					"Medium",
					fmt.Sprintf("The %s endpoint is publicly accessible, exposing internal system information.", mp.path),
					mp.path,
					"GET",
					"CWE-200",
					fmt.Sprintf(`curl %s`, url),
					fmt.Sprintf("HTTP %d - Data: %s", status, truncate(respBody, 300)),
					"info_leak",
					0,
				))
				break
			}
		}
	}

	return findings
}

func (p *InfoLeakProber) testAPIDocExposure(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	docPaths := []string{"/api-docs", "/swagger.json", "/api-docs/swagger.json",
		"/swagger-ui.html", "/openapi.json", "/openapi.yaml", "/redoc"}
	for _, path := range docPaths {
		url := cfg.BaseURL + path
		status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
		if err != nil || status != 200 {
			continue
		}

		lowerBody := strings.ToLower(respBody)
		if strings.Contains(lowerBody, "swagger") || strings.Contains(lowerBody, "openapi") ||
			strings.Contains(lowerBody, "paths") || strings.Contains(lowerBody, "api-docs") {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Information Disclosure - API Documentation Exposed (%s)", path),
				"Medium",
				"API documentation is publicly accessible, exposing all API endpoints, parameters, and data models to attackers.",
				path,
				"GET",
				"CWE-200",
				fmt.Sprintf(`curl %s`, url),
				fmt.Sprintf("HTTP %d - API docs: %s", status, truncate(respBody, 200)),
				"info_leak",
				0,
			))
			break
		}
	}

	return findings
}

func (p *InfoLeakProber) testAPIDataExposure(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil {
		return findings
	}

	// Check API endpoints that might expose sensitive data without auth
	tested := make(map[string]bool)
	for _, ep := range cfg.Classified.API {
		path := extractPath(ep.URL)

		if tested[path] {
			continue
		}
		tested[path] = true

		// Only check endpoints that returned data during discovery
		if ep.StatusCode != 200 || len(ep.Body) < 20 {
			continue
		}

		// Skip known public-by-design CMS APIs
		lowerPath := strings.ToLower(path)
		if strings.Contains(lowerPath, "wp-json/wp/v2/posts") ||
			strings.Contains(lowerPath, "wp-json/wp/v2/pages") ||
			strings.Contains(lowerPath, "wp-json/wp/v2/categories") ||
			strings.Contains(lowerPath, "wp-json/wp/v2/tags") ||
			strings.Contains(lowerPath, "wp-json/wp/v2/comments") ||
			strings.Contains(lowerPath, "wp-json/wp/v2/media") ||
			strings.Contains(lowerPath, "wp-json/oembed") ||
			strings.Contains(lowerPath, "wp-json/wp/v2/types") ||
			strings.Contains(lowerPath, "wp-json/wp/v2/statuses") ||
			strings.Contains(lowerPath, "/feed") ||
			strings.Contains(lowerPath, "/rss") {
			continue
		}

		lowerBody := strings.ToLower(ep.Body)

		// Only flag actually sensitive data — passwords, tokens, secrets, cards
		// NOT just "email" or "name" which appear in public APIs
		highSensitivity := []string{"password", "passwd", "secret", "token",
			"api_key", "apikey", "private_key", "credit_card", "cardnum",
			"ssn", "social_security"}

		for _, indicator := range highSensitivity {
			if strings.Contains(lowerBody, indicator) {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("Sensitive Data Exposure - %s API", path),
					"High",
					fmt.Sprintf("The %s endpoint exposes data containing '%s' without requiring authentication.", path, indicator),
					path,
					"GET",
					"CWE-200",
					fmt.Sprintf(`curl %s`, ep.URL),
					fmt.Sprintf("HTTP %d - Contains '%s': %s", ep.StatusCode, indicator, truncate(ep.Body, 200)),
					"info_leak",
					0,
				))
				break // One finding per endpoint
			}
		}
	}

	return findings
}

func (p *InfoLeakProber) testErrorDisclosure(cfg *ProberConfig, endpoints []types.Endpoint) []types.Finding {
	var findings []types.Finding

	// Test various endpoints for verbose error messages
	testPaths := []string{
		"/api/nonexistent_endpoint_test",
		"/api/users/0",
		"/api/users/undefined",
	}

	// Also test discovered endpoints with bad input
	for _, ep := range endpoints {
		if ep.HasCategory(types.CatAPI) {
			testPaths = append(testPaths, extractPath(ep.URL)+"/undefined")
			if len(testPaths) > 10 {
				break
			}
		}
	}

	for _, path := range testPaths {
		url := cfg.BaseURL + path
		status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
		if err != nil {
			continue
		}

		lowerBody := strings.ToLower(respBody)
		if (status >= 400 && status < 600) &&
			(strings.Contains(lowerBody, "stack") || strings.Contains(lowerBody, "trace") ||
				strings.Contains(lowerBody, "at module") || strings.Contains(lowerBody, "node_modules") ||
				strings.Contains(lowerBody, "sequelize") || strings.Contains(lowerBody, "typeerror") ||
				strings.Contains(lowerBody, "exception") || strings.Contains(lowerBody, "traceback") ||
				strings.Contains(lowerBody, "at com.") || strings.Contains(lowerBody, "at org.")) {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Verbose Error Messages - Stack Trace at %s", path),
				"Low",
				"The application returns detailed error messages including stack traces, revealing internal implementation details.",
				path,
				"GET",
				"CWE-209",
				fmt.Sprintf(`curl %s`, url),
				fmt.Sprintf("HTTP %d - Error details: %s", status, truncate(respBody, 200)),
				"info_leak",
				0,
			))
			break // One finding for error disclosure
		}
	}

	return findings
}

func (p *InfoLeakProber) testSecurityTxt(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	url := cfg.BaseURL + "/.well-known/security.txt"
	status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
	if err == nil && status == 200 && len(respBody) > 10 && !cfg.IsSPAResponse(url) {
		findings = append(findings, MakeFinding(
			"Information Disclosure - security.txt",
			"Info",
			"A security.txt file is present, which while good practice, may contain useful reconnaissance information.",
			"/.well-known/security.txt",
			"GET",
			"CWE-200",
			fmt.Sprintf(`curl %s`, url),
			fmt.Sprintf("HTTP %d - Content: %s", status, truncate(respBody, 200)),
			"info_leak",
			0,
		))
	}

	return findings
}

func (p *InfoLeakProber) testRobotsTxt(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	url := cfg.BaseURL + "/robots.txt"
	status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
	if err == nil && status == 200 && (strings.Contains(respBody, "Disallow") || strings.Contains(respBody, "Allow")) {
		findings = append(findings, MakeFinding(
			"Information Disclosure - robots.txt Reveals Hidden Paths",
			"Info",
			"robots.txt reveals paths that the application wants to keep from search engines, useful for reconnaissance.",
			"/robots.txt",
			"GET",
			"CWE-200",
			fmt.Sprintf(`curl %s`, url),
			fmt.Sprintf("HTTP %d - Content: %s", status, truncate(respBody, 200)),
			"info_leak",
			0,
		))
	}

	return findings
}
