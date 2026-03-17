package probers

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// XSSProber tests for Cross-Site Scripting vulnerabilities.
type XSSProber struct{}

func (p *XSSProber) Name() string { return "xss" }

func (p *XSSProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	if currentClassified != nil {
		cfg.Classified = currentClassified
	}
	var findings []types.Finding

	findings = append(findings, p.testSearchXSS(cfg)...)
	findings = append(findings, p.testDOMXSS(cfg)...)
	findings = append(findings, p.testStoredXSS(cfg)...)
	findings = append(findings, p.testParameterXSS(cfg, endpoints)...)

	return findings
}

func (p *XSSProber) testSearchXSS(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Get search endpoints from classifier
	var searchEndpoints []types.Endpoint
	if cfg.Classified != nil {
		searchEndpoints = cfg.Classified.Search
	}

	payloads := []struct {
		payload string
		desc    string
	}{
		{`<iframe src="javascript:alert('xss')">`, "iframe injection"},
		{`<script>alert('xss')</script>`, "script tag injection"},
		{`<img src=x onerror=alert('xss')>`, "img onerror injection"},
		{`<svg onload=alert('xss')>`, "SVG onload injection"},
	}

	for _, ep := range searchEndpoints {
		path := extractPath(ep.URL)
		baseEndpoint := strings.Split(ep.URL, "?")[0]

		// Find the search parameter
		paramToTest := findSearchParam(ep)

		for _, pl := range payloads {
			encoded := url.QueryEscape(pl.payload)
			fullURL := fmt.Sprintf("%s?%s=%s", baseEndpoint, paramToTest, encoded)
			status, _, respBody, err := cfg.DoRequest("GET", fullURL, nil, nil)
			if err != nil {
				continue
			}

			if strings.Contains(respBody, pl.payload) || strings.Contains(respBody, strings.ReplaceAll(pl.payload, "'", `\'`)) {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("Reflected XSS - Search Endpoint (%s)", pl.desc),
					"High",
					fmt.Sprintf("The search endpoint reflects user input without sanitization, enabling XSS via %s.", pl.desc),
					path+"?"+paramToTest+"=",
					"GET",
					"CWE-79",
					fmt.Sprintf(`curl "%s"`, fullURL),
					fmt.Sprintf("HTTP %d - Payload reflected in response: %s", status, truncate(respBody, 200)),
					"xss",
					0,
				))
				return findings
			} else if status == 200 && strings.Contains(respBody, "data") {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("Reflected XSS via API Response - Search (%s)", pl.desc),
					"Medium",
					fmt.Sprintf("The search endpoint includes user-controlled input in API response without sanitization. A client consuming this JSON could be vulnerable to %s.", pl.desc),
					path+"?"+paramToTest+"=",
					"GET",
					"CWE-79",
					fmt.Sprintf(`curl "%s"`, fullURL),
					fmt.Sprintf("HTTP %d - Input included in response body", status),
					"xss",
					0,
				))
				return findings
			}
		}
	}

	return findings
}

func (p *XSSProber) testDOMXSS(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Check main page for client-side frameworks that could enable DOM XSS
	status, _, respBody, err := cfg.DoRequest("GET", cfg.BaseURL, nil, nil)
	if err != nil || status != 200 {
		return findings
	}

	// Detect SPA frameworks
	spaIndicators := []string{"ng-app", "angular", "react", "vue", "__NEXT_DATA__",
		"runtime.js", "main.js", "app.js", "bundle.js"}
	isSPA := false
	for _, indicator := range spaIndicators {
		if strings.Contains(respBody, indicator) {
			isSPA = true
			break
		}
	}

	if isSPA {
		// Test hash-based DOM XSS
		testURL := cfg.BaseURL + "/#/search?q=<script>alert(1)</script>"
		s2, _, _, err2 := cfg.DoRequest("GET", testURL, nil, nil)
		if err2 == nil && s2 == 200 {
			findings = append(findings, MakeFinding(
				"DOM-based XSS via URL Fragment",
				"Medium",
				"The SPA processes URL fragments client-side. Malicious payloads in the URL hash/fragment can execute in the DOM context without server-side validation.",
				"/#/search?q=",
				"GET",
				"CWE-79",
				fmt.Sprintf(`Open in browser: %s`, testURL),
				"SPA detected - DOM rendering of URL fragment parameters without sanitization",
				"xss",
				0,
			))
		}
	}

	return findings
}

func (p *XSSProber) testStoredXSS(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.AuthToken == "" || cfg.Classified == nil {
		return findings
	}

	xssPayload := `<script>alert('xss')</script>`

	// Test stored XSS on API endpoints that accept user input
	for _, ep := range cfg.Classified.API {
		path := extractPath(ep.URL)

		// Look for endpoints that might accept reviews, comments, messages, profiles
		lowerPath := strings.ToLower(path)
		if !strings.Contains(lowerPath, "review") && !strings.Contains(lowerPath, "comment") &&
			!strings.Contains(lowerPath, "feedback") && !strings.Contains(lowerPath, "message") &&
			!strings.Contains(lowerPath, "profile") && !strings.Contains(lowerPath, "user") {
			continue
		}

		// Try POST with XSS in message/comment field
		for _, method := range []string{"POST", "PUT"} {
			for _, field := range []string{"message", "comment", "content", "body", "text", "description", "username", "name"} {
				body := fmt.Sprintf(`{"%s":"%s"}`, field, xssPayload)
				status, _, respBody, err := cfg.DoRequest(method, ep.URL,
					strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
				if err != nil {
					continue
				}

				if (status == 200 || status == 201) && strings.Contains(respBody, xssPayload) {
					findings = append(findings, MakeFinding(
						fmt.Sprintf("Stored XSS via %s field at %s", field, path),
						"High",
						fmt.Sprintf("The endpoint accepts and stores HTML/JavaScript in the '%s' field without sanitization.", field),
						path,
						method,
						"CWE-79",
						fmt.Sprintf(`curl -X %s %s -H "Content-Type: application/json" -d '%s'`, method, ep.URL, body),
						fmt.Sprintf("HTTP %d - XSS payload accepted: %s", status, truncate(respBody, 200)),
						"xss",
						0,
					))
					return findings
				}
			}
		}
	}

	return findings
}

func (p *XSSProber) testParameterXSS(cfg *ProberConfig, endpoints []types.Endpoint) []types.Finding {
	var findings []types.Finding
	tested := make(map[string]bool)

	xssPayload := `<img src=x onerror=alert(1)>`

	for _, ep := range endpoints {
		if len(ep.Parameters) == 0 {
			continue
		}
		path := extractPath(ep.URL)
		if tested[path] || ep.HasCategory(types.CatSearch) {
			continue
		}
		tested[path] = true

		for _, param := range ep.Parameters {
			testURL := fmt.Sprintf("%s?%s=%s", strings.Split(ep.URL, "?")[0], param, url.QueryEscape(xssPayload))
			_, _, respBody, err := cfg.DoRequest("GET", testURL, nil, nil)
			if err != nil {
				continue
			}

			if strings.Contains(respBody, xssPayload) {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("Reflected XSS - Parameter '%s' at %s", param, path),
					"Medium",
					fmt.Sprintf("Parameter '%s' is reflected in the response without encoding.", param),
					path,
					"GET",
					"CWE-79",
					fmt.Sprintf(`curl "%s"`, testURL),
					"Payload reflected in response body",
					"xss",
					0,
				))
			}
		}
	}

	return findings
}

func findSearchParam(ep types.Endpoint) string {
	searchParams := []string{"q", "query", "search", "keyword", "term", "s", "filter"}
	for _, p := range ep.Parameters {
		for _, sp := range searchParams {
			if strings.EqualFold(p, sp) {
				return p
			}
		}
	}
	if len(ep.Parameters) > 0 {
		return ep.Parameters[0]
	}
	return "q"
}
