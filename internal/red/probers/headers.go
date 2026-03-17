package probers

import (
	"context"
	"fmt"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// HeadersProber tests for missing security headers and misconfigurations.
type HeadersProber struct{}

func (p *HeadersProber) Name() string { return "headers" }

func (p *HeadersProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	if currentClassified != nil {
		cfg.Classified = currentClassified
	}
	var findings []types.Finding

	findings = append(findings, p.testSecurityHeaders(cfg)...)
	findings = append(findings, p.testCORSMisconfiguration(cfg)...)
	findings = append(findings, p.testCookieFlags(cfg)...)
	findings = append(findings, p.testServerHeader(cfg)...)
	findings = append(findings, p.testHTTPMethods(cfg)...)

	return findings
}

func (p *HeadersProber) testSecurityHeaders(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	status, headers, _, err := cfg.DoRequest("GET", cfg.BaseURL, nil, nil)
	if err != nil || status != 200 {
		return findings
	}

	headerChecks := []struct {
		header   string
		desc     string
		severity string
		cwe      string
	}{
		{"Content-Security-Policy", "Content Security Policy (CSP) not set - enables XSS attacks", "Medium", "CWE-693"},
		{"Strict-Transport-Security", "HTTP Strict Transport Security (HSTS) not set - enables MITM/downgrade attacks", "Medium", "CWE-311"},
		{"X-Frame-Options", "X-Frame-Options not set - enables clickjacking attacks", "Medium", "CWE-1021"},
		{"X-Content-Type-Options", "X-Content-Type-Options not set - enables MIME type sniffing attacks", "Low", "CWE-693"},
		{"X-XSS-Protection", "X-XSS-Protection header not set", "Low", "CWE-693"},
		{"Referrer-Policy", "Referrer-Policy not set - may leak sensitive URL parameters", "Low", "CWE-200"},
		{"Permissions-Policy", "Permissions-Policy not set - browser features not restricted", "Low", "CWE-693"},
	}

	for _, check := range headerChecks {
		val := headers.Get(check.header)
		if val == "" {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Missing Security Header - %s", check.header),
				check.severity,
				check.desc,
				"/",
				"GET",
				check.cwe,
				fmt.Sprintf(`curl -I %s`, cfg.BaseURL),
				fmt.Sprintf("HTTP %d - Header '%s' is missing from response", status, check.header),
				"misconfig",
				0,
			))
		} else if check.header == "Content-Security-Policy" && strings.Contains(val, "unsafe") {
			findings = append(findings, MakeFinding(
				"Weak Content Security Policy",
				"Medium",
				fmt.Sprintf("CSP contains 'unsafe-inline' or 'unsafe-eval' directives, weakening XSS protection. Value: %s", val),
				"/",
				"GET",
				"CWE-693",
				fmt.Sprintf(`curl -I %s`, cfg.BaseURL),
				fmt.Sprintf("CSP header: %s", val),
				"misconfig",
				0,
			))
		}
	}

	return findings
}

func (p *HeadersProber) testCORSMisconfiguration(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Test CORS on the base URL and on discovered API endpoints
	testURLs := []string{cfg.BaseURL}
	if cfg.Classified != nil && len(cfg.Classified.API) > 0 {
		testURLs = append(testURLs, cfg.Classified.API[0].URL)
	}

	testOrigins := []string{"https://evil.com", "null"}

	for _, testURL := range testURLs {
		for _, origin := range testOrigins {
			status, headers, _, err := cfg.DoRequest("GET", testURL, nil,
				map[string]string{"Origin": origin})
			if err != nil || status == 404 {
				continue
			}

			acao := headers.Get("Access-Control-Allow-Origin")
			acac := headers.Get("Access-Control-Allow-Credentials")
			path := extractPath(testURL)

			if acao == "*" {
				findings = append(findings, MakeFinding(
					"CORS Misconfiguration - Wildcard Origin",
					"Medium",
					"The application allows any origin via Access-Control-Allow-Origin: *, enabling cross-origin data theft.",
					path,
					"GET",
					"CWE-942",
					fmt.Sprintf(`curl -H "Origin: %s" -I %s`, origin, testURL),
					fmt.Sprintf("HTTP %d - ACAO: %s", status, acao),
					"misconfig",
					0,
				))
				return findings
			} else if acao == origin {
				sev := "Medium"
				desc := fmt.Sprintf("The application reflects the Origin header (%s) in ACAO.", origin)
				if acac == "true" {
					sev = "High"
					desc += " Combined with Access-Control-Allow-Credentials: true, this allows authenticated cross-origin attacks."
				}
				findings = append(findings, MakeFinding(
					"CORS Misconfiguration - Origin Reflection",
					sev,
					desc,
					path,
					"GET",
					"CWE-942",
					fmt.Sprintf(`curl -H "Origin: %s" -I %s`, origin, testURL),
					fmt.Sprintf("HTTP %d - ACAO: %s, ACAC: %s", status, acao, acac),
					"misconfig",
					0,
				))
				return findings
			}
		}
	}

	return findings
}

func (p *HeadersProber) testCookieFlags(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil || len(cfg.Classified.Login) == 0 {
		return findings
	}

	// Try to get cookies from login endpoints
	for _, ep := range cfg.Classified.Login {
		// Send a login request to get cookies
		body := `{"email":"test@test.com","password":"test"}`
		_, headers, _, err := cfg.DoRequest("POST", ep.URL,
			strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
		if err != nil {
			continue
		}

		cookies := headers.Values("Set-Cookie")
		if len(cookies) == 0 {
			continue
		}

		path := extractPath(ep.URL)
		for _, cookie := range cookies {
			cookieLower := strings.ToLower(cookie)
			cookieName := strings.Split(cookie, "=")[0]

			if !strings.Contains(cookieLower, "httponly") {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("Insecure Cookie - Missing HttpOnly Flag (%s)", cookieName),
					"Medium",
					fmt.Sprintf("Cookie '%s' is set without the HttpOnly flag, making it accessible to JavaScript and vulnerable to XSS-based session theft.", cookieName),
					path,
					"POST",
					"CWE-1004",
					fmt.Sprintf(`curl -I -X POST %s -H "Content-Type: application/json" -d '{"email":"test@test.com","password":"test"}'`, ep.URL),
					fmt.Sprintf("Set-Cookie: %s (missing HttpOnly)", truncate(cookie, 100)),
					"misconfig",
					0,
				))
			}

			if !strings.Contains(cookieLower, "secure") {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("Insecure Cookie - Missing Secure Flag (%s)", cookieName),
					"Medium",
					fmt.Sprintf("Cookie '%s' is set without the Secure flag, allowing transmission over unencrypted HTTP connections.", cookieName),
					path,
					"POST",
					"CWE-614",
					fmt.Sprintf(`curl -I -X POST %s`, ep.URL),
					fmt.Sprintf("Set-Cookie: %s (missing Secure)", truncate(cookie, 100)),
					"misconfig",
					0,
				))
			}

			if !strings.Contains(cookieLower, "samesite") {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("Insecure Cookie - Missing SameSite Attribute (%s)", cookieName),
					"Low",
					fmt.Sprintf("Cookie '%s' is set without the SameSite attribute, making it vulnerable to CSRF attacks.", cookieName),
					path,
					"POST",
					"CWE-1275",
					fmt.Sprintf(`curl -I -X POST %s`, ep.URL),
					fmt.Sprintf("Set-Cookie: %s (missing SameSite)", truncate(cookie, 100)),
					"misconfig",
					0,
				))
			}
		}
		break // Only need one endpoint
	}

	return findings
}

func (p *HeadersProber) testServerHeader(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	status, headers, _, err := cfg.DoRequest("GET", cfg.BaseURL, nil, nil)
	if err != nil {
		return findings
	}

	server := headers.Get("Server")
	xPowered := headers.Get("X-Powered-By")

	if server != "" {
		findings = append(findings, MakeFinding(
			"Information Disclosure - Server Header",
			"Low",
			fmt.Sprintf("The Server header discloses technology: %s. This aids attackers in identifying known vulnerabilities.", server),
			"/",
			"GET",
			"CWE-200",
			fmt.Sprintf(`curl -I %s`, cfg.BaseURL),
			fmt.Sprintf("HTTP %d - Server: %s", status, server),
			"info_leak",
			0,
		))
	}

	if xPowered != "" {
		findings = append(findings, MakeFinding(
			"Information Disclosure - X-Powered-By Header",
			"Low",
			fmt.Sprintf("The X-Powered-By header discloses technology: %s. This should be removed.", xPowered),
			"/",
			"GET",
			"CWE-200",
			fmt.Sprintf(`curl -I %s`, cfg.BaseURL),
			fmt.Sprintf("HTTP %d - X-Powered-By: %s", status, xPowered),
			"info_leak",
			0,
		))
	}

	return findings
}

func (p *HeadersProber) testHTTPMethods(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Test TRACE method
	status, _, respBody, err := cfg.DoRequest("TRACE", cfg.BaseURL, nil, nil)
	if err == nil && status == 200 {
		findings = append(findings, MakeFinding(
			"HTTP TRACE Method Enabled",
			"Medium",
			"The HTTP TRACE method is enabled, which can be used for Cross-Site Tracing (XST) attacks to steal credentials.",
			"/",
			"TRACE",
			"CWE-693",
			fmt.Sprintf(`curl -X TRACE %s`, cfg.BaseURL),
			fmt.Sprintf("HTTP %d - TRACE response: %s", status, truncate(respBody, 200)),
			"misconfig",
			0,
		))
	}

	// Test OPTIONS on a discovered API endpoint
	testURL := cfg.BaseURL
	if cfg.Classified != nil && len(cfg.Classified.API) > 0 {
		testURL = cfg.Classified.API[0].URL
	}
	status2, headers2, _, err2 := cfg.DoRequest("OPTIONS", testURL, nil, nil)
	if err2 == nil && status2 == 200 {
		allow := headers2.Get("Allow")
		if allow != "" && (strings.Contains(allow, "TRACE") || strings.Contains(allow, "DELETE")) {
			findings = append(findings, MakeFinding(
				"Dangerous HTTP Methods Allowed",
				"Low",
				fmt.Sprintf("The endpoint allows potentially dangerous HTTP methods: %s", allow),
				extractPath(testURL),
				"OPTIONS",
				"CWE-749",
				fmt.Sprintf(`curl -X OPTIONS -I %s`, testURL),
				fmt.Sprintf("HTTP %d - Allow: %s", status2, allow),
				"misconfig",
				0,
			))
		}
	}

	return findings
}
