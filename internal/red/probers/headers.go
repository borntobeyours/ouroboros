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

	// Test main page for missing headers
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

	// Test CORS with arbitrary origin
	testOrigins := []string{"https://evil.com", "null"}

	for _, origin := range testOrigins {
		status, headers, _, err := cfg.DoRequest("GET", cfg.BaseURL+"/rest/user/login", nil,
			map[string]string{"Origin": origin})
		if err != nil || status == 404 {
			continue
		}

		acao := headers.Get("Access-Control-Allow-Origin")
		acac := headers.Get("Access-Control-Allow-Credentials")

		if acao == "*" {
			findings = append(findings, MakeFinding(
				"CORS Misconfiguration - Wildcard Origin",
				"Medium",
				"The application allows any origin via Access-Control-Allow-Origin: *, enabling cross-origin data theft.",
				"/rest/user/login",
				"GET",
				"CWE-942",
				fmt.Sprintf(`curl -H "Origin: %s" -I %s/rest/user/login`, origin, cfg.BaseURL),
				fmt.Sprintf("HTTP %d - ACAO: %s", status, acao),
				"misconfig",
				0,
			))
			break
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
				"/rest/user/login",
				"GET",
				"CWE-942",
				fmt.Sprintf(`curl -H "Origin: %s" -I %s/rest/user/login`, origin, cfg.BaseURL),
				fmt.Sprintf("HTTP %d - ACAO: %s, ACAC: %s", status, acao, acac),
				"misconfig",
				0,
			))
			break
		}
	}

	return findings
}

func (p *HeadersProber) testCookieFlags(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Login to get a cookie
	body := `{"email":"' OR 1=1--","password":"anything"}`
	_, headers, _, err := cfg.DoRequest("POST", cfg.BaseURL+"/rest/user/login",
		strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
	if err != nil {
		return findings
	}

	cookies := headers.Values("Set-Cookie")
	for _, cookie := range cookies {
		cookieLower := strings.ToLower(cookie)
		cookieName := strings.Split(cookie, "=")[0]

		if !strings.Contains(cookieLower, "httponly") {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Insecure Cookie - Missing HttpOnly Flag (%s)", cookieName),
				"Medium",
				fmt.Sprintf("Cookie '%s' is set without the HttpOnly flag, making it accessible to JavaScript and vulnerable to XSS-based session theft.", cookieName),
				"/rest/user/login",
				"POST",
				"CWE-1004",
				fmt.Sprintf(`curl -I -X POST %s/rest/user/login -H "Content-Type: application/json" -d '{"email":"test@test.com","password":"test"}'`, cfg.BaseURL),
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
				"/rest/user/login",
				"POST",
				"CWE-614",
				fmt.Sprintf(`curl -I -X POST %s/rest/user/login`, cfg.BaseURL),
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
				"/rest/user/login",
				"POST",
				"CWE-1275",
				fmt.Sprintf(`curl -I -X POST %s/rest/user/login`, cfg.BaseURL),
				fmt.Sprintf("Set-Cookie: %s (missing SameSite)", truncate(cookie, 100)),
				"misconfig",
				0,
			))
		}
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

	// Test OPTIONS for unexpected methods
	status2, headers2, _, err2 := cfg.DoRequest("OPTIONS", cfg.BaseURL+"/rest/user/login", nil, nil)
	if err2 == nil && status2 == 200 {
		allow := headers2.Get("Allow")
		if allow != "" && (strings.Contains(allow, "TRACE") || strings.Contains(allow, "DELETE")) {
			findings = append(findings, MakeFinding(
				"Dangerous HTTP Methods Allowed",
				"Low",
				fmt.Sprintf("The endpoint allows potentially dangerous HTTP methods: %s", allow),
				"/rest/user/login",
				"OPTIONS",
				"CWE-749",
				fmt.Sprintf(`curl -X OPTIONS -I %s/rest/user/login`, cfg.BaseURL),
				fmt.Sprintf("HTTP %d - Allow: %s", status2, allow),
				"misconfig",
				0,
			))
		}
	}

	return findings
}
