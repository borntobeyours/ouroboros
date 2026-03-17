package probers

import (
	"context"
	"fmt"
	"strings"

	"github.com/ouroboros-security/ouroboros/pkg/types"
)

// InfoLeakProber tests for information disclosure and sensitive data exposure.
type InfoLeakProber struct{}

func (p *InfoLeakProber) Name() string { return "infoleaks" }

func (p *InfoLeakProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	var findings []types.Finding

	findings = append(findings, p.testFTPDirectory(cfg)...)
	findings = append(findings, p.testEncryptionKeys(cfg)...)
	findings = append(findings, p.testSupportLogs(cfg)...)
	findings = append(findings, p.testMetrics(cfg)...)
	findings = append(findings, p.testAPIDocExposure(cfg)...)
	findings = append(findings, p.testSensitiveFiles(cfg)...)
	findings = append(findings, p.testAPIDataExposure(cfg)...)
	findings = append(findings, p.testErrorDisclosure(cfg)...)
	findings = append(findings, p.testSnippets(cfg)...)
	findings = append(findings, p.testSecurityTxt(cfg)...)
	findings = append(findings, p.testRobotsTxt(cfg)...)
	findings = append(findings, p.testVideoPromotion(cfg)...)

	return findings
}

func (p *InfoLeakProber) testFTPDirectory(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Main FTP directory
	url := cfg.BaseURL + "/ftp"
	status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
	if err == nil && status == 200 {
		findings = append(findings, MakeFinding(
			"Information Disclosure - FTP Directory Listing",
			"Medium",
			"An FTP directory is publicly accessible, exposing internal files including confidential documents.",
			"/ftp",
			"GET",
			"CWE-548",
			fmt.Sprintf(`curl %s`, url),
			fmt.Sprintf("HTTP %d - Directory listing: %s", status, truncate(respBody, 200)),
			"info_leak",
			0,
		))
	}

	// Specific sensitive files in FTP
	ftpFiles := []struct {
		path     string
		desc     string
		severity string
	}{
		{"/ftp/acquisitions.md", "confidential acquisition document", "High"},
		{"/ftp/package.json.bak", "package.json backup exposing dependencies", "Medium"},
		{"/ftp/suspicious_errors.yml", "error configuration file with sensitive data", "Medium"},
		{"/ftp/encrypt.pyc", "compiled Python encryption script", "Medium"},
		{"/ftp/incident-support.kdbx", "KeePass database file", "High"},
	}

	for _, f := range ftpFiles {
		fURL := cfg.BaseURL + f.path
		s, _, rb, e := cfg.DoRequest("GET", fURL, nil, nil)
		if e == nil && s == 200 && len(rb) > 0 {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Sensitive File Exposure - %s", f.path),
				f.severity,
				fmt.Sprintf("Sensitive file accessible: %s (%s)", f.path, f.desc),
				f.path,
				"GET",
				"CWE-538",
				fmt.Sprintf(`curl %s`, fURL),
				fmt.Sprintf("HTTP %d - File accessible (%d bytes)", s, len(rb)),
				"info_leak",
				0,
			))
		}
	}

	// Null byte bypass for restricted files
	nullByteFiles := []struct {
		path string
		desc string
	}{
		{"/ftp/coupons_2013.md.bak%2500.md", "coupon codes via null byte bypass"},
		{"/ftp/eastere.gg%2500.md", "easter egg via null byte bypass"},
	}

	for _, f := range nullByteFiles {
		fURL := cfg.BaseURL + f.path
		s, _, rb, e := cfg.DoRequest("GET", fURL, nil, nil)
		if e == nil && s == 200 && len(rb) > 0 {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Path Traversal - Null Byte Bypass (%s)", f.desc),
				"High",
				fmt.Sprintf("File download restriction bypassed using null byte encoding: %s", f.path),
				f.path,
				"GET",
				"CWE-158",
				fmt.Sprintf(`curl "%s"`, fURL),
				fmt.Sprintf("HTTP %d - File downloaded (%d bytes): %s", s, len(rb), truncate(rb, 100)),
				"path_traversal",
				0,
			))
		}
	}

	return findings
}

func (p *InfoLeakProber) testEncryptionKeys(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	paths := []struct {
		path     string
		desc     string
		severity string
	}{
		{"/encryptionkeys", "encryption keys directory listing", "Critical"},
		{"/encryptionkeys/jwt.pub", "JWT public key exposed", "High"},
	}

	for _, kp := range paths {
		url := cfg.BaseURL + kp.path
		status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
		if err == nil && status == 200 && len(respBody) > 0 {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Cryptographic Key Exposure - %s", kp.desc),
				kp.severity,
				fmt.Sprintf("Encryption key material is publicly accessible at %s. This can be used to forge JWT tokens or decrypt sensitive data.", kp.path),
				kp.path,
				"GET",
				"CWE-321",
				fmt.Sprintf(`curl %s`, url),
				fmt.Sprintf("HTTP %d - Key data: %s", status, truncate(respBody, 200)),
				"info_leak",
				0,
			))
		}
	}

	return findings
}

func (p *InfoLeakProber) testSupportLogs(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	url := cfg.BaseURL + "/support/logs"
	status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
	if err == nil && (status == 200 || status == 403) {
		if status == 200 && len(respBody) > 0 {
			findings = append(findings, MakeFinding(
				"Information Disclosure - Support Logs Exposed",
				"High",
				"Application support logs are publicly accessible, potentially containing sensitive user data, stack traces, and internal system information.",
				"/support/logs",
				"GET",
				"CWE-532",
				fmt.Sprintf(`curl %s`, url),
				fmt.Sprintf("HTTP %d - Log data: %s", status, truncate(respBody, 200)),
				"info_leak",
				0,
			))
		}
	}

	return findings
}

func (p *InfoLeakProber) testMetrics(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	url := cfg.BaseURL + "/metrics"
	status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
	if err == nil && status == 200 && (strings.Contains(respBody, "process_") || strings.Contains(respBody, "nodejs") || strings.Contains(respBody, "http_")) {
		findings = append(findings, MakeFinding(
			"Information Disclosure - Prometheus Metrics Exposed",
			"Medium",
			"Application metrics endpoint is publicly accessible, exposing internal system metrics, memory usage, request counts, and endpoint information.",
			"/metrics",
			"GET",
			"CWE-200",
			fmt.Sprintf(`curl %s`, url),
			fmt.Sprintf("HTTP %d - Metrics data: %s", status, truncate(respBody, 300)),
			"info_leak",
			0,
		))
	}

	return findings
}

func (p *InfoLeakProber) testAPIDocExposure(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	docPaths := []string{"/api-docs", "/swagger.json", "/api-docs/swagger.json"}
	for _, path := range docPaths {
		url := cfg.BaseURL + path
		status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
		if err == nil && status == 200 && (strings.Contains(respBody, "swagger") || strings.Contains(respBody, "openapi") || strings.Contains(respBody, "paths")) {
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
			break // One finding is enough
		}
	}

	return findings
}

func (p *InfoLeakProber) testSensitiveFiles(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	sensitivePaths := []struct {
		path     string
		desc     string
		severity string
		cwe      string
	}{
		{"/.git/config", "Git configuration exposed", "High", "CWE-538"},
		{"/.git/HEAD", "Git HEAD reference exposed", "Medium", "CWE-538"},
		{"/.env", "Environment file exposed", "Critical", "CWE-538"},
		{"/backup", "Backup directory accessible", "High", "CWE-538"},
		{"/dump", "Database dump accessible", "Critical", "CWE-538"},
	}

	for _, sp := range sensitivePaths {
		url := cfg.BaseURL + sp.path
		status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
		if err == nil && status == 200 && len(respBody) > 10 {
			// SPA detection: skip if response is identical to base URL (catch-all route)
			if cfg.IsSPAResponse(url) {
				continue
			}
			// Additional check: skip if response is generic HTML without expected file content
			if strings.Contains(respBody, "<!doctype html>") && !strings.Contains(respBody, "ref:") && !strings.Contains(respBody, "[core]") {
				continue
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
	}

	return findings
}

func (p *InfoLeakProber) testAPIDataExposure(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// APIs that expose data without auth
	apiPaths := []struct {
		path string
		desc string
		data string
	}{
		{"/api/Products", "product catalog with sensitive pricing data", "name"},
		{"/api/Challenges", "challenge/vulnerability list exposed", "name"},
		{"/api/Quantitys", "product quantities exposed", "data"},
		{"/api/Recycles", "recycling data exposed", "data"},
	}

	for _, ap := range apiPaths {
		url := cfg.BaseURL + ap.path
		status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
		if err == nil && status == 200 && strings.Contains(respBody, ap.data) {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Sensitive Data Exposure - %s API", strings.TrimPrefix(ap.path, "/api/")),
				"Medium",
				fmt.Sprintf("The %s endpoint exposes %s without requiring authentication.", ap.path, ap.desc),
				ap.path,
				"GET",
				"CWE-200",
				fmt.Sprintf(`curl %s`, url),
				fmt.Sprintf("HTTP %d - Data: %s", status, truncate(respBody, 200)),
				"info_leak",
				0,
			))
		}
	}

	return findings
}

func (p *InfoLeakProber) testErrorDisclosure(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Trigger errors to check for stack traces
	errorPaths := []string{
		"/api/nonexistent",
		"/rest/products/search?q=",
		"/api/Users/0",
	}

	for _, path := range errorPaths {
		url := cfg.BaseURL + path
		status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
		if err != nil {
			continue
		}

		lowerBody := strings.ToLower(respBody)
		if (status >= 400 && status < 600) &&
			(strings.Contains(lowerBody, "stack") || strings.Contains(lowerBody, "trace") ||
				strings.Contains(lowerBody, "at module") || strings.Contains(lowerBody, "node_modules") ||
				strings.Contains(lowerBody, "sequelize") || strings.Contains(lowerBody, "typeerror")) {
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

func (p *InfoLeakProber) testSnippets(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	url := cfg.BaseURL + "/snippets"
	status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
	if err == nil && status == 200 && len(respBody) > 10 {
		findings = append(findings, MakeFinding(
			"Information Disclosure - Code Snippets Exposed",
			"Medium",
			"Code snippets endpoint exposes application source code fragments.",
			"/snippets",
			"GET",
			"CWE-540",
			fmt.Sprintf(`curl %s`, url),
			fmt.Sprintf("HTTP %d - Snippets: %s", status, truncate(respBody, 200)),
			"info_leak",
			0,
		))

		// Try individual snippet IDs
		for id := 1; id <= 3; id++ {
			sURL := fmt.Sprintf("%s/snippets/%d", cfg.BaseURL, id)
			s2, _, rb2, e2 := cfg.DoRequest("GET", sURL, nil, nil)
			if e2 == nil && s2 == 200 && len(rb2) > 10 {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("Source Code Disclosure - Code Snippet %d", id),
					"Medium",
					"Individual code snippets containing application source code are accessible.",
					fmt.Sprintf("/snippets/%d", id),
					"GET",
					"CWE-540",
					fmt.Sprintf(`curl %s`, sURL),
					fmt.Sprintf("HTTP %d - Source code: %s", s2, truncate(rb2, 200)),
					"info_leak",
					0,
				))
				break
			}
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

func (p *InfoLeakProber) testVideoPromotion(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	paths := []string{"/promotion", "/video"}
	for _, path := range paths {
		url := cfg.BaseURL + path
		status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
		if err == nil && status == 200 && len(respBody) > 0 && !cfg.IsSPAResponse(url) {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Unprotected Resource - %s endpoint", path),
				"Info",
				fmt.Sprintf("The %s endpoint serves content without access controls.", path),
				path,
				"GET",
				"CWE-200",
				fmt.Sprintf(`curl %s`, url),
				fmt.Sprintf("HTTP %d - Content available (%d bytes)", status, len(respBody)),
				"info_leak",
				0,
			))
		}
	}

	return findings
}
