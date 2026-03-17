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
	findings = append(findings, p.exploitGitExposure(cfg)...)
	findings = append(findings, p.exploitEnvFile(cfg)...)
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

// exploitGitExposure attempts full exploitation of exposed .git directories.
// Chain: .git/HEAD → ref → commit object → tree → blob (source code extraction)
func (p *InfoLeakProber) exploitGitExposure(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Step 1: Check .git/HEAD
	headURL := cfg.BaseURL + "/.git/HEAD"
	status, _, headBody, err := cfg.DoRequest("GET", headURL, nil, nil)
	if err != nil || status != 200 || len(headBody) < 5 {
		return findings
	}

	// Must contain "ref:" for a valid git HEAD
	headBody = strings.TrimSpace(headBody)
	if !strings.HasPrefix(headBody, "ref:") && len(headBody) != 40 {
		return findings
	}

	// Step 2: Resolve the ref to get commit hash
	var commitHash string
	var branch string
	if strings.HasPrefix(headBody, "ref:") {
		ref := strings.TrimSpace(strings.TrimPrefix(headBody, "ref:"))
		branch = strings.TrimPrefix(ref, "refs/heads/")
		refURL := cfg.BaseURL + "/.git/" + ref
		status, _, refBody, err := cfg.DoRequest("GET", refURL, nil, nil)
		if err == nil && status == 200 && len(refBody) >= 40 {
			commitHash = strings.TrimSpace(refBody)[:40]
		}

		// Also try packed-refs
		if commitHash == "" {
			packedURL := cfg.BaseURL + "/.git/packed-refs"
			_, _, packedBody, err := cfg.DoRequest("GET", packedURL, nil, nil)
			if err == nil && len(packedBody) > 0 {
				for _, line := range strings.Split(packedBody, "\n") {
					line = strings.TrimSpace(line)
					if strings.HasPrefix(line, "#") {
						continue
					}
					parts := strings.Fields(line)
					if len(parts) == 2 && parts[1] == ref {
						commitHash = parts[0]
						break
					}
				}
			}
		}
	} else {
		commitHash = headBody[:40]
		branch = "detached"
	}

	// Step 3: Try to read git config for remote URLs
	var remoteURL string
	configURL := cfg.BaseURL + "/.git/config"
	_, _, configBody, err := cfg.DoRequest("GET", configURL, nil, nil)
	if err == nil && len(configBody) > 0 {
		for _, line := range strings.Split(configBody, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "url = ") {
				remoteURL = strings.TrimPrefix(line, "url = ")
				break
			}
		}
	}

	// Step 4: Try to read git objects (commit → tree → blobs)
	var extractedFiles []string
	var extractedContent string

	if commitHash != "" {
		// Try loose object
		objPath := fmt.Sprintf("/.git/objects/%s/%s", commitHash[:2], commitHash[2:])
		objURL := cfg.BaseURL + objPath
		objStatus, _, _, _ := cfg.DoRequest("GET", objURL, nil, nil)

		if objStatus == 200 {
			extractedFiles = append(extractedFiles, fmt.Sprintf("commit object: %s", commitHash))
		}

		// Try info/packs to find pack files
		packsURL := cfg.BaseURL + "/.git/objects/info/packs"
		_, _, packsBody, _ := cfg.DoRequest("GET", packsURL, nil, nil)
		if len(packsBody) > 0 {
			extractedFiles = append(extractedFiles, "pack index accessible")
			for _, line := range strings.Split(packsBody, "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "P ") {
					packName := strings.TrimPrefix(line, "P ")
					// Try to access the pack index
					idxURL := cfg.BaseURL + "/.git/objects/pack/" + strings.Replace(packName, ".pack", ".idx", 1)
					idxStatus, _, _, _ := cfg.DoRequest("GET", idxURL, nil, nil)
					if idxStatus == 200 {
						extractedFiles = append(extractedFiles, fmt.Sprintf("pack index: %s", packName))
					}
				}
			}
		}
	}

	// Step 5: Try common source files via .git/logs
	logsURL := cfg.BaseURL + "/.git/logs/HEAD"
	_, _, logsBody, _ := cfg.DoRequest("GET", logsURL, nil, nil)
	if len(logsBody) > 0 {
		extractedFiles = append(extractedFiles, "git reflog (commit history)")
		// Extract commit messages from logs
		lines := strings.Split(logsBody, "\n")
		for i, line := range lines {
			if i >= 5 {
				break
			}
			if len(line) > 20 {
				extractedFiles = append(extractedFiles, fmt.Sprintf("  log: %s", truncate(line, 100)))
			}
		}
	}

	// Step 6: Try FETCH_HEAD, ORIG_HEAD for more info
	for _, ref := range []string{"FETCH_HEAD", "ORIG_HEAD", "COMMIT_EDITMSG", "description"} {
		refURL := cfg.BaseURL + "/.git/" + ref
		refStatus, _, refBody, _ := cfg.DoRequest("GET", refURL, nil, nil)
		if refStatus == 200 && len(refBody) > 0 {
			extractedFiles = append(extractedFiles, fmt.Sprintf("%s: %s", ref, truncate(strings.TrimSpace(refBody), 80)))
		}
	}

	// Build the finding based on exploitation depth
	if commitHash != "" || len(extractedFiles) > 0 {
		severity := "Critical"
		title := "Git Repository Exposed — Source Code Extractable"
		desc := fmt.Sprintf("The .git directory is fully accessible. Branch: %s.", branch)
		if commitHash != "" {
			desc += fmt.Sprintf(" Latest commit: %s.", commitHash[:8])
		}
		if remoteURL != "" {
			desc += fmt.Sprintf(" Remote: %s.", remoteURL)
		}
		desc += " An attacker can reconstruct the full source code using tools like git-dumper."

		evidence := fmt.Sprintf("HEAD: %s\n", headBody)
		if commitHash != "" {
			evidence += fmt.Sprintf("Commit hash: %s\n", commitHash)
		}
		if branch != "" {
			evidence += fmt.Sprintf("Branch: %s\n", branch)
		}
		if remoteURL != "" {
			evidence += fmt.Sprintf("Remote URL: %s\n", remoteURL)
		}
		if len(extractedFiles) > 0 {
			evidence += "Extracted:\n"
			for _, f := range extractedFiles {
				evidence += fmt.Sprintf("  - %s\n", f)
			}
		}

		poc := fmt.Sprintf("# Exploit chain:\ncurl %s/.git/HEAD\ncurl %s/.git/config\n", cfg.BaseURL, cfg.BaseURL)
		if commitHash != "" {
			poc += fmt.Sprintf("curl %s/.git/objects/%s/%s\n", cfg.BaseURL, commitHash[:2], commitHash[2:])
		}
		poc += fmt.Sprintf("\n# Full dump:\npip install git-dumper\ngit-dumper %s/.git/ ./dumped-repo", cfg.BaseURL)

		findings = append(findings, MakeFinding(
			title,
			severity,
			desc,
			"/.git/",
			"GET",
			"CWE-538",
			poc,
			evidence,
			"info_leak",
			0,
		))

		if extractedContent != "" {
			findings[len(findings)-1].ExfiltratedData = extractedContent
		}
	}

	return findings
}

// exploitEnvFile attempts to extract secrets from exposed .env files.
func (p *InfoLeakProber) exploitEnvFile(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	envPaths := []string{"/.env", "/.env.local", "/.env.production", "/.env.backup", "/.env.old", "/env", "/.env.dev"}
	for _, path := range envPaths {
		url := cfg.BaseURL + path
		status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
		if err != nil || status != 200 || len(respBody) < 5 {
			continue
		}

		// Must look like a .env file (KEY=VALUE format)
		if !strings.Contains(respBody, "=") {
			continue
		}

		// Skip HTML responses
		lower := strings.ToLower(respBody)
		if strings.Contains(lower, "<!doctype") || strings.Contains(lower, "<html") {
			continue
		}

		// SPA check
		if cfg.IsSPAResponse(url) {
			continue
		}

		// Extract actual secrets
		var secrets []string
		var hasRealSecrets bool
		sensitiveKeys := []string{"password", "secret", "key", "token", "api", "database", "db_",
			"redis", "smtp", "mail", "aws", "stripe", "paypal", "jwt", "auth", "private"}

		for _, line := range strings.Split(respBody, "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.ToLower(parts[0])
			value := strings.TrimSpace(parts[1])
			// Remove quotes
			value = strings.Trim(value, "\"'")

			for _, sensitive := range sensitiveKeys {
				if strings.Contains(key, sensitive) && len(value) > 0 && value != "null" && value != "false" {
					// Mask the value but show it was there
					masked := value
					if len(masked) > 4 {
						masked = masked[:2] + strings.Repeat("*", len(masked)-4) + masked[len(masked)-2:]
					}
					secrets = append(secrets, fmt.Sprintf("%s=%s", parts[0], masked))
					hasRealSecrets = true
					break
				}
			}
		}

		severity := "High"
		title := fmt.Sprintf("Environment File Exposed at %s", path)
		if hasRealSecrets {
			severity = "Critical"
			title = fmt.Sprintf("Environment File with Secrets Exposed at %s", path)
		}

		evidence := fmt.Sprintf("HTTP %d - %d lines, %d secrets found\n", status, len(strings.Split(respBody, "\n")), len(secrets))
		if len(secrets) > 0 {
			evidence += "Secrets (masked):\n"
			for _, s := range secrets {
				evidence += fmt.Sprintf("  %s\n", s)
			}
		}

		findings = append(findings, MakeFinding(
			title,
			severity,
			fmt.Sprintf("Environment configuration file at %s is publicly accessible, exposing %d secret values including API keys, database credentials, and tokens.", path, len(secrets)),
			path,
			"GET",
			"CWE-538",
			fmt.Sprintf("curl %s", url),
			evidence,
			"info_leak",
			0,
		))

		if hasRealSecrets {
			findings[len(findings)-1].ExfiltratedData = strings.Join(secrets, "\n")
		}

		break // One .env finding is enough
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
