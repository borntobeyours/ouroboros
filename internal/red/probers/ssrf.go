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

		// Find the redirect parameter
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
			paramToTest = "to" // Default
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
			} else if status == 403 || status == 406 {
				findings = append(findings, MakeFinding(
					"Open Redirect - Whitelist Restriction (Bypassable)",
					"Low",
					"The redirect endpoint has a whitelist restriction, but it may be bypassable.",
					path+"?"+paramToTest+"=",
					"GET",
					"CWE-601",
					fmt.Sprintf(`curl -I "%s"`, fullURL),
					fmt.Sprintf("HTTP %d - Blocked but whitelist bypass may be possible: %s", status, truncate(respBody, 100)),
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

	if cfg.AuthToken == "" {
		return findings
	}

	// Find endpoints that accept URL parameters
	urlParams := []string{"url", "imageurl", "image_url", "src", "href",
		"link", "callback", "uri", "endpoint"}

	ssrfTargets := []struct {
		url      string
		desc     string
		evidence string
	}{
		{"http://localhost/admin", "localhost SSRF", "admin"},
		{"http://127.0.0.1/", "loopback SSRF", ""},
		{"http://[::1]/", "IPv6 loopback SSRF", ""},
		{"http://169.254.169.254/latest/meta-data/", "AWS metadata SSRF", "ami-id"},
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

			for _, st := range ssrfTargets {
				// Try GET with URL param
				fullURL := fmt.Sprintf("%s?%s=%s", baseEndpoint, param, url.QueryEscape(st.url))
				status, _, respBody, err := cfg.DoRequest("GET", fullURL, nil, nil)
				if err != nil {
					continue
				}

				if status == 200 && (st.evidence == "" || strings.Contains(strings.ToLower(respBody), st.evidence)) {
					findings = append(findings, MakeFinding(
						fmt.Sprintf("SSRF via %s parameter - %s", param, st.desc),
						"High",
						fmt.Sprintf("The endpoint fetches arbitrary URLs server-side via the '%s' parameter: %s", param, st.url),
						path,
						"GET",
						"CWE-918",
						fmt.Sprintf(`curl "%s"`, fullURL),
						fmt.Sprintf("HTTP %d - Server fetched internal URL: %s", status, truncate(respBody, 200)),
						"ssrf",
						0,
					))
					return findings
				}

				// Try POST with JSON body
				body := fmt.Sprintf(`{"%s":"%s"}`, param, st.url)
				s2, _, rb2, e2 := cfg.DoRequest("POST", baseEndpoint,
					strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
				if e2 == nil && s2 == 200 {
					findings = append(findings, MakeFinding(
						fmt.Sprintf("SSRF via %s parameter (POST) - %s", param, st.desc),
						"High",
						fmt.Sprintf("The endpoint fetches arbitrary URLs server-side via POST '%s' parameter: %s", param, st.url),
						path,
						"POST",
						"CWE-918",
						fmt.Sprintf(`curl -X POST %s -H "Content-Type: application/json" -d '%s'`, baseEndpoint, body),
						fmt.Sprintf("HTTP %d - Response: %s", s2, truncate(rb2, 200)),
						"ssrf",
						0,
					))
					return findings
				}
			}
		}
	}

	return findings
}
