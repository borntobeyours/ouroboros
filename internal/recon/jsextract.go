package recon

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// JSExtractor finds and parses JavaScript files for endpoints and secrets.
type JSExtractor struct {
	target  string
	client  *http.Client
	workers int
}

// NewJSExtractor creates a new JS endpoint extractor.
func NewJSExtractor(target string, workers int) *JSExtractor {
	if workers <= 0 {
		workers = 10
	}
	return &JSExtractor{
		target:  target,
		workers: workers,
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
	}
}

// Extract fetches JS files from the target page and extracts endpoints and secrets.
func (je *JSExtractor) Extract() ([]types.JSEndpoint, []string) {
	// Step 1: Fetch the main page to find JS file URLs
	jsURLs := je.findJSFiles()
	if len(jsURLs) == 0 {
		return nil, nil
	}

	var mu sync.Mutex
	var allEndpoints []types.JSEndpoint
	var allSecrets []string
	seen := make(map[string]bool)

	// Step 2: Fetch and parse each JS file concurrently
	var wg sync.WaitGroup
	sem := make(chan struct{}, je.workers)

	for _, jsURL := range jsURLs {
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()

			body := je.fetchBody(u)
			if body == "" {
				return
			}

			endpoints := extractEndpoints(body, u)
			secrets := extractSecrets(body, u)

			mu.Lock()
			for _, ep := range endpoints {
				if !seen[ep.URL] {
					seen[ep.URL] = true
					allEndpoints = append(allEndpoints, ep)
				}
			}
			allSecrets = append(allSecrets, secrets...)
			mu.Unlock()
		}(jsURL)
	}
	wg.Wait()

	return allEndpoints, allSecrets
}

// findJSFiles fetches the main page and extracts script src URLs.
func (je *JSExtractor) findJSFiles() []string {
	body := je.fetchBody(je.target)
	if body == "" {
		return nil
	}

	base, err := url.Parse(je.target)
	if err != nil {
		return nil
	}

	// Find <script src="..."> tags
	srcRe := regexp.MustCompile(`<script[^>]*\ssrc=["']([^"']+)["']`)
	matches := srcRe.FindAllStringSubmatch(body, -1)

	seen := make(map[string]bool)
	var urls []string
	for _, m := range matches {
		src := m[1]
		resolved := resolveURL(base, src)
		if resolved != "" && !seen[resolved] && strings.HasSuffix(strings.Split(resolved, "?")[0], ".js") {
			seen[resolved] = true
			urls = append(urls, resolved)
		}
	}

	// Also look for inline script references to JS files
	jsRefRe := regexp.MustCompile(`["']((?:/|https?://)[^"']*\.js(?:\?[^"']*)?)["']`)
	for _, m := range jsRefRe.FindAllStringSubmatch(body, -1) {
		resolved := resolveURL(base, m[1])
		if resolved != "" && !seen[resolved] {
			seen[resolved] = true
			urls = append(urls, resolved)
		}
	}

	return urls
}

// fetchBody downloads a URL and returns the body as a string.
func (je *JSExtractor) fetchBody(rawURL string) string {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := je.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return ""
	}

	data, _ := io.ReadAll(io.LimitReader(resp.Body, 2*1024*1024)) // 2MB limit
	return string(data)
}

// resolveURL resolves a relative URL against a base.
func resolveURL(base *url.URL, ref string) string {
	if strings.HasPrefix(ref, "//") {
		ref = base.Scheme + ":" + ref
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ""
	}
	return base.ResolveReference(refURL).String()
}

// extractEndpoints finds API routes, URLs, and paths in JS source.
func extractEndpoints(js, source string) []types.JSEndpoint {
	var results []types.JSEndpoint

	patterns := []*regexp.Regexp{
		// API paths: "/api/v1/users", "/v2/auth"
		regexp.MustCompile(`["']((?:/api/|/v[0-9]+/)[a-zA-Z0-9/_\-{}:.]+)["']`),
		// Absolute paths starting with /
		regexp.MustCompile(`["'](/[a-zA-Z0-9_\-]+(?:/[a-zA-Z0-9_\-{}:.]+){1,6})["']`),
		// fetch/axios/xhr calls
		regexp.MustCompile(`(?:fetch|axios|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*["'` + "`" + `]((?:/|https?://)[^"'` + "`" + `\s]+)["'` + "`" + `]`),
		// URL assignments
		regexp.MustCompile(`(?:url|endpoint|baseUrl|apiUrl|href|action)\s*[:=]\s*["'` + "`" + `]((?:/|https?://)[^"'` + "`" + `\s]+)["'` + "`" + `]`),
		// Template literals with paths
		regexp.MustCompile("`(/[a-zA-Z0-9/_\\-]+(?:\\$\\{[^}]+\\}[a-zA-Z0-9/_\\-]*)+)`"),
		// Full URLs
		regexp.MustCompile(`["'](https?://[a-zA-Z0-9._\-]+(?:/[a-zA-Z0-9/_\-{}:.?&=]*)?)["']`),
	}

	seen := make(map[string]bool)
	for _, re := range patterns {
		matches := re.FindAllStringSubmatch(js, -1)
		for _, m := range matches {
			path := m[1]
			if seen[path] || isBoringPath(path) {
				continue
			}
			seen[path] = true
			results = append(results, types.JSEndpoint{
				URL:    path,
				Source: source,
				Type:   "endpoint",
			})
		}
	}

	return results
}

// extractSecrets finds hardcoded API keys, tokens, and secrets in JS source.
func extractSecrets(js, source string) []string {
	patterns := []*regexp.Regexp{
		// API keys (generic)
		regexp.MustCompile(`(?i)(?:api[_-]?key|apikey)\s*[:=]\s*["']([a-zA-Z0-9_\-]{20,})["']`),
		// AWS keys
		regexp.MustCompile(`(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}`),
		// Bearer tokens
		regexp.MustCompile(`(?i)(?:bearer|token|auth)\s*[:=]\s*["']([a-zA-Z0-9_\-.]{20,})["']`),
		// Private keys
		regexp.MustCompile(`-----BEGIN (?:RSA |EC )?PRIVATE KEY-----`),
		// Google API keys
		regexp.MustCompile(`AIza[0-9A-Za-z_-]{35}`),
		// Slack tokens
		regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,}`),
		// GitHub tokens
		regexp.MustCompile(`gh[ps]_[A-Za-z0-9_]{36,}`),
		// JWT tokens
		regexp.MustCompile(`eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+`),
		// Generic secrets
		regexp.MustCompile(`(?i)(?:secret|password|passwd|pwd)\s*[:=]\s*["']([^"']{8,})["']`),
	}

	var secrets []string
	seen := make(map[string]bool)
	for _, re := range patterns {
		matches := re.FindAllString(js, -1)
		for _, m := range matches {
			if !seen[m] {
				seen[m] = true
				secrets = append(secrets, "["+source+"] "+m)
			}
		}
	}
	return secrets
}

// isBoringPath filters out paths that are not interesting for security testing.
func isBoringPath(path string) bool {
	boring := []string{
		".css", ".png", ".jpg", ".gif", ".svg", ".ico", ".woff", ".ttf",
		".eot", ".map", ".chunk.", "webpack", "node_modules", "polyfill",
		"favicon", "manifest.json", "robots.txt", "sitemap",
	}
	lower := strings.ToLower(path)
	for _, b := range boring {
		if strings.Contains(lower, b) {
			return true
		}
	}
	// Filter very short paths
	if len(path) < 3 {
		return true
	}
	return false
}
