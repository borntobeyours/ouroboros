package recon

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// ParamDiscovery finds parameters through fuzzing, HTML mining, and JS analysis.
type ParamDiscovery struct {
	target  string
	client  *http.Client
	workers int
}

// NewParamDiscovery creates a new parameter discovery module.
func NewParamDiscovery(target string, workers int) *ParamDiscovery {
	if workers <= 0 {
		workers = 20
	}
	return &ParamDiscovery{
		target:  target,
		workers: workers,
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// Discover runs all parameter discovery methods and returns unique parameters.
func (pd *ParamDiscovery) Discover(htmlBody string, jsEndpoints []types.JSEndpoint, waybackURLs []types.WaybackURL) []types.Parameter {
	var mu sync.Mutex
	var allParams []types.Parameter
	seen := make(map[string]bool)

	addParam := func(p types.Parameter) {
		key := p.Endpoint + "|" + p.Name + "|" + p.Location
		mu.Lock()
		if !seen[key] {
			seen[key] = true
			allParams = append(allParams, p)
		}
		mu.Unlock()
	}

	var wg sync.WaitGroup

	// 1. Mine parameters from HTML forms
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, p := range pd.mineHTMLParams(htmlBody) {
			addParam(p)
		}
	}()

	// 2. Mine parameters from JS endpoints
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, p := range pd.mineJSParams(jsEndpoints) {
			addParam(p)
		}
	}()

	// 3. Mine parameters from wayback URLs
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, p := range pd.mineWaybackParams(waybackURLs) {
			addParam(p)
		}
	}()

	// 4. Fuzz common parameter names (checks for reflection)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, p := range pd.fuzzParams() {
			addParam(p)
		}
	}()

	wg.Wait()
	return allParams
}

// mineHTMLParams extracts parameters from <form> and <input> elements.
func (pd *ParamDiscovery) mineHTMLParams(body string) []types.Parameter {
	if body == "" {
		return nil
	}

	var params []types.Parameter

	// Find input names
	inputRe := regexp.MustCompile(`<input[^>]*\sname=["']([^"']+)["'][^>]*>`)
	for _, m := range inputRe.FindAllStringSubmatch(body, -1) {
		params = append(params, types.Parameter{
			Name:     m[1],
			Location: "form",
			Endpoint: pd.target,
			Source:   "html",
		})
	}

	// Find select names
	selectRe := regexp.MustCompile(`<select[^>]*\sname=["']([^"']+)["'][^>]*>`)
	for _, m := range selectRe.FindAllStringSubmatch(body, -1) {
		params = append(params, types.Parameter{
			Name:     m[1],
			Location: "form",
			Endpoint: pd.target,
			Source:   "html",
		})
	}

	// Find textarea names
	textareaRe := regexp.MustCompile(`<textarea[^>]*\sname=["']([^"']+)["'][^>]*>`)
	for _, m := range textareaRe.FindAllStringSubmatch(body, -1) {
		params = append(params, types.Parameter{
			Name:     m[1],
			Location: "form",
			Endpoint: pd.target,
			Source:   "html",
		})
	}

	// Find data attributes that look like parameters
	dataRe := regexp.MustCompile(`data-param(?:eter)?=["']([^"']+)["']`)
	for _, m := range dataRe.FindAllStringSubmatch(body, -1) {
		params = append(params, types.Parameter{
			Name:     m[1],
			Location: "query",
			Endpoint: pd.target,
			Source:   "html",
		})
	}

	return params
}

// mineJSParams extracts parameter names from discovered JS endpoints.
func (pd *ParamDiscovery) mineJSParams(endpoints []types.JSEndpoint) []types.Parameter {
	var params []types.Parameter
	for _, ep := range endpoints {
		if !strings.Contains(ep.URL, "?") {
			continue
		}
		parsed, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}
		for key := range parsed.Query() {
			params = append(params, types.Parameter{
				Name:     key,
				Location: "query",
				Endpoint: ep.URL,
				Source:   "js",
			})
		}
	}
	return params
}

// mineWaybackParams extracts parameter names from wayback URLs.
func (pd *ParamDiscovery) mineWaybackParams(urls []types.WaybackURL) []types.Parameter {
	var params []types.Parameter
	for _, wb := range urls {
		if !strings.Contains(wb.URL, "?") {
			continue
		}
		parsed, err := url.Parse(wb.URL)
		if err != nil {
			continue
		}
		for key := range parsed.Query() {
			params = append(params, types.Parameter{
				Name:     key,
				Location: "query",
				Endpoint: wb.URL,
				Source:   "wayback",
			})
		}
	}
	return params
}

// fuzzParams tests common parameter names against the target and checks for reflection.
func (pd *ParamDiscovery) fuzzParams() []types.Parameter {
	wordlist := commonParamWordlist()

	// Get baseline response
	baseResp := pd.fetchBody(pd.target)
	baseLen := len(baseResp)

	var mu sync.Mutex
	var params []types.Parameter
	var wg sync.WaitGroup
	sem := make(chan struct{}, pd.workers)

	canary := "ouro8x7z" // unique string to check reflection

	for _, param := range wordlist {
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()

			testURL := fmt.Sprintf("%s?%s=%s", pd.target, name, canary)
			body := pd.fetchBody(testURL)
			if body == "" {
				return
			}

			// Check if response differs meaningfully from baseline
			lenDiff := len(body) - baseLen
			if lenDiff < -50 || lenDiff > 50 || strings.Contains(body, canary) {
				p := types.Parameter{
					Name:      name,
					Location:  "query",
					Endpoint:  pd.target,
					Reflected: strings.Contains(body, canary),
					Source:    "wordlist",
				}
				mu.Lock()
				params = append(params, p)
				mu.Unlock()
			}
		}(param)
	}
	wg.Wait()

	return params
}

// fetchBody downloads a URL and returns the body string.
func (pd *ParamDiscovery) fetchBody(rawURL string) string {
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		return ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := pd.client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(io.LimitReader(resp.Body, 128*1024))
	return string(data)
}

// commonParamWordlist returns common parameter names used in web applications.
func commonParamWordlist() []string {
	return []string{
		// Auth
		"id", "user", "username", "email", "password", "pass", "token",
		"auth", "key", "api_key", "apikey", "session", "csrf",
		// Query/search
		"q", "query", "search", "keyword", "term", "filter",
		"sort", "order", "page", "limit", "offset", "per_page",
		// Data
		"name", "value", "data", "content", "body", "text", "message",
		"title", "description", "comment", "note",
		// File
		"file", "path", "filename", "filepath", "dir", "directory",
		"upload", "download", "url", "uri", "src", "source", "dest",
		// Navigation
		"redirect", "return", "returnUrl", "return_url", "next", "prev",
		"callback", "continue", "goto", "target", "ref", "referer",
		// Action
		"action", "cmd", "command", "exec", "run", "do",
		"type", "method", "mode", "format", "output",
		// IDs
		"uid", "pid", "cid", "oid", "tid", "gid",
		"user_id", "account_id", "order_id", "item_id", "product_id",
		// Template injection / SSTI
		"template", "view", "layout", "theme", "lang", "locale",
		// Debug
		"debug", "test", "verbose", "trace", "log",
		// Misc injection vectors
		"category", "cat", "tag", "label", "status", "state",
		"from", "to", "start", "end", "date", "time",
		"ip", "host", "port", "domain", "server",
		"admin", "role", "group", "permission",
		"include", "require", "import", "load", "read",
		"config", "setting", "option", "param", "var",
	}
}
