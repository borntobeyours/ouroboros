// Package plugin loads YAML-defined vulnerability probers from disk.
package plugin

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/borntobeyours/ouroboros/internal/red/probers"
	"github.com/borntobeyours/ouroboros/pkg/types"
)

// DefaultPluginsDir returns ~/.ouroboros/plugins/.
func DefaultPluginsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".ouroboros", "plugins")
}

// LoadPlugins reads every *.yaml file from dir and returns a Prober for each.
// Errors for individual files are collected but do not abort the load.
func LoadPlugins(dir string) ([]probers.Prober, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil // no plugin dir is fine
		}
		return nil, fmt.Errorf("read plugin dir %s: %w", dir, err)
	}

	var result []probers.Prober
	var errs []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		def, err := ParsePluginFile(data)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		if err := ValidatePluginDef(def); err != nil {
			errs = append(errs, fmt.Sprintf("%s: validation failed: %v", name, err))
			continue
		}
		result = append(result, &PluginProber{def: def})
	}

	if len(errs) > 0 {
		return result, fmt.Errorf("plugin load errors:\n  %s", strings.Join(errs, "\n  "))
	}
	return result, nil
}

// ValidatePluginDef checks required fields.
func ValidatePluginDef(def *types.PluginDef) error {
	if strings.TrimSpace(def.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if len(def.Requests) == 0 {
		return fmt.Errorf("at least one request is required")
	}
	if len(def.Matchers) == 0 {
		return fmt.Errorf("at least one matcher is required")
	}
	for i, r := range def.Requests {
		if r.Path == "" {
			return fmt.Errorf("request[%d]: path is required", i)
		}
	}
	return nil
}

// ──────────────────────────────────────────────────────
// PluginProber — wraps a PluginDef into the Prober interface
// ──────────────────────────────────────────────────────

// PluginProber adapts a PluginDef so it satisfies the probers.Prober interface.
type PluginProber struct {
	def    *types.PluginDef
	client *http.Client
}

func (p *PluginProber) Name() string { return "plugin:" + p.def.Name }

func (p *PluginProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	if p.client == nil {
		p.client = &http.Client{Timeout: 15 * time.Second}
	}

	sev := parseSeverity(p.def.Severity)
	var findings []types.Finding

	// Build probe targets: the base URL plus every discovered endpoint.
	urls := []string{target.URL}
	for _, ep := range endpoints {
		if ep.URL != "" {
			urls = append(urls, ep.URL)
		}
	}

	for _, baseURL := range urls {
		for _, req := range p.def.Requests {
			fullURL := joinPath(baseURL, req.Path)

			method := req.Method
			if method == "" {
				method = http.MethodGet
			}

			var bodyReader io.Reader
			if req.Body != "" {
				bodyReader = strings.NewReader(req.Body)
			}

			httpReq, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
			if err != nil {
				continue
			}
			for k, v := range req.Headers {
				httpReq.Header.Set(k, v)
			}
			// Inject target-level headers (auth, etc.)
			for k, v := range target.Headers {
				if strings.ToLower(k) != "x-recon-urls" {
					httpReq.Header.Set(k, v)
				}
			}

			resp, err := p.client.Do(httpReq)
			if err != nil {
				continue
			}
			respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
			resp.Body.Close()

			if p.matches(resp, string(respBody)) {
				extracted := p.extract(string(respBody))
				evidence := fmt.Sprintf("Status: %d", resp.StatusCode)
				if extracted != "" {
					evidence += "\nExtracted: " + extracted
				}

				f := types.Finding{
					Title:       p.def.Name,
					Description: p.def.Description,
					Severity:    sev,
					Endpoint:    fullURL,
					Method:      method,
					CWE:         p.def.CWE,
					Technique:   "plugin:" + p.def.Name,
					Evidence:    evidence,
					Confidence:  types.ConfMedium,
					FoundAt:     time.Now(),
				}
				f.AdjustSeverity()
				findings = append(findings, f)
				break // one finding per request definition is enough
			}
		}
	}

	return findings
}

// matches returns true if the response satisfies the plugin's matcher list.
// The default condition is "or" (any matcher can match).
func (p *PluginProber) matches(resp *http.Response, body string) bool {
	condition := "or"
	if len(p.def.Matchers) > 0 && strings.ToLower(p.def.Matchers[0].Condition) == "and" {
		condition = "and"
	}

	for _, m := range p.def.Matchers {
		hit := matcherHit(m, resp, body)
		if condition == "or" && hit {
			return true
		}
		if condition == "and" && !hit {
			return false
		}
	}
	return condition == "and" // all matched
}

func matcherHit(m types.PluginMatcher, resp *http.Response, body string) bool {
	if m.StatusCode != 0 && resp.StatusCode != m.StatusCode {
		return false
	}
	if m.BodyContains != "" && !strings.Contains(body, m.BodyContains) {
		return false
	}
	if m.HeaderContains != "" {
		found := false
		for k, vals := range resp.Header {
			for _, v := range vals {
				if strings.Contains(k+": "+v, m.HeaderContains) {
					found = true
					break
				}
			}
		}
		if !found {
			return false
		}
	}
	if m.Regex != "" {
		re, err := regexp.Compile(m.Regex)
		if err != nil || !re.MatchString(body) {
			return false
		}
	}
	return true
}

// extract runs extractors and returns a formatted string of captures.
func (p *PluginProber) extract(body string) string {
	var parts []string
	for _, ex := range p.def.Extractors {
		re, err := regexp.Compile(ex.Regex)
		if err != nil {
			continue
		}
		matches := re.FindAllStringSubmatch(body, 5)
		for _, m := range matches {
			if len(m) > 1 {
				parts = append(parts, fmt.Sprintf("%s=%s", ex.Name, m[1]))
			}
		}
	}
	return strings.Join(parts, ", ")
}

// joinPath appends path to a base URL, avoiding double slashes.
func joinPath(base, path string) string {
	base = strings.TrimRight(base, "/")
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

func parseSeverity(s string) types.Severity {
	sev, _ := types.ParseSeverity(s)
	if sev == 0 {
		return types.SeverityMedium
	}
	return sev
}

// ──────────────────────────────────────────────────────
// Minimal YAML parser for plugin files
// ──────────────────────────────────────────────────────

// ParsePluginFile parses a plugin YAML file into a PluginDef.
// It handles the specific subset of YAML used in plugin definitions.
func ParsePluginFile(data []byte) (*types.PluginDef, error) {
	def := &types.PluginDef{}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	// section tracks which top-level list we're parsing.
	section := ""
	// currentItem accumulates key:value pairs for the list item being built.
	currentItem := map[string]string{}
	// currentHeaders accumulates headers within a request block.
	currentHeaders := map[string]string{}
	inHeaders := false

	flushItem := func() {
		if len(currentItem) == 0 {
			return
		}
		switch section {
		case "requests":
			req := types.PluginRequest{
				Method:  currentItem["method"],
				Path:    currentItem["path"],
				Body:    currentItem["body"],
				Headers: copyMap(currentHeaders),
			}
			if req.Method == "" {
				req.Method = "GET"
			}
			def.Requests = append(def.Requests, req)
		case "matchers":
			m := types.PluginMatcher{
				BodyContains:   currentItem["body_contains"],
				HeaderContains: currentItem["header_contains"],
				Regex:          currentItem["regex"],
				Condition:      currentItem["condition"],
			}
			if sc, ok := currentItem["status_code"]; ok && sc != "" {
				m.StatusCode, _ = strconv.Atoi(sc)
			}
			def.Matchers = append(def.Matchers, m)
		case "extractors":
			ex := types.PluginExtractor{
				Name:  currentItem["name"],
				Regex: currentItem["regex"],
			}
			if ex.Name != "" || ex.Regex != "" {
				def.Extractors = append(def.Extractors, ex)
			}
		}
		currentItem = map[string]string{}
		currentHeaders = map[string]string{}
	}

	for _, rawLine := range lines {
		// Strip comments
		if commentIdx := strings.Index(rawLine, " #"); commentIdx >= 0 {
			rawLine = rawLine[:commentIdx]
		}
		if strings.HasPrefix(strings.TrimSpace(rawLine), "#") {
			continue
		}
		if strings.TrimSpace(rawLine) == "" {
			continue
		}

		indent := countLeadingSpaces(rawLine)
		line := strings.TrimSpace(rawLine)

		// Top-level key (no indent)
		if indent == 0 {
			inHeaders = false
			key, val := splitKV(line)
			switch key {
			case "name":
				def.Name = val
			case "description":
				def.Description = val
			case "severity":
				def.Severity = val
			case "cwe":
				def.CWE = val
			case "requests", "matchers", "extractors":
				flushItem()
				section = key
			}
			continue
		}

		// List item start (indent == 2, starts with "- ")
		if indent == 2 && strings.HasPrefix(line, "- ") {
			inHeaders = false
			flushItem()
			rest := strings.TrimPrefix(line, "- ")
			if rest == "" {
				continue
			}
			key, val := splitKV(rest)
			if key == "headers" {
				inHeaders = true
			} else {
				currentItem[key] = val
			}
			continue
		}

		// Nested key:value inside a list item (indent == 4)
		if indent == 4 {
			key, val := splitKV(line)
			if inHeaders {
				currentHeaders[key] = val
			} else if key == "headers" {
				inHeaders = true
			} else {
				currentItem[key] = val
			}
			continue
		}

		// Header values inside requests (indent == 6)
		if indent >= 6 {
			key, val := splitKV(line)
			if inHeaders {
				currentHeaders[key] = val
			}
			continue
		}
	}

	// Flush last item
	flushItem()

	return def, nil
}

func countLeadingSpaces(s string) int {
	n := 0
	for _, c := range s {
		if c == ' ' {
			n++
		} else {
			break
		}
	}
	return n
}

func splitKV(s string) (key, val string) {
	idx := strings.Index(s, ":")
	if idx < 0 {
		return strings.TrimSpace(s), ""
	}
	key = strings.TrimSpace(s[:idx])
	val = strings.TrimSpace(s[idx+1:])
	// Strip surrounding quotes
	if len(val) >= 2 && ((val[0] == '"' && val[len(val)-1] == '"') || (val[0] == '\'' && val[len(val)-1] == '\'')) {
		val = val[1 : len(val)-1]
	}
	return key, val
}

func copyMap(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}
