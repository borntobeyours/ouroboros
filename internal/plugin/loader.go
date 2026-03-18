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
		result = append(result, &PluginProber{def: def, filename: name})
	}

	if len(errs) > 0 {
		return result, fmt.Errorf("plugin load errors:\n  %s", strings.Join(errs, "\n  "))
	}
	return result, nil
}

// LoadPluginProbers is like LoadPlugins but returns []*PluginProber so callers
// can access tags and perform smart filtering before registering probers.
func LoadPluginProbers(dir string) ([]*PluginProber, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read plugin dir %s: %w", dir, err)
	}

	var result []*PluginProber
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
		result = append(result, &PluginProber{def: def, filename: name})
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
	def      *types.PluginDef
	client   *http.Client
	filename string // basename of the source YAML file, used for tag inference
}

func (p *PluginProber) Name() string { return "plugin:" + p.def.Name }

// Tags returns the tags defined in the template, or infers them from the filename.
func (p *PluginProber) Tags() []string {
	if len(p.def.Tags) > 0 {
		return p.def.Tags
	}
	return inferTagsFromFilename(p.filename)
}

// Severity returns the raw severity string from the plugin definition.
func (p *PluginProber) Severity() string { return p.def.Severity }

// Filename returns the source YAML filename.
func (p *PluginProber) Filename() string { return p.filename }

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
			case "tags":
				flushItem()
				section = "tags"
			case "requests", "matchers", "extractors":
				flushItem()
				section = key
			}
			continue
		}

		// List item start (indent == 2, starts with "- ")
		if indent == 2 && strings.HasPrefix(line, "- ") {
			// Tags are a plain string list — handle before the general map-item logic.
			if section == "tags" {
				tag := strings.TrimSpace(strings.TrimPrefix(line, "- "))
				if tag != "" {
					def.Tags = append(def.Tags, tag)
				}
				continue
			}
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

// inferTagsFromFilename derives technology tags from a template filename.
// This is the fallback when a template has no explicit tags: field.
func inferTagsFromFilename(filename string) []string {
	name := strings.ToLower(filepath.Base(filename))
	name = strings.TrimSuffix(name, ".yaml")
	name = strings.TrimSuffix(name, ".yml")

	// Takeovers are always relevant (generic subdomain checks).
	if strings.HasPrefix(name, "takeover") {
		return []string{"generic"}
	}

	has := func(sub string) bool { return strings.Contains(name, sub) }

	var tags []string
	add := func(ts ...string) { tags = append(tags, ts...) }

	// Frameworks / languages
	if has("struts") {
		add("apache", "java", "struts")
	}
	if has("spring") {
		add("java", "spring")
	}
	if has("log4") {
		add("java", "log4j")
	}
	if has("weblogic") {
		add("java", "weblogic", "oracle")
	}
	if has("tomcat") || has("ghostcat") {
		add("java", "tomcat")
	}
	if has("glassfish") {
		add("java", "glassfish")
	}
	if has("jboss") {
		add("java", "jboss")
	}
	if has("websphere") {
		add("java", "websphere")
	}
	if has("solr") {
		add("java", "solr", "apache")
	}
	if has("confluence") {
		add("java", "confluence")
	}
	if has("jenkins") {
		add("jenkins", "java")
	}
	if has("nexus") {
		add("java")
	}
	if has("sonarqube") {
		add("java")
	}
	if has("artifactory") {
		add("java")
	}
	if has("activemq") {
		add("activemq", "java")
	}
	if has("druid") {
		add("java")
	}
	if has("nacos") {
		add("java")
	}
	if has("spark") && !has("apache-spark") {
		add("java")
	}
	if has("teamcity") {
		add("java")
	}
	if has("glpi") {
		add("php")
	}
	if has("cacti") {
		add("php")
	}
	if has("october") {
		add("php")
	}
	if has("opencart") {
		add("php")
	}
	if has("prestashop") {
		add("php")
	}
	if has("typo3") {
		add("php")
	}
	if has("concrete5") {
		add("php")
	}
	if has("phpmyadmin") {
		add("php", "mysql")
	}
	if has("adminer") {
		add("php", "mysql")
	}
	if has("laravel") {
		add("php", "laravel")
	}
	if has("wordpress") || has("wp-") {
		add("php", "wordpress")
	}
	if has("joomla") {
		add("php", "joomla")
	}
	if has("drupal") {
		add("php", "drupal")
	}
	if has("magento") {
		add("php", "magento")
	}
	if has("roundcube") {
		add("php")
	}
	if has("php") && !has("phpmyadmin") {
		add("php")
	}
	if has("django") {
		add("python", "django")
	}
	if has("flask") {
		add("python", "flask")
	}
	if has("airflow") {
		add("python", "airflow")
	}
	if has("superset") {
		add("python", "superset")
	}
	if has("jupyter") {
		add("python", "jupyter")
	}
	if has("saltstack") {
		add("python", "saltstack")
	}
	if has("rails") {
		add("ruby", "rails")
	}
	if has("nodejs") || has("node-") || has("npm") {
		add("nodejs")
	}
	if has("express") {
		add("nodejs", "express")
	}
	if has("dotnet") || has("aspnet") || has("asp-net") || has("viewstate") || has("elmah") || has("trace-axd") {
		add("dotnet", "aspnet")
	}
	if has("exchange") || has("proxylogon") || has("proxyshell") || has("proxynotshell") {
		add("dotnet", "microsoft", "exchange")
	}
	if has("apisix") {
		add("go")
	}

	// Web servers
	if has("nginx") {
		add("nginx")
	}
	if has("apache") && !has("struts") && !has("solr") && !has("cassandra") && !has("activemq") && !has("kafka") {
		add("apache")
	}
	if has("iis") {
		add("iis")
	}

	// Databases
	if has("mysql") && !has("phpmyadmin") && !has("adminer") {
		add("mysql")
	}
	if has("postgres") || has("pgadmin") {
		add("postgres")
	}
	if has("mssql") {
		add("mssql")
	}
	if has("mongodb") || has("mongo") {
		add("mongodb")
	}
	if has("redis") {
		add("redis")
	}
	if has("elasticsearch") || has("kibana") {
		add("elasticsearch")
	}
	if has("cassandra") {
		add("cassandra")
	}
	if has("couchdb") {
		add("couchdb")
	}
	if has("influx") {
		add("influxdb")
	}
	if has("oracle") && !has("weblogic") {
		add("java", "oracle")
	}

	// Infrastructure / cloud
	if has("docker") {
		add("docker")
	}
	if has("kubernetes") || has("-k8s-") || has("rancher") || has("harbor") {
		add("kubernetes")
	}
	if has("portainer") || has("traefik") {
		add("docker")
	}
	if has("aws") || has("-s3-") || has("cloudfront") || has("amplify") || has("elastic-beanstalk") || has("minio") {
		add("aws")
	}
	if has("azure") {
		add("azure")
	}
	if has("gcp") || has("google-cloud") {
		add("gcp")
	}
	if has("vault") && !has("vmware") {
		add("vault")
	}
	if has("consul") {
		add("consul")
	}
	if has("rabbitmq") {
		add("rabbitmq")
	}

	// Networking / devices
	if has("cisco") {
		add("cisco")
	}
	if has("fortinet") || has("fortios") || has("fortimanager") || has("fortivpn") || has("forticlient") {
		add("fortinet")
	}
	if has("vmware") || has("vcenter") || has("xenserver") || has("proxmox") {
		add("vmware")
	}
	if has("paloalto") || has("panos") {
		add("paloalto")
	}
	if has("dlink") || has("linksys") || has("netgear") || has("mikrotik") || has("tp-link") ||
		has("trendnet") || has("asus-router") || has("zyxel") || has("ubiquiti") || has("opnsense") ||
		has("pfsense") || has("buffalo") {
		add("networking")
	}
	if has("camera") || has("axis-cam") || has("dahua") || has("foscam") || has("hikvision") ||
		has("netwave") || has("honeywell") {
		add("iot")
	}
	if has("printer") || has("brother") || has("canon") || has("ricoh") || has("hp-printer") {
		add("iot")
	}

	// Security tools / monitoring
	if has("grafana") {
		add("grafana")
	}
	if has("gitlab") {
		add("gitlab")
	}
	if has("gitea") {
		add("git")
	}
	if has("splunk") {
		add("splunk")
	}
	if has("nagios") || has("icinga") || has("zabbix") || has("prtg") {
		add("monitoring")
	}
	if has("haproxy") {
		add("nginx", "haproxy")
	}

	// Protocols / generic
	if has("graphql") {
		add("graphql")
	}
	if has("websocket") {
		add("websocket")
	}

	// Exposures and misconfigs: if nothing matched, tag as generic.
	if strings.HasPrefix(name, "exposure-") || strings.HasPrefix(name, "misconfig-") {
		if len(tags) == 0 {
			return []string{"generic"}
		}
	}

	// De-duplicate while preserving order.
	seen := make(map[string]bool, len(tags))
	deduped := tags[:0]
	for _, t := range tags {
		if !seen[t] {
			seen[t] = true
			deduped = append(deduped, t)
		}
	}
	return deduped
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
