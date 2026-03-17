package types

// ReconConfig controls which recon modules run and their settings.
type ReconConfig struct {
	Enabled        bool     `json:"enabled"`
	Modules        []string `json:"modules,omitempty"`        // empty = all
	PortScanPorts  []int    `json:"port_scan_ports,omitempty"` // custom ports (empty = top 1000)
	Workers        int      `json:"workers,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
}

// DefaultReconConfig returns a config with all modules enabled.
func DefaultReconConfig() ReconConfig {
	return ReconConfig{
		Enabled:        true,
		Workers:        50,
		TimeoutSeconds: 10,
	}
}

// ModuleEnabled returns true if the given module should run.
func (rc ReconConfig) ModuleEnabled(name string) bool {
	if len(rc.Modules) == 0 {
		return true // all enabled
	}
	for _, m := range rc.Modules {
		if m == name {
			return true
		}
	}
	return false
}

// PortResult represents a single open port discovery.
type PortResult struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // tcp
	Service  string `json:"service"`  // http, ssh, mysql, etc.
	Banner   string `json:"banner,omitempty"`
}

// TechFingerprint represents a detected technology.
type TechFingerprint struct {
	Name       string  `json:"name"`
	Version    string  `json:"version,omitempty"`
	Category   string  `json:"category"` // server, framework, language, cms, js-framework, cdn, waf
	Confidence float64 `json:"confidence"` // 0.0-1.0
}

// JSEndpoint represents a URL or secret extracted from JavaScript.
type JSEndpoint struct {
	URL    string `json:"url"`
	Source string `json:"source"` // which JS file it came from
	Type   string `json:"type"`   // endpoint, secret
}

// WaybackURL represents a URL discovered from the Wayback Machine.
type WaybackURL struct {
	URL       string `json:"url"`
	Timestamp string `json:"timestamp,omitempty"`
	MimeType  string `json:"mime_type,omitempty"`
	Status    string `json:"status,omitempty"` // status code from archive
	Alive     bool   `json:"alive"`            // still accessible
}

// Parameter represents a discovered parameter on the target.
type Parameter struct {
	Name      string `json:"name"`
	Location  string `json:"location"` // query, body, header, cookie, form
	Endpoint  string `json:"endpoint"` // which URL it was found on
	Reflected bool   `json:"reflected"` // value appears in response
	Source    string `json:"source"`    // wordlist, html, js, wayback
}

// ReconResult aggregates all recon module outputs.
type ReconResult struct {
	Ports        []PortResult      `json:"ports,omitempty"`
	Technologies []TechFingerprint `json:"technologies,omitempty"`
	JSEndpoints  []JSEndpoint      `json:"js_endpoints,omitempty"`
	WaybackURLs  []WaybackURL      `json:"wayback_urls,omitempty"`
	Parameters   []Parameter       `json:"parameters,omitempty"`

	// Aggregated endpoints for feeding into Red AI
	DiscoveredURLs []string `json:"discovered_urls,omitempty"`
	Secrets        []string `json:"secrets,omitempty"`
}
