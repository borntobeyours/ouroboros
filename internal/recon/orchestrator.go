package recon

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// Orchestrator runs all recon modules in optimal order and aggregates results.
type Orchestrator struct {
	target  string
	config  types.ReconConfig
	headers map[string]string
	logger  *log.Logger
	onEvent func(event string) // progress callback
}

// NewOrchestrator creates a new recon orchestrator.
func NewOrchestrator(target string, config types.ReconConfig, headers map[string]string, logger *log.Logger) *Orchestrator {
	return &Orchestrator{
		target:  target,
		config:  config,
		headers: headers,
		logger:  logger,
	}
}

// SetEventCallback sets a callback for progress updates.
func (o *Orchestrator) SetEventCallback(cb func(string)) {
	o.onEvent = cb
}

func (o *Orchestrator) emit(msg string) {
	if o.onEvent != nil {
		o.onEvent(msg)
	}
	if o.logger != nil {
		o.logger.Printf("[RECON] %s", msg)
	}
}

// Run executes all enabled recon modules and returns aggregated results.
func (o *Orchestrator) Run() *types.ReconResult {
	result := &types.ReconResult{}
	start := time.Now()

	parsed, err := url.Parse(o.target)
	if err != nil {
		o.emit(fmt.Sprintf("invalid target URL: %v", err))
		return result
	}
	host := parsed.Hostname()

	// === Phase 1: Port Scan (runs first — informs service detection) ===
	if o.config.ModuleEnabled("portscan") {
		o.emit("Port scanning...")
		scanner := NewPortScanner(host, o.config.PortScanPorts, o.config.Workers, time.Duration(o.config.TimeoutSeconds)*time.Second, nil)
		result.Ports = scanner.Scan()
		o.emit(fmt.Sprintf("Port scan complete: %d open ports", len(result.Ports)))

		// Add web ports to URL discovery
		for _, p := range result.Ports {
			if p.Service == "http" || p.Service == "http-proxy" || p.Service == "http-alt" {
				result.DiscoveredURLs = append(result.DiscoveredURLs, fmt.Sprintf("http://%s:%d", host, p.Port))
			} else if p.Service == "https" || p.Service == "https-alt" {
				result.DiscoveredURLs = append(result.DiscoveredURLs, fmt.Sprintf("https://%s:%d", host, p.Port))
			}
		}
	}

	// === Phase 2: Technology Fingerprinting ===
	if o.config.ModuleEnabled("techfp") {
		o.emit("Fingerprinting technologies...")
		fp := NewTechFingerprinter(o.target, o.headers)
		result.Technologies = fp.Fingerprint()
		o.emit(fmt.Sprintf("Tech fingerprint complete: %d technologies identified", len(result.Technologies)))
	}

	// === Phase 3: JavaScript Endpoint Extraction ===
	if o.config.ModuleEnabled("jsextract") {
		o.emit("Extracting JS endpoints...")
		extractor := NewJSExtractor(o.target, o.config.Workers)
		jsEndpoints, secrets := extractor.Extract()
		result.JSEndpoints = jsEndpoints
		result.Secrets = secrets
		o.emit(fmt.Sprintf("JS extraction complete: %d endpoints, %d secrets", len(jsEndpoints), len(secrets)))

		// Add JS endpoints to URL discovery
		for _, ep := range jsEndpoints {
			if strings.HasPrefix(ep.URL, "http") {
				result.DiscoveredURLs = append(result.DiscoveredURLs, ep.URL)
			} else if strings.HasPrefix(ep.URL, "/") {
				result.DiscoveredURLs = append(result.DiscoveredURLs, fmt.Sprintf("%s://%s%s", parsed.Scheme, parsed.Host, ep.URL))
			}
		}
	}

	// === Phase 4: Wayback Machine URL Mining ===
	if o.config.ModuleEnabled("wayback") {
		o.emit("Mining Wayback Machine...")
		miner := NewWaybackMiner(o.target, o.config.Workers)
		result.WaybackURLs = miner.Mine()
		o.emit(fmt.Sprintf("Wayback mining complete: %d URLs (%d alive)",
			len(result.WaybackURLs), countAliveWayback(result.WaybackURLs)))

		// Add alive wayback URLs to discovery
		for _, wb := range result.WaybackURLs {
			if wb.Alive {
				result.DiscoveredURLs = append(result.DiscoveredURLs, wb.URL)
			}
		}
	}

	// === Phase 5: Parameter Discovery (uses results from prior phases) ===
	if o.config.ModuleEnabled("params") {
		o.emit("Discovering parameters...")
		// Fetch main page body for HTML form mining
		htmlBody := ""
		if o.config.ModuleEnabled("techfp") {
			// We already fetched it in techfp, but fetch again for simplicity
			fetcher := NewJSExtractor(o.target, 1)
			htmlBody = fetcher.fetchBody(o.target)
		}
		pd := NewParamDiscovery(o.target, o.config.Workers)
		result.Parameters = pd.Discover(htmlBody, result.JSEndpoints, result.WaybackURLs)
		o.emit(fmt.Sprintf("Parameter discovery complete: %d params (%d reflected)",
			len(result.Parameters), countReflected(result.Parameters)))
	}

	// Deduplicate discovered URLs
	result.DiscoveredURLs = dedup(result.DiscoveredURLs)

	elapsed := time.Since(start).Round(time.Millisecond)
	o.emit(fmt.Sprintf("Recon complete in %s — %d new URLs, %d params, %d techs, %d ports",
		elapsed, len(result.DiscoveredURLs), len(result.Parameters),
		len(result.Technologies), len(result.Ports)))

	return result
}

func countAliveWayback(urls []types.WaybackURL) int {
	n := 0
	for _, u := range urls {
		if u.Alive {
			n++
		}
	}
	return n
}

func countReflected(params []types.Parameter) int {
	n := 0
	for _, p := range params {
		if p.Reflected {
			n++
		}
	}
	return n
}

func dedup(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
