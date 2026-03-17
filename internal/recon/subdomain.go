package recon

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// Subdomain holds a discovered subdomain and its metadata.
type Subdomain struct {
	Name      string   `json:"name"`
	IPs       []string `json:"ips,omitempty"`
	CNAMEs    []string `json:"cnames,omitempty"`
	HTTPCode  int      `json:"http_code,omitempty"`
	HTTPTitle string   `json:"http_title,omitempty"`
	HTTPS     bool     `json:"https,omitempty"`
	Alive     bool     `json:"alive"`
	Source    string   `json:"source"` // crtsh, dns, wordlist
	Takeover  string   `json:"takeover,omitempty"`
}

// EnumResult is the full enumeration result.
type EnumResult struct {
	Domain     string      `json:"domain"`
	Subdomains []Subdomain `json:"subdomains"`
	Total      int         `json:"total"`
	Alive      int         `json:"alive"`
	Duration   string      `json:"duration"`
}

// SubdomainEnum performs subdomain enumeration.
type SubdomainEnum struct {
	domain     string
	client     *http.Client
	dnsTimeout time.Duration
	workers    int
	onFound    func(sub Subdomain)
}

// NewSubdomainEnum creates a new enumerator.
func NewSubdomainEnum(domain string, onFound func(sub Subdomain)) *SubdomainEnum {
	return &SubdomainEnum{
		domain: strings.TrimPrefix(strings.TrimPrefix(domain, "https://"), "http://"),
		client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		dnsTimeout: 3 * time.Second,
		workers:    20,
		onFound:    onFound,
	}
}

// Run performs full subdomain enumeration.
func (e *SubdomainEnum) Run() *EnumResult {
	start := time.Now()

	// Remove port, path if any
	e.domain = strings.Split(e.domain, "/")[0]
	e.domain = strings.Split(e.domain, ":")[0]

	found := &sync.Map{}
	result := &EnumResult{Domain: e.domain}

	// Phase 1: crt.sh (Certificate Transparency)
	crtSubs := e.queryCrtSh()
	for _, s := range crtSubs {
		found.Store(s, "crtsh")
	}

	// Phase 2: DNS brute force with common wordlist
	dnsSubs := e.dnsWordlist()
	for _, s := range dnsSubs {
		found.Store(s, "wordlist")
	}

	// Phase 3: Collect all unique subdomains
	var allSubs []string
	found.Range(func(key, value interface{}) bool {
		allSubs = append(allSubs, key.(string))
		return true
	})
	sort.Strings(allSubs)

	// Phase 4: Resolve + probe alive (concurrent)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, e.workers)

	for _, sub := range allSubs {
		wg.Add(1)
		sem <- struct{}{}
		go func(name string) {
			defer wg.Done()
			defer func() { <-sem }()

			source := "crtsh"
			if v, ok := found.Load(name); ok {
				source = v.(string)
			}

			sd := e.probe(name, source)
			mu.Lock()
			result.Subdomains = append(result.Subdomains, sd)
			if sd.Alive {
				result.Alive++
			}
			mu.Unlock()

			if e.onFound != nil {
				e.onFound(sd)
			}
		}(sub)
	}
	wg.Wait()

	// Sort: alive first, then alphabetical
	sort.Slice(result.Subdomains, func(i, j int) bool {
		if result.Subdomains[i].Alive != result.Subdomains[j].Alive {
			return result.Subdomains[i].Alive
		}
		return result.Subdomains[i].Name < result.Subdomains[j].Name
	})

	result.Total = len(result.Subdomains)
	result.Duration = time.Since(start).Round(time.Second).String()
	return result
}

// queryCrtSh fetches subdomains from crt.sh certificate transparency logs.
func (e *SubdomainEnum) queryCrtSh() []string {
	url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", e.domain)
	resp, err := e.client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))

	var entries []struct {
		NameValue string `json:"name_value"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil
	}

	seen := make(map[string]bool)
	var subs []string
	for _, entry := range entries {
		for _, name := range strings.Split(entry.NameValue, "\n") {
			name = strings.TrimSpace(strings.ToLower(name))
			name = strings.TrimPrefix(name, "*.")
			if name == "" || !strings.HasSuffix(name, e.domain) || seen[name] {
				continue
			}
			seen[name] = true
			subs = append(subs, name)
		}
	}
	return subs
}

// dnsWordlist performs DNS resolution against a common subdomain wordlist.
func (e *SubdomainEnum) dnsWordlist() []string {
	wordlist := []string{
		"www", "mail", "ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
		"webdisk", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap",
		"test", "ns", "blog", "pop3", "dev", "www2", "admin", "forum", "news",
		"vpn", "ns3", "mail2", "new", "mysql", "old", "lists", "support",
		"mobile", "mx", "static", "docs", "beta", "shop", "sql", "secure",
		"demo", "cp", "calendar", "wiki", "web", "media", "email", "images",
		"img", "www1", "intranet", "portal", "video", "sip", "dns2", "api",
		"cdn", "stats", "cloud", "dns1", "ns4", "smtp2", "archive",
		"git", "staging", "app", "jenkins", "jira", "confluence",
		"grafana", "monitor", "prometheus", "kibana", "elastic",
		"redis", "postgres", "mongo", "rabbit", "mq", "queue",
		"auth", "sso", "login", "oauth", "id", "identity",
		"ci", "cd", "deploy", "build", "release", "registry",
		"backup", "bak", "storage", "s3", "assets", "files",
		"status", "health", "ping", "internal", "private",
		"stage", "stg", "uat", "qa", "sandbox", "preview",
		"api-v1", "api-v2", "api2", "graphql", "ws", "socket",
		"cms", "wp", "wordpress", "drupal", "magento",
		"crm", "erp", "hr", "helpdesk", "ticket",
		"lab", "labs", "research", "devops", "infra",
		"proxy", "gateway", "lb", "edge", "node",
		"panel", "dashboard", "console", "manage",
	}

	var mu sync.Mutex
	var found []string
	var wg sync.WaitGroup
	sem := make(chan struct{}, e.workers)

	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: e.dnsTimeout}
			return d.DialContext(ctx, "udp", "8.8.8.8:53")
		},
	}

	for _, word := range wordlist {
		wg.Add(1)
		sem <- struct{}{}
		go func(w string) {
			defer wg.Done()
			defer func() { <-sem }()

			host := fmt.Sprintf("%s.%s", w, e.domain)
			ctx, cancel := context.WithTimeout(context.Background(), e.dnsTimeout)
			defer cancel()

			ips, err := resolver.LookupHost(ctx, host)
			if err != nil || len(ips) == 0 {
				return
			}

			mu.Lock()
			found = append(found, host)
			mu.Unlock()
		}(word)
	}
	wg.Wait()

	return found
}

// probe checks if a subdomain is alive and gets HTTP info.
func (e *SubdomainEnum) probe(name, source string) Subdomain {
	sd := Subdomain{
		Name:   name,
		Source: source,
	}

	// DNS resolve
	ips, _ := net.LookupHost(name)
	sd.IPs = ips

	cnames, _ := net.LookupCNAME(name)
	if cnames != "" && cnames != name+"." {
		sd.CNAMEs = []string{strings.TrimSuffix(cnames, ".")}
	}

	if len(ips) == 0 {
		// Check for subdomain takeover (CNAME exists but no IP)
		if len(sd.CNAMEs) > 0 {
			sd.Takeover = checkTakeover(sd.CNAMEs[0])
		}
		return sd
	}

	// HTTP probe
	for _, scheme := range []string{"https", "http"} {
		url := fmt.Sprintf("%s://%s", scheme, name)
		resp, err := e.client.Get(url)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		resp.Body.Close()

		sd.HTTPCode = resp.StatusCode
		sd.Alive = true
		sd.HTTPS = scheme == "https"

		// Extract title
		bodyStr := string(body)
		if idx := strings.Index(bodyStr, "<title>"); idx >= 0 {
			end := strings.Index(bodyStr[idx:], "</title>")
			if end > 0 {
				sd.HTTPTitle = strings.TrimSpace(bodyStr[idx+7 : idx+end])
			}
		}
		break
	}

	return sd
}

// checkTakeover checks if CNAME points to a service vulnerable to subdomain takeover.
func checkTakeover(cname string) string {
	takeoverSignatures := map[string]string{
		"amazonaws.com":         "AWS S3 / CloudFront",
		"cloudfront.net":        "AWS CloudFront",
		"elasticbeanstalk.com":  "AWS Elastic Beanstalk",
		"s3.amazonaws.com":      "AWS S3",
		"s3-website":            "AWS S3 Website",
		"herokuapp.com":         "Heroku",
		"herokudns.com":         "Heroku",
		"github.io":             "GitHub Pages",
		"gitbook.io":            "GitBook",
		"ghost.io":              "Ghost",
		"netlify.app":           "Netlify",
		"netlify.com":           "Netlify",
		"vercel.app":            "Vercel",
		"now.sh":                "Vercel",
		"pantheon.io":           "Pantheon",
		"azurewebsites.net":     "Azure",
		"cloudapp.net":          "Azure",
		"trafficmanager.net":    "Azure Traffic Manager",
		"blob.core.windows.net": "Azure Blob",
		"shopify.com":           "Shopify",
		"myshopify.com":         "Shopify",
		"surge.sh":              "Surge",
		"bitbucket.io":          "Bitbucket",
		"zendesk.com":           "Zendesk",
		"readme.io":             "ReadMe",
		"freshdesk.com":         "Freshdesk",
		"wordpress.com":         "WordPress",
		"fly.dev":               "Fly.io",
		"render.com":            "Render",
		"onrender.com":          "Render",
		"railway.app":           "Railway",
	}

	cname = strings.ToLower(cname)
	for sig, service := range takeoverSignatures {
		if strings.Contains(cname, sig) {
			// Try to connect — if it fails, potential takeover
			conn, err := net.DialTimeout("tcp", cname+":443", 3*time.Second)
			if err != nil {
				return fmt.Sprintf("POTENTIAL TAKEOVER: %s (CNAME → %s, connection failed)", service, cname)
			}
			conn.Close()
		}
	}
	return ""
}
