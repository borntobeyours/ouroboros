package recon

import (
	"crypto/tls"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// TechFingerprinter detects technologies used by a web target.
type TechFingerprinter struct {
	target  string
	client  *http.Client
	headers map[string]string
}

// NewTechFingerprinter creates a new technology fingerprinter.
func NewTechFingerprinter(target string, headers map[string]string) *TechFingerprinter {
	return &TechFingerprinter{
		target:  target,
		headers: headers,
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

// Fingerprint fetches the target and analyzes headers, body, and cookies.
func (tf *TechFingerprinter) Fingerprint() []types.TechFingerprint {
	req, err := http.NewRequest("GET", tf.target, nil)
	if err != nil {
		return nil
	}
	for k, v := range tf.headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	resp, err := tf.client.Do(req)
	if err != nil {
		return nil
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()

	bodyStr := string(body)
	var results []types.TechFingerprint
	seen := make(map[string]bool)

	add := func(fp types.TechFingerprint) {
		key := fp.Name + fp.Version
		if seen[key] {
			return
		}
		seen[key] = true
		results = append(results, fp)
	}

	// === HTTP Header analysis ===
	if server := resp.Header.Get("Server"); server != "" {
		name, version := parseServerHeader(server)
		add(types.TechFingerprint{Name: name, Version: version, Category: "server", Confidence: 0.9})
	}
	if xpb := resp.Header.Get("X-Powered-By"); xpb != "" {
		name, version := parseServerHeader(xpb)
		add(types.TechFingerprint{Name: name, Version: version, Category: "framework", Confidence: 0.9})
	}
	if resp.Header.Get("X-AspNet-Version") != "" {
		add(types.TechFingerprint{Name: "ASP.NET", Version: resp.Header.Get("X-AspNet-Version"), Category: "framework", Confidence: 0.95})
	}
	if resp.Header.Get("X-AspNetMvc-Version") != "" {
		add(types.TechFingerprint{Name: "ASP.NET MVC", Version: resp.Header.Get("X-AspNetMvc-Version"), Category: "framework", Confidence: 0.95})
	}
	if via := resp.Header.Get("Via"); via != "" {
		if strings.Contains(strings.ToLower(via), "cloudfront") {
			add(types.TechFingerprint{Name: "CloudFront", Category: "cdn", Confidence: 0.9})
		} else if strings.Contains(strings.ToLower(via), "varnish") {
			add(types.TechFingerprint{Name: "Varnish", Category: "cdn", Confidence: 0.9})
		}
	}
	if resp.Header.Get("X-Varnish") != "" {
		add(types.TechFingerprint{Name: "Varnish", Category: "cdn", Confidence: 0.9})
	}
	if strings.Contains(resp.Header.Get("Set-Cookie"), "__cfduid") || resp.Header.Get("CF-RAY") != "" {
		add(types.TechFingerprint{Name: "Cloudflare", Category: "cdn", Confidence: 0.95})
	}
	if resp.Header.Get("X-Drupal-Cache") != "" || resp.Header.Get("X-Generator") == "Drupal" {
		add(types.TechFingerprint{Name: "Drupal", Category: "cms", Confidence: 0.9})
	}

	// === Cookie analysis ===
	for _, cookie := range resp.Cookies() {
		name := strings.ToLower(cookie.Name)
		switch {
		case name == "phpsessid" || name == "phpsess":
			add(types.TechFingerprint{Name: "PHP", Category: "language", Confidence: 0.85})
		case name == "jsessionid":
			add(types.TechFingerprint{Name: "Java", Category: "language", Confidence: 0.85})
		case name == "asp.net_sessionid" || name == ".aspxauth":
			add(types.TechFingerprint{Name: "ASP.NET", Category: "framework", Confidence: 0.85})
		case name == "laravel_session":
			add(types.TechFingerprint{Name: "Laravel", Category: "framework", Confidence: 0.9})
		case name == "_rails_session" || name == "_session_id":
			add(types.TechFingerprint{Name: "Ruby on Rails", Category: "framework", Confidence: 0.85})
		case name == "connect.sid":
			add(types.TechFingerprint{Name: "Express.js", Category: "framework", Confidence: 0.8})
		case name == "csrftoken" && strings.Contains(bodyStr, "django"):
			add(types.TechFingerprint{Name: "Django", Category: "framework", Confidence: 0.8})
		case name == "wp-settings" || strings.HasPrefix(name, "wordpress_"):
			add(types.TechFingerprint{Name: "WordPress", Category: "cms", Confidence: 0.9})
		}
	}

	// === HTML body analysis ===
	htmlPatterns := []struct {
		pattern    string
		name       string
		category   string
		confidence float64
		versionRe  string
	}{
		// CMS
		{`wp-content/`, "WordPress", "cms", 0.95, `<meta name="generator" content="WordPress ([\d.]+)`},
		{`/wp-includes/`, "WordPress", "cms", 0.95, ""},
		{`Joomla!`, "Joomla", "cms", 0.9, `<meta name="generator" content="Joomla! ([\d.]+)`},
		{`/media/jui/`, "Joomla", "cms", 0.85, ""},
		{`sites/default/files`, "Drupal", "cms", 0.85, ""},
		{`Drupal.settings`, "Drupal", "cms", 0.9, ""},
		{`/skin/frontend/`, "Magento", "cms", 0.85, ""},
		{`Mage.Cookies`, "Magento", "cms", 0.9, ""},
		{`Shopify.theme`, "Shopify", "cms", 0.9, ""},
		{`cdn.shopify.com`, "Shopify", "cms", 0.9, ""},

		// JS frameworks
		{`__next`, "Next.js", "js-framework", 0.85, ""},
		{`_next/static`, "Next.js", "js-framework", 0.9, ""},
		{`__nuxt`, "Nuxt.js", "js-framework", 0.85, ""},
		{`ng-version=`, "Angular", "js-framework", 0.9, `ng-version="([\d.]+)"`},
		{`ng-app`, "AngularJS", "js-framework", 0.85, ""},
		{`data-reactroot`, "React", "js-framework", 0.85, ""},
		{`__REACT_DEVTOOLS`, "React", "js-framework", 0.8, ""},
		{`data-v-`, "Vue.js", "js-framework", 0.75, ""},
		{`__VUE__`, "Vue.js", "js-framework", 0.85, ""},
		{`id="svelte-`, "Svelte", "js-framework", 0.85, ""},
		{`ember-view`, "Ember.js", "js-framework", 0.85, ""},
		{`data-turbo`, "Hotwire/Turbo", "js-framework", 0.8, ""},

		// Languages/frameworks from body
		{`<meta name="generator" content="Hugo`, "Hugo", "framework", 0.9, `Hugo ([\d.]+)`},
		{`powered by gatsby`, "Gatsby", "framework", 0.8, ""},
		{`<meta name="generator" content="Jekyll`, "Jekyll", "framework", 0.9, ""},
		{`<meta name="generator" content="Gatsby`, "Gatsby", "framework", 0.9, ""},

		// Analytics / third-party
		{`google-analytics.com/analytics.js`, "Google Analytics", "analytics", 0.9, ""},
		{`googletagmanager.com`, "Google Tag Manager", "analytics", 0.9, ""},
		{`hotjar.com`, "Hotjar", "analytics", 0.8, ""},
		{`cdn.segment.com`, "Segment", "analytics", 0.8, ""},

		// WAF signatures in body
		{`<title>Attention Required! | Cloudflare</title>`, "Cloudflare WAF", "waf", 0.95, ""},
		{`<title>Access Denied</title>`, "WAF", "waf", 0.5, ""},
	}

	for _, hp := range htmlPatterns {
		if strings.Contains(bodyStr, hp.pattern) {
			fp := types.TechFingerprint{
				Name:       hp.name,
				Category:   hp.category,
				Confidence: hp.confidence,
			}
			if hp.versionRe != "" {
				re := regexp.MustCompile(hp.versionRe)
				if m := re.FindStringSubmatch(bodyStr); len(m) > 1 {
					fp.Version = m[1]
				}
			}
			add(fp)
		}
	}

	// === Generator meta tag ===
	genRe := regexp.MustCompile(`<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']`)
	if m := genRe.FindStringSubmatch(bodyStr); len(m) > 1 {
		add(types.TechFingerprint{Name: m[1], Category: "cms", Confidence: 0.9})
	}

	return results
}

// parseServerHeader splits "nginx/1.18.0" into name and version.
func parseServerHeader(header string) (string, string) {
	header = strings.TrimSpace(header)
	if idx := strings.Index(header, "/"); idx > 0 {
		return header[:idx], header[idx+1:]
	}
	if idx := strings.Index(header, " "); idx > 0 {
		return header[:idx], ""
	}
	return header, ""
}
