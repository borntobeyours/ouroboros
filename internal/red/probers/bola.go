package probers

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// BOLAProber tests for Broken Object Level Authorization (BOLA) and
// Broken Function Level Authorization (BFLA) vulnerabilities.
// Unlike IDOR which tests direct object access, BOLA specifically tests
// authorization context differences: authenticated vs unauthenticated access,
// method tampering, and function-level authz bypasses.
type BOLAProber struct{}

func (p *BOLAProber) Name() string { return "bola" }

// uuidPattern matches standard UUID/GUID patterns in URLs.
var uuidPattern = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)

// objectIDParams are query parameter names that commonly reference user-owned objects.
var objectIDParams = []string{
	"user_id", "userid", "account_id", "accountid", "owner", "owner_id",
	"profile_id", "customer_id", "member_id", "org_id", "tenant_id",
}

func (p *BOLAProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	if currentClassified != nil {
		cfg.Classified = currentClassified
	}
	var findings []types.Finding

	// 1. Horizontal privilege escalation: auth vs no-auth on same resources
	findings = append(findings, p.testHorizontalPrivEsc(ctx, cfg, endpoints)...)

	// 2. HTTP method tampering on discovered endpoints
	findings = append(findings, p.testMethodTampering(ctx, cfg, endpoints)...)

	// 3. UUID/GUID object reference manipulation
	findings = append(findings, p.testUUIDManipulation(ctx, cfg, endpoints)...)

	// 4. Parameter-based object access swapping
	findings = append(findings, p.testParamObjectAccess(ctx, cfg, endpoints)...)

	// 5. BFLA: function-level authorization bypass
	findings = append(findings, p.testBFLA(ctx, cfg)...)

	return findings
}

// testHorizontalPrivEsc requests resource endpoints WITH auth, then replays
// the same requests WITHOUT auth. If both return 200 with matching content,
// the endpoint lacks authorization checks.
func (p *BOLAProber) testHorizontalPrivEsc(ctx context.Context, cfg *ProberConfig, endpoints []types.Endpoint) []types.Finding {
	var findings []types.Finding

	if cfg.AuthSession == nil && cfg.AuthToken == "" {
		return findings
	}

	tested := make(map[string]bool)

	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		path := extractPath(ep.URL)
		if tested[path] || IsStaticAssetURL(ep.URL) {
			continue
		}

		// Only test endpoints with object identifiers (numeric IDs, UUIDs, slugs)
		if !hasObjectIdentifier(path) {
			continue
		}
		tested[path] = true

		// Step 1: Request WITH auth (normal authenticated request)
		authStatus, _, authBody, err := cfg.DoRequest("GET", ep.URL, nil, nil)
		if err != nil || authStatus != 200 || len(authBody) < 30 {
			continue
		}

		// Skip SPA catch-all responses
		if cfg.IsSPAResponse(ep.URL) {
			continue
		}

		// Step 2: Request WITHOUT auth (strip all auth)
		noAuthStatus, _, noAuthBody, err := doRequestNoAuth(cfg, "GET", ep.URL, nil)
		if err != nil || noAuthStatus != 200 {
			continue
		}

		// Step 3: Compare — if both succeed with same data, BOLA confirmed
		if bodiesMatch(authBody, noAuthBody) && containsSensitiveData(noAuthBody) {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("BOLA - No Authorization Check on %s", path),
				"High",
				fmt.Sprintf("Endpoint %s returns identical data with and without authentication, indicating missing authorization checks.", path),
				path,
				"GET",
				"CWE-639",
				fmt.Sprintf(`curl "%s"  # no auth headers — returns same data as authenticated request`, ep.URL),
				fmt.Sprintf("Auth response (%d): %s | No-auth response (%d): %s",
					authStatus, truncate(authBody, 150), noAuthStatus, truncate(noAuthBody, 150)),
				"bola",
				0,
			))
		}
	}

	return findings
}

// testMethodTampering tries PUT/PATCH/DELETE on endpoints discovered via GET.
// If destructive methods succeed without auth, it's a BOLA write/delete.
func (p *BOLAProber) testMethodTampering(ctx context.Context, cfg *ProberConfig, endpoints []types.Endpoint) []types.Finding {
	var findings []types.Finding
	tested := make(map[string]bool)

	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		path := extractPath(ep.URL)
		if tested[path] || IsStaticAssetURL(ep.URL) {
			continue
		}

		if !hasObjectIdentifier(path) {
			continue
		}
		tested[path] = true

		// Try dangerous methods without auth
		methods := []struct {
			method string
			body   string
		}{
			{"PUT", `{"name":"bola_test"}`},
			{"PATCH", `{"name":"bola_test"}`},
			{"DELETE", ""},
		}

		for _, m := range methods {
			var bodyReader *strings.Reader
			headers := map[string]string{}
			if m.body != "" {
				bodyReader = strings.NewReader(m.body)
				headers["Content-Type"] = "application/json"
			}

			status, _, respBody, err := doRequestNoAuth(cfg, m.method, ep.URL, bodyReader)
			if err != nil {
				continue
			}

			// A successful mutation without auth is a serious BOLA finding
			if status == 200 || status == 204 {
				// Verify it's not just an error page or generic response
				if status == 200 && isGenericErrorPage(respBody) {
					continue
				}

				sev := "High"
				if m.method == "DELETE" {
					sev = "Critical"
				}

				findings = append(findings, MakeFinding(
					fmt.Sprintf("BOLA - Unauthorized %s on %s", m.method, path),
					sev,
					fmt.Sprintf("Endpoint %s accepts %s requests without authentication, allowing unauthorized modification/deletion of resources.", path, m.method),
					path,
					m.method,
					"CWE-639",
					fmt.Sprintf(`curl -X %s "%s" -H "Content-Type: application/json" -d '%s'`, m.method, ep.URL, m.body),
					fmt.Sprintf("HTTP %d - Response: %s", status, truncate(respBody, 200)),
					"bola",
					0,
				))
				break // One finding per endpoint
			}
		}
	}

	return findings
}

// testUUIDManipulation detects UUID patterns in URLs and tests access to
// adjacent objects by incrementing the last byte.
func (p *BOLAProber) testUUIDManipulation(ctx context.Context, cfg *ProberConfig, endpoints []types.Endpoint) []types.Finding {
	var findings []types.Finding
	tested := make(map[string]bool)

	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		path := extractPath(ep.URL)
		uuids := uuidPattern.FindAllString(path, -1)
		if len(uuids) == 0 {
			continue
		}

		// Use the last UUID in the path as the object reference
		originalUUID := uuids[len(uuids)-1]
		basePattern := strings.Replace(path, originalUUID, "UUID", 1)
		if tested[basePattern] {
			continue
		}
		tested[basePattern] = true

		// First verify the original UUID returns data
		origStatus, _, origBody, err := cfg.DoRequest("GET", ep.URL, nil, nil)
		if err != nil || origStatus != 200 || len(origBody) < 30 {
			continue
		}

		// Generate adjacent UUID by incrementing the last byte
		adjacentUUIDs := generateAdjacentUUIDs(originalUUID)

		for _, adjUUID := range adjacentUUIDs {
			testURL := strings.Replace(ep.URL, originalUUID, adjUUID, 1)

			status, _, respBody, err := doRequestNoAuth(cfg, "GET", testURL, nil)
			if err != nil || status != 200 || len(respBody) < 30 {
				continue
			}

			// The adjacent object must return different data (not the same object)
			// and contain sensitive fields
			if !bodiesMatch(origBody, respBody) && containsSensitiveData(respBody) {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("BOLA - UUID Enumeration at %s", basePattern),
					"High",
					fmt.Sprintf("Adjacent UUID objects at %s are accessible without authorization. Object references are predictable.", strings.Replace(path, originalUUID, "{uuid}", 1)),
					strings.Replace(path, originalUUID, "{uuid}", 1),
					"GET",
					"CWE-639",
					fmt.Sprintf(`curl "%s"`, testURL),
					fmt.Sprintf("Original UUID %s → HTTP %d | Adjacent UUID %s → HTTP %d with data: %s",
						truncate(originalUUID, 12), origStatus, truncate(adjUUID, 12), status, truncate(respBody, 150)),
					"bola",
					0,
				))
				break // One finding per pattern
			}
		}
	}

	return findings
}

// testParamObjectAccess detects query params like ?user_id=X and swaps values
// to test cross-user data access.
func (p *BOLAProber) testParamObjectAccess(ctx context.Context, cfg *ProberConfig, endpoints []types.Endpoint) []types.Finding {
	var findings []types.Finding
	tested := make(map[string]bool)

	for _, ep := range endpoints {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		u, err := url.Parse(ep.URL)
		if err != nil {
			continue
		}

		query := u.Query()
		if len(query) == 0 {
			continue
		}

		path := u.Path

		for _, paramName := range objectIDParams {
			origValue := query.Get(paramName)
			if origValue == "" {
				continue
			}

			testKey := path + "?" + paramName
			if tested[testKey] {
				continue
			}
			tested[testKey] = true

			// Get original response
			origStatus, _, origBody, err := cfg.DoRequest("GET", ep.URL, nil, nil)
			if err != nil || origStatus != 200 || len(origBody) < 30 {
				continue
			}

			// Swap the object ID value
			swappedValues := generateSwappedValues(origValue)

			for _, swapped := range swappedValues {
				testQuery := make(url.Values)
				for k, v := range query {
					testQuery[k] = v
				}
				testQuery.Set(paramName, swapped)
				u.RawQuery = testQuery.Encode()
				testURL := u.String()

				status, _, respBody, err := doRequestNoAuth(cfg, "GET", testURL, nil)
				if err != nil || status != 200 || len(respBody) < 30 {
					continue
				}

				// Must return different data (different user's data) with sensitive content
				if !bodiesMatch(origBody, respBody) && containsSensitiveData(respBody) {
					findings = append(findings, MakeFinding(
						fmt.Sprintf("BOLA - Parameter Tampering (%s) at %s", paramName, path),
						"High",
						fmt.Sprintf("Changing %s parameter returns different user's data without authorization checks.", paramName),
						path,
						"GET",
						"CWE-639",
						fmt.Sprintf(`curl "%s"`, testURL),
						fmt.Sprintf("Original %s=%s → different data with %s=%s: %s",
							paramName, origValue, paramName, swapped, truncate(respBody, 150)),
						"bola",
						0,
					))
					break
				}
			}
		}
	}

	return findings
}

// testBFLA tests Broken Function Level Authorization: accessing admin endpoints
// with regular user auth, user-data endpoints with no auth, and HTTP method
// override headers.
func (p *BOLAProber) testBFLA(ctx context.Context, cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil {
		return findings
	}

	// Test 1: Admin endpoints with no auth (using method override headers)
	findings = append(findings, p.testAdminMethodOverride(ctx, cfg)...)

	// Test 2: User-data endpoints with no auth
	findings = append(findings, p.testUserDataNoAuth(ctx, cfg)...)

	return findings
}

// testAdminMethodOverride tests admin endpoints with HTTP method override headers.
func (p *BOLAProber) testAdminMethodOverride(ctx context.Context, cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil {
		return findings
	}

	overrideHeaders := []struct {
		header string
		method string
	}{
		{"X-HTTP-Method-Override", "GET"},
		{"X-Method-Override", "GET"},
		{"X-HTTP-Method", "GET"},
	}

	for _, ep := range cfg.Classified.Admin {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		path := extractPath(ep.URL)

		if cfg.IsSPAResponse(ep.URL) {
			continue
		}

		// Try POST with method override to GET — bypasses some WAFs and middleware
		for _, oh := range overrideHeaders {
			status, _, respBody, err := doRequestNoAuth(cfg, "POST", ep.URL,
				strings.NewReader(""),
			)
			if err != nil {
				continue
			}

			// If POST alone returns admin data, that's already a BFLA
			if status == 200 && len(respBody) > 50 && containsAdminContent(respBody) {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("BFLA - Admin Endpoint Accessible via POST (%s)", path),
					"High",
					fmt.Sprintf("Admin endpoint %s is accessible via unauthenticated POST request.", path),
					path,
					"POST",
					"CWE-285",
					fmt.Sprintf(`curl -X POST "%s"`, ep.URL),
					fmt.Sprintf("HTTP %d - Admin data: %s", status, truncate(respBody, 200)),
					"bola",
					0,
				))
				break
			}

			// Try with method override header
			hdrs := map[string]string{oh.header: oh.method}
			status, _, respBody, err = doRequestNoAuth(cfg, "POST", ep.URL,
				strings.NewReader(""),
				hdrs,
			)
			if err != nil {
				continue
			}

			if status == 200 && len(respBody) > 50 && containsAdminContent(respBody) {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("BFLA - Admin Endpoint via Method Override (%s: %s) at %s", oh.header, oh.method, path),
					"High",
					fmt.Sprintf("Admin endpoint %s is accessible via %s header bypass without authentication.", path, oh.header),
					path,
					"POST",
					"CWE-285",
					fmt.Sprintf(`curl -X POST "%s" -H "%s: %s"`, ep.URL, oh.header, oh.method),
					fmt.Sprintf("HTTP %d - Response: %s", status, truncate(respBody, 200)),
					"bola",
					0,
				))
				break
			}
		}
	}

	return findings
}

// testUserDataNoAuth tests user-data endpoints with no authentication.
func (p *BOLAProber) testUserDataNoAuth(ctx context.Context, cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil || cfg.AuthSession == nil && cfg.AuthToken == "" {
		return findings
	}

	for _, ep := range cfg.Classified.UserData {
		select {
		case <-ctx.Done():
			return findings
		default:
		}

		path := extractPath(ep.URL)

		// First get response WITH auth
		authStatus, _, authBody, err := cfg.DoRequest("GET", ep.URL, nil, nil)
		if err != nil || authStatus != 200 || len(authBody) < 30 {
			continue
		}

		// Skip SPA catch-all
		if cfg.IsSPAResponse(ep.URL) {
			continue
		}

		// Then try WITHOUT auth
		noAuthStatus, _, noAuthBody, err := doRequestNoAuth(cfg, "GET", ep.URL, nil)
		if err != nil || noAuthStatus != 200 {
			continue
		}

		if bodiesMatch(authBody, noAuthBody) && containsSensitiveData(noAuthBody) {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("BFLA - User Data Exposed Without Auth at %s", path),
				"High",
				fmt.Sprintf("User data endpoint %s returns identical data with and without authentication.", path),
				path,
				"GET",
				"CWE-285",
				fmt.Sprintf(`curl "%s"`, ep.URL),
				fmt.Sprintf("Auth response: %s | No-auth response: %s",
					truncate(authBody, 150), truncate(noAuthBody, 150)),
				"bola",
				0,
			))
		}
	}

	return findings
}

// doRequestNoAuth sends a request without any authentication (strips auth
// headers and cookies). Accepts optional extra headers maps.
func doRequestNoAuth(cfg *ProberConfig, method, rawURL string, body *strings.Reader, extraHeaders ...map[string]string) (int, http.Header, string, error) {
	// Create a stripped config with no auth
	stripped := &ProberConfig{
		BaseURL:         cfg.BaseURL,
		Client:          cfg.Client,
		BaseFingerprint: cfg.BaseFingerprint,
		// AuthToken and AuthSession intentionally omitted
	}

	headers := map[string]string{}
	for _, eh := range extraHeaders {
		for k, v := range eh {
			headers[k] = v
		}
	}

	var bodyReader io.Reader
	if body != nil {
		body.Seek(0, 0)
		bodyReader = body
	}

	return stripped.DoRequest(method, rawURL, bodyReader, headers)
}

// hasObjectIdentifier checks if a URL path contains a likely object reference
// (numeric ID, UUID, or slug-like segment).
func hasObjectIdentifier(path string) bool {
	segments := strings.Split(path, "/")
	for _, seg := range segments {
		if seg == "" {
			continue
		}
		if isNumericStr(seg) {
			return true
		}
		if uuidPattern.MatchString(seg) {
			return true
		}
	}
	return false
}

// bodiesMatch returns true if two response bodies are substantially similar.
// Uses SHA256 comparison to avoid false positives from timestamps/nonces.
func bodiesMatch(a, b string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}

	// Length difference > 20% means different content
	lenDiff := len(a) - len(b)
	if lenDiff < 0 {
		lenDiff = -lenDiff
	}
	if float64(lenDiff)/float64(len(a)) > 0.2 {
		return false
	}

	// Hash comparison for exact match
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	if ha == hb {
		return true
	}

	// Fuzzy: if lengths are very similar and both contain JSON array/object markers,
	// consider them matching (timestamps and nonces may differ)
	if float64(lenDiff)/float64(len(a)) < 0.05 {
		return true
	}

	return false
}

// containsSensitiveData checks if a response body contains indicators of
// sensitive/user-owned data (PII fields, credentials, etc.).
func containsSensitiveData(body string) bool {
	lower := strings.ToLower(body)
	indicators := []string{
		"email", "username", "user_name", "phone", "address",
		"password", "secret", "token", "ssn", "credit_card",
		"account", "balance", "profile",
	}
	count := 0
	for _, ind := range indicators {
		if strings.Contains(lower, ind) {
			count++
		}
	}
	// Require at least 2 indicators to reduce false positives
	return count >= 2
}

// containsAdminContent checks if a response body contains actual admin data
// rather than a generic page or SPA shell.
func containsAdminContent(body string) bool {
	lower := strings.ToLower(body)
	// Must not be just an HTML shell
	if strings.Contains(lower, "<!doctype html>") && !strings.Contains(lower, `"data"`) {
		return false
	}
	adminIndicators := []string{"config", "version", "status", "admin", "setting",
		"user", "role", "permission", "dashboard", "system"}
	count := 0
	for _, ind := range adminIndicators {
		if strings.Contains(lower, ind) {
			count++
		}
	}
	return count >= 2
}

// isGenericErrorPage checks if a response is a generic error or default page
// rather than real data.
func isGenericErrorPage(body string) bool {
	lower := strings.ToLower(body)
	errorIndicators := []string{
		"not found", "404", "error", "method not allowed", "405",
		"<!doctype html>", "forbidden", "unauthorized",
	}
	for _, ind := range errorIndicators {
		if strings.Contains(lower, ind) {
			return true
		}
	}
	return false
}

// generateAdjacentUUIDs creates UUID variations by incrementing/decrementing
// the last byte of the given UUID.
func generateAdjacentUUIDs(uuid string) []string {
	if len(uuid) < 36 {
		return nil
	}

	var results []string
	lastChar := uuid[35]

	// Increment last hex char
	nextChar := incrementHexChar(lastChar)
	if nextChar != lastChar {
		results = append(results, uuid[:35]+string(nextChar))
	}

	// Decrement last hex char
	prevChar := decrementHexChar(lastChar)
	if prevChar != lastChar {
		results = append(results, uuid[:35]+string(prevChar))
	}

	// Also try incrementing the second-to-last char
	if len(uuid) >= 36 {
		penultChar := uuid[34]
		nextPenult := incrementHexChar(penultChar)
		if nextPenult != penultChar {
			results = append(results, uuid[:34]+string(nextPenult)+uuid[35:])
		}
	}

	return results
}

func incrementHexChar(c byte) byte {
	switch {
	case c >= '0' && c < '9':
		return c + 1
	case c == '9':
		return 'a'
	case c >= 'a' && c < 'f':
		return c + 1
	case c == 'f':
		return '0'
	default:
		return c
	}
}

func decrementHexChar(c byte) byte {
	switch {
	case c > '0' && c <= '9':
		return c - 1
	case c == '0':
		return 'f'
	case c > 'a' && c <= 'f':
		return c - 1
	case c == 'a':
		return '9'
	default:
		return c
	}
}

// generateSwappedValues creates alternative values for an object ID parameter.
func generateSwappedValues(original string) []string {
	var results []string

	// If numeric, try adjacent values
	if isNumericStr(original) {
		n := 0
		for _, c := range original {
			n = n*10 + int(c-'0')
		}
		if n > 1 {
			results = append(results, fmt.Sprintf("%d", n-1))
		}
		results = append(results, fmt.Sprintf("%d", n+1))
		// Also try 1 (admin is often ID 1)
		if n != 1 {
			results = append(results, "1")
		}
		return results
	}

	// If UUID, generate adjacent
	if uuidPattern.MatchString(original) {
		return generateAdjacentUUIDs(original)
	}

	// For string values, try common alternatives
	results = append(results, "admin", "1", "test")
	return results
}
