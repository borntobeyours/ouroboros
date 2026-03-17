package probers

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// IDORProber tests for Insecure Direct Object Reference vulnerabilities.
type IDORProber struct{}

func (p *IDORProber) Name() string { return "idor" }

func (p *IDORProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	if currentClassified != nil {
		cfg.Classified = currentClassified
	}
	var findings []types.Finding

	// 1. Test endpoints with numeric IDs for horizontal access
	findings = append(findings, p.testNumericIDEndpoints(cfg, endpoints)...)

	// 2. Test API list endpoints without auth
	findings = append(findings, p.testAPIListEndpoints(cfg)...)

	// 3. Test user data endpoints
	findings = append(findings, p.testUserDataEndpoints(cfg)...)

	return findings
}

func (p *IDORProber) testNumericIDEndpoints(cfg *ProberConfig, endpoints []types.Endpoint) []types.Finding {
	var findings []types.Finding
	tested := make(map[string]bool)

	for _, ep := range endpoints {
		path := extractPath(ep.URL)
		segments := strings.Split(path, "/")

		// Find segments that are numeric — these are IDOR candidates
		for i, seg := range segments {
			if seg == "" || !isNumericStr(seg) {
				continue
			}

			// Build a base path pattern (e.g., /api/users/{id})
			basePath := strings.Join(segments[:i], "/")
			if tested[basePath] {
				continue
			}
			tested[basePath] = true

			// Try accessing different IDs
			for id := 1; id <= 5; id++ {
				testSegments := make([]string, len(segments))
				copy(testSegments, segments)
				testSegments[i] = fmt.Sprintf("%d", id)
				testPath := strings.Join(testSegments, "/")

				u, _ := url.Parse(ep.URL)
				testURL := fmt.Sprintf("%s://%s%s", u.Scheme, u.Host, testPath)

				status, _, respBody, err := cfg.DoRequest("GET", testURL, nil, nil)
				if err != nil {
					continue
				}

				if status == 200 && len(respBody) > 20 {
					// Check for PII indicators
					lowerBody := strings.ToLower(respBody)
					hasPII := strings.Contains(lowerBody, "email") ||
						strings.Contains(lowerBody, "username") ||
						strings.Contains(lowerBody, "name") ||
						strings.Contains(lowerBody, "address") ||
						strings.Contains(lowerBody, "phone")

					if hasPII {
						findings = append(findings, MakeFinding(
							fmt.Sprintf("IDOR - Access Resource (ID: %d) at %s", id, basePath),
							"High",
							fmt.Sprintf("Resource at %s with ID %d is accessible, exposing potentially sensitive data.", basePath, id),
							testPath,
							"GET",
							"CWE-639",
							fmt.Sprintf(`curl %s -H "Authorization: %s"`, testURL, cfg.AuthToken),
							fmt.Sprintf("HTTP %d - Data returned: %s", status, truncate(respBody, 200)),
							"idor",
							0,
						))
						break // One finding per path pattern
					}

					// Also try modification (PUT)
					modBody := `{"description":"test_idor_probe"}`
					s2, _, rb2, e2 := cfg.DoRequest("PUT", testURL, strings.NewReader(modBody),
						map[string]string{"Content-Type": "application/json"})
					if e2 == nil && s2 == 200 {
						findings = append(findings, MakeFinding(
							fmt.Sprintf("IDOR - Modify Resource (ID: %d) at %s", id, basePath),
							"High",
							fmt.Sprintf("Resource at %s can be modified by any user via direct API access.", basePath),
							testPath,
							"PUT",
							"CWE-639",
							fmt.Sprintf(`curl -X PUT %s -H "Content-Type: application/json" -d '{"description":"test"}'`, testURL),
							fmt.Sprintf("HTTP %d - Resource modified: %s", s2, truncate(rb2, 200)),
							"idor",
							0,
						))
						break
					}
				}
			}
		}
	}

	return findings
}

func (p *IDORProber) testAPIListEndpoints(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil {
		return findings
	}

	// Test API endpoints that might list all records
	for _, ep := range cfg.Classified.API {
		path := extractPath(ep.URL)
		lowerPath := strings.ToLower(path)

		// Skip endpoints with IDs already (we test those above)
		segments := strings.Split(path, "/")
		hasID := false
		for _, s := range segments {
			if isNumericStr(s) {
				hasID = true
				break
			}
		}
		if hasID {
			continue
		}

		// Only test collection-like endpoints
		if !isCollectionEndpoint(lowerPath) {
			continue
		}

		// Skip known public-by-design APIs (CMS REST APIs, etc.)
		if isPublicAPIByDesign(lowerPath) {
			continue
		}

		status, _, respBody, err := cfg.DoRequest("GET", ep.URL, nil, nil)
		if err != nil || status != 200 {
			continue
		}

		lowerBody := strings.ToLower(respBody)
		// Require ACTUALLY sensitive data, not just "name" or "email" in a blog post
		hasSensitiveData := strings.Contains(lowerBody, "password") ||
			strings.Contains(lowerBody, "secret") ||
			strings.Contains(lowerBody, "token") ||
			strings.Contains(lowerBody, "ssn") ||
			strings.Contains(lowerBody, "credit_card") ||
			strings.Contains(lowerBody, "cardnum") ||
			(strings.Contains(lowerBody, "email") && strings.Contains(lowerBody, "phone"))

		if hasSensitiveData && (strings.Contains(respBody, "data") || strings.Contains(respBody, "[")) {
			sev := "Medium"
			if strings.Contains(lowerBody, "password") || strings.Contains(lowerBody, "card") {
				sev = "Critical"
			}

			findings = append(findings, MakeFinding(
				fmt.Sprintf("IDOR - List All Records at %s", path),
				sev,
				fmt.Sprintf("The %s endpoint exposes records with sensitive data without proper authorization.", path),
				path,
				"GET",
				"CWE-639",
				fmt.Sprintf(`curl %s`, ep.URL),
				fmt.Sprintf("HTTP %d - Data listed: %s", status, truncate(respBody, 300)),
				"idor",
				0,
			))
		}
	}

	return findings
}

func (p *IDORProber) testUserDataEndpoints(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil {
		return findings
	}

	for _, ep := range cfg.Classified.UserData {
		path := extractPath(ep.URL)

		// Try accessing without auth first
		status, _, respBody, err := cfg.DoRequest("GET", ep.URL, nil, nil)
		if err != nil {
			continue
		}

		if status == 200 && len(respBody) > 50 {
			lowerBody := strings.ToLower(respBody)
			if strings.Contains(lowerBody, "email") || strings.Contains(lowerBody, "user") {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("IDOR - User Data Exposed at %s", path),
					"High",
					fmt.Sprintf("User data endpoint %s is accessible and exposes user information.", path),
					path,
					"GET",
					"CWE-639",
					fmt.Sprintf(`curl %s`, ep.URL),
					fmt.Sprintf("HTTP %d - User data: %s", status, truncate(respBody, 200)),
					"idor",
					0,
				))
			}
		}
	}

	return findings
}

func isNumericStr(s string) bool {
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return len(s) > 0
}

// isPublicAPIByDesign checks for known public CMS/framework API patterns
// that expose data intentionally (WordPress REST API, etc.)
func isPublicAPIByDesign(path string) bool {
	publicPatterns := []string{
		"/wp-json/wp/v2/posts", "/wp-json/wp/v2/pages",
		"/wp-json/wp/v2/categories", "/wp-json/wp/v2/tags",
		"/wp-json/wp/v2/comments", "/wp-json/wp/v2/media",
		"/wp-json/wp/v2/types", "/wp-json/wp/v2/statuses",
		"/wp-json/wp/v2/taxonomies", "/wp-json/oembed",
		"/wp-json/", "/wp-json",
		"/api-docs", "/swagger", "/openapi",
		"/graphql", // introspection is separate finding
	}
	lower := strings.ToLower(path)
	for _, pp := range publicPatterns {
		if strings.HasPrefix(lower, pp) || lower == pp {
			return true
		}
	}
	return false
}

func isCollectionEndpoint(path string) bool {
	// Endpoints that look like they list collections of resources
	collectionIndicators := []string{"/users", "/products", "/orders", "/items",
		"/feedbacks", "/complaints", "/reviews", "/comments", "/messages",
		"/cards", "/addresses", "/accounts", "/customers", "/records",
		"/transactions", "/payments", "/notifications", "/files",
		"/entries", "/data", "/logs", "/events"}
	for _, ci := range collectionIndicators {
		if strings.HasSuffix(path, ci) || strings.Contains(path, ci+"/") {
			return true
		}
	}
	return false
}
