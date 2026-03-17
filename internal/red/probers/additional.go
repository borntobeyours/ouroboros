package probers

import (
	"context"
	"fmt"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// AdditionalProber covers miscellaneous checks not in other probers.
type AdditionalProber struct{}

func (p *AdditionalProber) Name() string { return "additional" }

func (p *AdditionalProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	if currentClassified != nil {
		cfg.Classified = currentClassified
	}
	var findings []types.Finding

	findings = append(findings, p.testErrorHandling(cfg, endpoints)...)
	findings = append(findings, p.testBusinessLogic(cfg, endpoints)...)
	findings = append(findings, p.testInputValidation(cfg)...)
	findings = append(findings, p.testDataExposure(cfg)...)

	return findings
}

func (p *AdditionalProber) testErrorHandling(cfg *ProberConfig, endpoints []types.Endpoint) []types.Finding {
	var findings []types.Finding

	// Test verbose errors on discovered endpoints with bad input
	for _, ep := range endpoints {
		if ep.HasCategory(types.CatStatic) {
			continue
		}

		path := extractPath(ep.URL)
		testPaths := []string{
			path + "/undefined",
			path + "/sleep(1)",
		}

		for _, tp := range testPaths {
			url := cfg.BaseURL + tp
			status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
			if err != nil {
				continue
			}

			lower := strings.ToLower(respBody)
			if status >= 400 && (strings.Contains(lower, "stacktrace") || strings.Contains(lower, "stack trace") ||
				strings.Contains(lower, "error:") || strings.Contains(lower, "sequelize") ||
				strings.Contains(lower, "at object.") || strings.Contains(lower, "node_modules") ||
				strings.Contains(lower, "exception") || strings.Contains(lower, "traceback")) {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("Verbose Error Messages - Stack Trace at %s", tp),
					"Low",
					"The application returns detailed error messages including stack traces, revealing internal implementation details.",
					tp,
					"GET",
					"CWE-209",
					fmt.Sprintf("curl %s", url),
					fmt.Sprintf("HTTP %d - Error response with implementation details", status),
					"info_leak",
					0,
				))
				return findings // One finding is enough
			}
		}
	}

	return findings
}

func (p *AdditionalProber) testBusinessLogic(cfg *ProberConfig, endpoints []types.Endpoint) []types.Finding {
	var findings []types.Finding

	if cfg.AuthToken == "" {
		return findings
	}

	// Test negative quantity/price manipulation on API endpoints
	for _, ep := range endpoints {
		if !ep.HasCategory(types.CatAPI) {
			continue
		}

		path := extractPath(ep.URL)
		lowerPath := strings.ToLower(path)

		// Look for cart/basket/order-like endpoints
		if !strings.Contains(lowerPath, "basket") && !strings.Contains(lowerPath, "cart") &&
			!strings.Contains(lowerPath, "order") && !strings.Contains(lowerPath, "item") {
			continue
		}

		// Try negative quantity
		payload := `{"ProductId":1,"BasketId":1,"quantity":-1}`
		status, _, body, err := cfg.DoRequest("POST", ep.URL,
			strings.NewReader(payload), map[string]string{"Content-Type": "application/json"})
		if err == nil && status == 200 {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Business Logic Flaw - Negative Quantity Accepted at %s", path),
				"High",
				"The endpoint accepts negative quantities for items, potentially allowing negative total prices.",
				path,
				"POST",
				"CWE-20",
				fmt.Sprintf(`curl -X POST %s -H "Content-Type: application/json" -d '%s'`, ep.URL, payload),
				fmt.Sprintf("HTTP %d - Negative quantity accepted: %s", status, truncate(body, 200)),
				"logic",
				0,
			))
			break
		}
	}

	return findings
}

func (p *AdditionalProber) testInputValidation(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil {
		return findings
	}

	// Test user registration with empty/missing fields
	for _, ep := range cfg.Classified.API {
		lowerPath := strings.ToLower(extractPath(ep.URL))
		if !strings.Contains(lowerPath, "user") && !strings.Contains(lowerPath, "register") &&
			!strings.Contains(lowerPath, "signup") {
			continue
		}

		// Skip endpoints with IDs
		path := extractPath(ep.URL)
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

		// Test with empty fields
		regPayload := `{"email":"","password":""}`
		status, _, body, err := cfg.DoRequest("POST", ep.URL,
			strings.NewReader(regPayload), map[string]string{"Content-Type": "application/json"})
		if err == nil && (status == 200 || status == 201) {
			findings = append(findings, MakeFinding(
				"Input Validation - Empty Registration Fields Accepted",
				"Medium",
				"The user registration endpoint processes requests with empty email and password fields.",
				path,
				"POST",
				"CWE-20",
				fmt.Sprintf(`curl -X POST %s -H "Content-Type: application/json" -d '%s'`, ep.URL, regPayload),
				fmt.Sprintf("HTTP %d - Registration response: %s", status, truncate(body, 200)),
				"logic",
				0,
			))
		}

		// Test extremely long input
		longInput := strings.Repeat("A", 10000)
		longPayload := fmt.Sprintf(`{"email":"%s@test.com","password":"test"}`, longInput)
		status2, _, _, err2 := cfg.DoRequest("POST", ep.URL,
			strings.NewReader(longPayload), map[string]string{"Content-Type": "application/json"})
		if err2 == nil && status2 != 413 && status2 != 400 {
			findings = append(findings, MakeFinding(
				"Input Validation - No Length Limit on User Input",
				"Low",
				"The registration endpoint accepts extremely long input without length validation.",
				path,
				"POST",
				"CWE-20",
				"curl -X POST ... -d '{\"email\":\"AAAA...(10000 chars)@test.com\",...}'",
				fmt.Sprintf("HTTP %d - 10,000 character input accepted", status2),
				"logic",
				0,
			))
		}

		break // Only test the first registration-like endpoint
	}

	return findings
}

func (p *AdditionalProber) testDataExposure(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.Classified == nil {
		return findings
	}

	// Check for API endpoints that expose data without auth
	for _, ep := range cfg.Classified.API {
		if ep.StatusCode != 200 || len(ep.Body) < 20 {
			continue
		}

		path := extractPath(ep.URL)
		lowerBody := strings.ToLower(ep.Body)

		// Skip endpoints that just return generic data
		if !strings.Contains(lowerBody, "data") && !strings.Contains(lowerBody, "status") &&
			!strings.Contains(lowerBody, "[") {
			continue
		}

		// Check for security-related data exposure
		securityIndicators := []string{"answer", "security", "captcha", "token"}
		for _, indicator := range securityIndicators {
			if strings.Contains(lowerBody, indicator) {
				findings = append(findings, MakeFinding(
					fmt.Sprintf("Security Data Exposure - %s at %s", indicator, path),
					"High",
					fmt.Sprintf("The endpoint %s exposes security-related data ('%s') without proper authentication.", path, indicator),
					path,
					"GET",
					"CWE-200",
					fmt.Sprintf("curl %s", ep.URL),
					fmt.Sprintf("HTTP %d - Contains '%s': %s", ep.StatusCode, indicator, truncate(ep.Body, 200)),
					"info_leak",
					0,
				))
				break
			}
		}
	}

	return findings
}
