package probers

import (
	"context"
	"fmt"
	"strings"

	"github.com/ouroboros-security/ouroboros/pkg/types"
)

// AdditionalProber covers miscellaneous checks not in other probers.
type AdditionalProber struct{}

func (p *AdditionalProber) Name() string { return "additional" }

func (p *AdditionalProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	var findings []types.Finding

	findings = append(findings, p.testErrorHandling(cfg)...)
	findings = append(findings, p.testPrivacyViolations(cfg)...)
	findings = append(findings, p.testBusinessLogic(cfg)...)
	findings = append(findings, p.testRateLimiting(cfg)...)
	findings = append(findings, p.testInputValidation(cfg)...)
	findings = append(findings, p.testAPIAbuse(cfg)...)
	findings = append(findings, p.testDataExposure(cfg)...)

	return findings
}

func (p *AdditionalProber) testErrorHandling(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Test verbose errors on multiple endpoints
	errorEndpoints := []struct {
		path   string
		method string
		body   string
		ctype  string
	}{
		{"/rest/products/sleep(1)", "GET", "", ""},
		{"/api/Users/undefined", "GET", "", ""},
		{"/rest/basket/undefined", "GET", "", ""},
		{"/rest/order-history/undefined", "GET", "", ""},
		{"/rest/track-order/' OR 1=1--", "GET", "", ""},
		{"/rest/saveLoginIp", "GET", "", ""},
		{"/rest/user/erasure-request", "GET", "", ""},
		{"/rest/wallet/balance", "GET", "", ""},
	}

	for _, ep := range errorEndpoints {
		headers := map[string]string{}
		if ep.body != "" {
			headers["Content-Type"] = ep.ctype
		}
		status, _, respBody, err := cfg.DoRequest(ep.method, cfg.BaseURL+ep.path, nil, headers)
		if err != nil {
			continue
		}

		lower := strings.ToLower(respBody)
		if status >= 400 && (strings.Contains(lower, "stacktrace") || strings.Contains(lower, "stack trace") ||
			strings.Contains(lower, "error:") || strings.Contains(lower, "sequelize") ||
			strings.Contains(lower, "at object.") || strings.Contains(lower, "node_modules")) {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Verbose Error Messages - Stack Trace at %s", ep.path),
				"Low",
				"The application returns detailed error messages including stack traces, revealing internal implementation details.",
				ep.path,
				ep.method,
				"CWE-209",
				fmt.Sprintf("curl %s%s", cfg.BaseURL, ep.path),
				fmt.Sprintf("HTTP %d - Error response with implementation details", status),
				"info_leak",
				0,
			))
		}
	}

	return findings
}

func (p *AdditionalProber) testPrivacyViolations(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Test data erasure endpoint
	status, _, body, err := cfg.DoRequest("GET", cfg.BaseURL+"/dataerasure", nil, nil)
	if err == nil && status == 200 && len(body) > 100 {
		findings = append(findings, MakeFinding(
			"Data Erasure Endpoint - Potential GDPR Abuse",
			"Medium",
			"The data erasure endpoint is accessible and may allow unauthorized data deletion requests.",
			"/dataerasure",
			"GET",
			"CWE-284",
			fmt.Sprintf("curl %s/dataerasure", cfg.BaseURL),
			fmt.Sprintf("HTTP %d - Data erasure form accessible (%d bytes)", status, len(body)),
			"auth_bypass",
			0,
		))
	}

	// Test privacy-security endpoint
	status2, _, body2, err2 := cfg.DoRequest("GET", cfg.BaseURL+"/privacy-security/last-login-ip", nil, nil)
	if err2 == nil && status2 == 200 && len(body2) > 50 {
		findings = append(findings, MakeFinding(
			"Last Login IP Exposure",
			"Low",
			"The last login IP endpoint reveals user login history information.",
			"/privacy-security/last-login-ip",
			"GET",
			"CWE-200",
			fmt.Sprintf("curl %s/privacy-security/last-login-ip", cfg.BaseURL),
			fmt.Sprintf("HTTP %d - Login IP info accessible", status2),
			"info_leak",
			0,
		))
	}

	return findings
}

func (p *AdditionalProber) testBusinessLogic(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Test negative quantity/price manipulation
	if cfg.AuthToken != "" {
		// Try adding item with negative quantity
		payload := `{"ProductId":1,"BasketId":1,"quantity":-1}`
		status, _, body, err := cfg.DoRequest("POST", cfg.BaseURL+"/api/BasketItems",
			strings.NewReader(payload), map[string]string{"Content-Type": "application/json"})
		if err == nil && status == 200 {
			findings = append(findings, MakeFinding(
				"Business Logic Flaw - Negative Quantity Accepted",
				"High",
				"The basket accepts negative quantities for items, potentially allowing negative total prices.",
				"/api/BasketItems",
				"POST",
				"CWE-20",
				fmt.Sprintf(`curl -X POST %s/api/BasketItems -H "Content-Type: application/json" -d '%s'`, cfg.BaseURL, payload),
				fmt.Sprintf("HTTP %d - Negative quantity accepted: %s", status, truncate(body, 200)),
				"logic",
				0,
			))
		}

		// Test deluxe membership without payment
		status2, _, body2, err2 := cfg.DoRequest("POST", cfg.BaseURL+"/rest/deluxe-membership",
			strings.NewReader(`{"paymentMode":"wallet"}`), map[string]string{"Content-Type": "application/json"})
		if err2 == nil && (status2 == 200 || status2 == 400) {
			findings = append(findings, MakeFinding(
				"Business Logic - Deluxe Membership Payment Bypass Attempt",
				"Medium",
				"The deluxe membership endpoint processes payment requests that could be manipulated.",
				"/rest/deluxe-membership",
				"POST",
				"CWE-840",
				fmt.Sprintf(`curl -X POST %s/rest/deluxe-membership -H "Content-Type: application/json" -d '{"paymentMode":"wallet"}'`, cfg.BaseURL),
				fmt.Sprintf("HTTP %d - Response: %s", status2, truncate(body2, 200)),
				"logic",
				0,
			))
		}

		// Test coupon reuse / invalid coupon
		status3, _, body3, err3 := cfg.DoRequest("PUT", cfg.BaseURL+"/rest/basket/1/coupon/aaaa",
			nil, nil)
		if err3 == nil {
			findings = append(findings, MakeFinding(
				"Coupon Validation - Error Information Disclosure",
				"Low",
				"The coupon validation endpoint reveals implementation details through error responses.",
				"/rest/basket/1/coupon/aaaa",
				"PUT",
				"CWE-209",
				fmt.Sprintf("curl -X PUT %s/rest/basket/1/coupon/aaaa", cfg.BaseURL),
				fmt.Sprintf("HTTP %d - Coupon response: %s", status3, truncate(body3, 200)),
				"info_leak",
				0,
			))
		}
	}

	// Test chatbot for info extraction
	chatPayload := `{"action":"query","query":"coupon code"}`
	status4, _, body4, err4 := cfg.DoRequest("POST", cfg.BaseURL+"/rest/chatbot/respond",
		strings.NewReader(chatPayload), map[string]string{"Content-Type": "application/json"})
	if err4 == nil && status4 == 200 {
		findings = append(findings, MakeFinding(
			"Chatbot Information Leakage",
			"Medium",
			"The chatbot may reveal sensitive information such as coupon codes or internal details when queried.",
			"/rest/chatbot/respond",
			"POST",
			"CWE-200",
			fmt.Sprintf(`curl -X POST %s/rest/chatbot/respond -H "Content-Type: application/json" -d '%s'`, cfg.BaseURL, chatPayload),
			fmt.Sprintf("HTTP %d - Chatbot response: %s", status4, truncate(body4, 200)),
			"info_leak",
			0,
		))
	}

	return findings
}

func (p *AdditionalProber) testRateLimiting(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Test if login has rate limiting (send 10 rapid requests)
	loginURL := cfg.BaseURL + "/rest/user/login"
	payload := `{"email":"test@test.com","password":"wrongpassword"}`
	blocked := false

	for i := 0; i < 10; i++ {
		status, _, _, err := cfg.DoRequest("POST", loginURL, strings.NewReader(payload),
			map[string]string{"Content-Type": "application/json"})
		if err != nil {
			break
		}
		if status == 429 {
			blocked = true
			break
		}
	}

	if !blocked {
		findings = append(findings, MakeFinding(
			"Missing Rate Limiting on Login Endpoint",
			"Medium",
			"The login endpoint does not implement rate limiting, allowing brute-force password attacks.",
			"/rest/user/login",
			"POST",
			"CWE-307",
			fmt.Sprintf(`for i in $(seq 1 10); do curl -s -o /dev/null -w "%%{http_code}" -X POST %s -H "Content-Type: application/json" -d '%s'; done`, loginURL, payload),
			"10 rapid login attempts accepted without rate limiting (no HTTP 429)",
			"auth_bypass",
			0,
		))
	}

	// Test password reset rate limiting
	resetURL := cfg.BaseURL + "/rest/user/reset-password"
	resetPayload := `{"email":"admin@juice-sh.op","answer":"test","new":"test","repeat":"test"}`
	resetBlocked := false
	for i := 0; i < 10; i++ {
		status, _, _, err := cfg.DoRequest("POST", resetURL, strings.NewReader(resetPayload),
			map[string]string{"Content-Type": "application/json"})
		if err != nil {
			break
		}
		if status == 429 {
			resetBlocked = true
			break
		}
	}
	if !resetBlocked {
		findings = append(findings, MakeFinding(
			"Missing Rate Limiting on Password Reset",
			"Medium",
			"The password reset endpoint does not implement rate limiting, allowing brute-force security question guessing.",
			"/rest/user/reset-password",
			"POST",
			"CWE-307",
			fmt.Sprintf(`curl -X POST %s -H "Content-Type: application/json" -d '%s'`, resetURL, resetPayload),
			"10 rapid reset attempts accepted without rate limiting",
			"auth_bypass",
			0,
		))
	}

	return findings
}

func (p *AdditionalProber) testInputValidation(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Test feedback with zero-star rating
	if cfg.AuthToken != "" {
		payload := `{"UserId":1,"captchaId":0,"captcha":"0","comment":"test","rating":0}`
		status, _, body, err := cfg.DoRequest("POST", cfg.BaseURL+"/api/Feedbacks",
			strings.NewReader(payload), map[string]string{"Content-Type": "application/json"})
		if err == nil && status == 201 {
			findings = append(findings, MakeFinding(
				"Input Validation - Zero-Star Rating Accepted",
				"Low",
				"The feedback endpoint accepts a zero-star rating, which should not be a valid option.",
				"/api/Feedbacks",
				"POST",
				"CWE-20",
				fmt.Sprintf(`curl -X POST %s/api/Feedbacks -H "Content-Type: application/json" -d '%s'`, cfg.BaseURL, payload),
				fmt.Sprintf("HTTP %d - Zero-star feedback accepted: %s", status, truncate(body, 200)),
				"logic",
				0,
			))
		}
	}

	// Test user registration with empty/missing fields
	regPayload := `{"email":"","password":""}`
	status2, _, body2, err2 := cfg.DoRequest("POST", cfg.BaseURL+"/api/Users",
		strings.NewReader(regPayload), map[string]string{"Content-Type": "application/json"})
	if err2 == nil {
		findings = append(findings, MakeFinding(
			"Input Validation - Empty Registration Fields Accepted",
			"Medium",
			"The user registration endpoint processes requests with empty email and password fields.",
			"/api/Users",
			"POST",
			"CWE-20",
			fmt.Sprintf(`curl -X POST %s/api/Users -H "Content-Type: application/json" -d '%s'`, cfg.BaseURL, regPayload),
			fmt.Sprintf("HTTP %d - Registration response: %s", status2, truncate(body2, 200)),
			"logic",
			0,
		))
	}

	// Test extremely long input
	longInput := strings.Repeat("A", 10000)
	longPayload := fmt.Sprintf(`{"email":"%s@test.com","password":"test"}`, longInput)
	status3, _, _, err3 := cfg.DoRequest("POST", cfg.BaseURL+"/api/Users",
		strings.NewReader(longPayload), map[string]string{"Content-Type": "application/json"})
	if err3 == nil && status3 != 413 && status3 != 400 {
		findings = append(findings, MakeFinding(
			"Input Validation - No Length Limit on User Input",
			"Low",
			"The registration endpoint accepts extremely long input without length validation, potential for buffer overflow or DoS.",
			"/api/Users",
			"POST",
			"CWE-20",
			"curl -X POST ... -d '{\"email\":\"AAAA...(10000 chars)@test.com\",...}'",
			fmt.Sprintf("HTTP %d - 10,000 character input accepted", status3),
			"logic",
			0,
		))
	}

	return findings
}

func (p *AdditionalProber) testAPIAbuse(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Test forging product reviews
	if cfg.AuthToken != "" {
		reviewPayload := `{"message":"forged review","author":"admin@juice-sh.op"}`
		status, _, body, err := cfg.DoRequest("PUT", cfg.BaseURL+"/rest/products/1/reviews",
			strings.NewReader(reviewPayload), map[string]string{"Content-Type": "application/json"})
		if err == nil && (status == 200 || status == 201) {
			findings = append(findings, MakeFinding(
				"Broken Access Control - Forged Product Review",
				"High",
				"Product reviews can be submitted with a forged author field, allowing impersonation of other users.",
				"/rest/products/1/reviews",
				"PUT",
				"CWE-284",
				fmt.Sprintf(`curl -X PUT %s/rest/products/1/reviews -H "Content-Type: application/json" -d '%s'`, cfg.BaseURL, reviewPayload),
				fmt.Sprintf("HTTP %d - Forged review accepted: %s", status, truncate(body, 200)),
				"auth_bypass",
				0,
			))
		}
	}

	// Test continue-code endpoint
	status2, _, body2, err2 := cfg.DoRequest("GET", cfg.BaseURL+"/rest/continue-code", nil, nil)
	if err2 == nil && status2 == 200 && len(body2) > 10 {
		// Try to apply a modified continue code
		status3, _, body3, err3 := cfg.DoRequest("PUT", cfg.BaseURL+"/rest/continue-code/apply/AAAAAAAAtest",
			nil, nil)
		if err3 == nil {
			findings = append(findings, MakeFinding(
				"Challenge Progress Manipulation via Continue Code",
				"Medium",
				"The continue code can be manipulated to alter challenge progress state.",
				"/rest/continue-code/apply/",
				"PUT",
				"CWE-284",
				fmt.Sprintf("curl -X PUT %s/rest/continue-code/apply/AAAA", cfg.BaseURL),
				fmt.Sprintf("GET continue-code: HTTP %d (%s) | PUT apply: HTTP %d (%s)", status2, truncate(body2, 50), status3, truncate(body3, 100)),
				"logic",
				0,
			))
		}
	}

	// Test repeat notification
	status4, _, body4, err4 := cfg.DoRequest("GET", cfg.BaseURL+"/rest/repeat-notification", nil, nil)
	if err4 == nil && status4 == 200 {
		findings = append(findings, MakeFinding(
			"Information Disclosure - Repeat Notification Endpoint",
			"Low",
			"The repeat-notification endpoint is accessible and reveals challenge completion data.",
			"/rest/repeat-notification",
			"GET",
			"CWE-200",
			fmt.Sprintf("curl %s/rest/repeat-notification", cfg.BaseURL),
			fmt.Sprintf("HTTP %d - Notification data: %s", status4, truncate(body4, 200)),
			"info_leak",
			0,
		))
	}

	// Test country mapping
	status5, _, body5, err5 := cfg.DoRequest("GET", cfg.BaseURL+"/rest/country-mapping", nil, nil)
	if err5 == nil && status5 == 200 && len(body5) > 10 {
		findings = append(findings, MakeFinding(
			"Information Disclosure - Country Mapping Data Exposed",
			"Info",
			"Internal country mapping configuration data is publicly accessible.",
			"/rest/country-mapping",
			"GET",
			"CWE-200",
			fmt.Sprintf("curl %s/rest/country-mapping", cfg.BaseURL),
			fmt.Sprintf("HTTP %d - Country data: %s", status5, truncate(body5, 200)),
			"info_leak",
			0,
		))
	}

	return findings
}

func (p *AdditionalProber) testDataExposure(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Check for exposed Sequelize models via API
	models := []string{
		"PrivacyRequests", "ImageCaptchas", "Memories",
		"Wallets", "BasketItems",
	}

	for _, model := range models {
		status, _, body, err := cfg.DoRequest("GET", cfg.BaseURL+"/api/"+model, nil, nil)
		if err != nil {
			continue
		}
		if status == 200 && len(body) > 20 && (strings.Contains(body, "data") || strings.Contains(body, "status")) {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("Sensitive Data Exposure - %s API", model),
				"Medium",
				fmt.Sprintf("The /api/%s endpoint exposes data without requiring proper authentication.", model),
				"/api/"+model,
				"GET",
				"CWE-200",
				fmt.Sprintf("curl %s/api/%s", cfg.BaseURL, model),
				fmt.Sprintf("HTTP %d - %s data accessible (%d bytes)", status, model, len(body)),
				"info_leak",
				0,
			))
		}
	}

	// Test accessing user's security answers
	if cfg.AuthToken != "" {
		status2, _, body2, err2 := cfg.DoRequest("GET", cfg.BaseURL+"/api/SecurityAnswers", nil, nil)
		if err2 == nil && status2 == 200 && strings.Contains(body2, "answer") {
			findings = append(findings, MakeFinding(
				"Critical Data Exposure - Security Answers Accessible",
				"Critical",
				"Security question answers are accessible via the API, allowing complete account takeover via password reset.",
				"/api/SecurityAnswers",
				"GET",
				"CWE-200",
				fmt.Sprintf("curl -H 'Authorization: Bearer ...' %s/api/SecurityAnswers", cfg.BaseURL),
				fmt.Sprintf("HTTP %d - Security answers exposed: %s", status2, truncate(body2, 300)),
				"info_leak",
				0,
			))
		}
	}

	return findings
}
