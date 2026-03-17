package blue

import (
	"fmt"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// GenerateQuickPatch generates a basic patch suggestion without AI for fallback.
func GenerateQuickPatch(finding types.Finding) types.Patch {
	patch := types.Patch{
		FindingID:  finding.ID,
		Confidence: "medium",
	}

	switch finding.Technique {
	case "sqli":
		patch.Description = "Use parameterized queries / prepared statements"
		patch.Code = "Use parameterized queries instead of string concatenation for SQL queries."
		patch.Hardening = "Enable WAF rules for SQL injection. Use an ORM where possible."
	case "xss":
		patch.Description = "Implement output encoding and Content Security Policy"
		patch.Code = "HTML-encode all user-controlled output. Use context-aware encoding."
		patch.ConfigChange = "Add Content-Security-Policy header: default-src 'self'"
		patch.Hardening = "Enable X-XSS-Protection header. Use HttpOnly cookies."
	case "ssrf":
		patch.Description = "Implement URL allowlist and block internal network access"
		patch.Code = "Validate URLs against an allowlist. Block private IP ranges (10.x, 172.16-31.x, 192.168.x, 127.x, 169.254.x)."
		patch.Hardening = "Use network segmentation. Disable unnecessary URL schemes."
	case "idor":
		patch.Description = "Implement proper authorization checks"
		patch.Code = "Verify that the authenticated user has permission to access the requested resource."
		patch.Hardening = "Use indirect references (UUIDs). Implement RBAC."
	case "auth_bypass":
		patch.Description = "Enforce authentication on all protected endpoints"
		patch.Code = "Apply authentication middleware to all protected routes."
		patch.Hardening = "Implement rate limiting. Use MFA for sensitive operations."
	case "command_injection":
		patch.Description = "Avoid shell execution and sanitize inputs"
		patch.Code = "Use language-native APIs instead of shell commands. If unavoidable, use strict allowlists."
		patch.Hardening = "Run with minimal OS privileges. Use containers/sandboxing."
	default:
		patch.Description = fmt.Sprintf("Remediate %s vulnerability", finding.Technique)
		patch.Code = "Review and fix the reported vulnerability following security best practices."
		patch.Hardening = "Implement defense-in-depth measures."
	}

	return patch
}

// FormatPatchReport creates a human-readable patch report.
func FormatPatchReport(patches []types.Patch) string {
	var sb strings.Builder

	for i, p := range patches {
		sb.WriteString(fmt.Sprintf("Patch %d (Finding: %s)\n", i+1, p.FindingID))
		sb.WriteString(fmt.Sprintf("  Description: %s\n", p.Description))
		if p.Code != "" {
			sb.WriteString(fmt.Sprintf("  Code Fix: %s\n", p.Code))
		}
		if p.ConfigChange != "" {
			sb.WriteString(fmt.Sprintf("  Config: %s\n", p.ConfigChange))
		}
		if p.Hardening != "" {
			sb.WriteString(fmt.Sprintf("  Hardening: %s\n", p.Hardening))
		}
		sb.WriteString(fmt.Sprintf("  Confidence: %s\n\n", p.Confidence))
	}

	return sb.String()
}
