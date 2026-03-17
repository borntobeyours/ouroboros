package blue

import "github.com/ouroboros-security/ouroboros/pkg/types"

// CategorizeFinding determines the category of a finding for targeted remediation.
func CategorizeFinding(f types.Finding) string {
	switch f.Technique {
	case "sqli":
		return "input_validation"
	case "xss":
		return "output_encoding"
	case "ssrf":
		return "network_security"
	case "idor":
		return "access_control"
	case "auth_bypass":
		return "authentication"
	case "command_injection":
		return "input_validation"
	case "path_traversal":
		return "input_validation"
	case "xxe":
		return "parser_security"
	case "csrf":
		return "session_security"
	case "misconfig":
		return "configuration"
	case "info_leak":
		return "information_security"
	default:
		return "general"
	}
}

// PrioritizeFindings sorts findings by severity for remediation order.
func PrioritizeFindings(findings []types.Finding) []types.Finding {
	// Simple insertion sort by severity (descending)
	sorted := make([]types.Finding, len(findings))
	copy(sorted, findings)

	for i := 1; i < len(sorted); i++ {
		key := sorted[i]
		j := i - 1
		for j >= 0 && sorted[j].Severity < key.Severity {
			sorted[j+1] = sorted[j]
			j--
		}
		sorted[j+1] = key
	}

	return sorted
}
