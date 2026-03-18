// Package compliance maps CWE identifiers to compliance framework requirements.
package compliance

import (
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// MapFinding attaches compliance mappings to a finding based on its CWE.
// If frameworks is empty, all available mappings are attached.
// Accepted framework tokens: "owasp", "pci", "cis", "nist".
func MapFinding(f *types.Finding, frameworks []string) {
	cwe := strings.ToUpper(strings.TrimSpace(f.CWE))
	if cwe == "" {
		return
	}
	mappings, ok := cweToMappings[cwe]
	if !ok {
		return
	}
	if len(frameworks) == 0 {
		f.Compliance = mappings
		return
	}

	want := make(map[string]bool, len(frameworks))
	for _, fw := range frameworks {
		want[strings.ToLower(strings.TrimSpace(fw))] = true
	}

	var filtered []types.ComplianceMapping
	for _, m := range mappings {
		fw := strings.ToLower(string(m.Framework))
		if (want["owasp"] && strings.Contains(fw, "owasp")) ||
			(want["pci"] && strings.Contains(fw, "pci")) ||
			(want["cis"] && strings.Contains(fw, "cis")) ||
			(want["nist"] && strings.Contains(fw, "nist")) {
			filtered = append(filtered, m)
		}
	}
	f.Compliance = filtered
}

// MapFindings applies compliance mappings to every finding in the slice.
func MapFindings(findings []types.Finding, frameworks []string) {
	for i := range findings {
		MapFinding(&findings[i], frameworks)
	}
}
