package report

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// SARIF v2.1.0 types for GitHub Code Scanning / CI integration.

type sarifLog struct {
	Schema  string      `json:"$schema"`
	Version string      `json:"version"`
	Runs    []sarifRun  `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string              `json:"id"`
	Name             string              `json:"name"`
	ShortDescription sarifMessage        `json:"shortDescription"`
	FullDescription  sarifMessage        `json:"fullDescription,omitempty"`
	HelpURI          string              `json:"helpUri,omitempty"`
	Properties       sarifRuleProperties `json:"properties,omitempty"`
}

type sarifRuleProperties struct {
	Tags     []string `json:"tags,omitempty"`
	Security struct {
		Severity string `json:"severity,omitempty"`
	} `json:"security-severity,omitempty"`
}

type sarifResult struct {
	RuleID    string           `json:"ruleId"`
	Level     string           `json:"level"`
	Message   sarifMessage     `json:"message"`
	Locations []sarifLocation  `json:"locations,omitempty"`
	Properties sarifResultProps `json:"properties,omitempty"`
}

type sarifResultProps struct {
	Confidence float64 `json:"confidence,omitempty"`
	CVSSScore  float64 `json:"cvss-score,omitempty"`
	CVSSVector string  `json:"cvss-vector,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

// ExportSARIF writes findings as SARIF v2.1.0 to a file.
// Compatible with GitHub Code Scanning, Azure DevOps, and other SARIF consumers.
func ExportSARIF(findings []types.Finding, session *types.ScanSession, path string) error {
	rules := make([]sarifRule, 0)
	results := make([]sarifResult, 0)
	ruleIndex := map[string]bool{}

	for _, f := range findings {
		ruleID := sarifRuleID(f)

		// Add rule if not seen
		if !ruleIndex[ruleID] {
			ruleIndex[ruleID] = true
			rule := sarifRule{
				ID:               ruleID,
				Name:             sanitizeName(f.Title),
				ShortDescription: sarifMessage{Text: f.Title},
			}
			if f.CWE != "" {
				rule.HelpURI = fmt.Sprintf("https://cwe.mitre.org/data/definitions/%s.html", strings.TrimPrefix(strings.ToUpper(f.CWE), "CWE-"))
				rule.Properties.Tags = []string{f.CWE, f.Technique}
			}
			rules = append(rules, rule)
		}

		// Map severity to SARIF level
		level := "note"
		sev := f.AdjustedSeverity
		if sev == 0 {
			sev = f.Severity
		}
		switch {
		case sev >= types.SeverityHigh:
			level = "error"
		case sev >= types.SeverityMedium:
			level = "warning"
		}

		// Build description with evidence
		desc := f.Description
		if f.PoC != "" {
			desc += fmt.Sprintf("\n\nPoC: %s", f.PoC)
		}
		if f.CVSS.Score > 0 {
			desc += fmt.Sprintf("\n\nCVSS: %.1f (%s) - %s", f.CVSS.Score, f.CVSS.Rating, f.CVSS.Vector)
		}

		result := sarifResult{
			RuleID:  ruleID,
			Level:   level,
			Message: sarifMessage{Text: desc},
			Locations: []sarifLocation{
				{
					PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{
							URI: f.Endpoint,
						},
					},
				},
			},
			Properties: sarifResultProps{
				Confidence: float64(f.Confidence),
				CVSSScore:  f.CVSS.Score,
				CVSSVector: f.CVSS.Vector,
			},
		}
		results = append(results, result)
	}

	log := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{
			{
				Tool: sarifTool{
					Driver: sarifDriver{
						Name:           "Ouroboros",
						Version:        "0.1.0",
						InformationURI: "https://github.com/borntobeyours/ouroboros",
						Rules:          rules,
					},
				},
				Results: results,
			},
		},
	}

	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal SARIF: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

func sarifRuleID(f types.Finding) string {
	// Generate a stable rule ID from technique + CWE
	tech := strings.ReplaceAll(f.Technique, " ", "-")
	if f.CWE != "" {
		return fmt.Sprintf("ouroboros/%s/%s", tech, strings.ToLower(f.CWE))
	}
	return fmt.Sprintf("ouroboros/%s", tech)
}

func sanitizeName(s string) string {
	// Convert "SQL Injection - Login Bypass (error-based)" to "SqlInjectionLoginBypass"
	s = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == ' ' {
			return r
		}
		return ' '
	}, s)
	words := strings.Fields(s)
	for i, w := range words {
		if len(w) > 0 {
			words[i] = strings.ToUpper(w[:1]) + strings.ToLower(w[1:])
		}
	}
	return strings.Join(words, "")
}
