package boss

import (
	"context"
	"fmt"
	"log"

	"github.com/borntobeyours/ouroboros/internal/ai"
	"github.com/borntobeyours/ouroboros/internal/red"
	"github.com/borntobeyours/ouroboros/pkg/types"
)

// Agent is the Final Boss validator - a more aggressive attacker for final validation.
type Agent struct {
	provider ai.Provider
	logger   *log.Logger
}

// NewAgent creates a new Final Boss agent.
func NewAgent(provider ai.Provider, logger *log.Logger) *Agent {
	return &Agent{
		provider: provider,
		logger:   logger,
	}
}

// Validate performs a final aggressive validation scan after convergence.
func (a *Agent) Validate(ctx context.Context, target types.Target, allFindings []types.Finding, allPatches []types.Patch) ([]types.Finding, error) {
	a.logger.Printf("[BOSS] Final Boss validation starting against %s", target.URL)
	a.logger.Printf("[BOSS] Previous rounds found %d vulnerabilities with %d patches applied", len(allFindings), len(allPatches))

	systemPrompt := buildBossPrompt()
	userPrompt := buildBossUserPrompt(target, allFindings, allPatches)

	resp, err := a.provider.Chat(ctx, ai.ChatRequest{
		Messages: []ai.Message{
			{Role: "user", Content: userPrompt},
		},
		SystemPrompt: systemPrompt,
		MaxTokens:    4096,
		Temperature:  0.9, // Higher temperature for more creative attacks
	})
	if err != nil {
		return nil, fmt.Errorf("Final Boss AI failed: %w", err)
	}

	findings, err := red.ParseFindings(resp.Content, -1) // -1 indicates boss round
	if err != nil {
		a.logger.Printf("[BOSS] Warning: could not parse AI response: %v", err)
		return []types.Finding{}, nil
	}

	a.logger.Printf("[BOSS] Final Boss found %d additional vulnerabilities", len(findings))
	return findings, nil
}

func buildBossPrompt() string {
	return `You are an elite red team operator performing a FINAL validation of a web application's security.
Previous red team and blue team rounds have already occurred. Your job is to find what they missed.

You are the FINAL BOSS. Think like an APT actor. Be creative. Be thorough. Be relentless.

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

OUTPUT FORMAT: Return ONLY a JSON array of findings (same format as standard scanner).
Each finding must have: title, severity, description, endpoint, method, cwe, poc, evidence, technique.
If no new vulnerabilities are found, return an empty array: []
Do NOT include any text outside the JSON array.`
}

func buildBossUserPrompt(target types.Target, findings []types.Finding, patches []types.Patch) string {
	prompt := fmt.Sprintf("TARGET: %s\n\n", target.URL)
	prompt += "KNOWN VULNERABILITIES (already found and patched):\n"
	for _, f := range findings {
		prompt += fmt.Sprintf("- [%s] %s at %s (technique: %s)\n", f.Severity, f.Title, f.Endpoint, f.Technique)
	}
	prompt += "\nAPPLIED PATCHES:\n"
	for _, p := range patches {
		prompt += fmt.Sprintf("- %s: %s\n", p.FindingID, p.Description)
	}
	prompt += "\nYour mission: Find vulnerabilities that the previous rounds MISSED. Think outside the box.\n"
	return prompt
}
