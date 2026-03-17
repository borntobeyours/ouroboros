package blue

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/ouroboros-security/ouroboros/internal/ai"
	"github.com/ouroboros-security/ouroboros/pkg/types"
)

// Agent is the Blue AI defender agent.
type Agent struct {
	provider ai.Provider
	logger   *log.Logger
}

// NewAgent creates a new Blue AI agent.
func NewAgent(provider ai.Provider, logger *log.Logger) *Agent {
	return &Agent{
		provider: provider,
		logger:   logger,
	}
}

// Defend analyzes findings and generates patches.
func (a *Agent) Defend(ctx context.Context, findings []types.Finding) ([]types.Patch, error) {
	if len(findings) == 0 {
		return nil, nil
	}

	a.logger.Printf("[BLUE] Analyzing %d findings...", len(findings))

	systemPrompt := BuildDefensePrompt()
	userPrompt := BuildAnalysisPrompt(findings)

	resp, err := a.provider.Chat(ctx, ai.ChatRequest{
		Messages: []ai.Message{
			{Role: "user", Content: userPrompt},
		},
		SystemPrompt: systemPrompt,
		MaxTokens:    4096,
		Temperature:  0.3,
	})
	if err != nil {
		return nil, fmt.Errorf("AI defense analysis failed: %w", err)
	}

	patches, err := ParsePatches(resp.Content)
	if err != nil {
		a.logger.Printf("[BLUE] Warning: could not parse AI response: %v", err)
		return []types.Patch{}, nil
	}

	a.logger.Printf("[BLUE] Generated %d patches", len(patches))
	return patches, nil
}

// BuildDefensePrompt creates the Blue AI system prompt.
func BuildDefensePrompt() string {
	return `You are a senior security engineer conducting a vulnerability assessment review.
Your job is to analyze reported vulnerabilities and provide actionable remediation guidance.

For each vulnerability, you must:
1. VALIDATE: Confirm whether this is a real vulnerability or a false positive
2. PATCH: Provide specific code fixes or configuration changes
3. HARDEN: Suggest additional hardening measures beyond the immediate fix

Your patches should follow security best practices:
- Use parameterized queries for SQL injection
- Implement proper output encoding for XSS
- Use allowlists for SSRF prevention
- Implement proper authorization checks for IDOR
- Use constant-time comparison for authentication
- Validate and sanitize all user input
- Apply principle of least privilege
- Enable security headers (CSP, X-Frame-Options, etc.)

OUTPUT FORMAT: Return ONLY a JSON array of patches. Each patch must have these fields:
{
  "finding_id": "string (the finding's ID)",
  "description": "string (what the patch does)",
  "code": "string (the actual code fix, if applicable)",
  "config_change": "string (configuration changes needed)",
  "hardening": "string (additional hardening recommendations)",
  "confidence": "high|medium|low"
}

Do NOT include any text outside the JSON array.`
}

// BuildAnalysisPrompt creates the per-request analysis prompt.
func BuildAnalysisPrompt(findings []types.Finding) string {
	var sb strings.Builder

	sb.WriteString("VULNERABILITIES TO ANALYZE AND PATCH:\n\n")
	for i, f := range findings {
		sb.WriteString(fmt.Sprintf("--- Finding %d ---\n", i+1))
		sb.WriteString(fmt.Sprintf("ID: %s\n", f.ID))
		sb.WriteString(fmt.Sprintf("Title: %s\n", f.Title))
		sb.WriteString(fmt.Sprintf("Severity: %s\n", f.Severity))
		sb.WriteString(fmt.Sprintf("Endpoint: [%s] %s\n", f.Method, f.Endpoint))
		sb.WriteString(fmt.Sprintf("CWE: %s\n", f.CWE))
		sb.WriteString(fmt.Sprintf("Technique: %s\n", f.Technique))
		sb.WriteString(fmt.Sprintf("Description: %s\n", f.Description))
		if f.PoC != "" {
			sb.WriteString(fmt.Sprintf("PoC: %s\n", f.PoC))
		}
		if f.Evidence != "" {
			sb.WriteString(fmt.Sprintf("Evidence: %s\n", f.Evidence))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("For each finding, provide a specific patch with code fix, config changes, and hardening recommendations.\n")

	return sb.String()
}

// ParsePatches parses the AI response into patches.
func ParsePatches(response string) ([]types.Patch, error) {
	response = strings.TrimSpace(response)
	if idx := strings.Index(response, "["); idx >= 0 {
		end := strings.LastIndex(response, "]")
		if end > idx {
			response = response[idx : end+1]
		}
	}

	var patches []types.Patch
	if err := json.Unmarshal([]byte(response), &patches); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}

	return patches, nil
}
