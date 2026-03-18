package blue

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/borntobeyours/ouroboros/internal/ai"
	"github.com/borntobeyours/ouroboros/pkg/types"
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
// For large finding sets, it batches into concurrent chunks.
func (a *Agent) Defend(ctx context.Context, findings []types.Finding) ([]types.Patch, error) {
	if len(findings) == 0 {
		return nil, nil
	}

	const batchSize = 10
	const maxConcurrent = 3 // Limit concurrent Claude Code processes

	// Small batch: single call
	if len(findings) <= batchSize {
		a.logger.Printf("[BLUE] Analyzing %d findings...", len(findings))
		return a.analyzeBatch(ctx, findings)
	}

	// Split into batches
	var batches [][]types.Finding
	for i := 0; i < len(findings); i += batchSize {
		end := i + batchSize
		if end > len(findings) {
			end = len(findings)
		}
		batches = append(batches, findings[i:end])
	}

	a.logger.Printf("[BLUE] Analyzing %d findings in %d concurrent batches (max %d parallel)...", len(findings), len(batches), maxConcurrent)

	// Run batches concurrently with semaphore
	type batchResult struct {
		patches []types.Patch
		err     error
		idx     int
	}

	results := make(chan batchResult, len(batches))
	sem := make(chan struct{}, maxConcurrent)

	for i, batch := range batches {
		sem <- struct{}{} // Acquire semaphore
		go func(idx int, b []types.Finding) {
			defer func() { <-sem }() // Release semaphore

			a.logger.Printf("[BLUE] Batch %d/%d started (%d findings)...", idx+1, len(batches), len(b))
			patches, err := a.analyzeBatch(ctx, b)
			if err != nil {
				a.logger.Printf("[BLUE] Batch %d failed: %v", idx+1, err)
			} else {
				a.logger.Printf("[BLUE] Batch %d done: %d patches", idx+1, len(patches))
			}
			results <- batchResult{patches: patches, err: err, idx: idx}
		}(i, batch)
	}

	// Collect results
	var allPatches []types.Patch
	succeeded := 0
	for range batches {
		r := <-results
		if r.err == nil {
			allPatches = append(allPatches, r.patches...)
			succeeded++
		}
	}

	a.logger.Printf("[BLUE] Generated %d patches (%d/%d batches succeeded)", len(allPatches), succeeded, len(batches))
	return allPatches, nil
}

// analyzeBatch analyzes a single batch of findings.
func (a *Agent) analyzeBatch(ctx context.Context, findings []types.Finding) ([]types.Patch, error) {
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

	// Strip markdown code blocks
	response = strings.TrimPrefix(response, "```json")
	response = strings.TrimPrefix(response, "```")
	response = strings.TrimSuffix(response, "```")
	response = strings.TrimSpace(response)

	if idx := strings.Index(response, "["); idx >= 0 {
		end := strings.LastIndex(response, "]")
		if end > idx {
			response = response[idx : end+1]
		}
	}

	// Fix common JSON issues from AI responses
	response = fixJSONEscaping(response)

	var patches []types.Patch
	if err := json.Unmarshal([]byte(response), &patches); err != nil {
		// Try to salvage by fixing common issues
		cleaned := strings.ReplaceAll(response, "\t", "\\t")
		cleaned = strings.ReplaceAll(cleaned, "\r", "")
		if err2 := json.Unmarshal([]byte(cleaned), &patches); err2 != nil {
			return nil, fmt.Errorf("parse AI response: %w (original: %w)", err2, err)
		}
	}

	return patches, nil
}

// fixJSONEscaping handles common escape character issues in AI-generated JSON.
func fixJSONEscaping(s string) string {
	// Fix unescaped control characters inside JSON strings
	var result strings.Builder
	inString := false
	escaped := false

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if escaped {
			result.WriteByte(ch)
			escaped = false
			continue
		}
		if ch == '\\' && inString {
			// Check for invalid escape sequences
			if i+1 < len(s) {
				next := s[i+1]
				validEscapes := `"\/bfnrtu`
				if strings.ContainsRune(validEscapes, rune(next)) {
					result.WriteByte(ch)
					escaped = true
					continue
				}
				// Invalid escape - double the backslash
				result.WriteString("\\\\")
				continue
			}
			result.WriteByte(ch)
			continue
		}
		if ch == '"' && !escaped {
			inString = !inString
		}
		// Replace raw control characters inside strings
		if inString && ch < 0x20 && ch != '\n' {
			result.WriteString(fmt.Sprintf("\\u%04x", ch))
			continue
		}
		result.WriteByte(ch)
	}
	return result.String()
}
