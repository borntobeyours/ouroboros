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
		preview := resp.Content
		if len(preview) > 300 {
			preview = preview[:300] + "..."
		}
		a.logger.Printf("[BLUE] Warning: could not parse AI response: %v (preview: %s)", err, preview)
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

	// Strip markdown code blocks (possibly nested)
	for strings.HasPrefix(response, "```") {
		if strings.HasPrefix(response, "```json") {
			response = strings.TrimPrefix(response, "```json")
		} else {
			response = strings.TrimPrefix(response, "```")
		}
		response = strings.TrimSpace(response)
	}
	for strings.HasSuffix(response, "```") {
		response = strings.TrimSuffix(response, "```")
		response = strings.TrimSpace(response)
	}

	// Extract all JSON arrays from the response and merge them.
	// This handles cases with multiple arrays, text between arrays, etc.
	var allPatches []types.Patch

	arrays := extractJSONArrays(response)
	if len(arrays) > 0 {
		for _, arr := range arrays {
			arr = fixTrailingCommas(arr)
			arr = fixJSONEscaping(arr)
			var patches []types.Patch
			if err := json.Unmarshal([]byte(arr), &patches); err == nil {
				allPatches = append(allPatches, patches...)
			}
		}
		if len(allPatches) > 0 {
			return allPatches, nil
		}
	}

	// Fallback: extract from first [ to last ] in the whole response
	if idx := strings.Index(response, "["); idx >= 0 {
		end := strings.LastIndex(response, "]")
		if end > idx {
			extracted := response[idx : end+1]
			extracted = fixTrailingCommas(extracted)
			extracted = fixJSONEscaping(extracted)
			if err := json.Unmarshal([]byte(extracted), &allPatches); err == nil {
				return allPatches, nil
			}
			// Try tab/carriage return cleanup
			cleaned := strings.ReplaceAll(extracted, "\t", "\\t")
			cleaned = strings.ReplaceAll(cleaned, "\r", "")
			if err := json.Unmarshal([]byte(cleaned), &allPatches); err == nil {
				return allPatches, nil
			}
		}
	}

	// Try wrapping comma-separated objects in an array.
	// Claude sometimes returns {obj1}, {obj2} without the outer [...].
	trimmed := strings.TrimSpace(response)
	if len(trimmed) > 0 && trimmed[0] == '{' {
		wrapped := "[" + trimmed + "]"
		wrapped = fixTrailingCommas(wrapped)
		wrapped = fixJSONEscaping(wrapped)
		if err := json.Unmarshal([]byte(wrapped), &allPatches); err == nil && len(allPatches) > 0 {
			return allPatches, nil
		}
	}

	// Last resort: try json.Decoder for streaming/concatenated JSON objects,
	// stripping commas between top-level values.
	cleaned := stripInterObjectCommas(response)
	dec := json.NewDecoder(strings.NewReader(cleaned))
	for dec.More() {
		var patch types.Patch
		if err := dec.Decode(&patch); err != nil {
			break
		}
		if patch.FindingID != "" {
			allPatches = append(allPatches, patch)
		}
	}
	if len(allPatches) > 0 {
		return allPatches, nil
	}

	return nil, fmt.Errorf("parse AI response: no valid patches found in response (%d chars)", len(response))
}

// extractJSONArrays finds all top-level JSON arrays in a string by bracket matching.
func extractJSONArrays(s string) []string {
	var arrays []string
	i := 0
	for i < len(s) {
		if s[i] == '[' {
			depth := 0
			inStr := false
			esc := false
			for j := i; j < len(s); j++ {
				ch := s[j]
				if esc {
					esc = false
					continue
				}
				if ch == '\\' && inStr {
					esc = true
					continue
				}
				if ch == '"' {
					inStr = !inStr
					continue
				}
				if inStr {
					continue
				}
				if ch == '[' {
					depth++
				} else if ch == ']' {
					depth--
					if depth == 0 {
						arrays = append(arrays, s[i:j+1])
						i = j + 1
						break
					}
				}
				if j == len(s)-1 {
					// Unmatched bracket, skip
					i = j + 1
				}
			}
		} else {
			i++
		}
	}
	return arrays
}

// fixTrailingCommas removes trailing commas before ] and } in JSON.
func fixTrailingCommas(s string) string {
	// Remove ,] and ,} patterns (with optional whitespace between)
	var result strings.Builder
	inStr := false
	esc := false
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if esc {
			result.WriteByte(ch)
			esc = false
			continue
		}
		if ch == '\\' && inStr {
			result.WriteByte(ch)
			esc = true
			continue
		}
		if ch == '"' {
			inStr = !inStr
			result.WriteByte(ch)
			continue
		}
		if inStr {
			result.WriteByte(ch)
			continue
		}
		if ch == ',' {
			// Look ahead past whitespace for ] or }
			j := i + 1
			for j < len(s) && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r') {
				j++
			}
			if j < len(s) && (s[j] == ']' || s[j] == '}') {
				// Skip this trailing comma
				continue
			}
		}
		result.WriteByte(ch)
	}
	return result.String()
}

// stripInterObjectCommas removes commas between top-level JSON objects/arrays.
// Input like `{...}, {...}` or `[...], [...]` becomes `{...} {...}` or `[...] [...]`.
func stripInterObjectCommas(s string) string {
	var result strings.Builder
	inStr := false
	esc := false
	depth := 0

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if esc {
			result.WriteByte(ch)
			esc = false
			continue
		}
		if ch == '\\' && inStr {
			result.WriteByte(ch)
			esc = true
			continue
		}
		if ch == '"' {
			inStr = !inStr
			result.WriteByte(ch)
			continue
		}
		if inStr {
			result.WriteByte(ch)
			continue
		}
		if ch == '{' || ch == '[' {
			depth++
		} else if ch == '}' || ch == ']' {
			depth--
		}
		// Skip commas at depth 0 (between top-level values)
		if ch == ',' && depth == 0 {
			result.WriteByte(' ')
			continue
		}
		result.WriteByte(ch)
	}
	return result.String()
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
