package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// ClaudeCode implements the Provider interface using the Claude Code CLI.
// This leverages Claude Max subscription (unlimited usage, no API key needed).
type ClaudeCode struct {
	model      string
	binaryPath string
	timeout    time.Duration
}

// NewClaudeCode creates a new Claude Code provider.
func NewClaudeCode(model string) *ClaudeCode {
	if model == "" {
		model = "sonnet" // Claude Code default
	}

	// Find claude binary
	binaryPath := "claude"
	if path, err := exec.LookPath("claude"); err == nil {
		binaryPath = path
	}

	return &ClaudeCode{
		model:      model,
		binaryPath: binaryPath,
		timeout:    600 * time.Second,
	}
}

func (c *ClaudeCode) Name() string { return "claude-code" }

func (c *ClaudeCode) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	// Build the prompt from messages
	prompt := c.buildPrompt(req)

	// Build command args
	args := []string{
		"--print",                                    // Non-interactive, full output
		"--permission-mode", "bypassPermissions",     // No permission prompts
		"--output-format", "json",                    // Structured JSON output
		"--max-turns", "1",                           // Single turn only
		"--tools", "",                                // Disable all tools, pure reasoning
		"--model", c.model,                           // Model selection
	}

	// Add system prompt if provided
	if req.SystemPrompt != "" {
		args = append(args, "--system-prompt", req.SystemPrompt)
	}

	// The actual prompt goes last
	args = append(args, prompt)

	// Create a fully independent context for the CLI subprocess.
	// The parent ctx from the engine loop can get canceled during phase
	// transitions, which would kill the claude CLI mid-response.
	// We ONLY use our own timeout as the cancellation mechanism.
	cmdCtx, cancel := context.WithTimeout(context.Background(), c.timeout)
	defer cancel()

	cmd := exec.CommandContext(cmdCtx, c.binaryPath, args...)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	start := time.Now()
	err := cmd.Run()
	elapsed := time.Since(start)

	if err != nil {
		// Check if it's our timeout
		if cmdCtx.Err() == context.DeadlineExceeded {
			return nil, fmt.Errorf("claude-code timeout after %s (elapsed: %s)", c.timeout, elapsed)
		}
		// Try to extract useful error from stderr
		errMsg := strings.TrimSpace(stderr.String())
		if errMsg == "" {
			errMsg = err.Error()
		}
		return nil, fmt.Errorf("claude-code error (after %s): %s", elapsed, errMsg)
	}

	// Parse JSON output
	content, err := c.parseOutput(stdout.Bytes())
	if err != nil {
		// Fallback: treat entire stdout as plain text response
		content = strings.TrimSpace(stdout.String())
		if content == "" {
			return nil, fmt.Errorf("claude-code returned empty response")
		}
	}

	// Estimate tokens (claude CLI doesn't report exact usage)
	inputTokens := estimateTokens(prompt)
	outputTokens := estimateTokens(content)

	_ = elapsed // Could log latency if needed

	return &ChatResponse{
		Content: content,
		Model:   "claude-code/" + c.model,
		Usage: Usage{
			InputTokens:  inputTokens,
			OutputTokens: outputTokens,
		},
	}, nil
}

// buildPrompt constructs a single prompt from the message history.
func (c *ClaudeCode) buildPrompt(req ChatRequest) string {
	if len(req.Messages) == 1 {
		return req.Messages[0].Content
	}

	var sb strings.Builder
	for _, msg := range req.Messages {
		switch msg.Role {
		case "user":
			sb.WriteString(msg.Content)
			sb.WriteString("\n\n")
		case "assistant":
			sb.WriteString("[Previous AI response]\n")
			sb.WriteString(msg.Content)
			sb.WriteString("\n\n")
		}
	}
	return strings.TrimSpace(sb.String())
}

// parseOutput extracts the text content from Claude Code JSON output.
func (c *ClaudeCode) parseOutput(data []byte) (string, error) {
	// Claude Code --output-format json returns:
	// {"type":"result","result":"...","usage":{...},...}
	var result struct {
		Type    string `json:"type"`
		Result  string `json:"result"`
		IsError bool   `json:"is_error"`
		Usage   struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(data, &result); err == nil {
		if result.Result != "" {
			return result.Result, nil
		}
	}

	// Fallback: try as array of conversation messages
	var turns []struct {
		Type    string `json:"type"`
		Role    string `json:"role"`
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Text string `json:"text"`
	}

	if err := json.Unmarshal(data, &turns); err == nil {
		for i := len(turns) - 1; i >= 0; i-- {
			turn := turns[i]
			if turn.Role == "assistant" {
				for _, c := range turn.Content {
					if c.Type == "text" && c.Text != "" {
						return c.Text, nil
					}
				}
			}
			if turn.Text != "" {
				return turn.Text, nil
			}
		}
	}

	return "", fmt.Errorf("could not parse claude-code output")
}

// estimateTokens gives a rough token count (1 token ≈ 4 chars for English).
func estimateTokens(text string) int {
	return len(text) / 4
}
