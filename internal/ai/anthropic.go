package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const anthropicAPIURL = "https://api.anthropic.com/v1/messages"

// Anthropic implements the Provider interface for Claude.
type Anthropic struct {
	apiKey string
	model  string
	client *http.Client
}

func NewAnthropic(apiKey, model string) *Anthropic {
	if model == "" {
		model = "claude-sonnet-4-20250514"
	}
	return &Anthropic{
		apiKey: apiKey,
		model:  model,
		client: &http.Client{},
	}
}

func (a *Anthropic) Name() string { return "anthropic" }

func (a *Anthropic) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	model := req.Model
	if model == "" {
		model = a.model
	}
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	// Build Anthropic API request
	messages := make([]map[string]string, 0, len(req.Messages))
	for _, m := range req.Messages {
		messages = append(messages, map[string]string{
			"role":    m.Role,
			"content": m.Content,
		})
	}

	body := map[string]interface{}{
		"model":      model,
		"max_tokens": maxTokens,
		"messages":   messages,
	}
	if req.SystemPrompt != "" {
		body["system"] = req.SystemPrompt
	}
	if req.Temperature > 0 {
		body["temperature"] = req.Temperature
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicAPIURL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("x-api-key", a.apiKey)
	httpReq.Header.Set("anthropic-version", "2023-06-01")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anthropic API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var apiResp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		Model string `json:"model"`
		Usage struct {
			InputTokens  int `json:"input_tokens"`
			OutputTokens int `json:"output_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	content := ""
	if len(apiResp.Content) > 0 {
		content = apiResp.Content[0].Text
	}

	return &ChatResponse{
		Content: content,
		Model:   apiResp.Model,
		Usage: Usage{
			InputTokens:  apiResp.Usage.InputTokens,
			OutputTokens: apiResp.Usage.OutputTokens,
		},
	}, nil
}
