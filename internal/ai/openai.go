package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const openaiAPIURL = "https://api.openai.com/v1/chat/completions"

// OpenAI implements the Provider interface for OpenAI models.
type OpenAI struct {
	apiKey string
	model  string
	client *http.Client
}

func NewOpenAI(apiKey, model string) *OpenAI {
	if model == "" {
		model = "gpt-4o"
	}
	return &OpenAI{
		apiKey: apiKey,
		model:  model,
		client: &http.Client{},
	}
}

func (o *OpenAI) Name() string { return "openai" }

func (o *OpenAI) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	model := req.Model
	if model == "" {
		model = o.model
	}
	maxTokens := req.MaxTokens
	if maxTokens == 0 {
		maxTokens = 4096
	}

	messages := make([]map[string]string, 0, len(req.Messages)+1)
	if req.SystemPrompt != "" {
		messages = append(messages, map[string]string{
			"role":    "system",
			"content": req.SystemPrompt,
		})
	}
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
	if req.Temperature > 0 {
		body["temperature"] = req.Temperature
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, openaiAPIURL, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+o.apiKey)

	resp, err := o.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("send request: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("openai API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var apiResp struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Model string `json:"model"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	content := ""
	if len(apiResp.Choices) > 0 {
		content = apiResp.Choices[0].Message.Content
	}

	return &ChatResponse{
		Content: content,
		Model:   apiResp.Model,
		Usage: Usage{
			InputTokens:  apiResp.Usage.PromptTokens,
			OutputTokens: apiResp.Usage.CompletionTokens,
		},
	}, nil
}
