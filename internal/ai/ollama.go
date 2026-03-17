package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// Ollama implements the Provider interface for local Ollama models.
type Ollama struct {
	model   string
	baseURL string
	client  *http.Client
}

func NewOllama(model, baseURL string) *Ollama {
	if model == "" {
		model = "llama3"
	}
	if baseURL == "" {
		baseURL = "http://localhost:11434"
	}
	return &Ollama{
		model:   model,
		baseURL: baseURL,
		client:  &http.Client{},
	}
}

func (o *Ollama) Name() string { return "ollama" }

func (o *Ollama) Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error) {
	model := req.Model
	if model == "" {
		model = o.model
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
		"model":    model,
		"messages": messages,
		"stream":   false,
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request: %w", err)
	}

	url := o.baseURL + "/api/chat"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

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
		return nil, fmt.Errorf("ollama API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var apiResp struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Model string `json:"model"`
	}
	if err := json.Unmarshal(respBody, &apiResp); err != nil {
		return nil, fmt.Errorf("unmarshal response: %w", err)
	}

	return &ChatResponse{
		Content: apiResp.Message.Content,
		Model:   apiResp.Model,
	}, nil
}
