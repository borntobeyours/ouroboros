package ai

import "context"

// Message represents a chat message.
type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// ChatRequest holds a request to the AI provider.
type ChatRequest struct {
	Messages    []Message `json:"messages"`
	Model       string    `json:"model,omitempty"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
	Temperature float64   `json:"temperature,omitempty"`
	SystemPrompt string   `json:"-"`
}

// ChatResponse holds the AI provider's response.
type ChatResponse struct {
	Content string `json:"content"`
	Model   string `json:"model"`
	Usage   Usage  `json:"usage"`
}

// Usage tracks token usage.
type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

// Provider is the interface for AI backends.
type Provider interface {
	// Name returns the provider name.
	Name() string
	// Chat sends a chat request and returns the response.
	Chat(ctx context.Context, req ChatRequest) (*ChatResponse, error)
}

// NewProvider creates a provider by name.
func NewProvider(name, model, apiKey string) (Provider, error) {
	switch name {
	case "anthropic":
		return NewAnthropic(apiKey, model), nil
	case "openai":
		return NewOpenAI(apiKey, model), nil
	case "ollama":
		return NewOllama(model, "http://localhost:11434"), nil
	case "claude-code", "claudecode", "claude":
		return NewClaudeCode(model), nil
	case "openrouter":
		return NewOpenRouter(apiKey, model), nil
	default:
		return NewAnthropic(apiKey, model), nil
	}
}
