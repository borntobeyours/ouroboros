package red

import (
	"context"
	"fmt"
	"log"

	"github.com/borntobeyours/ouroboros/internal/ai"
	"github.com/borntobeyours/ouroboros/internal/target"
	"github.com/borntobeyours/ouroboros/pkg/types"
)

// Scanner uses AI to analyze endpoints for vulnerabilities.
type Scanner struct {
	provider ai.Provider
	logger   *log.Logger
}

// NewScanner creates a new AI-powered vulnerability scanner.
func NewScanner(provider ai.Provider, logger *log.Logger) *Scanner {
	return &Scanner{
		provider: provider,
		logger:   logger,
	}
}

// Scan analyzes discovered URLs for vulnerabilities using AI.
func (s *Scanner) Scan(ctx context.Context, t types.Target, urls []string, previousFindings []types.Finding, patches []types.Patch, loop int) ([]types.Finding, error) {
	// Discover endpoint metadata
	endpoints := target.DiscoverEndpoints(urls, t.Headers)
	s.logger.Printf("[SCANNER] Probed %d endpoints", len(endpoints))

	// Build AI prompt
	systemPrompt := BuildAttackPrompt()
	userPrompt := BuildUserPrompt(t, urls, endpoints, previousFindings, patches)

	// Call AI provider
	resp, err := s.provider.Chat(ctx, ai.ChatRequest{
		Messages: []ai.Message{
			{Role: "user", Content: userPrompt},
		},
		SystemPrompt: systemPrompt,
		MaxTokens:    4096,
		Temperature:  0.7,
	})
	if err != nil {
		return nil, fmt.Errorf("AI scan failed: %w", err)
	}

	// Parse findings from AI response
	findings, err := ParseFindings(resp.Content, loop)
	if err != nil {
		s.logger.Printf("[SCANNER] Warning: could not parse AI response: %v", err)
		return []types.Finding{}, nil
	}

	return findings, nil
}
