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

	const batchSize = 20
	const maxConcurrent = 2

	// Small set: single call
	if len(urls) <= batchSize {
		return s.scanBatch(ctx, t, urls, endpoints, previousFindings, patches, loop)
	}

	// Large set: batch URLs into concurrent chunks
	var batches [][]string
	for i := 0; i < len(urls); i += batchSize {
		end := i + batchSize
		if end > len(urls) {
			end = len(urls)
		}
		batches = append(batches, urls[i:end])
	}

	s.logger.Printf("[SCANNER] Scanning %d URLs in %d batches (max %d parallel)", len(urls), len(batches), maxConcurrent)

	type batchResult struct {
		findings []types.Finding
		err      error
		idx      int
	}

	results := make(chan batchResult, len(batches))
	sem := make(chan struct{}, maxConcurrent)

	for i, batch := range batches {
		sem <- struct{}{}
		go func(idx int, batchURLs []string) {
			defer func() { <-sem }()
			batchEndpoints := target.DiscoverEndpoints(batchURLs, t.Headers)
			s.logger.Printf("[SCANNER] Batch %d/%d started (%d URLs)...", idx+1, len(batches), len(batchURLs))
			findings, err := s.scanBatch(ctx, t, batchURLs, batchEndpoints, previousFindings, patches, loop)
			if err != nil {
				s.logger.Printf("[SCANNER] Batch %d failed: %v", idx+1, err)
			} else {
				s.logger.Printf("[SCANNER] Batch %d done: %d findings", idx+1, len(findings))
			}
			results <- batchResult{findings: findings, err: err, idx: idx}
		}(i, batch)
	}

	var allFindings []types.Finding
	succeeded := 0
	for range batches {
		r := <-results
		if r.err == nil {
			allFindings = append(allFindings, r.findings...)
			succeeded++
		}
	}

	s.logger.Printf("[SCANNER] Total: %d findings from %d/%d batches", len(allFindings), succeeded, len(batches))
	return allFindings, nil
}

func (s *Scanner) scanBatch(ctx context.Context, t types.Target, urls []string, endpoints []types.Endpoint, previousFindings []types.Finding, patches []types.Patch, loop int) ([]types.Finding, error) {
	systemPrompt := BuildAttackPrompt()
	userPrompt := BuildUserPrompt(t, urls, endpoints, previousFindings, patches)

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

	findings, err := ParseFindings(resp.Content, loop)
	if err != nil {
		s.logger.Printf("[SCANNER] Warning: could not parse AI response: %v", err)
		return []types.Finding{}, nil
	}

	return findings, nil
}
