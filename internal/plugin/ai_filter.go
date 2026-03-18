package plugin

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/borntobeyours/ouroboros/internal/ai"
	"github.com/borntobeyours/ouroboros/pkg/types"
)

// AIFilter selects relevant templates via a single AI call, with an in-memory
// cache keyed on the sorted set of detected technology names.
type AIFilter struct {
	mu    sync.Mutex
	cache map[string][]*PluginProber
}

// NewAIFilter creates a new AIFilter with an empty cache.
func NewAIFilter() *AIFilter {
	return &AIFilter{cache: make(map[string][]*PluginProber)}
}

// Filter returns the subset of probers relevant to the detected tech stack.
//
// Strategy:
//  1. Check cache — return immediately on hit.
//  2. Send a single AI call: tech stack + all template filenames → relevant filenames.
//  3. Map the AI response back to probers.
//  4. If the AI call fails, times out, or returns <5 results, fall back to
//     tag-based filtering.
//  5. Cache the result before returning.
func (f *AIFilter) Filter(ctx context.Context, provider ai.Provider, ps []*PluginProber, techs []types.TechFingerprint) []*PluginProber {
	if len(techs) == 0 {
		return FilterByTechnology(ps, techs)
	}

	cacheKey := cacheKeyFor(techs)

	f.mu.Lock()
	if cached, ok := f.cache[cacheKey]; ok {
		f.mu.Unlock()
		return cached
	}
	f.mu.Unlock()

	// Build tech description.
	techParts := make([]string, 0, len(techs))
	for _, t := range techs {
		s := t.Name
		if t.Version != "" {
			s += " " + t.Version
		}
		techParts = append(techParts, s)
	}
	techDesc := strings.Join(techParts, ", ")

	// Collect all template filenames.
	filenames := make([]string, 0, len(ps))
	for _, p := range ps {
		filenames = append(filenames, p.filename)
	}

	prompt := fmt.Sprintf(
		"Given target tech stack: [%s].\n\n"+
			"Which of these %d security templates are relevant?\n"+
			"Return ONLY the filenames, one per line, with no other text:\n\n%s",
		techDesc, len(filenames), strings.Join(filenames, "\n"),
	)

	// Hard cap: AI selection must finish within 30 s.
	aiCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	result := f.fallback(ps, techs) // prepare fallback early

	resp, err := provider.Chat(aiCtx, ai.ChatRequest{
		Messages:    []ai.Message{{Role: "user", Content: prompt}},
		MaxTokens:   2048,
		Temperature: 0,
	})
	if err != nil {
		// AI unavailable — use tag-based fallback.
		f.store(cacheKey, result)
		return result
	}

	// Parse AI response: one filename per line.
	selected := make(map[string]bool)
	for _, line := range strings.Split(resp.Content, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			selected[line] = true
		}
	}

	// Map back to probers.
	var aiResult []*PluginProber
	for _, p := range ps {
		if selected[p.filename] {
			aiResult = append(aiResult, p)
		}
	}

	// Sanity check: if AI returned < 5 filenames, the response is probably
	// malformed — fall back to tag-based filtering.
	if len(aiResult) < 5 {
		f.store(cacheKey, result)
		return result
	}

	f.store(cacheKey, aiResult)
	return aiResult
}

func (f *AIFilter) fallback(ps []*PluginProber, techs []types.TechFingerprint) []*PluginProber {
	return FilterByTechnology(ps, techs)
}

func (f *AIFilter) store(key string, ps []*PluginProber) {
	f.mu.Lock()
	f.cache[key] = ps
	f.mu.Unlock()
}

// cacheKeyFor builds a stable, sorted cache key from a tech fingerprint slice.
func cacheKeyFor(techs []types.TechFingerprint) string {
	names := make([]string, len(techs))
	for i, t := range techs {
		names[i] = strings.ToLower(t.Name)
	}
	sort.Strings(names)
	return strings.Join(names, ",")
}
