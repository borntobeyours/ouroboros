package red

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/borntobeyours/ouroboros/internal/ai"
	"github.com/borntobeyours/ouroboros/internal/auth"
	"github.com/borntobeyours/ouroboros/internal/red/probers"
	target_pkg "github.com/borntobeyours/ouroboros/internal/target"
	"github.com/borntobeyours/ouroboros/pkg/types"
)

// Agent is the Red AI attacker agent.
type Agent struct {
	provider      ai.Provider
	crawler       *Crawler
	scanner       *Scanner
	exploiter     *Exploiter
	activeExploit *ActiveExploiter
	logger        *log.Logger
	lastEndpoints []types.Endpoint // cached from last crawl
}

// NewAgent creates a new Red AI agent.
func NewAgent(provider ai.Provider, logger *log.Logger) *Agent {
	return &Agent{
		provider:      provider,
		crawler:       NewCrawler(logger),
		scanner:       NewScanner(provider, logger),
		exploiter:     NewExploiter(logger),
		activeExploit: NewActiveExploiter(provider, logger),
		logger:        logger,
	}
}

// SetAuth configures the auth session on the crawler and global probers.
func (a *Agent) SetAuth(s *auth.AuthSession) {
	a.crawler.SetAuth(s)
	probers.SetAuthSession(s)
}

// Attack performs a full attack cycle against the target.
func (a *Agent) Attack(ctx context.Context, target types.Target, previousFindings []types.Finding, patches []types.Patch, loop int) ([]types.Finding, error) {
	a.logger.Printf("[RED] Starting attack loop %d against %s", loop, target.URL)

	// Phase 1: Crawl and discover endpoints
	a.logger.Printf("[RED] Phase 1: Crawling target...")
	urls, err := a.crawler.Crawl(ctx, target.URL)
	if err != nil {
		return nil, fmt.Errorf("crawl target: %w", err)
	}
	a.logger.Printf("[RED] Discovered %d URLs", len(urls))

	// Get endpoint context
	endpoints := target_pkg.DiscoverEndpoints(urls, target.Headers)
	a.lastEndpoints = endpoints

	// Phase 1.5: Classify discovered endpoints
	a.logger.Printf("[RED] Classifying %d endpoints...", len(endpoints))
	classified := ClassifyEndpoints(endpoints)
	a.logger.Printf("[RED] Classification: %d login, %d API, %d search, %d admin, %d upload, %d redirect, %d user-data",
		len(classified.Login), len(classified.API), len(classified.Search),
		len(classified.Admin), len(classified.FileUpload), len(classified.Redirect),
		len(classified.UserData))

	// Phase 2: Technique-specific active probers
	a.logger.Printf("[RED] Phase 2: Running technique-specific probers...")

	// On first loop, try to authenticate for deeper scanning (skip if session already set)
	proberTarget := target
	if loop == 1 && probers.GetAuthSession() == nil {
		a.logger.Printf("[RED] Attempting authentication...")
		token, err := probers.AttemptAuth(target.URL, classified)
		if err != nil {
			a.logger.Printf("[RED] Auth attempt failed (will scan unauthenticated): %v", err)
		} else {
			a.logger.Printf("[RED] Authentication successful, enabling authenticated scanning")
			if proberTarget.Headers == nil {
				proberTarget.Headers = make(map[string]string)
			}
			proberTarget.Headers["Authorization"] = token
		}
	}

	proberFindings := probers.RunAllProbersWithClassified(ctx, proberTarget, endpoints, classified, loop)
	a.logger.Printf("[RED] Probers found %d findings", len(proberFindings))

	// Phase 3: AI-powered vulnerability analysis (supplements probers)
	a.logger.Printf("[RED] Phase 3: AI-powered vulnerability scanning...")
	aiFindings, err := a.scanner.Scan(ctx, target, urls, previousFindings, patches, loop)
	if err != nil {
		a.logger.Printf("[RED] AI scan error (continuing with prober results): %v", err)
		aiFindings = nil
	}
	a.logger.Printf("[RED] AI found %d potential vulnerabilities", len(aiFindings))

	// Combine prober findings (already confirmed) with AI findings
	var allFindings []types.Finding
	allFindings = append(allFindings, proberFindings...)

	if len(aiFindings) > 0 {
		// Phase 4: AI-guided active exploitation of AI-discovered findings
		a.logger.Printf("[RED] Phase 4: AI-guided active exploitation (%d AI targets)...", len(aiFindings))
		activeResults := a.activeExploit.ExploitAll(ctx, aiFindings, target, endpoints)

		for i, f := range aiFindings {
			if i < len(activeResults) && activeResults[i].Exploited {
				f.Confirmed = true
				f.ExploitEvidence = activeResults[i].Evidence
				f.ExfiltratedData = activeResults[i].DataExfiled
				if activeResults[i].SevUpgrade != "" {
					upgraded, _ := types.ParseSeverity(activeResults[i].SevUpgrade)
					if upgraded > f.Severity {
						f.Severity = upgraded
					}
				}
				if activeResults[i].Chain != "" {
					f.ExploitEvidence += " [" + activeResults[i].Chain + "]"
				}
			}
			allFindings = append(allFindings, f)
		}

		exploitedCount := 0
		for _, r := range activeResults {
			if r.Exploited {
				exploitedCount++
			}
		}
		a.logger.Printf("[RED] Exploitation complete: %d/%d AI findings confirmed", exploitedCount, len(aiFindings))
	}

	// Phase 5: SPA false positive filtering
	if len(allFindings) > 0 {
		baseFP := fingerprint(target.URL)
		if baseFP != "" {
			filtered := make([]types.Finding, 0, len(allFindings))
			for _, f := range allFindings {
				epURL := f.Endpoint
				if !strings.HasPrefix(epURL, "http") {
					epURL = strings.TrimRight(target.URL, "/") + f.Endpoint
				}
				shouldCheck := strings.Contains(f.Endpoint, ".env") ||
					strings.Contains(f.Endpoint, ".git") ||
					strings.Contains(f.Endpoint, "/admin") ||
					strings.Contains(f.Endpoint, "/backup") ||
					strings.Contains(f.Endpoint, "/dump")
				if shouldCheck && fingerprint(epURL) == baseFP {
					a.logger.Printf("[RED] Filtered SPA false positive: %s (%s)", f.Title, f.Endpoint)
					continue
				}
				filtered = append(filtered, f)
			}
			allFindings = filtered
		}
	}

	// Phase 6: Deduplicate findings (probers + AI may find the same vuln)
	beforeDedup := len(allFindings)
	allFindings = types.DeduplicateFindings(allFindings)
	if beforeDedup > len(allFindings) {
		a.logger.Printf("[RED] Dedup: removed %d duplicate findings (%d → %d)", beforeDedup-len(allFindings), beforeDedup, len(allFindings))
	}

	// Phase 7: Confidence scoring and severity adjustment
	ScoreConfidence(allFindings)
	proven, high, medium, low := 0, 0, 0, 0
	for _, f := range allFindings {
		switch {
		case f.Confidence >= 95:
			proven++
		case f.Confidence >= 75:
			high++
		case f.Confidence >= 50:
			medium++
		default:
			low++
		}
	}
	a.logger.Printf("[RED] Confidence: %d proven, %d high, %d medium, %d low", proven, high, medium, low)

	a.logger.Printf("[RED] Total findings this loop: %d", len(allFindings))
	return allFindings, nil
}

// fingerprint returns a hash of the response body for dedup/SPA detection.
func fingerprint(url string) string {
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(r *http.Request, via []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	h := sha256.Sum256(body)
	return fmt.Sprintf("%x", h[:8])
}

// BuildAttackPrompt creates the Red AI system prompt.
func BuildAttackPrompt() string {
	return `You are an expert penetration tester and security researcher conducting an authorized security assessment.
Your approach should be methodical, thorough, and creative - think like a real attacker.

METHODOLOGY:
1. Analyze the target's technology stack, endpoints, and response patterns
2. Identify potential attack surfaces (input fields, parameters, headers, cookies)
3. Test for OWASP Top 10 vulnerabilities systematically
4. Look for logic flaws, authentication bypasses, and authorization issues
5. Consider chained attacks where multiple low-severity issues combine into high-severity ones

ATTACK TECHNIQUES TO CONSIDER:
- SQL Injection (error-based, blind, time-based, UNION-based)
- Cross-Site Scripting (reflected, stored, DOM-based)
- Server-Side Request Forgery (SSRF)
- Insecure Direct Object References (IDOR)
- Authentication/Authorization bypass
- Command Injection (OS command, code injection)
- Path Traversal / Local File Inclusion
- XML External Entity (XXE)
- Cross-Site Request Forgery (CSRF)
- Security Misconfigurations (headers, CORS, verbose errors)
- Sensitive Data Exposure (information leakage, debug endpoints)
- Broken Access Control

For each vulnerability found, provide:
- A clear title
- Severity (Critical, High, Medium, Low, Info)
- Detailed description of the vulnerability
- The specific endpoint and HTTP method affected
- A proof-of-concept (PoC) showing how to exploit it
- The relevant CWE identifier
- Evidence from the response that confirms the vulnerability

OUTPUT FORMAT: Return ONLY a JSON array of findings. Each finding must have these fields:
{
  "title": "string",
  "severity": "Critical|High|Medium|Low|Info",
  "description": "string",
  "endpoint": "string",
  "method": "GET|POST|PUT|DELETE|PATCH",
  "cwe": "CWE-XXX",
  "poc": "string",
  "evidence": "string",
  "technique": "sqli|xss|ssrf|idor|auth_bypass|command_injection|path_traversal|xxe|csrf|misconfig|info_leak"
}

If no vulnerabilities are found, return an empty array: []
Do NOT include any text outside the JSON array.`
}

// BuildUserPrompt creates the per-request user prompt with context.
func BuildUserPrompt(target types.Target, urls []string, endpoints []types.Endpoint, previousFindings []types.Finding, patches []types.Patch) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("TARGET: %s\n\n", target.URL))

	sb.WriteString(fmt.Sprintf("DISCOVERED ENDPOINTS (%d total):\n", len(endpoints)))
	for _, ep := range endpoints {
		sb.WriteString(fmt.Sprintf("\n--- [%s] %s (status: %d, type: %s) ---\n", ep.Method, ep.URL, ep.StatusCode, ep.ContentType))
		if len(ep.Parameters) > 0 {
			sb.WriteString(fmt.Sprintf("  Parameters: %s\n", strings.Join(ep.Parameters, ", ")))
		}
		if len(ep.ResponseHeaders) > 0 {
			sb.WriteString("  Security Headers:\n")
			for k, v := range ep.ResponseHeaders {
				sb.WriteString(fmt.Sprintf("    %s: %s\n", k, v))
			}
		}
		if ep.Body != "" && (strings.Contains(ep.ContentType, "json") || strings.Contains(ep.ContentType, "xml") || ep.StatusCode >= 400) {
			body := ep.Body
			if len(body) > 1000 {
				body = body[:1000] + "...[truncated]"
			}
			sb.WriteString(fmt.Sprintf("  Response Body:\n  %s\n", body))
		}
	}
	sb.WriteString("\n")

	if len(previousFindings) > 0 {
		sb.WriteString("PREVIOUSLY FOUND VULNERABILITIES (find NEW ones or bypasses):\n")
		for _, f := range previousFindings {
			sb.WriteString(fmt.Sprintf("- [%s] %s at %s (%s)\n", f.Severity, f.Title, f.Endpoint, f.Technique))
		}
		sb.WriteString("\n")
	}

	if len(patches) > 0 {
		sb.WriteString("PATCHES APPLIED BY BLUE TEAM (try to bypass these):\n")
		for _, p := range patches {
			sb.WriteString(fmt.Sprintf("- Finding %s: %s\n", p.FindingID, p.Description))
			if p.Code != "" {
				sb.WriteString(fmt.Sprintf("  Patch code: %s\n", p.Code))
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString("INSTRUCTIONS:\n")
	if len(previousFindings) > 0 {
		sb.WriteString("- Focus on finding NEW vulnerabilities not previously discovered\n")
		sb.WriteString("- Try to BYPASS the patches applied by the Blue team\n")
		sb.WriteString("- Think creatively about alternative attack vectors\n")
	} else {
		sb.WriteString("- Perform a comprehensive initial security assessment\n")
		sb.WriteString("- Test all discovered endpoints for OWASP Top 10 vulnerabilities\n")
	}

	return sb.String()
}

// ParseFindings parses the AI response into findings.
func ParseFindings(response string, loop int) ([]types.Finding, error) {
	response = strings.TrimSpace(response)
	if idx := strings.Index(response, "["); idx >= 0 {
		end := strings.LastIndex(response, "]")
		if end > idx {
			response = response[idx : end+1]
		}
	}

	var rawFindings []struct {
		Title       string `json:"title"`
		Severity    string `json:"severity"`
		Description string `json:"description"`
		Endpoint    string `json:"endpoint"`
		Method      string `json:"method"`
		CWE         string `json:"cwe"`
		PoC         string `json:"poc"`
		Evidence    string `json:"evidence"`
		Technique   string `json:"technique"`
	}

	if err := json.Unmarshal([]byte(response), &rawFindings); err != nil {
		return nil, fmt.Errorf("parse AI response: %w", err)
	}

	findings := make([]types.Finding, 0, len(rawFindings))
	for _, rf := range rawFindings {
		sev, _ := types.ParseSeverity(rf.Severity)
		f := types.Finding{
			Title:       rf.Title,
			Description: rf.Description,
			Severity:    sev,
			Endpoint:    rf.Endpoint,
			Method:      rf.Method,
			CWE:         rf.CWE,
			PoC:         rf.PoC,
			Evidence:    rf.Evidence,
			Technique:   rf.Technique,
			FoundAt:     time.Now(),
			Loop:        loop,
		}
		f.ID = f.Signature()
		findings = append(findings, f)
	}

	return findings, nil
}
