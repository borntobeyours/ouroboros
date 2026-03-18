// Package integrations provides third-party platform integrations.
package integrations

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/borntobeyours/ouroboros/internal/report"
	"github.com/borntobeyours/ouroboros/pkg/types"
)

// GitHubConfig holds the configuration for GitHub PR integration.
type GitHubConfig struct {
	// Token is the GitHub personal access token. If empty, GITHUB_TOKEN is used.
	Token string
	// Repo is the repository in "owner/repo" format.
	Repo string
	// PRNumber is the pull request (issue) number to comment on.
	PRNumber int
}

// GitHubClient posts scan results as a pull request comment.
type GitHubClient struct {
	cfg    GitHubConfig
	client *http.Client
}

// NewGitHubClient creates a GitHubClient, resolving the token from the environment
// if not set in cfg.
func NewGitHubClient(cfg GitHubConfig) *GitHubClient {
	if cfg.Token == "" {
		cfg.Token = os.Getenv("GITHUB_TOKEN")
	}
	return &GitHubClient{
		cfg:    cfg,
		client: &http.Client{Timeout: 30 * time.Second},
	}
}

// DiffInfo contains optional baseline comparison data for the PR comment.
type DiffInfo struct {
	Fixed      int
	New        int
	Persistent int
}

// PostPRComment posts a formatted scan summary as a comment on the configured PR.
// diff may be nil if no baseline comparison was performed.
func (g *GitHubClient) PostPRComment(
	findings []types.Finding,
	session *types.ScanSession,
	threshold types.Severity,
	failCount int,
	diff *DiffInfo,
) error {
	if g.cfg.Token == "" {
		return fmt.Errorf("GitHub token not set: provide --github-token or set GITHUB_TOKEN")
	}
	parts := strings.SplitN(g.cfg.Repo, "/", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return fmt.Errorf("invalid GitHub repo %q: expected owner/repo", g.cfg.Repo)
	}

	body := g.formatComment(findings, session, threshold, failCount, diff)

	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/issues/%d/comments",
		parts[0], parts[1], g.cfg.PRNumber)

	payload, err := json.Marshal(map[string]string{"body": body})
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+g.cfg.Token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")

	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("GitHub API returned HTTP %d", resp.StatusCode)
	}
	return nil
}

// formatComment builds the markdown body for the PR comment.
func (g *GitHubClient) formatComment(
	findings []types.Finding,
	session *types.ScanSession,
	threshold types.Severity,
	failCount int,
	diff *DiffInfo,
) string {
	var sb strings.Builder

	// Header
	sb.WriteString("## Ouroboros Security Scan\n\n")
	sb.WriteString(fmt.Sprintf("**Target:** `%s`  \n", session.Config.Target.URL))
	sb.WriteString(fmt.Sprintf("**Session:** `%s`  \n", session.ID[:8]))
	sb.WriteString(fmt.Sprintf("**Scanned:** %s  \n\n", session.StartedAt.Format("2006-01-02 15:04 UTC")))

	// Pass / fail badge
	if failCount > 0 {
		sb.WriteString(fmt.Sprintf("> **❌ FAILED** — %d finding(s) at **%s** severity or above\n\n", failCount, threshold))
	} else {
		sb.WriteString("> **✅ PASSED** — no findings at or above threshold\n\n")
	}

	// Diff summary (only when baseline was used)
	if diff != nil {
		sb.WriteString("### Diff vs Baseline\n\n")
		sb.WriteString(fmt.Sprintf("| Fixed | Persistent | New |\n|-------|-----------|-----|\n| %d | %d | %d |\n\n",
			diff.Fixed, diff.Persistent, diff.New))
	}

	// Severity breakdown
	counts := map[types.Severity]int{}
	for _, f := range findings {
		sev := f.AdjustedSeverity
		if sev == 0 {
			sev = f.Severity
		}
		counts[sev]++
	}

	sb.WriteString("### Severity Summary\n\n")
	sb.WriteString("| Severity | Count |\n|----------|-------|\n")
	for _, sev := range []types.Severity{
		types.SeverityCritical, types.SeverityHigh,
		types.SeverityMedium, types.SeverityLow, types.SeverityInfo,
	} {
		if n := counts[sev]; n > 0 {
			badge := severityBadge(sev)
			sb.WriteString(fmt.Sprintf("| %s | %d |\n", badge, n))
		}
	}
	sb.WriteString("\n")

	// Top 5 critical/high findings
	top := topFindings(findings, 5)
	if len(top) > 0 {
		sb.WriteString("### Top Findings\n\n")
		sb.WriteString("| # | Severity | Title | CWE | CVSS | Confidence |\n")
		sb.WriteString("|---|----------|-------|-----|------|------------|\n")
		for i, f := range top {
			sev := f.AdjustedSeverity
			if sev == 0 {
				sev = f.Severity
			}
			cweLink := f.CWE
			if cweNum := extractCWENumber(f.CWE); cweNum != "" {
				cweLink = fmt.Sprintf("[%s](https://cwe.mitre.org/data/definitions/%s.html)", f.CWE, cweNum)
			}
			sb.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %.1f | %d%% |\n",
				i+1, severityBadge(sev), f.Title, cweLink, f.CVSS.Score, f.Confidence))
		}
		sb.WriteString("\n")
	}

	// Full findings list in expandable section
	if len(findings) > 5 {
		sb.WriteString("<details>\n")
		sb.WriteString(fmt.Sprintf("<summary>All findings (%d total)</summary>\n\n", len(findings)))
		sb.WriteString("| # | Severity | Title | Endpoint | CWE | CVSS |\n")
		sb.WriteString("|---|----------|-------|----------|-----|------|\n")
		for i, f := range findings {
			sev := f.AdjustedSeverity
			if sev == 0 {
				sev = f.Severity
			}
			cweLink := f.CWE
			if cweNum := extractCWENumber(f.CWE); cweNum != "" {
				cweLink = fmt.Sprintf("[%s](https://cwe.mitre.org/data/definitions/%s.html)", f.CWE, cweNum)
			}
			ep := f.Endpoint
			if len(ep) > 60 {
				ep = ep[:57] + "..."
			}
			sb.WriteString(fmt.Sprintf("| %d | %s | %s | `%s %s` | %s | %.1f |\n",
				i+1, severityBadge(sev), f.Title, f.Method, ep, cweLink, f.CVSS.Score))
		}
		sb.WriteString("\n</details>\n\n")
	}

	sb.WriteString("---\n")
	sb.WriteString("*Generated by [Ouroboros](https://github.com/borntobeyours/ouroboros)*\n")

	return sb.String()
}

// PostDiffPRComment is a convenience wrapper for CI commands that used a baseline.
func (g *GitHubClient) PostDiffPRComment(
	findings []types.Finding,
	session *types.ScanSession,
	threshold types.Severity,
	failCount int,
	diffResult *report.DiffResult,
) error {
	var di *DiffInfo
	if diffResult != nil {
		di = &DiffInfo{
			Fixed:      len(diffResult.Fixed),
			New:        len(diffResult.New),
			Persistent: len(diffResult.Persistent),
		}
	}
	return g.PostPRComment(findings, session, threshold, failCount, di)
}

// severityBadge returns a simple text label for a severity level.
func severityBadge(sev types.Severity) string {
	switch sev {
	case types.SeverityCritical:
		return "🔴 Critical"
	case types.SeverityHigh:
		return "🟠 High"
	case types.SeverityMedium:
		return "🟡 Medium"
	case types.SeverityLow:
		return "🔵 Low"
	default:
		return "⚪ Info"
	}
}

// topFindings returns up to n critical/high findings, then others up to n total.
func topFindings(findings []types.Finding, n int) []types.Finding {
	var priority, rest []types.Finding
	for _, f := range findings {
		sev := f.AdjustedSeverity
		if sev == 0 {
			sev = f.Severity
		}
		if sev >= types.SeverityHigh {
			priority = append(priority, f)
		} else {
			rest = append(rest, f)
		}
	}
	result := append(priority, rest...)
	if len(result) > n {
		result = result[:n]
	}
	return result
}

// extractCWENumber returns the numeric part of a CWE string, e.g. "89" from "CWE-89".
func extractCWENumber(cwe string) string {
	upper := strings.ToUpper(strings.TrimSpace(cwe))
	if idx := strings.Index(upper, "CWE-"); idx >= 0 {
		num := upper[idx+4:]
		// Trim any trailing non-numeric characters
		end := 0
		for end < len(num) && num[end] >= '0' && num[end] <= '9' {
			end++
		}
		if end > 0 {
			return num[:end]
		}
	}
	return ""
}
