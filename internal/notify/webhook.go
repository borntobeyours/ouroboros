// Package notify sends scan results to external webhook endpoints.
package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// WebhookFormat describes the payload shape sent to the endpoint.
type WebhookFormat string

const (
	FormatJSON    WebhookFormat = "json"
	FormatDiscord WebhookFormat = "discord"
	FormatSlack   WebhookFormat = "slack"
)

// Event names used in WebhookConfig.Events.
const (
	EventScanComplete   = "scan_complete"
	EventFindingCritical = "finding_critical"
	EventScanError      = "scan_error"
)

// WebhookConfig holds configuration for a single webhook destination.
type WebhookConfig struct {
	URL     string
	Headers map[string]string
	// Events that trigger this webhook. Empty means all events.
	Events []string
	Format WebhookFormat
}

// Notifier sends webhook payloads after scan events.
type Notifier struct {
	cfg    WebhookConfig
	client *http.Client
}

// NewNotifier creates a Notifier. Format is auto-detected from URL if not set.
func NewNotifier(cfg WebhookConfig) *Notifier {
	if cfg.Format == "" {
		cfg.Format = autoDetectFormat(cfg.URL)
	}
	return &Notifier{
		cfg: cfg,
		client: &http.Client{
			Timeout: 15 * time.Second,
		},
	}
}

// autoDetectFormat inspects the URL to guess Discord or Slack.
func autoDetectFormat(rawURL string) WebhookFormat {
	lower := strings.ToLower(rawURL)
	if strings.Contains(lower, "discord.com/api/webhooks") {
		return FormatDiscord
	}
	if strings.Contains(lower, "hooks.slack.com") || strings.Contains(lower, "slack.com/services") {
		return FormatSlack
	}
	return FormatJSON
}

// wantsEvent returns true if the notifier is configured to fire for the given event.
func (n *Notifier) wantsEvent(event string) bool {
	if len(n.cfg.Events) == 0 {
		return true
	}
	for _, e := range n.cfg.Events {
		if e == event {
			return true
		}
	}
	return false
}

// NotifyScanComplete fires the scan_complete event and, for each critical
// finding, the finding_critical event.
func (n *Notifier) NotifyScanComplete(session *types.ScanSession, findings []types.Finding) {
	if n.wantsEvent(EventScanComplete) {
		payload := n.buildPayload(EventScanComplete, session, findings, nil)
		_ = n.sendWithRetry(payload)
	}

	if n.wantsEvent(EventFindingCritical) {
		for _, f := range findings {
			sev := f.AdjustedSeverity
			if sev == 0 {
				sev = f.Severity
			}
			if sev >= types.SeverityCritical {
				payload := n.buildPayload(EventFindingCritical, session, nil, &f)
				_ = n.sendWithRetry(payload)
			}
		}
	}
}

// NotifyScanError fires the scan_error event.
func (n *Notifier) NotifyScanError(sessionID, target string, scanErr error) {
	if !n.wantsEvent(EventScanError) {
		return
	}
	payload := map[string]interface{}{
		"event":      EventScanError,
		"session_id": sessionID,
		"target":     target,
		"error":      scanErr.Error(),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	}
	_ = n.sendWithRetry(n.wrapFormat(EventScanError, payload))
}

// ──────────────────────────────────────────────
// Payload builders
// ──────────────────────────────────────────────

// ScanPayload is the generic JSON payload shape.
type ScanPayload struct {
	Event             string                 `json:"event"`
	SessionID         string                 `json:"session_id"`
	Target            string                 `json:"target"`
	Duration          string                 `json:"duration"`
	FindingsCount     int                    `json:"findings_count"`
	SeverityBreakdown map[string]int         `json:"severity_breakdown"`
	TopFindings       []topFinding           `json:"top_findings,omitempty"`
	Timestamp         string                 `json:"timestamp"`
	Extra             map[string]interface{} `json:"extra,omitempty"`
}

type topFinding struct {
	Title    string  `json:"title"`
	Severity string  `json:"severity"`
	Endpoint string  `json:"endpoint"`
	CVSS     float64 `json:"cvss"`
}

func (n *Notifier) buildPayload(event string, session *types.ScanSession, findings []types.Finding, single *types.Finding) interface{} {
	dur := ""
	if !session.FinishedAt.IsZero() {
		dur = session.FinishedAt.Sub(session.StartedAt).Round(time.Second).String()
	}

	breakdown := map[string]int{}
	top := make([]topFinding, 0, 5)
	for _, f := range findings {
		sev := f.AdjustedSeverity
		if sev == 0 {
			sev = f.Severity
		}
		breakdown[sev.String()]++
		if len(top) < 5 {
			top = append(top, topFinding{
				Title:    f.Title,
				Severity: sev.String(),
				Endpoint: f.Endpoint,
				CVSS:     f.CVSS.Score,
			})
		}
	}

	base := ScanPayload{
		Event:             event,
		SessionID:         session.ID,
		Target:            session.Config.Target.URL,
		Duration:          dur,
		FindingsCount:     len(findings),
		SeverityBreakdown: breakdown,
		TopFindings:       top,
		Timestamp:         time.Now().UTC().Format(time.RFC3339),
	}

	if single != nil {
		base.Extra = map[string]interface{}{
			"finding_title":    single.Title,
			"finding_endpoint": single.Endpoint,
			"finding_cwe":      single.CWE,
		}
	}

	return n.wrapFormat(event, base)
}

func (n *Notifier) wrapFormat(event string, data interface{}) interface{} {
	switch n.cfg.Format {
	case FormatDiscord:
		return n.discordEmbed(event, data)
	case FormatSlack:
		return n.slackBlocks(event, data)
	default:
		return data
	}
}

// ──────────────────────────────────────────────
// Discord webhook payload
// ──────────────────────────────────────────────

func (n *Notifier) discordEmbed(event string, data interface{}) map[string]interface{} {
	color := 0x3498db // blue default

	var title, description string
	switch p := data.(type) {
	case ScanPayload:
		title = fmt.Sprintf("Ouroboros — %s", eventLabel(event))
		description = fmt.Sprintf("**Target:** %s\n**Findings:** %d\n**Duration:** %s",
			p.Target, p.FindingsCount, p.Duration)
		if p.FindingsCount > 0 {
			color = severityColor(p.SeverityBreakdown)
		} else {
			color = 0x2ecc71 // green: clean
		}
	default:
		raw, _ := json.Marshal(data)
		title = eventLabel(event)
		description = string(raw)
	}

	embed := map[string]interface{}{
		"title":       title,
		"description": description,
		"color":       color,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
		"footer":      map[string]string{"text": "Ouroboros Security Scanner"},
	}

	if p, ok := data.(ScanPayload); ok && len(p.SeverityBreakdown) > 0 {
		fields := make([]map[string]interface{}, 0, len(p.SeverityBreakdown))
		for sev, cnt := range p.SeverityBreakdown {
			fields = append(fields, map[string]interface{}{
				"name":   sev,
				"value":  fmt.Sprintf("%d", cnt),
				"inline": true,
			})
		}
		embed["fields"] = fields
	}

	return map[string]interface{}{
		"username": "Ouroboros",
		"embeds":   []interface{}{embed},
	}
}

func severityColor(breakdown map[string]int) int {
	if breakdown["Critical"] > 0 {
		return 0xe74c3c // red
	}
	if breakdown["High"] > 0 {
		return 0xe67e22 // orange
	}
	if breakdown["Medium"] > 0 {
		return 0xf1c40f // yellow
	}
	return 0x2ecc71 // green
}

func eventLabel(event string) string {
	switch event {
	case EventScanComplete:
		return "Scan Complete"
	case EventFindingCritical:
		return "Critical Finding Detected"
	case EventScanError:
		return "Scan Error"
	default:
		return event
	}
}

// ──────────────────────────────────────────────
// Slack webhook payload
// ──────────────────────────────────────────────

func (n *Notifier) slackBlocks(event string, data interface{}) map[string]interface{} {
	var text string
	switch p := data.(type) {
	case ScanPayload:
		text = fmt.Sprintf("*Ouroboros — %s*\n*Target:* %s\n*Findings:* %d  *Duration:* %s",
			eventLabel(event), p.Target, p.FindingsCount, p.Duration)
		if len(p.SeverityBreakdown) > 0 {
			parts := make([]string, 0, len(p.SeverityBreakdown))
			for sev, cnt := range p.SeverityBreakdown {
				parts = append(parts, fmt.Sprintf("%s: %d", sev, cnt))
			}
			text += "\n" + strings.Join(parts, "  |  ")
		}
	default:
		raw, _ := json.Marshal(data)
		text = fmt.Sprintf("*%s*\n```%s```", eventLabel(event), string(raw))
	}

	return map[string]interface{}{
		"blocks": []interface{}{
			map[string]interface{}{
				"type": "section",
				"text": map[string]string{
					"type": "mrkdwn",
					"text": text,
				},
			},
		},
	}
}

// ──────────────────────────────────────────────
// HTTP send with exponential backoff (max 3 retries)
// ──────────────────────────────────────────────

func (n *Notifier) sendWithRetry(payload interface{}) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("webhook marshal: %w", err)
	}

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			wait := time.Duration(1<<uint(attempt-1)) * time.Second // 1s, 2s
			time.Sleep(wait)
		}
		if err := n.doSend(body); err != nil {
			lastErr = err
			continue
		}
		return nil
	}
	return fmt.Errorf("webhook failed after 3 attempts: %w", lastErr)
}

func (n *Notifier) doSend(body []byte) error {
	req, err := http.NewRequest(http.MethodPost, n.cfg.URL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "Ouroboros-Scanner/1.0")
	for k, v := range n.cfg.Headers {
		req.Header.Set(k, v)
	}

	resp, err := n.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}
