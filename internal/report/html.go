package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// ExportHTML writes findings as a self-contained HTML report.
func ExportHTML(findings []types.Finding, session *types.ScanSession, path string) error {
	// Count stats
	critCount, highCount, medCount, lowCount, infoCount := 0, 0, 0, 0, 0
	proven, highConf, medConf, lowConf := 0, 0, 0, 0
	for _, f := range findings {
		sev := f.AdjustedSeverity
		if sev == 0 {
			sev = f.Severity
		}
		switch sev {
		case types.SeverityCritical:
			critCount++
		case types.SeverityHigh:
			highCount++
		case types.SeverityMedium:
			medCount++
		case types.SeverityLow:
			lowCount++
		default:
			infoCount++
		}
		switch {
		case f.Confidence >= 95:
			proven++
		case f.Confidence >= 75:
			highConf++
		case f.Confidence >= 50:
			medConf++
		default:
			lowConf++
		}
	}

	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ouroboros Security Report</title>
<style>
  :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #e6edf3; --muted: #8b949e; --accent: #58a6ff; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; max-width: 1200px; margin: 0 auto; }
  h1 { font-size: 2rem; margin-bottom: 0.5rem; }
  h1 span { color: var(--accent); }
  .subtitle { color: var(--muted); margin-bottom: 2rem; }
  .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .meta-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; }
  .meta-card .label { color: var(--muted); font-size: 0.85rem; text-transform: uppercase; letter-spacing: 0.05em; }
  .meta-card .value { font-size: 1.5rem; font-weight: 600; margin-top: 0.25rem; }
  .stats { display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }
  .stat { padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600; font-size: 0.9rem; }
  .stat-crit { background: #da36361a; color: #f85149; border: 1px solid #da363633; }
  .stat-high { background: #db61001a; color: #f0883e; border: 1px solid #db610033; }
  .stat-med { background: #d299001a; color: #d29922; border: 1px solid #d2990033; }
  .stat-low { background: #58a6ff1a; color: #58a6ff; border: 1px solid #58a6ff33; }
  .stat-info { background: #8b949e1a; color: #8b949e; border: 1px solid #8b949e33; }
  .stat-proven { background: #3fb9501a; color: #3fb950; border: 1px solid #3fb95033; }
  .chart-row { display: flex; height: 12px; border-radius: 6px; overflow: hidden; margin-bottom: 2rem; }
  .chart-seg { transition: width 0.3s; }
  .finding { background: var(--card); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
  .finding-header { padding: 1rem 1.25rem; cursor: pointer; display: flex; align-items: center; gap: 0.75rem; user-select: none; }
  .finding-header:hover { background: #1c2128; }
  .finding-body { padding: 0 1.25rem 1.25rem; display: none; border-top: 1px solid var(--border); padding-top: 1rem; }
  .finding.open .finding-body { display: block; }
  .finding-header .arrow { transition: transform 0.2s; color: var(--muted); }
  .finding.open .finding-header .arrow { transform: rotate(90deg); }
  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; text-transform: uppercase; }
  .badge-crit { background: #da3636; color: #fff; }
  .badge-high { background: #db6100; color: #fff; }
  .badge-med { background: #d29922; color: #000; }
  .badge-low { background: #58a6ff; color: #000; }
  .badge-info { background: #8b949e; color: #000; }
  .cvss { font-family: monospace; color: var(--muted); font-size: 0.85rem; }
  .conf { font-size: 0.8rem; padding: 0.1rem 0.4rem; border-radius: 3px; }
  .conf-proven { background: #3fb95033; color: #3fb950; }
  .conf-high { background: #3fb95022; color: #56d364; }
  .conf-med { background: #d2990022; color: #d29922; }
  .conf-low { background: #f8514922; color: #f85149; }
  .detail-grid { display: grid; grid-template-columns: 120px 1fr; gap: 0.5rem; font-size: 0.9rem; }
  .detail-grid dt { color: var(--muted); font-weight: 600; }
  .detail-grid dd { word-break: break-all; }
  pre { background: #0d1117; border: 1px solid var(--border); border-radius: 6px; padding: 1rem; overflow-x: auto; font-size: 0.85rem; margin-top: 0.5rem; }
  code { font-family: 'SF Mono', 'Fira Code', monospace; }
  .evidence { margin-top: 1rem; }
  .evidence-label { color: var(--accent); font-weight: 600; font-size: 0.85rem; text-transform: uppercase; margin-bottom: 0.25rem; }
  .footer { text-align: center; color: var(--muted); margin-top: 3rem; font-size: 0.85rem; }
  .filter-bar { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; flex-wrap: wrap; }
  .filter-btn { padding: 0.4rem 0.8rem; border-radius: 6px; border: 1px solid var(--border); background: var(--card); color: var(--text); cursor: pointer; font-size: 0.85rem; }
  .filter-btn:hover, .filter-btn.active { border-color: var(--accent); color: var(--accent); }
  .title-text { flex: 1; font-weight: 600; }
  .vector { font-family: monospace; font-size: 0.8rem; color: var(--muted); word-break: break-all; }
</style>
</head>
<body>
`)

	// Header
	sb.WriteString(fmt.Sprintf(`<h1>🐍 <span>Ouroboros</span> Security Report</h1>
<p class="subtitle">Security that attacks itself until nothing can.</p>
`))

	// Meta cards
	duration := session.FinishedAt.Sub(session.StartedAt).Round(time.Second)
	sb.WriteString(fmt.Sprintf(`<div class="meta">
  <div class="meta-card"><div class="label">Target</div><div class="value" style="font-size:1rem;word-break:break-all;">%s</div></div>
  <div class="meta-card"><div class="label">Findings</div><div class="value">%d</div></div>
  <div class="meta-card"><div class="label">Duration</div><div class="value">%s</div></div>
  <div class="meta-card"><div class="label">Loops</div><div class="value">%d</div></div>
  <div class="meta-card"><div class="label">Session</div><div class="value" style="font-size:0.85rem;">%s</div></div>
  <div class="meta-card"><div class="label">Date</div><div class="value" style="font-size:1rem;">%s</div></div>
</div>
`, session.Config.Target.URL, len(findings), duration, len(session.Loops), session.ID, session.StartedAt.Format("2006-01-02 15:04")))

	// Severity bar chart
	total := len(findings)
	if total > 0 {
		sb.WriteString(`<div class="chart-row">`)
		if critCount > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="chart-seg" style="width:%.1f%%;background:#f85149;" title="Critical: %d"></div>`, float64(critCount)/float64(total)*100, critCount))
		}
		if highCount > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="chart-seg" style="width:%.1f%%;background:#f0883e;" title="High: %d"></div>`, float64(highCount)/float64(total)*100, highCount))
		}
		if medCount > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="chart-seg" style="width:%.1f%%;background:#d29922;" title="Medium: %d"></div>`, float64(medCount)/float64(total)*100, medCount))
		}
		if lowCount > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="chart-seg" style="width:%.1f%%;background:#58a6ff;" title="Low: %d"></div>`, float64(lowCount)/float64(total)*100, lowCount))
		}
		if infoCount > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="chart-seg" style="width:%.1f%%;background:#8b949e;" title="Info: %d"></div>`, float64(infoCount)/float64(total)*100, infoCount))
		}
		sb.WriteString("</div>\n")
	}

	// Stats badges
	sb.WriteString(`<div class="stats">`)
	if critCount > 0 {
		sb.WriteString(fmt.Sprintf(`<span class="stat stat-crit">%d Critical</span>`, critCount))
	}
	if highCount > 0 {
		sb.WriteString(fmt.Sprintf(`<span class="stat stat-high">%d High</span>`, highCount))
	}
	if medCount > 0 {
		sb.WriteString(fmt.Sprintf(`<span class="stat stat-med">%d Medium</span>`, medCount))
	}
	if lowCount > 0 {
		sb.WriteString(fmt.Sprintf(`<span class="stat stat-low">%d Low</span>`, lowCount))
	}
	if infoCount > 0 {
		sb.WriteString(fmt.Sprintf(`<span class="stat stat-info">%d Info</span>`, infoCount))
	}
	sb.WriteString(fmt.Sprintf(`<span class="stat stat-proven">%d Proven</span>`, proven))
	if highConf > 0 {
		sb.WriteString(fmt.Sprintf(`<span class="stat stat-proven" style="opacity:0.7">%d High Conf</span>`, highConf))
	}
	sb.WriteString("</div>\n")

	// Filter bar
	sb.WriteString(`<div class="filter-bar">
  <button class="filter-btn active" onclick="filterAll()">All</button>
  <button class="filter-btn" onclick="filterSev('crit')">Critical</button>
  <button class="filter-btn" onclick="filterSev('high')">High</button>
  <button class="filter-btn" onclick="filterSev('med')">Medium</button>
  <button class="filter-btn" onclick="filterSev('low')">Low</button>
  <button class="filter-btn" onclick="filterConf(95)">Proven Only</button>
  <button class="filter-btn" onclick="filterConf(75)">High+ Confidence</button>
</div>
`)

	// Findings
	for i, f := range findings {
		sev := f.AdjustedSeverity
		if sev == 0 {
			sev = f.Severity
		}
		sevClass := sevToBadgeClass(sev)
		confClass := confToClass(f.Confidence)

		sb.WriteString(fmt.Sprintf(`<div class="finding" data-sev="%s" data-conf="%d">`, sevClass, f.Confidence))
		sb.WriteString(fmt.Sprintf(`<div class="finding-header" onclick="this.parentElement.classList.toggle('open')">
  <span class="arrow">▶</span>
  <span class="badge badge-%s">%s</span>
  <span class="title-text">%d. %s</span>`, sevClass, sev, i+1, escapeHTML(f.Title)))

		if f.CVSS.Score > 0 {
			sb.WriteString(fmt.Sprintf(`<span class="cvss">CVSS %.1f</span>`, f.CVSS.Score))
		}
		sb.WriteString(fmt.Sprintf(`<span class="conf %s">%d%% %s</span>`, confClass, f.Confidence, f.Confidence.String()))
		sb.WriteString("</div>\n")

		// Body
		sb.WriteString(`<div class="finding-body"><dl class="detail-grid">`)
		sb.WriteString(fmt.Sprintf(`<dt>Endpoint</dt><dd><code>%s %s</code></dd>`, f.Method, escapeHTML(f.Endpoint)))
		if f.CWE != "" {
			sb.WriteString(fmt.Sprintf(`<dt>CWE</dt><dd><a href="https://cwe.mitre.org/data/definitions/%s.html" style="color:var(--accent)">%s</a></dd>`, strings.TrimPrefix(strings.ToUpper(f.CWE), "CWE-"), f.CWE))
		}
		sb.WriteString(fmt.Sprintf(`<dt>Technique</dt><dd>%s</dd>`, f.Technique))
		if f.CVSS.Score > 0 {
			sb.WriteString(fmt.Sprintf(`<dt>CVSS</dt><dd>%.1f (%s) <span class="vector">%s</span></dd>`, f.CVSS.Score, f.CVSS.Rating, f.CVSS.Vector))
		}
		sb.WriteString(fmt.Sprintf(`<dt>Loop</dt><dd>%d</dd>`, f.Loop))
		sb.WriteString("</dl>\n")

		if f.Description != "" {
			sb.WriteString(fmt.Sprintf(`<p style="margin-top:1rem;color:var(--muted)">%s</p>`, escapeHTML(f.Description)))
		}

		if f.PoC != "" {
			sb.WriteString(`<div class="evidence"><div class="evidence-label">PoC</div>`)
			sb.WriteString(fmt.Sprintf("<pre><code>%s</code></pre></div>\n", escapeHTML(f.PoC)))
		}
		if f.ExploitEvidence != "" {
			sb.WriteString(`<div class="evidence"><div class="evidence-label">Exploit Evidence</div>`)
			sb.WriteString(fmt.Sprintf("<pre><code>%s</code></pre></div>\n", escapeHTML(f.ExploitEvidence)))
		}
		if f.ExfiltratedData != "" {
			sb.WriteString(`<div class="evidence"><div class="evidence-label">Exfiltrated Data</div>`)
			sb.WriteString(fmt.Sprintf("<pre><code>%s</code></pre></div>\n", escapeHTML(f.ExfiltratedData)))
		}
		if f.Remediation != "" {
			sb.WriteString(`<div class="evidence"><div class="evidence-label">Remediation</div>`)
			sb.WriteString(fmt.Sprintf("<p>%s</p></div>\n", escapeHTML(f.Remediation)))
		}
		sb.WriteString("</div></div>\n")
	}

	// Footer
	sb.WriteString(fmt.Sprintf(`<div class="footer">Generated by Ouroboros v0.1.0 • %s • <a href="https://github.com/borntobeyours/ouroboros" style="color:var(--accent)">github.com/borntobeyours/ouroboros</a></div>`, time.Now().Format("2006-01-02 15:04:05")))

	// JavaScript for filtering
	sb.WriteString(`
<script>
function filterAll() {
  document.querySelectorAll('.finding').forEach(el => el.style.display = '');
  setActive(0);
}
function filterSev(sev) {
  document.querySelectorAll('.finding').forEach(el => {
    el.style.display = el.dataset.sev === sev ? '' : 'none';
  });
  const btns = document.querySelectorAll('.filter-btn');
  btns.forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
}
function filterConf(min) {
  document.querySelectorAll('.finding').forEach(el => {
    el.style.display = parseInt(el.dataset.conf) >= min ? '' : 'none';
  });
  const btns = document.querySelectorAll('.filter-btn');
  btns.forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
}
function setActive(idx) {
  const btns = document.querySelectorAll('.filter-btn');
  btns.forEach(b => b.classList.remove('active'));
  btns[idx].classList.add('active');
}
</script>
</body></html>`)

	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

func sevToBadgeClass(sev types.Severity) string {
	switch sev {
	case types.SeverityCritical:
		return "crit"
	case types.SeverityHigh:
		return "high"
	case types.SeverityMedium:
		return "med"
	case types.SeverityLow:
		return "low"
	default:
		return "info"
	}
}

func confToClass(c types.Confidence) string {
	switch {
	case c >= 95:
		return "conf-proven"
	case c >= 75:
		return "conf-high"
	case c >= 50:
		return "conf-med"
	default:
		return "conf-low"
	}
}

func escapeHTML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	return s
}
