package report

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/borntobeyours/ouroboros/pkg/types"
)

// DiffResult holds categorized findings between two scans.
type DiffResult struct {
	Fixed      []types.Finding
	Persistent []types.Finding
	New        []types.Finding
}

// ExportDiffMarkdown writes a diff report as Markdown.
func ExportDiffMarkdown(diff DiffResult, before, after *types.ScanSession, path string) error {
	var sb strings.Builder

	sb.WriteString("# Ouroboros Scan Diff Report\n\n")
	sb.WriteString(fmt.Sprintf("**Baseline:** %s (%s) — %s\n\n", before.ID[:8], before.Config.Target.URL, before.StartedAt.Format(time.RFC3339)))
	sb.WriteString(fmt.Sprintf("**Current:** %s (%s) — %s\n\n", after.ID[:8], after.Config.Target.URL, after.StartedAt.Format(time.RFC3339)))
	sb.WriteString("---\n\n")

	sb.WriteString("## Summary\n\n")
	sb.WriteString(fmt.Sprintf("| Status | Count |\n|--------|-------|\n"))
	sb.WriteString(fmt.Sprintf("| ✅ Fixed | %d |\n", len(diff.Fixed)))
	sb.WriteString(fmt.Sprintf("| ⚠️ Persistent | %d |\n", len(diff.Persistent)))
	sb.WriteString(fmt.Sprintf("| 🆕 New | %d |\n\n", len(diff.New)))

	if len(diff.Fixed) > 0 {
		sb.WriteString("## ✅ Fixed (Remediated)\n\n")
		for i, f := range diff.Fixed {
			sev := f.AdjustedSeverity
			if sev == 0 {
				sev = f.Severity
			}
			cvss := ""
			if f.CVSS.Score > 0 {
				cvss = fmt.Sprintf(" (CVSS: %.1f)", f.CVSS.Score)
			}
			sb.WriteString(fmt.Sprintf("%d. **[%s]** %s%s\n", i+1, sev, f.Title, cvss))
		}
		sb.WriteString("\n")
	}

	if len(diff.New) > 0 {
		sb.WriteString("## 🆕 New Findings (Regressions)\n\n")
		for i, f := range diff.New {
			sev := f.AdjustedSeverity
			if sev == 0 {
				sev = f.Severity
			}
			cvss := ""
			if f.CVSS.Score > 0 {
				cvss = fmt.Sprintf(" (CVSS: %.1f)", f.CVSS.Score)
			}
			sb.WriteString(fmt.Sprintf("%d. **[%s]** %s%s\n", i+1, sev, f.Title, cvss))
			if f.Endpoint != "" {
				sb.WriteString(fmt.Sprintf("   - Endpoint: `%s %s`\n", f.Method, f.Endpoint))
			}
		}
		sb.WriteString("\n")
	}

	if len(diff.Persistent) > 0 {
		sb.WriteString("## ⚠️ Persistent (Still Present)\n\n")
		for i, f := range diff.Persistent {
			sev := f.AdjustedSeverity
			if sev == 0 {
				sev = f.Severity
			}
			cvss := ""
			if f.CVSS.Score > 0 {
				cvss = fmt.Sprintf(" (CVSS: %.1f)", f.CVSS.Score)
			}
			sb.WriteString(fmt.Sprintf("%d. **[%s]** %s%s\n", i+1, sev, f.Title, cvss))
		}
	}

	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

// ExportDiffHTML writes a diff report as HTML.
func ExportDiffHTML(diff DiffResult, before, after *types.ScanSession, path string) error {
	var sb strings.Builder

	sb.WriteString(`<!DOCTYPE html>
<html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Ouroboros Diff Report</title>
<style>
  :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #e6edf3; --muted: #8b949e; --green: #3fb950; --red: #f85149; --yellow: #d29922; --blue: #58a6ff; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; padding: 2rem; max-width: 1000px; margin: 0 auto; }
  h1 { font-size: 2rem; margin-bottom: 0.5rem; }
  h2 { margin: 2rem 0 1rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }
  .subtitle { color: var(--muted); margin-bottom: 2rem; }
  .summary { display: flex; gap: 1rem; margin: 2rem 0; flex-wrap: wrap; }
  .summary-card { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; flex: 1; min-width: 150px; text-align: center; }
  .summary-card .number { font-size: 2.5rem; font-weight: 700; }
  .summary-card .label { color: var(--muted); font-size: 0.9rem; }
  .fixed .number { color: var(--green); }
  .persistent .number { color: var(--yellow); }
  .new .number { color: var(--red); }
  .finding-list { list-style: none; }
  .finding-item { background: var(--card); border: 1px solid var(--border); border-radius: 6px; padding: 0.75rem 1rem; margin-bottom: 0.5rem; display: flex; align-items: center; gap: 0.75rem; }
  .finding-item .icon { font-size: 1.2rem; }
  .finding-item .sev { font-size: 0.75rem; font-weight: 600; padding: 0.1rem 0.4rem; border-radius: 3px; text-transform: uppercase; }
  .sev-crit { background: #da3636; color: #fff; }
  .sev-high { background: #db6100; color: #fff; }
  .sev-med { background: #d29922; color: #000; }
  .sev-low { background: var(--blue); color: #000; }
  .sev-info { background: var(--muted); color: #000; }
  .finding-item .title { flex: 1; }
  .finding-item .cvss { color: var(--muted); font-family: monospace; font-size: 0.85rem; }
  .progress { display: flex; height: 8px; border-radius: 4px; overflow: hidden; margin: 1rem 0; }
  .progress .seg { transition: width 0.3s; }
  .footer { text-align: center; color: var(--muted); margin-top: 3rem; font-size: 0.85rem; }
</style></head><body>
`)

	sb.WriteString(`<h1>🐍 Ouroboros Diff Report</h1>`)
	sb.WriteString(fmt.Sprintf(`<p class="subtitle">%s → %s</p>`, before.ID[:8], after.ID[:8]))

	// Summary cards
	total := len(diff.Fixed) + len(diff.Persistent) + len(diff.New)
	sb.WriteString(`<div class="summary">`)
	sb.WriteString(fmt.Sprintf(`<div class="summary-card fixed"><div class="number">%d</div><div class="label">Fixed ✅</div></div>`, len(diff.Fixed)))
	sb.WriteString(fmt.Sprintf(`<div class="summary-card persistent"><div class="number">%d</div><div class="label">Persistent ⚠️</div></div>`, len(diff.Persistent)))
	sb.WriteString(fmt.Sprintf(`<div class="summary-card new"><div class="number">%d</div><div class="label">New 🆕</div></div>`, len(diff.New)))
	sb.WriteString(`</div>`)

	// Progress bar
	if total > 0 {
		sb.WriteString(`<div class="progress">`)
		if len(diff.Fixed) > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="seg" style="width:%.1f%%;background:var(--green)"></div>`, float64(len(diff.Fixed))/float64(total)*100))
		}
		if len(diff.Persistent) > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="seg" style="width:%.1f%%;background:var(--yellow)"></div>`, float64(len(diff.Persistent))/float64(total)*100))
		}
		if len(diff.New) > 0 {
			sb.WriteString(fmt.Sprintf(`<div class="seg" style="width:%.1f%%;background:var(--red)"></div>`, float64(len(diff.New))/float64(total)*100))
		}
		sb.WriteString(`</div>`)
	}

	// Fixed
	if len(diff.Fixed) > 0 {
		sb.WriteString(`<h2>✅ Fixed (Remediated)</h2><ul class="finding-list">`)
		for _, f := range diff.Fixed {
			writeDiffItem(&sb, f, "✅")
		}
		sb.WriteString(`</ul>`)
	}

	// New
	if len(diff.New) > 0 {
		sb.WriteString(`<h2>🆕 New Findings (Regressions)</h2><ul class="finding-list">`)
		for _, f := range diff.New {
			writeDiffItem(&sb, f, "🆕")
		}
		sb.WriteString(`</ul>`)
	}

	// Persistent
	if len(diff.Persistent) > 0 {
		sb.WriteString(`<h2>⚠️ Persistent (Still Present)</h2><ul class="finding-list">`)
		for _, f := range diff.Persistent {
			writeDiffItem(&sb, f, "⚠️")
		}
		sb.WriteString(`</ul>`)
	}

	sb.WriteString(fmt.Sprintf(`<div class="footer">Generated by Ouroboros • %s</div>`, time.Now().Format("2006-01-02 15:04:05")))
	sb.WriteString(`</body></html>`)

	return os.WriteFile(path, []byte(sb.String()), 0o644)
}

func writeDiffItem(sb *strings.Builder, f types.Finding, icon string) {
	sev := f.AdjustedSeverity
	if sev == 0 {
		sev = f.Severity
	}
	sevClass := "sev-info"
	switch sev {
	case types.SeverityCritical:
		sevClass = "sev-crit"
	case types.SeverityHigh:
		sevClass = "sev-high"
	case types.SeverityMedium:
		sevClass = "sev-med"
	case types.SeverityLow:
		sevClass = "sev-low"
	}

	cvss := ""
	if f.CVSS.Score > 0 {
		cvss = fmt.Sprintf(`<span class="cvss">CVSS %.1f</span>`, f.CVSS.Score)
	}

	sb.WriteString(fmt.Sprintf(`<li class="finding-item"><span class="icon">%s</span><span class="sev %s">%s</span><span class="title">%s</span>%s</li>`,
		icon, sevClass, sev, escapeHTML(f.Title), cvss))
}
