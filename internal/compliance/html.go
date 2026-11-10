package compliance

import (
	"html"
	"strconv"
	"strings"
	"time"
)

// HTML renders the scorecard as a self-contained HTML document for the admin UI
// "compliance" view. It carries its own inline styles so it can be served
// directly (in an iframe or a new tab) without depending on the dashboard's
// stylesheet.
func (card Scorecard) HTML() string {
	var b strings.Builder
	b.WriteString(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">`)
	b.WriteString(`<meta name="viewport" content="width=device-width, initial-scale=1">`)
	b.WriteString("<title>Compliance Scorecard</title>")
	b.WriteString("<style>" + complianceCSS + "</style></head><body>")

	b.WriteString(`<div class="wrap">`)
	b.WriteString("<h1>Compliance Scorecard</h1>")

	// Header cards.
	b.WriteString(`<div class="cards">`)
	b.WriteString(card.headerCard("Overall", strings.ToUpper(string(card.Status)),
		"score "+pct(card.Score)+" · grade "+card.Grade, statusClass(card.Status)))
	b.WriteString(card.headerCard("SLSA (estimated)", html.EscapeString(card.SLSA.Track),
		html.EscapeString(card.SLSA.Rationale), slsaClass(card.SLSA.BuildLevel)))
	b.WriteString(card.headerCard("Controls",
		strconv.Itoa(card.Summary.Pass)+" / "+strconv.Itoa(totalScored(card))+" passing",
		strconv.Itoa(card.Summary.Warn)+" warn · "+strconv.Itoa(card.Summary.Fail)+" fail · "+strconv.Itoa(card.Summary.NA)+" n/a",
		""))
	b.WriteString("</div>")

	if card.Version != "" {
		b.WriteString(`<p class="meta">Proxy version <code>` + html.EscapeString(card.Version) + `</code> · generated ` +
			html.EscapeString(card.GeneratedAt.Format(time.RFC3339)) + `</p>`)
	} else {
		b.WriteString(`<p class="meta">Generated ` + html.EscapeString(card.GeneratedAt.Format(time.RFC3339)) + `</p>`)
	}

	// Controls table.
	b.WriteString(`<table><thead><tr><th>Status</th><th>Control</th><th>Score</th><th>Frameworks</th><th>Detail</th></tr></thead><tbody>`)
	for _, c := range card.Controls {
		score := "—"
		if c.Status != StatusNA {
			score = pct(c.Score)
		}
		b.WriteString(`<tr><td><span class="badge ` + statusClass(c.Status) + `">` +
			html.EscapeString(string(c.Status)) + `</span></td>`)
		b.WriteString(`<td><strong>` + html.EscapeString(c.Title) + `</strong><br><span class="cid">` + html.EscapeString(c.ID) + `</span></td>`)
		b.WriteString(`<td>` + score + `</td>`)
		b.WriteString(`<td>` + html.EscapeString(strings.Join(c.Frameworks, ", ")) + `</td>`)
		b.WriteString(`<td>` + html.EscapeString(c.Detail) + `</td></tr>`)
	}
	b.WriteString("</tbody></table>")

	b.WriteString(`<p class="footnote">This scorecard is a self-assessment derived from observed proxy telemetry; the SLSA build level is estimated, not asserted by an external verifier.</p>`)
	b.WriteString("</div></body></html>")
	return b.String()
}

func (card Scorecard) headerCard(label, big, sub, cls string) string {
	c := "card"
	if cls != "" {
		c += " " + cls
	}
	return `<div class="` + c + `"><div class="label">` + html.EscapeString(label) +
		`</div><div class="big">` + big + `</div><div class="sub">` + sub + `</div></div>`
}

func totalScored(card Scorecard) int {
	return card.Summary.Pass + card.Summary.Warn + card.Summary.Fail
}

func statusClass(s Status) string {
	switch s {
	case StatusPass:
		return "ok"
	case StatusWarn:
		return "warn"
	case StatusFail:
		return "fail"
	default:
		return "na"
	}
}

func slsaClass(level int) string {
	if level >= 2 {
		return "ok"
	}
	if level == 1 {
		return "warn"
	}
	return "fail"
}

const complianceCSS = `
:root{--bg:#0f1419;--panel:#1a2029;--fg:#e6e9ef;--muted:#9aa4b2;--ok:#2ea043;--warn:#d29922;--fail:#da3633;--na:#6e7681;--border:#2d333b}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
.wrap{max-width:1000px;margin:0 auto;padding:24px}
h1{font-size:22px;margin:0 0 16px}
.cards{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:12px}
.card{flex:1;min-width:220px;background:var(--panel);border:1px solid var(--border);border-left:4px solid var(--na);border-radius:8px;padding:14px}
.card.ok{border-left-color:var(--ok)}.card.warn{border-left-color:var(--warn)}.card.fail{border-left-color:var(--fail)}
.card .label{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.card .big{font-size:22px;font-weight:700;margin:4px 0}
.card .sub{color:var(--muted);font-size:13px}
.meta{color:var(--muted);margin:4px 0 18px}
code{background:#0b0f14;padding:1px 5px;border-radius:4px}
table{width:100%;border-collapse:collapse;background:var(--panel);border:1px solid var(--border);border-radius:8px;overflow:hidden}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:none}
.cid{color:var(--muted);font-size:12px}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;font-weight:600;text-transform:uppercase}
.badge.ok{background:rgba(46,160,67,.16);color:#3fb950}
.badge.warn{background:rgba(210,153,34,.16);color:#d29922}
.badge.fail{background:rgba(218,54,51,.16);color:#f85149}
.badge.na{background:rgba(110,118,129,.16);color:#9aa4b2}
.footnote{color:var(--muted);font-size:12px;margin-top:16px}
`
