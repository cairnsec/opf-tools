/**
 * OPF → standalone HTML. A single self-contained page (inline CSS, no assets)
 * that renders a finding library for reading or sharing.
 */
import {
  type OpfDocument,
  type OpfFinding,
  type OpfSeverity,
  SEVERITIES,
  allCwes,
  assertOpf,
  coerceSeverity,
  escapeHtml,
  htmlToText,
  sortedBySeverity,
} from './core.js'

const SEV_LABEL: Record<OpfSeverity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Info',
}
const SEV_COLOR: Record<OpfSeverity, string> = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d4a017',
  low: '#2563eb',
  informational: '#64748b',
}

function para(label: string, value?: string): string {
  const v = htmlToText(value)
  if (!v) return ''
  const body = escapeHtml(v).replace(/\n/g, '<br>')
  return `<div class="block"><h4>${label}</h4><p>${body}</p></div>`
}

function findingCard(f: OpfFinding): string {
  const sev = coerceSeverity(f.severity)
  const meta: string[] = []
  if (typeof f.cvssScore === 'number')
    meta.push(`CVSS ${escapeHtml(String(f.cvssScore))}${f.cvssVector ? ` <code>${escapeHtml(f.cvssVector)}</code>` : ''}`)
  const cwes = allCwes(f)
  if (cwes.length) meta.push(cwes.map((c) => escapeHtml(c)).join(', '))
  if (f.owaspCategory) meta.push(escapeHtml(f.owaspCategory))

  const parts: string[] = []
  parts.push(`<article class="finding">`)
  parts.push(
    `<header><span class="badge" style="background:${SEV_COLOR[sev]}">${SEV_LABEL[sev]}</span>` +
      `<h3>${escapeHtml(f.title)}</h3></header>`,
  )
  if (meta.length) parts.push(`<div class="meta">${meta.join(' &middot; ')}</div>`)
  parts.push(para('Description', f.description))
  parts.push(para('Impact', f.impact))
  parts.push(para('Recommendation', f.recommendation))
  parts.push(para('Technical detail', f.technicalDetails))
  if (f.stepsToReproduce?.length) {
    parts.push(
      `<div class="block"><h4>Steps to reproduce</h4><ol>${f.stepsToReproduce
        .map((s) => `<li>${escapeHtml(htmlToText(s))}</li>`)
        .join('')}</ol></div>`,
    )
  }
  if (f.affectedAssets?.length) {
    parts.push(
      `<div class="block"><h4>Affected assets</h4><ul>${f.affectedAssets
        .map((a) => `<li><code>${escapeHtml(a)}</code></li>`)
        .join('')}</ul></div>`,
    )
  }
  if (f.references?.length) {
    parts.push(
      `<div class="block"><h4>References</h4><ul>${f.references
        .map((r) => `<li><a href="${escapeHtml(r.url)}" rel="noopener noreferrer">${escapeHtml(r.title || r.url)}</a></li>`)
        .join('')}</ul></div>`,
    )
  }
  parts.push(`</article>`)
  return parts.join('')
}

const STYLE = `
:root{color-scheme:light dark}
*{box-sizing:border-box}
body{font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;margin:0;color:#e5e7eb;background:#0b0b0d}
.wrap{max-width:820px;margin:0 auto;padding:2.5rem 1.25rem}
h1{font-size:1.9rem;margin:0 0 .25rem}
.sub{color:#9ca3af;margin:0 0 2rem}
table.summary{border-collapse:collapse;margin:0 0 2rem;font-size:.95rem}
table.summary td,table.summary th{border:1px solid #26262c;padding:.35rem .8rem;text-align:left}
.finding{border:1px solid #26262c;border-radius:12px;padding:1.25rem 1.4rem;margin:0 0 1.25rem;background:#141418}
.finding header{display:flex;align-items:center;gap:.75rem;margin-bottom:.5rem}
.finding h3{font-size:1.15rem;margin:0}
.badge{color:#fff;font-size:.72rem;font-weight:700;letter-spacing:.03em;text-transform:uppercase;padding:.2rem .55rem;border-radius:999px}
.meta{color:#9ca3af;font-size:.85rem;margin-bottom:.9rem}
.block{margin:.75rem 0}
.block h4{font-size:.78rem;text-transform:uppercase;letter-spacing:.05em;color:#9ca3af;margin:0 0 .3rem}
.block p{margin:0}
code{background:#26262c;padding:.05rem .35rem;border-radius:4px;font-size:.85em}
a{color:#8ab4ff}
ul,ol{margin:.3rem 0;padding-left:1.4rem}
`

export interface OpfToHtmlOptions {
  title?: string
}

/** Render an OPF document as a self-contained HTML page. */
export function opfToHtml(doc: OpfDocument, options: OpfToHtmlOptions = {}): string {
  assertOpf(doc)
  const title = options.title ?? (doc.metadata?.source ? `${doc.metadata.source} findings` : 'Findings')

  const counts: Record<OpfSeverity, number> = { critical: 0, high: 0, medium: 0, low: 0, informational: 0 }
  for (const f of doc.findings) counts[coerceSeverity(f.severity)]++
  const summaryRows = SEVERITIES.filter((s) => counts[s])
    .map((s) => `<tr><td><span class="badge" style="background:${SEV_COLOR[s]}">${SEV_LABEL[s]}</span></td><td>${counts[s]}</td></tr>`)
    .join('')

  const cards = sortedBySeverity(doc.findings)
    .filter((f) => f?.title)
    .map(findingCard)
    .join('\n')

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<style>${STYLE}</style>
</head>
<body>
<div class="wrap">
<h1>${escapeHtml(title)}</h1>
<p class="sub">${doc.findings.length} finding(s)${doc.metadata?.source ? ` &middot; ${escapeHtml(doc.metadata.source)}` : ''}</p>
<table class="summary"><tr><th>Severity</th><th>Count</th></tr>${summaryRows}<tr><td><strong>Total</strong></td><td><strong>${doc.findings.length}</strong></td></tr></table>
${cards}
</div>
</body>
</html>
`
}
