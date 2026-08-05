/**
 * OPF → Markdown. Renders a finding library as a readable Markdown document:
 * a severity summary table, then one section per finding, most-severe first.
 */
import {
  type OpfDocument,
  type OpfFinding,
  type OpfSeverity,
  SEVERITIES,
  allCwes,
  assertOpf,
  coerceSeverity,
  htmlToText,
  sortedBySeverity,
} from './core.js'

const SEV_LABEL: Record<OpfSeverity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Informational',
}

export interface OpfToMarkdownOptions {
  /** Document H1. Default: metadata.source + " findings", else "Findings". */
  title?: string
  /** Include the severity summary table. Default true. */
  summary?: boolean
}

function findingSection(f: OpfFinding): string {
  const sev = coerceSeverity(f.severity)
  const lines: string[] = []
  lines.push(`## ${f.title}`)
  const meta: string[] = [`**Severity:** ${SEV_LABEL[sev]}`]
  if (typeof f.cvssScore === 'number') meta.push(`**CVSS:** ${f.cvssScore}${f.cvssVector ? ` (\`${f.cvssVector}\`)` : ''}`)
  const cwes = allCwes(f)
  if (cwes.length) meta.push(`**CWE:** ${cwes.join(', ')}`)
  if (f.cveIds?.length) meta.push(`**CVE:** ${f.cveIds.join(', ')}`)
  if (f.owaspCategory) meta.push(`**OWASP:** ${f.owaspCategory}`)
  if (f.category && f.category !== 'general') meta.push(`**Category:** ${f.category}`)
  lines.push(meta.join('  \n'))
  lines.push('')

  const desc = htmlToText(f.description)
  if (desc) lines.push(desc, '')
  const impact = htmlToText(f.impact)
  if (impact) lines.push('**Impact**', '', impact, '')
  const rec = htmlToText(f.recommendation)
  if (rec) lines.push('**Recommendation**', '', rec, '')
  const tech = htmlToText(f.technicalDetails)
  if (tech) lines.push('**Technical detail**', '', tech, '')

  if (f.stepsToReproduce?.length) {
    lines.push('**Steps to reproduce**', '')
    f.stepsToReproduce.forEach((s, i) => lines.push(`${i + 1}. ${htmlToText(s)}`))
    lines.push('')
  }
  if (f.affectedAssets?.length) {
    lines.push('**Affected assets**', '')
    f.affectedAssets.forEach((a) => lines.push(`- \`${a}\``))
    lines.push('')
  }
  if (f.references?.length) {
    lines.push('**References**', '')
    f.references.forEach((r) => lines.push(`- [${r.title || r.url}](${r.url})`))
    lines.push('')
  }
  return lines.join('\n').trimEnd()
}

/** Render an OPF document as Markdown. */
export function opfToMarkdown(doc: OpfDocument, options: OpfToMarkdownOptions = {}): string {
  assertOpf(doc)
  const title = options.title ?? (doc.metadata?.source ? `${doc.metadata.source} findings` : 'Findings')
  const out: string[] = [`# ${title}`, '']

  if (doc.metadata?.description) out.push(htmlToText(doc.metadata.description), '')

  if (options.summary !== false && doc.findings.length) {
    const counts: Record<OpfSeverity, number> = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
    }
    for (const f of doc.findings) counts[coerceSeverity(f.severity)]++
    out.push('| Severity | Count |', '|---|---|')
    for (const s of SEVERITIES) if (counts[s]) out.push(`| ${SEV_LABEL[s]} | ${counts[s]} |`)
    out.push(`| **Total** | **${doc.findings.length}** |`, '')
  }

  for (const f of sortedBySeverity(doc.findings)) {
    if (!f?.title) continue
    out.push(findingSection(f), '')
  }

  return out.join('\n').replace(/\n{3,}/g, '\n\n').trimEnd() + '\n'
}
