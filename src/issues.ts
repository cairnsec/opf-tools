/**
 * Canonical issue model shared by every issue-tracker adapter.
 *
 * OPF describes findings; issue trackers (Jira, GitHub, GitLab, Linear, Azure
 * Boards, ServiceNow, ...) describe tickets. Rather than write a bespoke OPF->X
 * mapping per tracker, we map OPF once to a neutral `IssueDraft`, then each
 * adapter is a thin renderer over that: a CSV column profile (this file) or an
 * API payload builder (e.g. jira.ts).
 *
 * Adding a tracker that imports CSV is a new case in `renderIssuesCsv`.
 * Adding a tracker with a REST API is a small file modelled on jira.ts.
 *
 * OPF spec: https://cairnsecurity.com/opf
 */
import {
  type OpfDocument,
  type OpfFinding,
  type OpfSeverity,
  allCwes,
  assertOpf,
  coerceSeverity,
  effectiveScore,
  guardCsvCell,
  htmlToText,
  makeUniqueId,
  slugify,
  sortedBySeverity,
} from './core.js'

/** Default severity -> priority names (Jira's built-in scheme). Override via options.priorityMap. */
export const SEVERITY_TO_PRIORITY: Record<OpfSeverity, string> = {
  critical: 'Highest',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Lowest',
}

/** Trackers with a built-in CSV column profile. */
export type TrackerId = 'generic' | 'jira' | 'github' | 'linear' | 'azure-devops'

export const TRACKERS: TrackerId[] = ['generic', 'jira', 'github', 'linear', 'azure-devops']

/** A tracker-neutral ticket derived from one OPF finding. */
export interface IssueDraft {
  /** Stable external key for de-dupe / idempotent sync (the OPF finding id). */
  externalId: string
  /** Ticket summary / title. */
  title: string
  /** Rendered ticket body (Markdown). */
  body: string
  severity: OpfSeverity
  /** Mapped priority name. */
  priority: string
  /** Slugged, space-free labels/tags. */
  labels: string[]
  /** Suggested issue type. Default "Bug". */
  issueType: string
  /** Structured fields for trackers with custom columns/fields. */
  fields: {
    cvssScore: number
    cvssVector?: string
    cwe?: string
    cwes: string[]
    cve: string[]
    owasp?: string
    assets: string[]
  }
  /** External references. */
  links: Array<{ title?: string; url: string }>
}

export interface OpfToIssuesOptions {
  /** Override severity -> priority mapping. */
  priorityMap?: Record<OpfSeverity, string>
  /** Issue type for created tickets. Default "Bug". */
  issueType?: string
  /** Extra labels applied to every issue. */
  extraLabels?: string[]
}

function labelsFor(f: OpfFinding, sev: OpfSeverity, extra: string[]): string[] {
  const out = new Set<string>(['opf', `severity:${sev}`])
  if (f.testType) out.add(slugify(f.testType))
  if (f.category) out.add(slugify(f.category))
  if (f.owaspCategory) out.add(slugify(f.owaspCategory))
  for (const t of f.mitreTechniques ?? []) out.add(slugify(t))
  for (const e of extra) out.add(slugify(e))
  return [...out]
}

function buildBody(f: OpfFinding): string {
  const sev = coerceSeverity(f.severity)
  const parts: string[] = []

  const desc = htmlToText(f.description)
  if (desc) parts.push(desc)

  const impact = htmlToText(f.impact)
  if (impact) parts.push(`## Impact\n\n${impact}`)

  if (f.stepsToReproduce?.length) {
    parts.push(
      '## Steps to reproduce\n\n' +
        f.stepsToReproduce.map((s, i) => `${i + 1}. ${htmlToText(s)}`).join('\n'),
    )
  }

  const rec = htmlToText(f.recommendation)
  if (rec) parts.push(`## Recommendation\n\n${rec}`)

  const meta: string[] = [
    `- Severity: ${sev}`,
    `- CVSS: ${effectiveScore(f)}${f.cvssVector ? ` (${f.cvssVector})` : ''}`,
  ]
  const cwes = allCwes(f)
  if (cwes.length) meta.push(`- CWE: ${cwes.join(', ')}`)
  if (f.cveIds?.length) meta.push(`- CVE: ${f.cveIds.join(', ')}`)
  if (f.owaspCategory) meta.push(`- OWASP: ${f.owaspCategory}`)
  if (f.affectedAssets?.length) meta.push(`- Affected: ${f.affectedAssets.join(', ')}`)
  parts.push('## Details\n\n' + meta.join('\n'))

  if (f.references?.length) {
    parts.push(
      '## References\n\n' +
        f.references.map((r) => `- ${r.title ? `${r.title}: ` : ''}${r.url}`).join('\n'),
    )
  }
  return parts.join('\n\n')
}

/**
 * Map an OPF document to tracker-neutral issue drafts, ordered most-severe
 * first (stable within a severity). A finding without a title is exported under
 * a generated "Untitled finding" title rather than being silently dropped, so a
 * malformed finding still becomes a visible ticket instead of vanishing.
 */
export function opfToIssues(doc: OpfDocument, options: OpfToIssuesOptions = {}): IssueDraft[] {
  assertOpf(doc)
  const pmap = options.priorityMap ?? SEVERITY_TO_PRIORITY
  const issueType = options.issueType ?? 'Bug'
  const extra = options.extraLabels ?? []
  const uid = makeUniqueId()

  const findings = doc.findings.filter((f): f is OpfFinding => Boolean(f))
  const drafts: IssueDraft[] = []
  for (const f of sortedBySeverity(findings)) {
    const sev = coerceSeverity(f.severity)
    const cwes = allCwes(f)
    const title = f.title || `Untitled finding${f.id ? ` ${f.id}` : ''}`
    drafts.push({
      externalId: uid(f.id, title),
      title,
      body: buildBody(f),
      severity: sev,
      priority: pmap[sev],
      labels: labelsFor(f, sev, extra),
      issueType,
      fields: {
        cvssScore: effectiveScore(f),
        cvssVector: f.cvssVector,
        cwe: cwes[0],
        cwes,
        cve: f.cveIds ?? [],
        owasp: f.owaspCategory,
        assets: f.affectedAssets ?? [],
      },
      links: (f.references ?? []).map((r) => ({ title: r.title, url: r.url })),
    })
  }
  return drafts
}

/**
 * Parse an HTTP response body as JSON, or throw a labelled error instead of
 * leaking a raw SyntaxError when a proxy/CDN returns a non-JSON body on an
 * otherwise-successful response. `createdCount` is folded into the message so
 * partial progress is still reported. Shared by the sequential push adapters.
 */
export function parseJsonResponse(text: string, label: string, status: number, createdCount: number): unknown {
  if (!text) return null
  try {
    return JSON.parse(text)
  } catch {
    throw new Error(
      `${label} returned a non-JSON response (${status}) after ${createdCount} created: ${text.slice(0, 500)}`,
    )
  }
}

// --- CSV rendering ---------------------------------------------------------

function esc(v: string): string {
  const g = guardCsvCell(v)
  return /[",\r\n]/.test(g) ? `"${g.replace(/"/g, '""')}"` : g
}

function toCsv(headers: string[], rows: string[][]): string {
  const lines = [headers.map(esc).join(',')]
  for (const r of rows) lines.push(r.map(esc).join(','))
  return lines.join('\r\n') + '\r\n'
}

/**
 * Severity -> Linear priority: 0 none, 1 urgent, 2 high, 3 medium, 4 low.
 * Single source of truth shared by the CSV profile and the Linear REST adapter.
 */
export const LINEAR_PRIORITY: Record<OpfSeverity, number> = {
  critical: 1,
  high: 2,
  medium: 3,
  low: 4,
  informational: 0,
}

/**
 * Severity -> Azure DevOps Boards priority: integer 1 (highest) .. 4 (lowest).
 * Single source of truth shared by the CSV profile and the Azure REST adapter.
 */
export const ADO_PRIORITY: Record<OpfSeverity, number> = {
  critical: 1,
  high: 2,
  medium: 3,
  low: 4,
  informational: 4,
}

/**
 * Render issue drafts as a CSV importable by the named tracker. Column shapes
 * match each tool's import wizard; `generic` is a neutral superset.
 *
 * - jira:         External System Import. Multi-value labels use repeated
 *                 `Labels` columns, which Jira collapses into one field.
 * - github:       title/body/labels, consumable by gh-CSV import tools.
 * - linear:       Title/Description/Priority(0-4)/Labels/Status.
 * - azure-devops: Work Item Type/Title/Description/Priority(1-4)/Tags.
 */
export function renderIssuesCsv(drafts: IssueDraft[], tracker: TrackerId = 'generic'): string {
  switch (tracker) {
    case 'jira': {
      const maxLabels = drafts.reduce((m, d) => Math.max(m, d.labels.length), 0)
      const headers = [
        'Summary',
        'Issue Type',
        'Priority',
        'Description',
        'CVSS Score',
        'CVSS Vector',
        'CWE',
        'CVE',
        'Affected Assets',
        'OPF Id',
        ...Array<string>(maxLabels).fill('Labels'),
      ]
      const rows = drafts.map((d) => [
        d.title,
        d.issueType,
        d.priority,
        d.body,
        String(d.fields.cvssScore),
        d.fields.cvssVector ?? '',
        d.fields.cwes.join(' '),
        d.fields.cve.join(' '),
        d.fields.assets.join(' '),
        d.externalId,
        ...d.labels,
        ...Array<string>(maxLabels - d.labels.length).fill(''),
      ])
      return toCsv(headers, rows)
    }
    case 'github': {
      const headers = ['title', 'body', 'labels']
      const rows = drafts.map((d) => [d.title, d.body, d.labels.join(',')])
      return toCsv(headers, rows)
    }
    case 'linear': {
      const headers = ['Title', 'Description', 'Priority', 'Labels', 'Status']
      const rows = drafts.map((d) => [d.title, d.body, String(LINEAR_PRIORITY[d.severity]), d.labels.join(','), 'Backlog'])
      return toCsv(headers, rows)
    }
    case 'azure-devops': {
      const headers = ['Work Item Type', 'Title', 'Description', 'Priority', 'Tags']
      const rows = drafts.map((d) => [d.issueType, d.title, d.body, String(ADO_PRIORITY[d.severity]), d.labels.join('; ')])
      return toCsv(headers, rows)
    }
    default: {
      const headers = [
        'id',
        'title',
        'severity',
        'priority',
        'type',
        'labels',
        'cvssScore',
        'cvssVector',
        'cwe',
        'cve',
        'assets',
        'body',
      ]
      const rows = drafts.map((d) => [
        d.externalId,
        d.title,
        d.severity,
        d.priority,
        d.issueType,
        d.labels.join(','),
        String(d.fields.cvssScore),
        d.fields.cvssVector ?? '',
        d.fields.cwes.join(' '),
        d.fields.cve.join(' '),
        d.fields.assets.join(' '),
        d.body,
      ])
      return toCsv(headers, rows)
    }
  }
}

/** OPF -> tracker-importable CSV in one call. */
export function opfToIssuesCsv(
  doc: OpfDocument,
  tracker: TrackerId = 'generic',
  options: OpfToIssuesOptions = {},
): string {
  return renderIssuesCsv(opfToIssues(doc, options), tracker)
}
