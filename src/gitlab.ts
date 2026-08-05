/**
 * OPF → GitLab Security Report (SAST, schema 15.x).
 *
 * GitLab renders vulnerabilities from a report artifact on merge requests and
 * the security dashboard. Emitting this lets an OPF library surface there.
 *
 * Schema: https://gitlab.com/gitlab-org/security-products/security-report-schemas
 */
import {
  type OpfDocument,
  type OpfFinding,
  type OpfSeverity,
  allCwes,
  assertOpf,
  coerceSeverity,
  htmlToText,
  makeUniqueId,
} from './core.js'

const SEVERITY_TO_GL: Record<OpfSeverity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Info',
}

export interface GitLabReport {
  version: string
  scan: Record<string, unknown>
  vulnerabilities: Array<Record<string, unknown>>
}

export interface OpfToGitLabOptions {
  /** Value used for scan.start_time/end_time. Pass a fixed timestamp for reproducible output. */
  timestamp?: string
}

function identifiers(f: OpfFinding): Array<Record<string, unknown>> {
  const ids: Array<Record<string, unknown>> = []
  for (const cwe of allCwes(f)) {
    const num = /(\d+)/.exec(cwe)?.[1]
    ids.push({
      type: 'cwe',
      name: cwe,
      value: num ?? cwe,
      url: num ? `https://cwe.mitre.org/data/definitions/${num}.html` : undefined,
    })
  }
  for (const cve of f.cveIds ?? []) {
    ids.push({ type: 'cve', name: cve, value: cve, url: `https://nvd.nist.gov/vuln/detail/${cve}` })
  }
  if (f.id) ids.push({ type: 'opf', name: `OPF-${f.id}`, value: f.id })
  return ids
}

/** Convert an OPF document to a GitLab SAST security report. */
export function opfToGitLab(doc: OpfDocument, options: OpfToGitLabOptions = {}): GitLabReport {
  assertOpf(doc)
  const ts = options.timestamp ?? doc.metadata?.exportedAt ?? '1970-01-01T00:00:00'
  const uid = makeUniqueId()

  const vulnerabilities: Array<Record<string, unknown>> = []
  for (const f of doc.findings) {
    if (!f?.title) continue
    const id = uid(f.id, f.title)
    const ids = identifiers(f)
    const desc = [htmlToText(f.description), htmlToText(f.impact) && `Impact: ${htmlToText(f.impact)}`]
      .filter(Boolean)
      .join('\n\n')

    const v: Record<string, unknown> = {
      id,
      category: 'sast',
      name: f.title,
      description: desc || f.title,
      severity: SEVERITY_TO_GL[coerceSeverity(f.severity)],
      identifiers: ids.length ? ids : [{ type: 'opf', name: f.title, value: id }],
      location: { file: (f.affectedAssets ?? [])[0] ?? 'finding-library', start_line: 1 },
    }
    const solution = htmlToText(f.recommendation)
    if (solution) v.solution = solution
    if (f.references?.length) v.links = f.references.map((r) => ({ name: r.title, url: r.url }))
    vulnerabilities.push(v)
  }

  return {
    version: '15.0.6',
    scan: {
      type: 'sast',
      status: 'success',
      start_time: ts,
      end_time: ts,
      analyzer: { id: 'opf-tools', name: 'OPF Tools', version: '0.1.0', vendor: { name: 'Cairn Security' } },
      scanner: { id: 'opf-tools', name: 'OPF Tools', version: '0.1.0', vendor: { name: 'Cairn Security' } },
    },
    vulnerabilities,
  }
}
