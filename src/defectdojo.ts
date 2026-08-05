/**
 * OPF → DefectDojo "Generic Findings Import" JSON.
 *
 * DefectDojo is the most widely used open-source vulnerability manager. Its
 * generic importer accepts a `{ findings: [...] }` document; emitting it means
 * an OPF library imports straight into DefectDojo with no custom parser.
 *
 * Format: https://documentation.defectdojo.com/integrations/parsers/file/generic/
 */
import {
  type OpfDocument,
  type OpfFinding,
  type OpfSeverity,
  allCwes,
  assertOpf,
  coerceSeverity,
  cweNumber,
  htmlToText,
} from './core.js'

const SEVERITY_TO_DD: Record<OpfSeverity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Info',
}

export interface DefectDojoFinding {
  title: string
  severity: string
  description: string
  [key: string]: unknown
}

export interface DefectDojoImport {
  findings: DefectDojoFinding[]
}

function ddDate(iso?: string): string | undefined {
  if (!iso) return undefined
  const m = /^(\d{4}-\d{2}-\d{2})/.exec(iso)
  return m ? m[1] : undefined
}

/** Convert an OPF document to a DefectDojo Generic Findings Import document. */
export function opfToDefectDojo(doc: OpfDocument): DefectDojoImport {
  assertOpf(doc)
  const date = ddDate(doc.metadata?.exportedAt)

  const findings: DefectDojoFinding[] = []
  for (const f of doc.findings) {
    if (!f?.title) continue
    const out: DefectDojoFinding = {
      title: f.title,
      severity: SEVERITY_TO_DD[coerceSeverity(f.severity)],
      description: htmlToText(f.description) || f.title,
    }
    if (date) out.date = date

    const cwe = allCwes(f)[0]
    const n = cwe ? cweNumber(cwe) : null
    if (n != null) out.cwe = n
    if (f.cveIds?.length) out.cve = f.cveIds[0]
    if (f.cvssVector) out.cvssv3 = f.cvssVector
    if (typeof f.cvssScore === 'number') out.cvssv3_score = f.cvssScore

    const impact = htmlToText(f.impact)
    if (impact) out.impact = impact
    const mitigation = htmlToText(f.recommendation)
    if (mitigation) out.mitigation = mitigation

    if (f.stepsToReproduce?.length) {
      out.steps_to_reproduce = f.stepsToReproduce.map((s, i) => `${i + 1}. ${htmlToText(s)}`).join('\n')
    }
    if (f.references?.length) {
      out.references = f.references.map((r) => (r.title ? `${r.title}: ${r.url}` : r.url)).join('\n')
    }
    const assets = (f.affectedAssets ?? []).filter((a): a is string => typeof a === 'string' && !!a.trim())
    if (assets.length) {
      out.endpoints = assets
      out.file_path = assets[0]
    }
    if (f.id) {
      out.unique_id_from_tool = f.id
      out.vuln_id_from_tool = f.id
    }

    const tags: string[] = []
    if (f.testType) tags.push(f.testType)
    if (f.owaspCategory) tags.push(f.owaspCategory)
    for (const t of f.mitreTechniques ?? []) tags.push(t)
    if (tags.length) out.tags = tags

    findings.push(out)
  }

  return { findings }
}
