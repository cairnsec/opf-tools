/**
 * OPF validator. A dependency-free structural check of an OPF 1.1 document:
 * version shape, findings array, and the required per-finding fields. Returns
 * a result rather than throwing, so it can back a CLI or a CI gate.
 */
import { SEVERITIES, type OpfSeverity } from './core.js'

export interface ValidationIssue {
  path: string
  message: string
}

export interface ValidationResult {
  valid: boolean
  errors: ValidationIssue[]
  warnings: ValidationIssue[]
}

const SEVERITY_SET = new Set<string>(SEVERITIES as OpfSeverity[])

/** Validate an arbitrary value as an OPF 1.1 document. */
export function validateOpf(input: unknown): ValidationResult {
  const errors: ValidationIssue[] = []
  const warnings: ValidationIssue[] = []
  const err = (path: string, message: string) => errors.push({ path, message })
  const warn = (path: string, message: string) => warnings.push({ path, message })

  if (input === null || typeof input !== 'object' || Array.isArray(input)) {
    return { valid: false, errors: [{ path: '', message: 'document must be a JSON object' }], warnings }
  }
  const doc = input as Record<string, unknown>

  if (typeof doc.opfVersion !== 'string') err('opfVersion', 'required string is missing')
  else if (!/^1\.\d+$/.test(doc.opfVersion)) err('opfVersion', `must match 1.x, got "${doc.opfVersion}"`)

  if (doc.textFormat != null && !['html', 'markdown', 'text'].includes(doc.textFormat as string))
    err('textFormat', 'must be one of html | markdown | text')

  if (!Array.isArray(doc.findings)) {
    err('findings', 'required array is missing')
    return { valid: errors.length === 0, errors, warnings }
  }

  doc.findings.forEach((raw, i) => {
    const p = `findings[${i}]`
    if (raw === null || typeof raw !== 'object' || Array.isArray(raw)) {
      err(p, 'must be an object')
      return
    }
    const f = raw as Record<string, unknown>
    if (typeof f.title !== 'string' || !f.title.trim()) err(`${p}.title`, 'required non-empty string is missing')
    if (typeof f.severity !== 'string') err(`${p}.severity`, 'required string is missing')
    else if (!SEVERITY_SET.has(f.severity)) err(`${p}.severity`, `must be one of ${SEVERITIES.join(' | ')}, got "${f.severity}"`)

    if (f.cvssScore != null && (typeof f.cvssScore !== 'number' || f.cvssScore < 0 || f.cvssScore > 10))
      err(`${p}.cvssScore`, 'must be a number between 0 and 10')

    for (const arrField of ['cweIds', 'cveIds', 'mitreTechniques', 'affectedAssets', 'stepsToReproduce']) {
      if (f[arrField] != null && !Array.isArray(f[arrField])) err(`${p}.${arrField}`, 'must be an array')
    }
    if (f.references != null) {
      if (!Array.isArray(f.references)) err(`${p}.references`, 'must be an array')
      else
        f.references.forEach((r, j) => {
          if (!r || typeof r !== 'object' || typeof (r as { url?: unknown }).url !== 'string')
            err(`${p}.references[${j}].url`, 'reference requires a url string')
        })
    }
    if (f.cvssVector != null && typeof f.cvssVector === 'string' && !/^CVSS:\d/.test(f.cvssVector))
      warn(`${p}.cvssVector`, 'does not look like a CVSS vector string')
  })

  return { valid: errors.length === 0, errors, warnings }
}
