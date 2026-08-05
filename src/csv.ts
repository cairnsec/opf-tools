/**
 * OPF ↔ CSV. A flat, spreadsheet-friendly view of a finding library, and a
 * reader that turns such a sheet back into OPF. RFC-4180 quoting.
 */
import {
  type OpfDocument,
  type OpfFinding,
  allCwes,
  assertOpf,
  coerceSeverity,
  htmlToText,
  newOpfDocument,
} from './core.js'

const COLUMNS = [
  'id',
  'title',
  'severity',
  'cvssScore',
  'cvssVector',
  'cwe',
  'cve',
  'category',
  'testType',
  'owaspCategory',
  'description',
  'impact',
  'recommendation',
  'affectedAssets',
  'references',
] as const

function csvEscape(value: string): string {
  if (/[",\r\n]/.test(value)) return `"${value.replace(/"/g, '""')}"`
  return value
}

function cell(f: OpfFinding, col: (typeof COLUMNS)[number]): string {
  switch (col) {
    case 'id':
      return f.id ?? ''
    case 'title':
      return f.title ?? ''
    case 'severity':
      return coerceSeverity(f.severity)
    case 'cvssScore':
      return typeof f.cvssScore === 'number' ? String(f.cvssScore) : ''
    case 'cvssVector':
      return f.cvssVector ?? ''
    case 'cwe':
      return allCwes(f).join('; ')
    case 'cve':
      return (f.cveIds ?? []).join('; ')
    case 'category':
      return f.category ?? ''
    case 'testType':
      return f.testType ?? ''
    case 'owaspCategory':
      return f.owaspCategory ?? ''
    case 'description':
      return htmlToText(f.description)
    case 'impact':
      return htmlToText(f.impact)
    case 'recommendation':
      return htmlToText(f.recommendation)
    case 'affectedAssets':
      return (f.affectedAssets ?? []).join('; ')
    case 'references':
      return (f.references ?? []).map((r) => r.url).join('; ')
  }
}

/** Render an OPF document as CSV. */
export function opfToCsv(doc: OpfDocument): string {
  assertOpf(doc)
  const rows = [COLUMNS.join(',')]
  for (const f of doc.findings) {
    if (!f?.title) continue
    rows.push(COLUMNS.map((c) => csvEscape(cell(f, c))).join(','))
  }
  return rows.join('\r\n') + '\r\n'
}

/** Parse RFC-4180 CSV text into rows of string cells. */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = []
  let row: string[] = []
  let field = ''
  let inQuotes = false
  const s = text.replace(/\r\n/g, '\n').replace(/\r/g, '\n')

  for (let i = 0; i < s.length; i++) {
    const ch = s[i]
    if (inQuotes) {
      if (ch === '"') {
        if (s[i + 1] === '"') {
          field += '"'
          i++
        } else inQuotes = false
      } else field += ch
    } else if (ch === '"') {
      inQuotes = true
    } else if (ch === ',') {
      row.push(field)
      field = ''
    } else if (ch === '\n') {
      row.push(field)
      rows.push(row)
      row = []
      field = ''
    } else field += ch
  }
  if (field.length || row.length) {
    row.push(field)
    rows.push(row)
  }
  return rows.filter((r) => r.some((c) => c.trim() !== ''))
}

function splitList(value: string): string[] {
  return value
    .split(/[;|]/)
    .map((s) => s.trim())
    .filter(Boolean)
}

/**
 * Parse a CSV back into an OPF document. Recognises the columns emitted by
 * `opfToCsv`; header matching is case-insensitive and unknown columns are
 * ignored. Only `title` and `severity` are required per row.
 */
export function csvToOpf(text: string, source = 'CSV'): OpfDocument {
  const rows = parseCsv(text)
  if (!rows.length) return newOpfDocument(source)
  const header = rows[0].map((h) => h.trim().toLowerCase())
  const idx = (name: string) => header.indexOf(name.toLowerCase())
  const col = (r: string[], name: string) => {
    const i = idx(name)
    return i >= 0 ? (r[i] ?? '').trim() : ''
  }

  const doc = newOpfDocument(source)
  for (const r of rows.slice(1)) {
    const title = col(r, 'title')
    if (!title) continue
    const f: OpfFinding = { title, severity: coerceSeverity(col(r, 'severity')) }
    const id = col(r, 'id')
    if (id) f.id = id
    const score = col(r, 'cvssScore') || col(r, 'cvss')
    if (score && !Number.isNaN(Number(score))) f.cvssScore = Number(score)
    const vector = col(r, 'cvssVector')
    if (vector) f.cvssVector = vector
    const cwe = col(r, 'cwe')
    if (cwe) f.cweIds = splitList(cwe)
    const cve = col(r, 'cve')
    if (cve) f.cveIds = splitList(cve)
    const category = col(r, 'category')
    if (category) f.category = category
    const testType = col(r, 'testType')
    if (testType) f.testType = testType
    const owasp = col(r, 'owaspCategory')
    if (owasp) f.owaspCategory = owasp
    const desc = col(r, 'description')
    if (desc) f.description = desc
    const impact = col(r, 'impact')
    if (impact) f.impact = impact
    const rec = col(r, 'recommendation')
    if (rec) f.recommendation = rec
    const assets = col(r, 'affectedAssets')
    if (assets) f.affectedAssets = splitList(assets)
    const refs = col(r, 'references')
    if (refs) f.references = splitList(refs).map((url) => ({ url }))
    doc.findings.push(f)
  }
  if (doc.metadata) doc.metadata.findingCount = doc.findings.length
  return doc
}
