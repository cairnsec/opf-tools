/**
 * OPF ↔ DefectDojo.
 *
 * DefectDojo is the most widely used open-source vulnerability manager.
 *   - opfToDefectDojo: OPF → the generic importer's `{ findings: [...] }` document,
 *     so an OPF library imports straight in with no custom parser.
 *   - defectDojoToOpf / fetchDefectDojoOpf: DefectDojo REST-API findings → OPF, so
 *     everything DefectDojo aggregates (~200 scanners) becomes reachable as OPF.
 *
 * Generic import: https://documentation.defectdojo.com/integrations/parsers/file/generic/
 * Findings API:   GET /api/v2/findings/  (auth header: `Authorization: Token <key>`)
 */
import {
  type OpfDocument,
  type OpfFinding,
  type OpfReference,
  type OpfSeverity,
  allCwes,
  assertOpf,
  coerceSeverity,
  cweNumber,
  htmlToText,
  newOpfDocument,
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

// --- DefectDojo → OPF ------------------------------------------------------

/** A DefectDojo REST-API finding (the fields this converter reads; others ignored). */
export interface DefectDojoApiFinding {
  id?: number
  title?: string
  severity?: string
  description?: string
  mitigation?: string
  impact?: string
  steps_to_reproduce?: string
  references?: string
  cwe?: number
  cvssv3?: string
  cvssv3_score?: number
  cvssv4?: string
  cvssv4_score?: number
  vulnerability_ids?: Array<{ vulnerability_id?: string }>
  endpoints?: unknown[]
  tags?: unknown
  unique_id_from_tool?: string
  vuln_id_from_tool?: string
  active?: boolean
  false_p?: boolean
  duplicate?: boolean
  [key: string]: unknown
}

interface DefectDojoPage {
  next?: string | null
  results?: DefectDojoApiFinding[]
}

export interface DdToOpfOptions {
  /** Include findings marked inactive. Default false. */
  includeInactive?: boolean
  /** Include findings flagged false-positive. Default false. */
  includeFalsePositives?: boolean
  /** Include findings flagged duplicate. Default false. */
  includeDuplicates?: boolean
  /** metadata.source on the emitted document. Default "DefectDojo". */
  source?: string
  /** metadata.exportedAt on the emitted document. */
  exportedAt?: string
}

function extractFindings(input: unknown): DefectDojoApiFinding[] {
  if (Array.isArray(input)) return input as DefectDojoApiFinding[]
  if (input && typeof input === 'object') {
    const o = input as Record<string, unknown>
    if (Array.isArray(o.results)) return o.results as DefectDojoApiFinding[]
    if (Array.isArray(o.findings)) return o.findings as DefectDojoApiFinding[]
  }
  throw new TypeError(
    'defectDojoToOpf: expected a DefectDojo findings array, {results:[...]}, or {findings:[...]}',
  )
}

function shouldInclude(dd: DefectDojoApiFinding, o: DdToOpfOptions): boolean {
  if (!o.includeInactive && dd.active === false) return false
  if (!o.includeFalsePositives && dd.false_p === true) return false
  if (!o.includeDuplicates && dd.duplicate === true) return false
  return true
}

/** Split DefectDojo's free-text steps into an OPF array, stripping any `N.` numbering. */
function splitSteps(text: unknown): string[] {
  if (typeof text !== 'string') return []
  return text
    .split(/\r?\n/)
    .map((line) => line.replace(/^\s*\d+[.)]\s*/, '').trim())
    .filter(Boolean)
}

/** Extract one reference per line from DefectDojo's free-text references field. */
function parseReferences(text: unknown): OpfReference[] {
  if (typeof text !== 'string') return []
  const out: OpfReference[] = []
  for (const line of text.split(/\r?\n/)) {
    const trimmed = line.trim()
    if (!trimmed) continue
    const m = /(https?:\/\/\S+)/.exec(trimmed)
    if (!m) continue
    const label = trimmed.slice(0, m.index).replace(/[:\-\s]+$/, '').trim()
    out.push(label ? { url: m[1], title: label } : { url: m[1] })
  }
  return out
}

/** Merge one entry into a finding's customFields without clobbering existing keys. */
function addCustomField(f: OpfFinding, key: string, value: unknown): void {
  f.customFields = { ...(f.customFields ?? {}), [key]: value }
}

/** Read the CVSS version from a vector's `CVSS:x.y` prefix, else the fallback. */
function cvssVersionOf(vector: string, fallback: string): string {
  const m = /^CVSS:(\d+\.\d+)/.exec(vector)
  return m ? m[1] : fallback
}

/** The severities coerceSeverity treats as informational; used to detect a real downgrade. */
const INFORMATIONAL_ALIASES = new Set(['informational', 'info', 'information', 'none'])

/** Route DefectDojo's flat tags into OPF owasp/mitre fields, the rest into customFields. */
function routeTags(f: OpfFinding, tags: unknown): void {
  if (!Array.isArray(tags)) return
  const mitre: string[] = []
  const other: string[] = []
  let owasp: string | undefined
  for (const raw of tags) {
    const t = typeof raw === 'string' ? raw.trim() : ''
    if (!t) continue
    if (/^A\d{1,2}:\d{4}/i.test(t)) {
      if (owasp === undefined) owasp = t
      else other.push(t)
    } else if (/^T\d{4,}(\.\d+)?$/i.test(t)) {
      mitre.push(t)
    } else {
      other.push(t)
    }
  }
  if (owasp) f.owaspCategory = owasp
  if (mitre.length) f.mitreTechniques = mitre
  if (other.length) addCustomField(f, 'tags', other)
}

function ddFindingToOpf(dd: DefectDojoApiFinding): OpfFinding | null {
  const title = typeof dd.title === 'string' ? dd.title.trim() : ''
  if (!title) return null

  const f: OpfFinding = { title, severity: coerceSeverity(dd.severity) }

  // If a non-empty severity was not recognised, coerceSeverity silently downgrades
  // it to informational; preserve the original so the downgrade stays auditable.
  const rawSeverity = typeof dd.severity === 'string' ? dd.severity.trim() : ''
  if (rawSeverity && f.severity === 'informational' && !INFORMATIONAL_ALIASES.has(rawSeverity.toLowerCase())) {
    addCustomField(f, 'originalSeverity', rawSeverity)
  }

  const id = dd.unique_id_from_tool || dd.vuln_id_from_tool || (dd.id != null ? String(dd.id) : '')
  if (id) f.id = id

  if (typeof dd.description === 'string' && dd.description) f.description = dd.description
  if (typeof dd.impact === 'string' && dd.impact) f.impact = dd.impact
  if (typeof dd.mitigation === 'string' && dd.mitigation) f.recommendation = dd.mitigation

  // Prefer a v4 vector, then v3; fall back to whichever score is present.
  if (dd.cvssv4) {
    f.cvssVector = dd.cvssv4
    f.cvssVersion = cvssVersionOf(dd.cvssv4, '4.0')
    if (typeof dd.cvssv4_score === 'number') f.cvssScore = dd.cvssv4_score
  } else if (dd.cvssv3) {
    f.cvssVector = dd.cvssv3
    f.cvssVersion = cvssVersionOf(dd.cvssv3, '3.1')
    if (typeof dd.cvssv3_score === 'number') f.cvssScore = dd.cvssv3_score
  } else if (typeof dd.cvssv4_score === 'number') {
    f.cvssScore = dd.cvssv4_score
  } else if (typeof dd.cvssv3_score === 'number') {
    f.cvssScore = dd.cvssv3_score
  }

  if (typeof dd.cwe === 'number' && dd.cwe > 0) f.cweIds = [`CWE-${dd.cwe}`]

  // Guard the array like the sibling fields: a non-array vulnerability_ids from
  // the untrusted API must not crash the whole conversion via .map.
  const vulnIds = (Array.isArray(dd.vulnerability_ids) ? dd.vulnerability_ids : [])
    .map((v) => (v && typeof v.vulnerability_id === 'string' ? v.vulnerability_id : ''))
    .filter(Boolean)
  const cves = vulnIds.filter((v) => /^CVE-/i.test(v))
  if (cves.length) f.cveIds = cves
  // Non-CVE identifiers (GHSA, OSV, vendor ids) have no OPF field; keep them in
  // customFields rather than dropping them silently.
  const otherIds = vulnIds.filter((v) => !/^CVE-/i.test(v))
  if (otherIds.length) addCustomField(f, 'vulnerabilityIds', otherIds)

  const steps = splitSteps(dd.steps_to_reproduce)
  if (steps.length) f.stepsToReproduce = steps

  const refs = parseReferences(dd.references)
  if (refs.length) f.references = refs

  // The findings API returns `endpoints` as numeric ids, which are dropped here;
  // only string endpoints are carried through. Resolving ids to URLs is a future opt-in.
  const assets = (Array.isArray(dd.endpoints) ? dd.endpoints : []).filter(
    (e): e is string => typeof e === 'string' && !!e.trim(),
  )
  if (assets.length) f.affectedAssets = assets

  routeTags(f, dd.tags)
  return f
}

/**
 * Convert DefectDojo findings JSON to an OPF document. Accepts a REST-API page
 * (`{ results: [...] }`), a bare findings array, or a `{ findings: [...] }`
 * object. By default excludes inactive, false-positive and duplicate findings.
 */
export function defectDojoToOpf(input: unknown, options: DdToOpfOptions = {}): OpfDocument {
  const incoming = extractFindings(input)
  const doc = newOpfDocument(options.source ?? 'DefectDojo', options.exportedAt)
  doc.textFormat = 'markdown'
  for (const dd of incoming) {
    if (!shouldInclude(dd, options)) continue
    const f = ddFindingToOpf(dd)
    if (f) doc.findings.push(f)
  }
  if (doc.metadata) doc.metadata.findingCount = doc.findings.length
  return doc
}

export interface FetchDefectDojoOptions extends DdToOpfOptions {
  /** DefectDojo base URL, e.g. https://dojo.example.com. Trailing slashes trimmed. */
  baseUrl: string
  /** API token (DefectDojo uses `Authorization: Token <key>`). */
  apiToken: string
  /** Server-side scoping filters passed as query params. */
  filters?: {
    product?: string | number
    engagement?: string | number
    test?: string | number
    severity?: string
    active?: boolean
    /** Page size. Default 100. */
    limit?: number
  }
  /** Safety cap on pages followed. Default 100. */
  maxPages?: number
  /** Injected fetch, for testing. Defaults to the global fetch (Node >= 18). */
  fetch?: typeof fetch
}

/**
 * Pull findings from a live DefectDojo instance (following pagination) and
 * convert them to OPF. Rejects with the status and how many findings were
 * collected if a page fails.
 */
export async function fetchDefectDojoOpf(options: FetchDefectDojoOptions): Promise<OpfDocument> {
  const doFetch = options.fetch ?? globalThis.fetch
  if (typeof doFetch !== 'function') {
    throw new Error('fetchDefectDojoOpf: no fetch available (use Node >= 18 or pass options.fetch)')
  }
  if (!options.baseUrl) throw new TypeError('fetchDefectDojoOpf: options.baseUrl is required')

  const base = options.baseUrl.replace(/\/+$/, '')
  const headers = { Authorization: `Token ${options.apiToken}`, Accept: 'application/json' }
  const maxPages = options.maxPages ?? 100

  const filters = options.filters ?? {}
  const params = new URLSearchParams()
  if (filters.product != null) params.set('product', String(filters.product))
  if (filters.engagement != null) params.set('engagement', String(filters.engagement))
  if (filters.test != null) params.set('test', String(filters.test))
  if (filters.severity) params.set('severity', filters.severity)
  if (filters.active != null) params.set('active', String(filters.active))
  params.set('limit', String(filters.limit ?? 100))

  const baseOrigin = new URL(base).origin
  let url: string | null = `${base}/api/v2/findings/?${params.toString()}`
  const all: DefectDojoApiFinding[] = []

  for (let page = 0; url && page < maxPages; page++) {
    const res = await doFetch(url, { method: 'GET', headers })
    const text = await res.text()
    if (!res.ok) {
      throw new Error(`DefectDojo fetch failed (${res.status}) after ${all.length} findings: ${text.slice(0, 500)}`)
    }
    let body: DefectDojoPage
    try {
      body = text ? (JSON.parse(text) as DefectDojoPage) : {}
    } catch {
      throw new Error(`DefectDojo returned a non-JSON response (${res.status}): ${text.slice(0, 500)}`)
    }
    if (Array.isArray(body.results)) {
      all.push(...body.results)
    } else if (body.results != null) {
      // A present-but-non-array results is a shape mismatch (e.g. an error
      // envelope on a 200); reject it rather than silently treating it as empty.
      throw new TypeError(
        `DefectDojo page had a non-array "results" (${typeof body.results}); unexpected response shape: ${text.slice(0, 300)}`,
      )
    }
    // Follow pagination only within the configured origin: the API token must
    // never be sent to a host a compromised/MITM'd DefectDojo redirects us to.
    if (typeof body.next === 'string' && body.next) {
      const nextUrl = new URL(body.next, base)
      if (nextUrl.origin !== baseOrigin) {
        throw new Error(
          `DefectDojo pagination pointed off-origin (${nextUrl.origin}); refusing to send the API token there`,
        )
      }
      url = nextUrl.toString()
    } else {
      url = null
    }
  }

  // If pagination is still pending we hit the page cap: fail loud rather than
  // return a truncated OPF that looks complete.
  if (url) {
    throw new Error(
      `fetchDefectDojoOpf: stopped at maxPages=${maxPages} (~${all.length} findings) with more pages remaining; raise options.maxPages or narrow filters`,
    )
  }

  // A server-side `active=false` filter implies the caller wants inactive
  // findings, so honour it on the client side unless explicitly overridden.
  const includeInactive = options.includeInactive ?? (filters.active === false)
  return defectDojoToOpf(all, { ...options, includeInactive })
}
