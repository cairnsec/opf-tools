/**
 * Shared core for the OPF converter suite: the OPF 1.1 types and the small
 * text/id helpers every converter needs. Zero dependencies.
 *
 * OPF spec: https://cairnsecurity.com/opf
 */

export type OpfSeverity = 'critical' | 'high' | 'medium' | 'low' | 'informational'

export const SEVERITIES: OpfSeverity[] = ['critical', 'high', 'medium', 'low', 'informational']

/** Severity → sort rank (0 = most severe), for ordering output. */
export const SEVERITY_RANK: Record<OpfSeverity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  informational: 4,
}

/** Synthetic CVSS score per severity, used when a finding carries no cvssScore. */
export const SEVERITY_TO_SCORE: Record<OpfSeverity, number> = {
  critical: 9.5,
  high: 8.0,
  medium: 5.5,
  low: 2.0,
  informational: 0.0,
}

export interface OpfReference {
  title?: string
  url: string
  type?: string
}

export interface OpfFinding {
  id?: string
  title: string
  severity: OpfSeverity
  category?: string
  testType?: string
  description?: string
  impact?: string
  recommendation?: string
  technicalDetails?: string
  cvssScore?: number
  cvssVector?: string
  cvssVersion?: string
  cweId?: string
  cweIds?: string[]
  cveIds?: string[]
  owaspCategory?: string
  mitreTechniques?: string[]
  affectedAssets?: string[]
  references?: OpfReference[]
  stepsToReproduce?: string[]
  customFields?: Record<string, unknown>
  [key: string]: unknown
}

export interface OpfDocument {
  opfVersion: string
  textFormat?: 'html' | 'markdown' | 'text'
  metadata?: {
    source?: string
    exportedAt?: string
    description?: string
    findingCount?: number
  }
  findings: OpfFinding[]
}

export const OPF_VERSION = '1.1'

/** Assert (loosely) that a value is an OPF document; throw otherwise. */
export function assertOpf(doc: unknown): asserts doc is OpfDocument {
  if (!doc || typeof doc !== 'object' || !Array.isArray((doc as OpfDocument).findings)) {
    throw new TypeError('expected an OPF document with a findings array')
  }
}

/** Build an empty OPF document with sensible metadata defaults. */
export function newOpfDocument(source = 'opf-tools', exportedAt?: string): OpfDocument {
  return {
    opfVersion: OPF_VERSION,
    textFormat: 'text',
    metadata: { source, ...(exportedAt ? { exportedAt } : {}), findingCount: 0 },
    findings: [],
  }
}

/** Coerce an arbitrary string to a known OPF severity, defaulting to informational. */
export function coerceSeverity(input: unknown): OpfSeverity {
  const s = String(input ?? '').toLowerCase().trim()
  if (s === 'critical' || s === 'crit') return 'critical'
  if (s === 'high') return 'high'
  if (s === 'medium' || s === 'moderate' || s === 'med') return 'medium'
  if (s === 'low') return 'low'
  if (s === 'informational' || s === 'info' || s === 'information' || s === 'none') return 'informational'
  return 'informational'
}

/** Convert OPF HTML/markdown text into plain text. */
export function htmlToText(input?: string): string {
  if (!input) return ''
  return input
    .replace(/<br\s*\/?>/gi, '\n')
    .replace(/<\/(p|div|li|h[1-6]|tr)>/gi, '\n')
    .replace(/<li[^>]*>/gi, '- ')
    .replace(/<[^>]+>/g, '')
    .replace(/&nbsp;/gi, ' ')
    .replace(/&amp;/gi, '&')
    .replace(/&lt;/gi, '<')
    .replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"')
    .replace(/&#0?39;|&apos;|&rsquo;|&lsquo;/gi, "'")
    .replace(/&ldquo;|&rdquo;/gi, '"')
    .replace(/&mdash;/gi, '-')
    .replace(/&#\d+;/g, '')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim()
}

/** Escape text for safe insertion into HTML. */
export function escapeHtml(input: string): string {
  return input
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

export function slugify(input: string): string {
  return (
    input
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 80) || 'finding'
  )
}

/** Normalise a CWE id ("CWE-89", "89", "cwe 89") to canonical "CWE-89". */
export function normalizeCwe(id: string): string | null {
  const m = /(\d+)/.exec(id)
  return m ? `CWE-${m[1]}` : null
}

/** Numeric CWE, e.g. "CWE-89" → 89. */
export function cweNumber(id: string): number | null {
  const m = /(\d+)/.exec(id)
  return m ? Number(m[1]) : null
}

/** All CWE ids on a finding, canonicalised and de-duped (cweIds + legacy cweId). */
export function allCwes(f: OpfFinding): string[] {
  const raw = [...(f.cweIds ?? []), ...(f.cweId ? [f.cweId] : [])]
  const seen = new Set<string>()
  const out: string[] = []
  for (const c of raw) {
    const n = normalizeCwe(c)
    if (n && !seen.has(n)) {
      seen.add(n)
      out.push(n)
    }
  }
  return out
}

/** CVSS score for a finding: the explicit score, else derived from severity. */
export function effectiveScore(f: OpfFinding): number {
  return typeof f.cvssScore === 'number' ? f.cvssScore : SEVERITY_TO_SCORE[coerceSeverity(f.severity)]
}

/** A stable, unique id generator that de-dupes collisions with a -2/-3 suffix. */
export function makeUniqueId(): (preferred: string | undefined, fallback: string) => string {
  const used = new Set<string>()
  return (preferred, fallback) => {
    let id = (typeof preferred === 'string' && preferred.trim()) || slugify(fallback)
    if (used.has(id)) {
      let n = 2
      while (used.has(`${id}-${n}`)) n++
      id = `${id}-${n}`
    }
    used.add(id)
    return id
  }
}

/** Findings sorted most-severe first, stable within a severity. */
export function sortedBySeverity(findings: OpfFinding[]): OpfFinding[] {
  return findings
    .map((f, i) => ({ f, i }))
    .sort((a, b) => SEVERITY_RANK[coerceSeverity(a.f.severity)] - SEVERITY_RANK[coerceSeverity(b.f.severity)] || a.i - b.i)
    .map((x) => x.f)
}
