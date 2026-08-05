/**
 * OPF ↔ SARIF 2.1.0.
 *
 * SARIF is what GitHub code scanning, Azure DevOps and the VS Code SARIF
 * Viewer read. `opfToSarif` lets an OPF library be triaged there; `sarifToOpf`
 * brings scanner SARIF back into OPF.
 *
 * SARIF 2.1.0: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */
import {
  type OpfDocument,
  type OpfFinding,
  type OpfSeverity,
  allCwes,
  assertOpf,
  coerceSeverity,
  effectiveScore,
  htmlToText,
  makeUniqueId,
  newOpfDocument,
} from './core.js'

const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json'

export type SarifLevel = 'error' | 'warning' | 'note' | 'none'

const SEVERITY_TO_LEVEL: Record<OpfSeverity, SarifLevel> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  informational: 'note',
}

const LEVEL_TO_SEVERITY: Record<SarifLevel, OpfSeverity> = {
  error: 'high',
  warning: 'medium',
  note: 'low',
  none: 'informational',
}

export interface SarifLog {
  $schema: string
  version: '2.1.0'
  runs: unknown[]
}

export interface OpfToSarifOptions {
  toolName?: string
  informationUri?: string
  placeholderUri?: string
}

function cweTag(id: string): string | null {
  const m = /(\d+)/.exec(id)
  return m ? `external/cwe/cwe-${m[1]}` : null
}

function buildTags(f: OpfFinding): string[] {
  const tags = new Set<string>(['security'])
  if (f.testType) tags.add(f.testType)
  if (f.category && f.category !== 'general') tags.add(f.category)
  for (const c of allCwes(f)) {
    const t = cweTag(c)
    if (t) tags.add(t)
  }
  if (f.owaspCategory) tags.add(`external/owasp/${f.owaspCategory.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '')}`)
  for (const t of f.mitreTechniques ?? []) tags.add(`external/mitre/attack/${t}`)
  return [...tags]
}

function buildHelp(f: OpfFinding): { text: string; markdown: string } {
  const textParts: string[] = []
  const mdParts: string[] = []
  const push = (label: string, value?: string) => {
    const v = htmlToText(value)
    if (!v) return
    textParts.push(label ? `${label}:\n${v}` : v)
    mdParts.push(label ? `**${label}**\n\n${v}` : v)
  }
  push('', f.description)
  push('Impact', f.impact)
  push('Recommendation', f.recommendation)
  push('Technical detail', f.technicalDetails)
  if (f.stepsToReproduce?.length) {
    const steps = f.stepsToReproduce.map((s, i) => `${i + 1}. ${htmlToText(s)}`).join('\n')
    textParts.push(`Steps to reproduce:\n${steps}`)
    mdParts.push(`**Steps to reproduce**\n\n${steps}`)
  }
  if (f.references?.length) {
    mdParts.push(`**References**\n\n${f.references.map((r) => `- [${r.title || r.url}](${r.url})`).join('\n')}`)
    textParts.push(`References:\n${f.references.map((r) => r.url).join('\n')}`)
  }
  return { text: textParts.join('\n\n'), markdown: mdParts.join('\n\n') }
}

/** Convert an OPF document to a SARIF 2.1.0 log. */
export function opfToSarif(doc: OpfDocument, options: OpfToSarifOptions = {}): SarifLog {
  assertOpf(doc)
  const toolName = options.toolName ?? doc.metadata?.source ?? 'OPF'
  const informationUri = options.informationUri ?? 'https://cairnsecurity.com/opf'
  const uid = makeUniqueId()

  const rules: unknown[] = []
  const results: unknown[] = []

  for (const f of doc.findings) {
    if (!f || typeof f.title !== 'string' || !f.title.trim()) continue
    const severity = coerceSeverity(f.severity)
    const level = SEVERITY_TO_LEVEL[severity]
    const ruleId = uid(f.id, f.title)
    const help = buildHelp(f)
    const cwes = allCwes(f)
    const secSeverity = effectiveScore(f).toFixed(1)
    const fullDesc = htmlToText(f.description)

    const ruleProps: Record<string, unknown> = {
      tags: buildTags(f),
      'security-severity': secSeverity,
      'opf-severity': severity,
    }
    if (cwes.length) ruleProps.cwe = cwes
    if (f.cveIds?.length) ruleProps.cve = f.cveIds
    if (f.owaspCategory) ruleProps.owasp = f.owaspCategory
    if (f.mitreTechniques?.length) ruleProps.mitre = f.mitreTechniques
    if (f.cvssVector || typeof f.cvssScore === 'number') {
      ruleProps.cvss = {
        ...(typeof f.cvssScore === 'number' ? { score: f.cvssScore } : {}),
        ...(f.cvssVector ? { vector: f.cvssVector } : {}),
        ...(f.cvssVersion ? { version: f.cvssVersion } : {}),
      }
    }

    const rule: Record<string, unknown> = {
      id: ruleId,
      name: f.title,
      shortDescription: { text: f.title },
      defaultConfiguration: { level },
      properties: ruleProps,
    }
    if (fullDesc) rule.fullDescription = { text: fullDesc }
    if (help.text) rule.help = { text: help.text, ...(help.markdown ? { markdown: help.markdown } : {}) }
    const helpUri = f.references?.find((r) => r.url)?.url
    if (helpUri) rule.helpUri = helpUri

    const assets = (f.affectedAssets ?? []).filter((a) => typeof a === 'string' && a.trim())
    const uris = assets.length ? assets : options.placeholderUri ? [options.placeholderUri] : []
    const locations = uris.map((uri) => ({ physicalLocation: { artifactLocation: { uri } } }))

    const result: Record<string, unknown> = {
      ruleId,
      ruleIndex: rules.length,
      level,
      message: { text: fullDesc || f.title },
      partialFingerprints: { opfFindingId: ruleId },
      properties: { 'security-severity': secSeverity },
    }
    if (locations.length) result.locations = locations

    rules.push(rule)
    results.push(result)
  }

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: toolName,
            version: doc.opfVersion,
            informationUri,
            rules,
            properties: {
              opfVersion: doc.opfVersion,
              ...(doc.metadata?.exportedAt ? { exportedAt: doc.metadata.exportedAt } : {}),
            },
          },
        },
        results,
      },
    ],
  }
}

/* ----------------------------------------------------------------------- */
/*  SARIF → OPF                                                             */
/* ----------------------------------------------------------------------- */

interface SarifRuleLike {
  id?: string
  name?: string
  shortDescription?: { text?: string }
  fullDescription?: { text?: string }
  help?: { text?: string; markdown?: string }
  helpUri?: string
  defaultConfiguration?: { level?: string }
  properties?: Record<string, unknown>
}

function cweFromTags(tags: unknown): string[] {
  if (!Array.isArray(tags)) return []
  const out: string[] = []
  for (const t of tags) {
    const m = /cwe[-/](\d+)/i.exec(String(t))
    if (m) out.push(`CWE-${m[1]}`)
  }
  return out
}

/**
 * Convert a SARIF 2.1.0 log into an OPF document. Each result becomes a
 * finding; its rule supplies the title, description and metadata. Severity is
 * taken from `security-severity` (CVSS) when present, else the SARIF level.
 */
export function sarifToOpf(sarif: unknown, source = 'SARIF'): OpfDocument {
  const log = sarif as { runs?: unknown[] }
  if (!log || !Array.isArray(log.runs)) {
    throw new TypeError('expected a SARIF log with a runs array')
  }
  const doc = newOpfDocument(source)

  for (const runU of log.runs) {
    const run = runU as {
      tool?: { driver?: { rules?: SarifRuleLike[] } }
      results?: unknown[]
    }
    const rules = run.tool?.driver?.rules ?? []
    const results = Array.isArray(run.results) ? run.results : []

    for (const resU of results) {
      const res = resU as {
        ruleId?: string
        ruleIndex?: number
        level?: string
        message?: { text?: string }
        locations?: Array<{ physicalLocation?: { artifactLocation?: { uri?: string } } }>
        properties?: Record<string, unknown>
      }
      const rule =
        (typeof res.ruleIndex === 'number' ? rules[res.ruleIndex] : undefined) ??
        rules.find((r) => r.id === res.ruleId) ??
        ({} as SarifRuleLike)

      const title =
        rule.shortDescription?.text || rule.name || res.message?.text || res.ruleId || 'Untitled finding'

      const secSev = res.properties?.['security-severity'] ?? rule.properties?.['security-severity']
      const score = secSev != null && !Number.isNaN(Number(secSev)) ? Number(secSev) : undefined
      const severity: OpfSeverity = score != null ? scoreToSeverity(score) : LEVEL_TO_SEVERITY[(res.level as SarifLevel) || (rule.defaultConfiguration?.level as SarifLevel) || 'warning'] ?? 'medium'

      const cwes = [
        ...cweFromTags(rule.properties?.tags),
        ...(Array.isArray(rule.properties?.cwe) ? (rule.properties!.cwe as string[]) : []),
      ]
      const assets = (res.locations ?? [])
        .map((l) => l.physicalLocation?.artifactLocation?.uri)
        .filter((u): u is string => typeof u === 'string')

      const finding: OpfFinding = {
        id: res.ruleId,
        title,
        severity,
        description: rule.fullDescription?.text || rule.help?.text || res.message?.text || '',
      }
      const cvss = rule.properties?.cvss as { score?: number; vector?: string; version?: string } | undefined
      if (typeof cvss?.score === 'number') finding.cvssScore = cvss.score
      else if (score != null) finding.cvssScore = score
      if (cvss?.vector) finding.cvssVector = cvss.vector
      if (cvss?.version) finding.cvssVersion = cvss.version
      if (cwes.length) finding.cweIds = [...new Set(cwes)]
      if (rule.helpUri) finding.references = [{ url: rule.helpUri }]
      if (assets.length) finding.affectedAssets = assets
      if (Array.isArray(rule.properties?.tags)) {
        const tt = (rule.properties!.tags as string[]).find((t) => !t.includes('/') && t !== 'security')
        if (tt) finding.testType = tt
      }

      doc.findings.push(finding)
    }
  }

  if (doc.metadata) doc.metadata.findingCount = doc.findings.length
  return doc
}

function scoreToSeverity(score: number): OpfSeverity {
  if (score >= 9.0) return 'critical'
  if (score >= 7.0) return 'high'
  if (score >= 4.0) return 'medium'
  if (score > 0) return 'low'
  return 'informational'
}
