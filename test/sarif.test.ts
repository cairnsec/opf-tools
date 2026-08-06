import { describe, it, expect } from 'vitest'
import { opfToSarif, htmlToText, VERSION, type OpfDocument } from '../src/index.js'

const doc = (findings: unknown[]): OpfDocument =>
  ({ opfVersion: '1.1', metadata: { source: 'Cairn' }, findings }) as OpfDocument

describe('opfToSarif — document shape', () => {
  it('emits a valid SARIF 2.1.0 skeleton', () => {
    const s = opfToSarif(doc([]))
    expect(s.version).toBe('2.1.0')
    expect(s.$schema).toMatch(/sarif-2\.1\.0/)
    expect(s.runs).toHaveLength(1)
    expect(s.runs[0].tool.driver.name).toBe('Cairn')
    expect(s.runs[0].tool.driver.version).toBe('1.1')
    expect(s.runs[0].results).toEqual([])
    expect(s.runs[0].tool.driver.rules).toEqual([])
  })

  it('names the driver from options, then metadata.source, then "OPF"', () => {
    expect(opfToSarif(doc([]), { toolName: 'X' }).runs[0].tool.driver.name).toBe('X')
    expect(opfToSarif({ opfVersion: '1.1', findings: [] }).runs[0].tool.driver.name).toBe('OPF')
  })

  it('throws on a non-OPF object', () => {
    expect(() => opfToSarif({} as never)).toThrow(/findings array/)
  })
})

describe('opfToSarif — finding → rule + result', () => {
  const full = {
    id: 'global-cwe-89-1',
    title: 'SQL injection in the report search endpoint',
    severity: 'critical',
    category: 'Injection',
    testType: 'web-application',
    description: 'The q parameter is concatenated into the query.',
    impact: 'An attacker can read arbitrary rows.',
    recommendation: 'Use parameterised queries.',
    cvssScore: 9.8,
    cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
    cvssVersion: '3.1',
    cweIds: ['CWE-89'],
    owaspCategory: 'A03:2021 Injection',
    mitreTechniques: ['T1190'],
    affectedAssets: ['https://app.example.com/search', 'https://app.example.com/api'],
    references: [{ title: 'CWE-89', url: 'https://cwe.mitre.org/data/definitions/89.html', type: 'cwe' }],
    stepsToReproduce: ["Send ' OR 1=1 in q", 'Observe the full result set'],
  }

  it('maps a full finding onto one rule and one result', () => {
    const s = opfToSarif(doc([full]))
    expect(s.runs[0].tool.driver.rules).toHaveLength(1)
    expect(s.runs[0].results).toHaveLength(1)

    const rule = s.runs[0].tool.driver.rules[0]
    expect(rule.id).toBe('global-cwe-89-1')
    expect(rule.shortDescription?.text).toBe(full.title)
    expect(rule.defaultConfiguration?.level).toBe('error')
    expect(rule.helpUri).toBe('https://cwe.mitre.org/data/definitions/89.html')
    expect(rule.help?.markdown).toMatch(/\*\*Recommendation\*\*/)
    expect(rule.help?.markdown).toMatch(/Steps to reproduce/)
  })

  it('carries CVSS as security-severity and the vector in properties', () => {
    const rule = opfToSarif(doc([full])).runs[0].tool.driver.rules[0]
    expect(rule.properties?.['security-severity']).toBe('9.8')
    expect((rule.properties as any).cvss.vector).toContain('CVSS:3.1')
    expect((rule.properties as any).cvss.version).toBe('3.1')
  })

  it('emits GitHub-style CWE / OWASP / MITRE tags', () => {
    const rule = opfToSarif(doc([full])).runs[0].tool.driver.rules[0]
    const tags = rule.properties?.tags as string[]
    expect(tags).toContain('security')
    expect(tags).toContain('external/cwe/cwe-89')
    expect(tags).toContain('external/mitre/attack/T1190')
    expect(tags.some((t) => t.startsWith('external/owasp/'))).toBe(true)
  })

  it('turns affectedAssets into result locations', () => {
    const result = opfToSarif(doc([full])).runs[0].results[0]
    expect(result.locations).toHaveLength(2)
    expect(result.locations?.[0].physicalLocation.artifactLocation.uri).toBe(
      'https://app.example.com/search',
    )
    expect(result.ruleIndex).toBe(0)
    expect(result.ruleId).toBe('global-cwe-89-1')
  })
})

describe('opfToSarif — severity mapping', () => {
  const sevRule = (severity: string) =>
    opfToSarif(doc([{ title: `f-${severity}`, severity }])).runs[0].tool.driver.rules[0]

  it('maps severities to SARIF levels', () => {
    expect(sevRule('critical').defaultConfiguration?.level).toBe('error')
    expect(sevRule('high').defaultConfiguration?.level).toBe('error')
    expect(sevRule('medium').defaultConfiguration?.level).toBe('warning')
    expect(sevRule('low').defaultConfiguration?.level).toBe('note')
    expect(sevRule('informational').defaultConfiguration?.level).toBe('note')
  })

  it('synthesises security-severity from severity when no CVSS score', () => {
    expect(sevRule('critical').properties?.['security-severity']).toBe('9.5')
    expect(sevRule('high').properties?.['security-severity']).toBe('8.0')
    expect(sevRule('medium').properties?.['security-severity']).toBe('5.5')
    expect(sevRule('low').properties?.['security-severity']).toBe('2.0')
  })
})

describe('opfToSarif — edge cases', () => {
  it('generates a slug id when the finding has none, and dedupes collisions', () => {
    const s = opfToSarif(
      doc([
        { title: 'Weak TLS config', severity: 'medium' },
        { title: 'Weak TLS config', severity: 'medium' },
      ]),
    )
    const ids = s.runs[0].tool.driver.rules.map((r) => r.id)
    expect(ids[0]).toBe('weak-tls-config')
    expect(ids[1]).toBe('weak-tls-config-2')
    expect(new Set(ids).size).toBe(2)
  })

  it('skips a finding with no usable title rather than emit an invalid rule', () => {
    const s = opfToSarif(doc([{ severity: 'low' }, { title: '  ', severity: 'low' }, { title: 'ok', severity: 'low' }]))
    expect(s.runs[0].tool.driver.rules).toHaveLength(1)
    expect(s.runs[0].tool.driver.rules[0].id).toBe('ok')
  })

  it('omits locations when a finding has no assets (and no placeholder)', () => {
    const r = opfToSarif(doc([{ title: 'no-asset', severity: 'low' }])).runs[0].results[0]
    expect(r.locations).toBeUndefined()
  })

  it('uses the placeholder URI when configured and no assets exist', () => {
    const r = opfToSarif(doc([{ title: 'no-asset', severity: 'low' }]), {
      placeholderUri: 'finding-library',
    }).runs[0].results[0]
    expect(r.locations?.[0].physicalLocation.artifactLocation.uri).toBe('finding-library')
  })

  it('strips HTML from OPF text (textFormat: html)', () => {
    const r = opfToSarif(
      doc([
        {
          title: 'html finding',
          severity: 'high',
          description: '<p>Bucket policy grants <strong>s3:GetObject</strong> to&nbsp;*.</p>',
        },
      ]),
    ).runs[0].tool.driver.rules[0]
    expect(rule => rule).toBeTruthy()
    expect(r.fullDescription?.text).toBe('Bucket policy grants s3:GetObject to *.')
    expect(r.fullDescription?.text).not.toContain('<')
  })

  it('normalises assorted CWE id spellings to tags', () => {
    const rule = opfToSarif(doc([{ title: 't', severity: 'low', cweIds: ['89', 'CWE-79'] }])).runs[0]
      .tool.driver.rules[0]
    const tags = rule.properties?.tags as string[]
    expect(tags).toContain('external/cwe/cwe-89')
    expect(tags).toContain('external/cwe/cwe-79')
  })
})

describe('htmlToText', () => {
  it('unescapes entities and collapses block tags to newlines', () => {
    expect(htmlToText('<p>a</p><p>b</p>')).toBe('a\nb')
    expect(htmlToText('x &amp; y &lt;z&gt;')).toBe('x & y <z>')
    expect(htmlToText(undefined)).toBe('')
  })
})

describe('version', () => {
  it('TOOLS_VERSION matches package.json, so emitted reports do not drift', async () => {
    const { readFileSync } = await import('node:fs')
    const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf-8'))
    expect(VERSION).toBe(pkg.version)
  })
})
