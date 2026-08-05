import { describe, it, expect } from 'vitest'
import {
  opfToSarif,
  sarifToOpf,
  opfToMarkdown,
  opfToHtml,
  opfToCsv,
  csvToOpf,
  opfToDefectDojo,
  opfToGitLab,
  validateOpf,
  htmlToText,
  type OpfDocument,
} from '../src/index.js'

const FULL: OpfDocument = {
  opfVersion: '1.1',
  textFormat: 'html',
  metadata: { source: 'Cairn', exportedAt: '2026-07-31T12:00:00Z', findingCount: 2 },
  findings: [
    {
      id: 'global-cwe-89-1',
      title: 'SQL injection in the report search endpoint',
      severity: 'critical',
      category: 'Injection',
      testType: 'web-application',
      description: '<p>The <code>q</code> parameter is concatenated into the query.</p>',
      impact: 'An attacker can read arbitrary rows.',
      recommendation: 'Use parameterised queries.',
      cvssScore: 9.8,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      cvssVersion: '3.1',
      cweIds: ['CWE-89'],
      owaspCategory: 'A03:2021 Injection',
      mitreTechniques: ['T1190'],
      affectedAssets: ['https://app.example.com/search'],
      references: [{ title: 'CWE-89', url: 'https://cwe.mitre.org/data/definitions/89.html', type: 'cwe' }],
      stepsToReproduce: ["Send ' OR 1=1 in q", 'Observe the full result set'],
    },
    { title: 'S3 bucket allows public read', severity: 'high', description: 'Bucket grants s3:GetObject to *.' },
  ],
}

describe('SARIF', () => {
  it('opfToSarif emits valid SARIF 2.1.0 with security-severity and tags', () => {
    const s = opfToSarif(FULL)
    expect(s.version).toBe('2.1.0')
    const run = s.runs[0] as any
    expect(run.tool.driver.rules).toHaveLength(2)
    const r0 = run.tool.driver.rules[0]
    expect(r0.defaultConfiguration.level).toBe('error')
    expect(r0.properties['security-severity']).toBe('9.8')
    expect(r0.properties.tags).toContain('external/cwe/cwe-89')
    expect(run.results[0].locations[0].physicalLocation.artifactLocation.uri).toBe('https://app.example.com/search')
    // derived score for the High with no CVSS
    expect(run.tool.driver.rules[1].properties['security-severity']).toBe('8.0')
  })

  it('sarifToOpf round-trips core fields back to OPF', () => {
    const sarif = opfToSarif(FULL)
    const back = sarifToOpf(sarif)
    expect(back.opfVersion).toMatch(/^1\./)
    expect(back.findings).toHaveLength(2)
    const f = back.findings[0]
    expect(f.title).toBe(FULL.findings[0].title)
    expect(f.severity).toBe('critical')
    expect(f.cvssScore).toBe(9.8)
    expect(f.cweIds).toContain('CWE-89')
    expect(f.affectedAssets).toContain('https://app.example.com/search')
  })

  it('sarifToOpf maps level to severity when no security-severity present', () => {
    const doc = sarifToOpf({
      runs: [
        {
          tool: { driver: { rules: [{ id: 'r1', shortDescription: { text: 'X' } }] } },
          results: [{ ruleId: 'r1', ruleIndex: 0, level: 'warning', message: { text: 'X' } }],
        },
      ],
    })
    expect(doc.findings[0].severity).toBe('medium')
  })
})

describe('Markdown', () => {
  it('renders a summary table and a section per finding, most-severe first', () => {
    const md = opfToMarkdown(FULL)
    expect(md).toMatch(/^# Cairn findings/)
    expect(md).toContain('| Critical | 1 |')
    expect(md).toContain('| High | 1 |')
    // critical section comes before high
    expect(md.indexOf('SQL injection')).toBeLessThan(md.indexOf('S3 bucket'))
    expect(md).toContain('**Recommendation**')
    expect(md).not.toContain('<p>')
  })
})

describe('HTML', () => {
  it('produces a self-contained page and escapes content', () => {
    const doc: OpfDocument = {
      opfVersion: '1.1',
      findings: [{ title: 'XSS <script>alert(1)</script>', severity: 'medium', description: 'a & b' }],
    }
    const html = opfToHtml(doc)
    expect(html).toMatch(/^<!doctype html>/i)
    expect(html).toContain('<style>')
    expect(html).toContain('&lt;script&gt;')
    expect(html).not.toContain('<script>alert(1)')
  })
})

describe('CSV', () => {
  it('opfToCsv escapes commas/quotes/newlines', () => {
    const doc: OpfDocument = {
      opfVersion: '1.1',
      findings: [{ title: 'Has, comma "and" quote', severity: 'low', description: 'line1\nline2' }],
    }
    const csv = opfToCsv(doc)
    expect(csv.split('\r\n')[0]).toContain('title')
    expect(csv).toContain('"Has, comma ""and"" quote"')
    expect(csv).toContain('"line1\nline2"')
  })

  it('round-trips OPF -> CSV -> OPF for core fields', () => {
    const csv = opfToCsv(FULL)
    const back = csvToOpf(csv)
    expect(back.findings).toHaveLength(2)
    const f = back.findings[0]
    expect(f.title).toBe(FULL.findings[0].title)
    expect(f.severity).toBe('critical')
    expect(f.cvssScore).toBe(9.8)
    expect(f.cweIds).toContain('CWE-89')
    expect(f.affectedAssets).toContain('https://app.example.com/search')
  })
})

describe('DefectDojo', () => {
  it('emits Generic Findings Import with capitalised severity and integer cwe', () => {
    const dd = opfToDefectDojo(FULL)
    expect(dd.findings).toHaveLength(2)
    const f = dd.findings[0]
    expect(f.severity).toBe('Critical')
    expect(f.cwe).toBe(89)
    expect(f.cvssv3).toContain('CVSS:3.1')
    expect(f.cvssv3_score).toBe(9.8)
    expect(f.mitigation).toBe('Use parameterised queries.')
    expect(f.date).toBe('2026-07-31')
    expect(f.endpoints).toContain('https://app.example.com/search')
    expect(dd.findings[1].severity).toBe('High')
  })
})

describe('GitLab', () => {
  it('emits a SAST report with identifiers and severity', () => {
    const gl = opfToGitLab(FULL)
    expect(gl.scan.type).toBe('sast')
    expect(gl.vulnerabilities).toHaveLength(2)
    const v = gl.vulnerabilities[0] as any
    expect(v.severity).toBe('Critical')
    expect(v.category).toBe('sast')
    expect(v.identifiers.some((id: any) => id.type === 'cwe' && id.value === '89')).toBe(true)
    expect(v.solution).toBe('Use parameterised queries.')
  })
})

describe('validate', () => {
  it('passes a good document', () => {
    expect(validateOpf(FULL).valid).toBe(true)
  })

  it('flags missing version, bad severity, out-of-range cvss', () => {
    const r = validateOpf({
      findings: [{ title: 'ok', severity: 'spicy', cvssScore: 42 }],
    })
    expect(r.valid).toBe(false)
    const paths = r.errors.map((e) => e.path)
    expect(paths).toContain('opfVersion')
    expect(paths).toContain('findings[0].severity')
    expect(paths).toContain('findings[0].cvssScore')
  })

  it('warns on a malformed CVSS vector but stays valid', () => {
    const r = validateOpf({ opfVersion: '1.1', findings: [{ title: 't', severity: 'low', cvssVector: 'nope' }] })
    expect(r.valid).toBe(true)
    expect(r.warnings.some((w) => w.path.endsWith('cvssVector'))).toBe(true)
  })
})

describe('htmlToText', () => {
  it('strips tags and unescapes entities', () => {
    expect(htmlToText('<p>a &amp; b</p>')).toBe('a & b')
  })
})
