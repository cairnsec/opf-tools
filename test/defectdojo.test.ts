import { describe, it, expect } from 'vitest'
import { defectDojoToOpf, fetchDefectDojoOpf, opfToDefectDojo } from '../src/index.js'

const PAGE = {
  count: 3,
  next: null,
  results: [
    {
      id: 1,
      title: 'SQL injection in search',
      severity: 'Critical',
      description: 'The q parameter is concatenated.',
      mitigation: 'Use parameterised queries.',
      impact: 'Arbitrary rows readable.',
      cvssv3: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      cvssv3_score: 9.8,
      cwe: 89,
      vulnerability_ids: [{ vulnerability_id: 'CVE-2026-0001' }, { vulnerability_id: 'GHSA-xxxx' }],
      steps_to_reproduce: "1. Send ' OR 1=1\n2. Observe the full result set",
      references: 'OWASP: https://owasp.org/a03\nhttps://cwe.mitre.org/data/definitions/89.html',
      endpoints: ['https://app.example.com/search'],
      tags: ['A03:2021 Injection', 'T1190', 'web-application'],
      active: true,
      false_p: false,
      duplicate: false,
    },
    {
      id: 2,
      title: 'SSRF via webhook',
      severity: 'High',
      cvssv4: 'CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N',
      cvssv4_score: 9.3,
      active: true,
    },
    { id: 3, title: 'noise', severity: 'Low', false_p: true, active: true },
  ],
}

describe('defectDojoToOpf', () => {
  it('converts a REST-API page, inverting the parser mapping', () => {
    const doc = defectDojoToOpf(PAGE)
    expect(doc.opfVersion).toBe('1.1')
    expect(doc.textFormat).toBe('markdown')
    expect(doc.metadata?.source).toBe('DefectDojo')
    // finding 3 (false-positive) excluded by default
    expect(doc.findings.map((f) => f.title)).toEqual(['SQL injection in search', 'SSRF via webhook'])
    expect(doc.metadata?.findingCount).toBe(2)

    const a = doc.findings[0]
    expect(a.severity).toBe('critical')
    expect(a.id).toBe('1')
    expect(a.cvssVersion).toBe('3.1')
    expect(a.cvssVector).toContain('CVSS:3.1')
    expect(a.cvssScore).toBe(9.8)
    expect(a.cweIds).toEqual(['CWE-89'])
    expect(a.cveIds).toEqual(['CVE-2026-0001']) // CVE id routed to cveIds
    expect(a.recommendation).toBe('Use parameterised queries.')
    expect(a.impact).toBe('Arbitrary rows readable.')
    expect(a.stepsToReproduce).toEqual(["Send ' OR 1=1", 'Observe the full result set']) // numbering stripped
    expect(a.references).toEqual([
      { url: 'https://owasp.org/a03', title: 'OWASP' },
      { url: 'https://cwe.mitre.org/data/definitions/89.html' },
    ])
    expect(a.affectedAssets).toEqual(['https://app.example.com/search'])
    expect(a.owaspCategory).toBe('A03:2021 Injection')
    expect(a.mitreTechniques).toEqual(['T1190'])
    // non-CVE identifier preserved rather than dropped, alongside the leftover tag
    expect(a.customFields).toEqual({ vulnerabilityIds: ['GHSA-xxxx'], tags: ['web-application'] })
  })

  it('prefers a v4 vector and routes it to cvssVersion 4.0 without a v3 vector', () => {
    const b = defectDojoToOpf(PAGE).findings[1]
    expect(b.cvssVersion).toBe('4.0')
    expect(b.cvssVector).toContain('CVSS:4.0')
    expect(b.cvssScore).toBe(9.3)
  })

  it('includes false-positive/duplicate/inactive findings only when asked', () => {
    expect(defectDojoToOpf(PAGE, { includeFalsePositives: true }).findings).toHaveLength(3)
  })

  it('accepts a bare array and a {findings:[...]} object, and rejects junk', () => {
    expect(defectDojoToOpf(PAGE.results).findings).toHaveLength(2)
    expect(defectDojoToOpf({ findings: PAGE.results }).findings).toHaveLength(2)
    expect(() => defectDojoToOpf(42 as unknown)).toThrow(/DefectDojo findings/)
  })

  it('does not crash on a non-array vulnerability_ids from the untrusted API', () => {
    const doc = defectDojoToOpf([
      { title: 'malformed', severity: 'High', vulnerability_ids: 'CVE-2026-9' as unknown },
      { title: 'ok', severity: 'Low' },
    ])
    expect(doc.findings.map((f) => f.title)).toEqual(['malformed', 'ok'])
    expect(doc.findings[0].cveIds).toBeUndefined() // a non-array yields no ids, but no throw
  })

  it('reads the CVSS version from the vector prefix (3.0 not mislabeled 3.1)', () => {
    const doc = defectDojoToOpf([
      { title: 'v3.0', severity: 'Medium', cvssv3: 'CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N', cvssv3_score: 6.3 },
    ])
    expect(doc.findings[0].cvssVersion).toBe('3.0')
  })

  it('preserves an unrecognised severity instead of silently downgrading it', () => {
    const doc = defectDojoToOpf([{ title: 'weird', severity: 'Blocker' }])
    expect(doc.findings[0].severity).toBe('informational')
    expect(doc.findings[0].customFields).toEqual({ originalSeverity: 'Blocker' })
  })

  it('round-trips core fields through OPF -> DefectDojo -> OPF', () => {
    const back = defectDojoToOpf({ findings: opfToDefectDojo(defectDojoToOpf(PAGE)).findings })
    const a = back.findings[0]
    expect(a.title).toBe('SQL injection in search')
    expect(a.severity).toBe('critical')
    expect(a.cweIds).toEqual(['CWE-89'])
  })
})

describe('fetchDefectDojoOpf', () => {
  function stub(pages: unknown[]) {
    const calls: Array<{ url: string; init: any }> = []
    let i = 0
    const fn = (async (url: string, init: any) => {
      calls.push({ url, init })
      const body = pages[Math.min(i++, pages.length - 1)]
      return { ok: true, status: 200, text: async () => JSON.stringify(body) }
    }) as unknown as typeof fetch
    return { fn, calls }
  }

  it('follows pagination, sends a Token header, and applies filters', async () => {
    const { fn, calls } = stub([
      { next: 'https://dojo.example.com/api/v2/findings/?limit=100&offset=100', results: [{ id: 1, title: 'a', severity: 'High', active: true }] },
      { next: null, results: [{ id: 2, title: 'b', severity: 'Low', active: true }] },
    ])
    const doc = await fetchDefectDojoOpf({
      baseUrl: 'https://dojo.example.com/',
      apiToken: 'tok123',
      filters: { engagement: 7, limit: 100 },
      fetch: fn,
    })
    expect(doc.findings.map((f) => f.title)).toEqual(['a', 'b'])
    expect(calls).toHaveLength(2)
    expect(calls[0].url).toContain('https://dojo.example.com/api/v2/findings/?')
    expect(calls[0].url).toContain('engagement=7')
    expect(calls[0].init.headers.Authorization).toBe('Token tok123')
    // second request follows the server-provided next URL verbatim
    expect(calls[1].url).toBe('https://dojo.example.com/api/v2/findings/?limit=100&offset=100')
  })

  it('throws with the count collected so far when a page fails', async () => {
    const fn = (async () => ({ ok: false, status: 502, text: async () => 'bad gateway' })) as unknown as typeof fetch
    await expect(fetchDefectDojoOpf({ baseUrl: 'https://x', apiToken: 't', fetch: fn })).rejects.toThrow(/502.*after 0 findings/)
  })

  it('throws a labelled error on a non-JSON response', async () => {
    const fn = (async () => ({ ok: true, status: 200, text: async () => '<html>nope</html>' })) as unknown as typeof fetch
    await expect(fetchDefectDojoOpf({ baseUrl: 'https://x', apiToken: 't', fetch: fn })).rejects.toThrow(/non-JSON/)
  })

  it('refuses to follow an off-origin pagination next (no token exfiltration)', async () => {
    const { fn } = stub([{ next: 'https://evil.attacker.com/api/v2/findings/?offset=100', results: [{ id: 1, title: 'a', severity: 'High', active: true }] }])
    await expect(
      fetchDefectDojoOpf({ baseUrl: 'https://dojo.example.com', apiToken: 'secret', fetch: fn }),
    ).rejects.toThrow(/off-origin/)
  })

  it('rejects a page whose results is present but not an array', async () => {
    const { fn } = stub([{ next: null, results: { detail: 'unexpected' } }])
    await expect(
      fetchDefectDojoOpf({ baseUrl: 'https://dojo.example.com', apiToken: 't', fetch: fn }),
    ).rejects.toThrow(/non-array "results"/)
  })

  it('fails loud instead of silently truncating when maxPages is hit with pages remaining', async () => {
    // every page reports another `next`, so the cap is reached with data still pending
    const fn = (async () => ({
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ next: 'https://dojo.example.com/api/v2/findings/?offset=999', results: [{ id: 1, title: 'x', severity: 'Low', active: true }] }),
    })) as unknown as typeof fetch
    await expect(
      fetchDefectDojoOpf({ baseUrl: 'https://dojo.example.com', apiToken: 't', maxPages: 2, fetch: fn }),
    ).rejects.toThrow(/maxPages=2.*more pages remaining/)
  })

  it('honours a server-side active=false filter on the client side', async () => {
    const { fn } = stub([{ next: null, results: [{ id: 1, title: 'inactive one', severity: 'Low', active: false }] }])
    const doc = await fetchDefectDojoOpf({
      baseUrl: 'https://dojo.example.com',
      apiToken: 't',
      filters: { active: false },
      fetch: fn,
    })
    expect(doc.findings.map((f) => f.title)).toEqual(['inactive one'])
  })
})
