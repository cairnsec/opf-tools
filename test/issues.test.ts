import { describe, it, expect } from 'vitest'
import {
  opfToIssues,
  opfToIssuesCsv,
  opfToJiraCsv,
  opfToJiraRest,
  pushToJira,
  opfToGitHubIssues,
  pushToGitHub,
  opfToGitLabIssues,
  pushToGitLabIssues,
  opfToLinearInputs,
  pushToLinear,
  opfToAzureWorkItems,
  pushToAzure,
  opfToServiceNowRecords,
  pushToServiceNow,
  opfToCsv,
  csvToOpf,
  parseCsv,
  type OpfDocument,
} from '../src/index.js'

/** A fetch stub that records calls and returns a fixed ok/body. */
function stubFetch(status: number, body: unknown) {
  const calls: Array<{ url: string; init: any }> = []
  const fn = (async (url: string, init: any) => {
    calls.push({ url, init })
    return { ok: status >= 200 && status < 300, status, text: async () => (typeof body === 'string' ? body : JSON.stringify(body)) }
  }) as unknown as typeof fetch
  return { fn, calls }
}

const DOC: OpfDocument = {
  opfVersion: '1.1',
  textFormat: 'html',
  metadata: { source: 'Cairn', exportedAt: '2026-07-31T12:00:00Z' },
  findings: [
    {
      id: 'sqli-1',
      title: 'SQL injection in search',
      severity: 'critical',
      testType: 'web application',
      description: '<p>The <code>q</code> parameter is concatenated into the query.</p>',
      impact: 'Read arbitrary rows.',
      recommendation: 'Use parameterised queries.',
      cvssScore: 9.8,
      cvssVector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
      cweIds: ['CWE-89'],
      cveIds: ['CVE-2026-1234'],
      owaspCategory: 'A03:2021 Injection',
      affectedAssets: ['https://app.example.com/search'],
      references: [{ title: 'CWE-89', url: 'https://cwe.mitre.org/data/definitions/89.html' }],
      stepsToReproduce: ["Send ' OR 1=1 in q", 'Observe the full result set'],
    },
    { title: 'S3 bucket allows public read', severity: 'high', description: 'Bucket grants s3:GetObject to *.' },
  ],
}

describe('opfToIssues', () => {
  it('maps severity to priority and builds labels + a structured body', () => {
    const [a, b] = opfToIssues(DOC)
    expect(a.priority).toBe('Highest')
    expect(b.priority).toBe('High')
    expect(a.externalId).toBe('sqli-1')
    expect(a.labels).toContain('severity:critical')
    expect(a.labels).toContain('web-application') // testType slugged, space-free
    expect(a.fields.cvssScore).toBe(9.8)
    expect(a.fields.cwe).toBe('CWE-89')
    // body sections + HTML flattened
    expect(a.body).toContain('## Impact')
    expect(a.body).toContain('## Steps to reproduce')
    expect(a.body).toContain('1. Send')
    expect(a.body).not.toContain('<p>')
    // High finding with no CVSS gets a derived score
    expect(b.fields.cvssScore).toBe(8.0)
  })

  it('respects a custom priority map and issue type', () => {
    const [a] = opfToIssues(DOC, {
      issueType: 'Vulnerability',
      priorityMap: { critical: 'P1', high: 'P2', medium: 'P3', low: 'P4', informational: 'P5' },
    })
    expect(a.priority).toBe('P1')
    expect(a.issueType).toBe('Vulnerability')
  })

  it('orders drafts most-severe first regardless of document order', () => {
    const doc: OpfDocument = {
      opfVersion: '1.1',
      findings: [
        { title: 'low one', severity: 'low' },
        { title: 'crit one', severity: 'critical' },
        { title: 'med one', severity: 'medium' },
      ],
    }
    expect(opfToIssues(doc).map((d) => d.severity)).toEqual(['critical', 'medium', 'low'])
  })

  it('ships a titleless finding under a generated title instead of dropping it', () => {
    const doc: OpfDocument = { opfVersion: '1.1', findings: [{ id: 'f-9', title: '', severity: 'high' }] }
    const drafts = opfToIssues(doc)
    expect(drafts).toHaveLength(1)
    expect(drafts[0].title).toBe('Untitled finding f-9')
    expect(drafts[0].externalId).toBe('f-9')
  })

  it('tolerates null/empty entries in the findings array without crashing', () => {
    const doc = { opfVersion: '1.1', findings: [null, { title: 'real', severity: 'low' }] } as unknown as OpfDocument
    const drafts = opfToIssues(doc)
    expect(drafts.map((d) => d.title)).toEqual(['real'])
  })
})

describe('CSV formula injection (CWE-1236)', () => {
  const evil: OpfDocument = {
    opfVersion: '1.1',
    findings: [{ title: '=HYPERLINK("http://evil")', severity: 'high' }],
  }

  it('guards issue-CSV cells beginning with a formula trigger', () => {
    const rows = parseCsv(opfToIssuesCsv(evil, 'github'))
    expect(rows[1][0]).toBe('\'=HYPERLINK("http://evil")')
  })

  it('guards the library CSV writer too, and un-guards on read so the round-trip is lossless', () => {
    const doc: OpfDocument = { opfVersion: '1.1', findings: [{ title: '=cmd|calc', severity: 'low' }] }
    const csv = opfToCsv(doc)
    expect(parseCsv(csv)[1][1]).toBe("'=cmd|calc") // title column is guarded on disk
    expect(csvToOpf(csv).findings[0].title).toBe('=cmd|calc') // but restored on read
  })

  it('round-trips a value that already begins with an apostrophe without dropping it', () => {
    // guard must be injective: "'=x" and "=x" must not collapse to the same cell.
    for (const title of ["'=x", "'@handle", "'already quoted", '=x', 'plain']) {
      const doc: OpfDocument = { opfVersion: '1.1', findings: [{ title, severity: 'low' }] }
      expect(csvToOpf(opfToCsv(doc)).findings[0].title).toBe(title)
    }
  })
})

describe('issue CSV', () => {
  it('jira CSV carries mappable columns and repeated Labels', () => {
    const rows = parseCsv(opfToJiraCsv(DOC))
    const header = rows[0]
    expect(header.slice(0, 4)).toEqual(['Summary', 'Issue Type', 'Priority', 'Description'])
    expect(header).toContain('CVSS Score')
    expect(header).toContain('OPF Id')
    expect(header.filter((h) => h === 'Labels').length).toBeGreaterThan(0)
    const first = rows[1]
    expect(first[0]).toBe('SQL injection in search')
    expect(first[2]).toBe('Highest')
  })

  it('github CSV is title/body/labels', () => {
    const rows = parseCsv(opfToIssuesCsv(DOC, 'github'))
    expect(rows[0]).toEqual(['title', 'body', 'labels'])
    expect(rows[1][0]).toBe('SQL injection in search')
    expect(rows[1][2]).toContain('severity:critical')
  })

  it('linear CSV maps severity to a numeric priority', () => {
    const rows = parseCsv(opfToIssuesCsv(DOC, 'linear'))
    expect(rows[0]).toEqual(['Title', 'Description', 'Priority', 'Labels', 'Status'])
    expect(rows[1][2]).toBe('1') // critical -> urgent
  })
})

describe('opfToJiraRest', () => {
  it('produces a bulk-create payload with project, type, priority and labels', () => {
    const payload = opfToJiraRest(DOC, { projectKey: 'SEC' })
    expect(payload.issueUpdates).toHaveLength(2)
    const f = payload.issueUpdates[0].fields as Record<string, any>
    expect(f.project).toEqual({ key: 'SEC' })
    expect(f.issuetype).toEqual({ name: 'Bug' })
    expect(f.summary).toBe('SQL injection in search')
    expect(f.priority).toEqual({ name: 'Highest' })
    expect(f.labels).toContain('severity:critical')
  })

  it('throws without a project key', () => {
    expect(() => opfToJiraRest(DOC, { projectKey: '' })).toThrow(/projectKey/)
  })
})

describe('pushToJira', () => {
  it('POSTs the bulk payload with basic auth to the bulk endpoint', async () => {
    const calls: Array<{ url: string; init: any }> = []
    const fakeFetch = (async (url: string, init: any) => {
      calls.push({ url, init })
      return {
        ok: true,
        status: 201,
        text: async () => JSON.stringify({ issues: [{ id: '1' }, { id: '2' }] }),
      }
    }) as unknown as typeof fetch

    const res = (await pushToJira(DOC, {
      baseUrl: 'https://acme.atlassian.net/',
      email: 'bot@acme.com',
      apiToken: 'tok',
      projectKey: 'SEC',
      fetch: fakeFetch,
    })) as any

    expect(res.issues).toHaveLength(2)
    expect(calls[0].url).toBe('https://acme.atlassian.net/rest/api/2/issue/bulk')
    expect(calls[0].init.method).toBe('POST')
    expect(calls[0].init.headers.Authorization).toBe('Basic ' + Buffer.from('bot@acme.com:tok').toString('base64'))
    expect(JSON.parse(calls[0].init.body).issueUpdates).toHaveLength(2)
  })

  it('rejects on a non-ok response', async () => {
    const fakeFetch = (async () => ({ ok: false, status: 400, text: async () => 'bad project' })) as unknown as typeof fetch
    await expect(
      pushToJira(DOC, { baseUrl: 'https://x', email: 'e', apiToken: 't', projectKey: 'SEC', fetch: fakeFetch }),
    ).rejects.toThrow(/400/)
  })
})

describe('opfToGitHubIssues', () => {
  it('produces one create-issue body per finding with Markdown body and labels', () => {
    const payloads = opfToGitHubIssues(DOC)
    expect(payloads).toHaveLength(2)
    expect(payloads[0].title).toBe('SQL injection in search')
    expect(payloads[0].labels).toContain('severity:critical')
    expect(payloads[0].body).toContain('## Recommendation')
  })
})

describe('pushToGitHub', () => {
  it('POSTs each issue to the repo issues endpoint with a bearer token', async () => {
    const calls: Array<{ url: string; init: any }> = []
    const fakeFetch = (async (url: string, init: any) => {
      calls.push({ url, init })
      return { ok: true, status: 201, text: async () => JSON.stringify({ number: calls.length }) }
    }) as unknown as typeof fetch

    const res = (await pushToGitHub(DOC, {
      owner: 'cairnsec',
      repo: 'findings',
      token: 'ghp_x',
      assignees: ['alice'],
      fetch: fakeFetch,
    })) as any[]

    expect(res.map((r) => r.number)).toEqual([1, 2])
    expect(calls).toHaveLength(2)
    expect(calls[0].url).toBe('https://api.github.com/repos/cairnsec/findings/issues')
    expect(calls[0].init.headers.Authorization).toBe('Bearer ghp_x')
    expect(calls[0].init.headers['X-GitHub-Api-Version']).toBe('2022-11-28')
    expect(JSON.parse(calls[0].init.body).assignees).toEqual(['alice'])
  })

  it('reports how many were created when a later create fails', async () => {
    let n = 0
    const fakeFetch = (async () => {
      n++
      return n === 1
        ? { ok: true, status: 201, text: async () => JSON.stringify({ number: 1 }) }
        : { ok: false, status: 422, text: async () => 'validation failed' }
    }) as unknown as typeof fetch

    await expect(
      pushToGitHub(DOC, { owner: 'o', repo: 'r', token: 't', fetch: fakeFetch }),
    ).rejects.toThrow(/after 1 created/)
  })
})

describe('GitLab issues', () => {
  it('builds create-issue bodies with comma-separated labels', () => {
    const p = opfToGitLabIssues(DOC)
    expect(p).toHaveLength(2)
    expect(p[0].title).toBe('SQL injection in search')
    expect(p[0].labels).toContain('severity:critical')
    expect(p[0].labels).toContain(',') // comma-separated string, not array
  })

  it('POSTs to the project issues endpoint with a PRIVATE-TOKEN header', async () => {
    const { fn, calls } = stubFetch(201, { iid: 1 })
    await pushToGitLabIssues(DOC, { projectId: 'group/app', token: 'glpat', fetch: fn })
    expect(calls).toHaveLength(2)
    expect(calls[0].url).toBe('https://gitlab.com/api/v4/projects/group%2Fapp/issues')
    expect(calls[0].init.headers['PRIVATE-TOKEN']).toBe('glpat')
  })
})

describe('Linear', () => {
  it('maps severity to numeric priority and requires a teamId', () => {
    const inputs = opfToLinearInputs(DOC, { teamId: 'team-1' })
    expect(inputs[0]).toMatchObject({ teamId: 'team-1', priority: 1 }) // critical -> urgent
    expect(inputs[1].priority).toBe(2) // high
    expect(() => opfToLinearInputs(DOC, { teamId: '' })).toThrow(/teamId/)
  })

  it('runs the issueCreate mutation and fails on GraphQL errors', async () => {
    const ok = stubFetch(200, { data: { issueCreate: { success: true, issue: { id: 'x' } } } })
    await pushToLinear(DOC, { apiKey: 'lin_key', teamId: 't', fetch: ok.fn })
    expect(ok.calls[0].url).toBe('https://api.linear.app/graphql')
    expect(ok.calls[0].init.headers.Authorization).toBe('lin_key')
    expect(JSON.parse(ok.calls[0].init.body).query).toContain('IssueCreate')

    const bad = stubFetch(200, { errors: [{ message: 'no access' }] })
    await expect(pushToLinear(DOC, { apiKey: 'k', teamId: 't', fetch: bad.fn })).rejects.toThrow(/no access/)
  })
})

describe('Azure Boards', () => {
  it('emits a JSON-Patch document per work item', () => {
    const items = opfToAzureWorkItems(DOC)
    expect(items[0].type).toBe('Bug')
    const title = items[0].document.find((o) => o.path === '/fields/System.Title')
    const prio = items[0].document.find((o) => o.path === '/fields/Microsoft.VSTS.Common.Priority')
    expect(title?.value).toBe('SQL injection in search')
    expect(prio?.value).toBe(1) // critical -> 1
  })

  it('POSTs json-patch to the workitems endpoint with basic PAT auth', async () => {
    const { fn, calls } = stubFetch(200, { id: 42 })
    await pushToAzure(DOC, { org: 'acme', project: 'Security', token: 'pat', fetch: fn })
    expect(calls[0].url).toBe('https://dev.azure.com/acme/Security/_apis/wit/workitems/$Bug?api-version=7.0')
    expect(calls[0].init.headers['Content-Type']).toBe('application/json-patch+json')
    expect(calls[0].init.headers.Authorization).toBe('Basic ' + Buffer.from(':pat').toString('base64'))
  })
})

describe('ServiceNow', () => {
  it('maps severity to impact/urgency and defaults to the incident table', () => {
    const recs = opfToServiceNowRecords(DOC)
    expect(recs[0].short_description).toBe('SQL injection in search')
    expect(recs[0].impact).toBe('1')
    expect(recs[0].urgency).toBe('1')
    expect(recs[1].impact).toBe('1') // high -> 1
  })

  it('POSTs to the Table API with basic auth and an overridable table', async () => {
    const { fn, calls } = stubFetch(201, { result: { sys_id: 'abc' } })
    await pushToServiceNow(DOC, {
      instanceUrl: 'https://dev123.service-now.com/',
      user: 'admin',
      password: 'pw',
      table: 'sn_si_incident',
      fetch: fn,
    })
    expect(calls[0].url).toBe('https://dev123.service-now.com/api/now/table/sn_si_incident')
    expect(calls[0].init.headers.Authorization).toBe('Basic ' + Buffer.from('admin:pw').toString('base64'))
  })
})

describe('push error handling (finalize hardening)', () => {
  it('Linear surfaces the HTTP status when the error body is not JSON', async () => {
    const { fn } = stubFetch(502, '<html>bad gateway</html>')
    // Must report 502, not a misleading JSON SyntaxError from parsing the HTML body.
    await expect(pushToLinear(DOC, { apiKey: 'k', teamId: 't', fetch: fn })).rejects.toThrow(/502/)
  })

  it('Linear rejects a 200 response whose issueCreate.success is false', async () => {
    const { fn } = stubFetch(200, { data: { issueCreate: { success: false, issue: null } } })
    await expect(pushToLinear(DOC, { apiKey: 'k', teamId: 't', fetch: fn })).rejects.toThrow(/success=false/)
  })

  it('Jira rejects a 2xx bulk response that reports per-issue errors', async () => {
    // /issue/bulk returns 201 on a PARTIAL failure: some created, some rejected.
    const { fn } = stubFetch(201, { issues: [{ id: '1' }], errors: [{ status: 400, failedElementNumber: 1 }] })
    await expect(
      pushToJira(DOC, { baseUrl: 'https://x', email: 'e', apiToken: 't', projectKey: 'SEC', fetch: fn }),
    ).rejects.toThrow(/1 failure\(s\) after 1 created/)
  })

  it('GitHub caps labels at 50 characters to avoid a 422', () => {
    const doc: OpfDocument = {
      opfVersion: '1.1',
      findings: [{ title: 't', severity: 'low', testType: 'x'.repeat(80) }],
    }
    const [payload] = opfToGitHubIssues(doc)
    expect(payload.labels.every((l) => l.length <= 50)).toBe(true)
    expect(payload.labels).toContain('x'.repeat(50))
  })

  it('sequential adapters report a non-JSON 2xx body as a labelled error, not a raw SyntaxError', async () => {
    // e.g. a caching proxy returns an HTML interstitial on an otherwise-ok create.
    const { fn } = stubFetch(200, '<html>ok</html>')
    await expect(
      pushToGitHub(DOC, { owner: 'o', repo: 'r', token: 't', fetch: fn }),
    ).rejects.toThrow(/GitHub returned a non-JSON response \(200\)/)
  })
})
