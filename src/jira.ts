/**
 * OPF -> Jira. Three paths, cheapest first:
 *   - opfToJiraCsv:  a Jira-importable CSV (External System Import wizard).
 *   - opfToJiraRest: the POST /rest/api/2/issue/bulk request body (pure).
 *   - pushToJira:    optionally send that body to a live Jira Cloud/DC instance.
 *
 * The pure builders let you review or diff what will be created before any
 * network call. `pushToJira` is the only function here with side effects.
 *
 * CSV import:  https://support.atlassian.com/jira-cloud-administration/docs/import-data-from-a-csv-file/
 * Bulk create: https://developer.atlassian.com/cloud/jira/platform/rest/v2/api-group-issues/#api-rest-api-2-issue-bulk-post
 */
import { type OpfDocument } from './core.js'
import { type IssueDraft, type OpfToIssuesOptions, opfToIssues, renderIssuesCsv } from './issues.js'

export type OpfToJiraOptions = OpfToIssuesOptions

/** OPF -> Jira-importable CSV. Map the columns in Jira's import wizard. */
export function opfToJiraCsv(doc: OpfDocument, options: OpfToJiraOptions = {}): string {
  return renderIssuesCsv(opfToIssues(doc, options), 'jira')
}

export interface JiraRestOptions extends OpfToIssuesOptions {
  /** Target project key, e.g. "SEC". Required. */
  projectKey: string
  /** Attach the labels array to each issue. Default true. */
  labels?: boolean
}

export interface JiraBulkPayload {
  issueUpdates: Array<{ fields: Record<string, unknown> }>
}

/** Shape of the /issue/bulk response we inspect: created issues plus per-element errors. */
interface JiraBulkResponse {
  issues?: unknown[]
  errors?: unknown[]
}

function draftToFields(d: IssueDraft, projectKey: string, includeLabels: boolean): Record<string, unknown> {
  const fields: Record<string, unknown> = {
    project: { key: projectKey },
    issuetype: { name: d.issueType },
    summary: d.title,
    description: d.body,
    priority: { name: d.priority },
  }
  if (includeLabels) fields.labels = d.labels
  return fields
}

/** OPF -> Jira bulk-create request body. Pure; makes no network call. */
export function opfToJiraRest(doc: OpfDocument, options: JiraRestOptions): JiraBulkPayload {
  if (!options.projectKey) throw new TypeError('opfToJiraRest: options.projectKey is required')
  const includeLabels = options.labels !== false
  const drafts = opfToIssues(doc, options)
  return { issueUpdates: drafts.map((d) => ({ fields: draftToFields(d, options.projectKey, includeLabels) })) }
}

export interface PushToJiraOptions extends JiraRestOptions {
  /** Base URL, e.g. "https://acme.atlassian.net". Trailing slashes are trimmed. */
  baseUrl: string
  /** Account email (Jira Cloud basic-auth username). */
  email: string
  /** API token (Jira Cloud) or password (Jira Data Center). */
  apiToken: string
  /** Injected fetch, for testing. Defaults to the global fetch (Node >= 18). */
  fetch?: typeof fetch
}

/**
 * Create the issues in a live Jira instance via the bulk endpoint. Resolves
 * with Jira's parsed response, or rejects with the status and body on failure.
 */
export async function pushToJira(doc: OpfDocument, options: PushToJiraOptions): Promise<unknown> {
  const doFetch = options.fetch ?? globalThis.fetch
  if (typeof doFetch !== 'function') {
    throw new Error('pushToJira: no fetch available (use Node >= 18 or pass options.fetch)')
  }
  const payload = opfToJiraRest(doc, options)
  const url = `${options.baseUrl.replace(/\/+$/, '')}/rest/api/2/issue/bulk`
  const auth = Buffer.from(`${options.email}:${options.apiToken}`).toString('base64')

  const res = await doFetch(url, {
    method: 'POST',
    headers: {
      Authorization: `Basic ${auth}`,
      'Content-Type': 'application/json',
      Accept: 'application/json',
    },
    body: JSON.stringify(payload),
  })

  const text = await res.text()
  let body: JiraBulkResponse | null
  try {
    body = text ? (JSON.parse(text) as JiraBulkResponse) : null
  } catch {
    throw new Error(`Jira returned a non-JSON response (${res.status}): ${text.slice(0, 500)}`)
  }
  // The bulk endpoint returns 2xx with a populated `errors` array on a PARTIAL
  // failure (some issues created, some rejected). A bare res.ok check would
  // report those dropped findings as successes, so inspect `errors` too.
  const failures = Array.isArray(body?.errors) ? body.errors.length : 0
  if (!res.ok || failures > 0) {
    const created = Array.isArray(body?.issues) ? body.issues.length : 0
    throw new Error(
      `Jira bulk create reported ${failures} failure(s) after ${created} created (${res.status}): ${JSON.stringify(
        body?.errors ?? text,
      ).slice(0, 500)}`,
    )
  }
  return body
}
