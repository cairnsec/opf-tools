/**
 * OPF -> Linear (GraphQL).
 *
 *   - opfToLinearInputs: `IssueCreateInput` objects (pure, testable).
 *   - pushToLinear:      run the issueCreate mutation for each, in a live team.
 *
 * Linear's API is GraphQL. Labels are referenced by id, which needs a lookup
 * this converter does not do, so labels are omitted from the mutation; severity
 * is preserved as Linear's numeric priority (0 none, 1 urgent .. 4 low) and the
 * OPF labels remain visible in the Markdown description.
 *
 * API: https://developers.linear.app/docs/graphql/working-with-the-graphql-api
 */
import { type OpfDocument } from './core.js'
import { LINEAR_PRIORITY, type IssueDraft, type OpfToIssuesOptions, opfToIssues } from './issues.js'

export interface OpfToLinearOptions extends OpfToIssuesOptions {
  /** Target team id (UUID). Required. */
  teamId: string
}

/** A Linear `IssueCreateInput`. */
export interface LinearIssueInput {
  teamId: string
  title: string
  description: string
  priority: number
}

function draftToInput(d: IssueDraft, teamId: string): LinearIssueInput {
  return { teamId, title: d.title, description: d.body, priority: LINEAR_PRIORITY[d.severity] }
}

/** OPF -> Linear IssueCreateInput objects. Pure; makes no network call. */
export function opfToLinearInputs(doc: OpfDocument, options: OpfToLinearOptions): LinearIssueInput[] {
  if (!options.teamId) throw new TypeError('opfToLinearInputs: options.teamId is required')
  return opfToIssues(doc, options).map((d) => draftToInput(d, options.teamId))
}

export interface PushToLinearOptions extends OpfToLinearOptions {
  /** Personal API key or OAuth token. */
  apiKey: string
  /** API endpoint. Default https://api.linear.app/graphql. */
  endpoint?: string
  /** Injected fetch, for testing. Defaults to the global fetch (Node >= 18). */
  fetch?: typeof fetch
}

const ISSUE_CREATE = `mutation IssueCreate($input: IssueCreateInput!) {
  issueCreate(input: $input) { success issue { id identifier url } }
}`

interface LinearResponse {
  data?: { issueCreate?: { success?: boolean; issue?: unknown } }
  errors?: unknown[]
}

/**
 * Create the issues in a live Linear team, one mutation at a time. Rejects with
 * the status/GraphQL errors and how many were created if one fails.
 */
export async function pushToLinear(doc: OpfDocument, options: PushToLinearOptions): Promise<unknown[]> {
  const doFetch = options.fetch ?? globalThis.fetch
  if (typeof doFetch !== 'function') {
    throw new Error('pushToLinear: no fetch available (use Node >= 18 or pass options.fetch)')
  }

  const endpoint = options.endpoint ?? 'https://api.linear.app/graphql'
  const headers = {
    Authorization: options.apiKey,
    'Content-Type': 'application/json',
    Accept: 'application/json',
  }

  const inputs = opfToLinearInputs(doc, options)
  const created: unknown[] = []
  for (const input of inputs) {
    const res = await doFetch(endpoint, {
      method: 'POST',
      headers,
      body: JSON.stringify({ query: ISSUE_CREATE, variables: { input } }),
    })
    const text = await res.text()
    if (!res.ok) {
      throw new Error(`Linear issueCreate failed (${res.status}) after ${created.length} created: ${text.slice(0, 500)}`)
    }
    let json: LinearResponse | null
    try {
      json = text ? (JSON.parse(text) as LinearResponse) : null
    } catch {
      throw new Error(
        `Linear returned a non-JSON response (${res.status}) after ${created.length} created: ${text.slice(0, 500)}`,
      )
    }
    if (json?.errors?.length) {
      throw new Error(
        `Linear issueCreate errored after ${created.length} created: ${JSON.stringify(json.errors).slice(0, 500)}`,
      )
    }
    const payload = json?.data?.issueCreate
    if (!payload?.success) {
      throw new Error(
        `Linear issueCreate returned success=false after ${created.length} created: ${text.slice(0, 500)}`,
      )
    }
    created.push(payload)
  }
  return created
}
