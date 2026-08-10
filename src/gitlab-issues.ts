/**
 * OPF -> GitLab Issues. (Distinct from gitlab.ts, which emits a GitLab SAST
 * security *report*; this creates tracker issues.)
 *
 *   - opfToGitLabIssues: create-issue request bodies (pure, testable).
 *   - pushToGitLabIssues: create those issues in a live project.
 *
 * GitLab has no bulk issue endpoint, so the push POSTs one issue at a time to
 * /api/v4/projects/:id/issues. `labels` is a comma-separated string per the
 * API; the description is Markdown, which GitLab renders natively.
 *
 * Create issue: https://docs.gitlab.com/ee/api/issues.html#new-issue
 */
import { type OpfDocument } from './core.js'
import { type IssueDraft, type OpfToIssuesOptions, opfToIssues, parseJsonResponse } from './issues.js'

export type OpfToGitLabIssuesOptions = OpfToIssuesOptions

/** A GitLab create-issue request body. */
export interface GitLabIssuePayload {
  title: string
  description: string
  /** Comma-separated label list, as the GitLab API expects. */
  labels: string
}

function draftToPayload(d: IssueDraft): GitLabIssuePayload {
  return { title: d.title, description: d.body, labels: d.labels.join(',') }
}

/** OPF -> GitLab create-issue request bodies. Pure; makes no network call. */
export function opfToGitLabIssues(doc: OpfDocument, options: OpfToGitLabIssuesOptions = {}): GitLabIssuePayload[] {
  return opfToIssues(doc, options).map(draftToPayload)
}

export interface PushToGitLabIssuesOptions extends OpfToGitLabIssuesOptions {
  /** Numeric project id or URL-encoded "group/project" path. */
  projectId: string | number
  /** Personal/project access token with `api` scope. */
  token: string
  /** API base URL. Default https://gitlab.com; set for self-managed GitLab. */
  baseUrl?: string
  /** Injected fetch, for testing. Defaults to the global fetch (Node >= 18). */
  fetch?: typeof fetch
}

/**
 * Create the issues in a live GitLab project, one at a time. Rejects with the
 * status, body, and how many were already created if a create fails.
 */
export async function pushToGitLabIssues(doc: OpfDocument, options: PushToGitLabIssuesOptions): Promise<unknown[]> {
  const doFetch = options.fetch ?? globalThis.fetch
  if (typeof doFetch !== 'function') {
    throw new Error('pushToGitLabIssues: no fetch available (use Node >= 18 or pass options.fetch)')
  }
  if (options.projectId === undefined || options.projectId === '') {
    throw new TypeError('pushToGitLabIssues: options.projectId is required')
  }

  const base = (options.baseUrl ?? 'https://gitlab.com').replace(/\/+$/, '')
  const url = `${base}/api/v4/projects/${encodeURIComponent(String(options.projectId))}/issues`
  const headers = {
    'PRIVATE-TOKEN': options.token,
    'Content-Type': 'application/json',
    Accept: 'application/json',
  }

  const payloads = opfToGitLabIssues(doc, options)
  const created: unknown[] = []
  for (const p of payloads) {
    const res = await doFetch(url, { method: 'POST', headers, body: JSON.stringify(p) })
    const text = await res.text()
    if (!res.ok) {
      throw new Error(
        `GitLab create issue failed (${res.status}) after ${created.length} created: ${text.slice(0, 500)}`,
      )
    }
    created.push(parseJsonResponse(text, 'GitLab', res.status, created.length))
  }
  return created
}
