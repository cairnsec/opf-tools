/**
 * OPF -> GitHub Issues. Two paths:
 *   - opfToGitHubIssues: the create-issue request bodies (pure, testable).
 *   - pushToGitHub:      create those issues in a live repository.
 *
 * GitHub has no bulk issue endpoint, so `pushToGitHub` POSTs one issue at a
 * time to /repos/{owner}/{repo}/issues. Labels that do not yet exist are
 * created automatically when the token can write to the repo. The finding body
 * is already Markdown, which GitHub renders natively.
 *
 * Create issue: https://docs.github.com/en/rest/issues/issues#create-an-issue
 */
import { type OpfDocument } from './core.js'
import { type IssueDraft, type OpfToIssuesOptions, opfToIssues, parseJsonResponse } from './issues.js'

export type OpfToGitHubOptions = OpfToIssuesOptions

/** A GitHub create-issue request body. */
export interface GitHubIssuePayload {
  title: string
  body: string
  labels: string[]
}

/** GitHub rejects (422) any label name longer than 50 characters. */
const GITHUB_LABEL_MAX = 50

/** Cap each label at GitHub's 50-char limit, de-duping any collisions caused by truncation. */
function capLabels(labels: string[]): string[] {
  const seen = new Set<string>()
  const out: string[] = []
  for (const label of labels) {
    const capped = label.length > GITHUB_LABEL_MAX ? label.slice(0, GITHUB_LABEL_MAX) : label
    if (!seen.has(capped)) {
      seen.add(capped)
      out.push(capped)
    }
  }
  return out
}

function draftToPayload(d: IssueDraft): GitHubIssuePayload {
  return { title: d.title, body: d.body, labels: capLabels(d.labels) }
}

/** OPF -> GitHub create-issue request bodies. Pure; makes no network call. */
export function opfToGitHubIssues(doc: OpfDocument, options: OpfToGitHubOptions = {}): GitHubIssuePayload[] {
  return opfToIssues(doc, options).map(draftToPayload)
}

export interface PushToGitHubOptions extends OpfToGitHubOptions {
  /** Repository owner (user or org). */
  owner: string
  /** Repository name. */
  repo: string
  /** A token with `repo` (or fine-grained Issues: write) scope. */
  token: string
  /** API base URL. Default GitHub.com; set for GitHub Enterprise Server. */
  baseUrl?: string
  /** Extra assignees to set on every created issue. */
  assignees?: string[]
  /** Injected fetch, for testing. Defaults to the global fetch (Node >= 18). */
  fetch?: typeof fetch
}

/**
 * Create the issues in a live GitHub repository, one at a time, and resolve
 * with GitHub's parsed response for each. If a create fails, rejects with the
 * status, body, and how many issues were already created (so a retry can pick
 * up where it stopped).
 */
export async function pushToGitHub(doc: OpfDocument, options: PushToGitHubOptions): Promise<unknown[]> {
  const doFetch = options.fetch ?? globalThis.fetch
  if (typeof doFetch !== 'function') {
    throw new Error('pushToGitHub: no fetch available (use Node >= 18 or pass options.fetch)')
  }
  if (!options.owner || !options.repo) {
    throw new TypeError('pushToGitHub: options.owner and options.repo are required')
  }

  const base = (options.baseUrl ?? 'https://api.github.com').replace(/\/+$/, '')
  const url = `${base}/repos/${options.owner}/${options.repo}/issues`
  const headers = {
    Authorization: `Bearer ${options.token}`,
    Accept: 'application/vnd.github+json',
    'Content-Type': 'application/json',
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'opf-tools',
  }

  const payloads = opfToGitHubIssues(doc, options)
  const created: unknown[] = []
  for (const p of payloads) {
    const body = options.assignees?.length ? { ...p, assignees: options.assignees } : p
    const res = await doFetch(url, { method: 'POST', headers, body: JSON.stringify(body) })
    const text = await res.text()
    if (!res.ok) {
      throw new Error(
        `GitHub create issue failed (${res.status}) after ${created.length} created: ${text.slice(0, 500)}`,
      )
    }
    created.push(parseJsonResponse(text, 'GitHub', res.status, created.length))
  }
  return created
}
