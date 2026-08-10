/**
 * OPF -> Azure DevOps Boards work items.
 *
 *   - opfToAzureWorkItems: JSON-Patch documents + work-item type (pure).
 *   - pushToAzure:         create each work item in a live project.
 *
 * Azure Boards creates work items with a JSON-Patch body sent to
 * POST {org}/{project}/_apis/wit/workitems/${type}. Priority is an integer
 * 1 (highest) .. 4 (lowest); tags are a semicolon-separated string.
 *
 * API: https://learn.microsoft.com/en-us/rest/api/azure/devops/wit/work-items/create
 */
import { type OpfDocument } from './core.js'
import { ADO_PRIORITY, type IssueDraft, type OpfToIssuesOptions, opfToIssues, parseJsonResponse } from './issues.js'

export type OpfToAzureOptions = OpfToIssuesOptions

export interface AzurePatchOp {
  op: 'add'
  path: string
  value: unknown
}

/** A work item to create: its type and the JSON-Patch document that defines it. */
export interface AzureWorkItem {
  type: string
  document: AzurePatchOp[]
}

function draftToWorkItem(d: IssueDraft): AzureWorkItem {
  const document: AzurePatchOp[] = [
    { op: 'add', path: '/fields/System.Title', value: d.title },
    { op: 'add', path: '/fields/System.Description', value: d.body },
    { op: 'add', path: '/fields/Microsoft.VSTS.Common.Priority', value: ADO_PRIORITY[d.severity] },
    { op: 'add', path: '/fields/System.Tags', value: d.labels.join('; ') },
  ]
  return { type: d.issueType, document }
}

/** OPF -> Azure Boards work items. Pure; makes no network call. */
export function opfToAzureWorkItems(doc: OpfDocument, options: OpfToAzureOptions = {}): AzureWorkItem[] {
  return opfToIssues(doc, options).map(draftToWorkItem)
}

export interface PushToAzureOptions extends OpfToAzureOptions {
  /** Organization name or full org URL (https://dev.azure.com/{org}). */
  org: string
  /** Project name or id. */
  project: string
  /** Personal access token with Work Items (write) scope. */
  token: string
  /** API version. Default "7.0". */
  apiVersion?: string
  /** Injected fetch, for testing. Defaults to the global fetch (Node >= 18). */
  fetch?: typeof fetch
}

function orgBase(org: string): string {
  if (/^https?:\/\//.test(org)) return org.replace(/\/+$/, '')
  return `https://dev.azure.com/${org}`
}

/**
 * Create the work items in a live Azure DevOps project, one at a time. Rejects
 * with the status, body, and how many were created if one fails.
 */
export async function pushToAzure(doc: OpfDocument, options: PushToAzureOptions): Promise<unknown[]> {
  const doFetch = options.fetch ?? globalThis.fetch
  if (typeof doFetch !== 'function') {
    throw new Error('pushToAzure: no fetch available (use Node >= 18 or pass options.fetch)')
  }
  if (!options.org || !options.project) {
    throw new TypeError('pushToAzure: options.org and options.project are required')
  }

  const version = options.apiVersion ?? '7.0'
  const base = orgBase(options.org)
  const auth = Buffer.from(`:${options.token}`).toString('base64')
  const headers = {
    Authorization: `Basic ${auth}`,
    'Content-Type': 'application/json-patch+json',
    Accept: 'application/json',
  }

  const items = opfToAzureWorkItems(doc, options)
  const created: unknown[] = []
  for (const item of items) {
    const url = `${base}/${encodeURIComponent(options.project)}/_apis/wit/workitems/$${encodeURIComponent(
      item.type,
    )}?api-version=${version}`
    const res = await doFetch(url, { method: 'POST', headers, body: JSON.stringify(item.document) })
    const text = await res.text()
    if (!res.ok) {
      throw new Error(
        `Azure create work item failed (${res.status}) after ${created.length} created: ${text.slice(0, 500)}`,
      )
    }
    created.push(parseJsonResponse(text, 'Azure', res.status, created.length))
  }
  return created
}
