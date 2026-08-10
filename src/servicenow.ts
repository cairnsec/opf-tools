/**
 * OPF -> ServiceNow (Table API).
 *
 *   - opfToServiceNowRecords: table records (pure, testable).
 *   - pushToServiceNow:        insert each record into a live instance.
 *
 * ServiceNow creates records with POST /api/now/table/{table}. The default
 * table is `incident`; severity maps to the standard impact/urgency scale
 * (1 high .. 3 low), from which ServiceNow derives priority.
 *
 * API: https://docs.servicenow.com/bundle/utah-application-development/page/integrate/inbound-rest/concept/c_TableAPI.html
 */
import { type OpfDocument, type OpfSeverity } from './core.js'
import { type IssueDraft, type OpfToIssuesOptions, opfToIssues, parseJsonResponse } from './issues.js'

/** Severity -> ServiceNow impact/urgency: 1 high, 2 medium, 3 low. */
const SN_IMPACT: Record<OpfSeverity, string> = {
  critical: '1',
  high: '1',
  medium: '2',
  low: '3',
  informational: '3',
}

export type OpfToServiceNowOptions = OpfToIssuesOptions

/** A ServiceNow table record. */
export interface ServiceNowRecord {
  short_description: string
  description: string
  impact: string
  urgency: string
  /** Space-separated work notes tag list mirroring the OPF labels. */
  work_notes: string
  [field: string]: unknown
}

function draftToRecord(d: IssueDraft): ServiceNowRecord {
  const level = SN_IMPACT[d.severity]
  return {
    short_description: d.title,
    description: d.body,
    impact: level,
    urgency: level,
    work_notes: d.labels.join(' '),
  }
}

/** OPF -> ServiceNow table records. Pure; makes no network call. */
export function opfToServiceNowRecords(doc: OpfDocument, options: OpfToServiceNowOptions = {}): ServiceNowRecord[] {
  return opfToIssues(doc, options).map(draftToRecord)
}

export interface PushToServiceNowOptions extends OpfToServiceNowOptions {
  /** Instance URL, e.g. https://dev12345.service-now.com. */
  instanceUrl: string
  /** Basic-auth user. */
  user: string
  /** Basic-auth password. */
  password: string
  /** Target table. Default "incident". */
  table?: string
  /** Injected fetch, for testing. Defaults to the global fetch (Node >= 18). */
  fetch?: typeof fetch
}

/**
 * Insert the records into a live ServiceNow instance, one at a time. Rejects
 * with the status, body, and how many were created if one fails.
 */
export async function pushToServiceNow(doc: OpfDocument, options: PushToServiceNowOptions): Promise<unknown[]> {
  const doFetch = options.fetch ?? globalThis.fetch
  if (typeof doFetch !== 'function') {
    throw new Error('pushToServiceNow: no fetch available (use Node >= 18 or pass options.fetch)')
  }
  if (!options.instanceUrl) throw new TypeError('pushToServiceNow: options.instanceUrl is required')

  const table = options.table ?? 'incident'
  const base = options.instanceUrl.replace(/\/+$/, '')
  const url = `${base}/api/now/table/${encodeURIComponent(table)}`
  const auth = Buffer.from(`${options.user}:${options.password}`).toString('base64')
  const headers = {
    Authorization: `Basic ${auth}`,
    'Content-Type': 'application/json',
    Accept: 'application/json',
  }

  const records = opfToServiceNowRecords(doc, options)
  const created: unknown[] = []
  for (const record of records) {
    const res = await doFetch(url, { method: 'POST', headers, body: JSON.stringify(record) })
    const text = await res.text()
    if (!res.ok) {
      throw new Error(
        `ServiceNow insert failed (${res.status}) after ${created.length} created: ${text.slice(0, 500)}`,
      )
    }
    created.push(parseJsonResponse(text, 'ServiceNow', res.status, created.length))
  }
  return created
}
