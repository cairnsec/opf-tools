/**
 * opf-tools — converters between the Open Pentest Format (OPF) and the formats
 * teams already use: SARIF, DefectDojo, GitLab, Markdown, HTML and CSV.
 *
 * OPF spec: https://cairnsecurity.com/opf
 */
export * from './core.js'
export { opfToSarif, sarifToOpf, type SarifLog, type SarifLevel, type OpfToSarifOptions } from './sarif.js'
export { opfToMarkdown, type OpfToMarkdownOptions } from './markdown.js'
export { opfToHtml, type OpfToHtmlOptions } from './html.js'
export { opfToCsv, csvToOpf, parseCsv } from './csv.js'
export {
  opfToDefectDojo,
  defectDojoToOpf,
  fetchDefectDojoOpf,
  type DefectDojoImport,
  type DefectDojoFinding,
  type DefectDojoApiFinding,
  type DdToOpfOptions,
  type FetchDefectDojoOptions,
} from './defectdojo.js'
export { opfToGitLab, type GitLabReport, type OpfToGitLabOptions } from './gitlab.js'
export {
  opfToIssues,
  opfToIssuesCsv,
  renderIssuesCsv,
  SEVERITY_TO_PRIORITY,
  TRACKERS,
  type IssueDraft,
  type OpfToIssuesOptions,
  type TrackerId,
} from './issues.js'
export {
  opfToJiraCsv,
  opfToJiraRest,
  pushToJira,
  type OpfToJiraOptions,
  type JiraRestOptions,
  type JiraBulkPayload,
  type PushToJiraOptions,
} from './jira.js'
export {
  opfToGitHubIssues,
  pushToGitHub,
  type OpfToGitHubOptions,
  type GitHubIssuePayload,
  type PushToGitHubOptions,
} from './github.js'
export {
  opfToGitLabIssues,
  pushToGitLabIssues,
  type OpfToGitLabIssuesOptions,
  type GitLabIssuePayload,
  type PushToGitLabIssuesOptions,
} from './gitlab-issues.js'
export {
  opfToLinearInputs,
  pushToLinear,
  type OpfToLinearOptions,
  type LinearIssueInput,
  type PushToLinearOptions,
} from './linear.js'
export {
  opfToAzureWorkItems,
  pushToAzure,
  type OpfToAzureOptions,
  type AzureWorkItem,
  type AzurePatchOp,
  type PushToAzureOptions,
} from './azure.js'
export {
  opfToServiceNowRecords,
  pushToServiceNow,
  type OpfToServiceNowOptions,
  type ServiceNowRecord,
  type PushToServiceNowOptions,
} from './servicenow.js'
export { validateOpf, type ValidationResult, type ValidationIssue } from './validate.js'

export { TOOLS_VERSION as VERSION } from './core.js'
