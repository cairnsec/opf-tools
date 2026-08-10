# opf-tools

Converters between the [Open Pentest Format](https://github.com/cairnsec/opf) (OPF) and the formats security teams already use.

OPF is a small, portable JSON format for pentest findings and finding libraries. On its own a portable format is only half the story, it has to reach the tools people actually run. `opf-tools` is that bridge: it turns an OPF library into SARIF, DefectDojo, GitLab, Jira, issue-tracker CSV, Markdown, HTML or CSV, and reads SARIF and CSV back into OPF.

Zero runtime dependencies. Library + `opf` CLI. MIT.

## Converters

| Command | From → To | Use it for |
|---------|-----------|------------|
| `sarif` | OPF → SARIF 2.1.0 | GitHub code scanning, Azure DevOps, VS Code SARIF Viewer |
| `from-sarif` | SARIF → OPF | Bring scanner output into an OPF library |
| `defectdojo` | OPF → DefectDojo Generic Findings Import | Import a library into DefectDojo, no custom parser |
| `gitlab` | OPF → GitLab SAST report | Surface findings on GitLab MRs / security dashboard |
| `jira-csv` | OPF → Jira-importable CSV | Bulk-create issues via Jira's CSV import wizard |
| `jira-rest` | OPF → Jira bulk-create JSON | Review the `/issue/bulk` payload before sending it |
| `jira-push` | OPF → live Jira issues | Create issues directly via the Jira REST API |
| `github-rest` / `github-push` | OPF → GitHub issues (JSON / live) | Review payloads, or create via the GitHub REST API |
| `gitlab-issues-rest` / `gitlab-issues-push` | OPF → GitLab issues (JSON / live) | Create issues via the GitLab API |
| `linear-rest` / `linear-push` | OPF → Linear issues (JSON / live) | Create issues via the Linear GraphQL API |
| `azure-rest` / `azure-push` | OPF → Azure Boards work items (JSON / live) | Create work items via the Azure DevOps API |
| `servicenow-rest` / `servicenow-push` | OPF → ServiceNow records (JSON / live) | Insert records via the ServiceNow Table API |
| `github-csv` | OPF → GitHub Issues CSV | Import into GitHub issues |
| `linear-csv` | OPF → Linear CSV | Import into Linear |
| `azure-csv` | OPF → Azure Boards CSV | Import into Azure DevOps Boards |
| `issues-csv` | OPF → generic issue CSV | Any tracker with a CSV importer |
| `markdown` | OPF → Markdown | A readable, diffable finding document |
| `html` | OPF → standalone HTML | A self-contained page to open or share |
| `csv` | OPF → CSV | Spreadsheets, triage, bulk edit |
| `from-csv` | CSV → OPF | Turn a spreadsheet back into a library |
| `validate` | OPF → pass/fail | Check a document in CI or a pre-commit hook |

## Install

```bash
npm install @cairnsec/opf-tools
```

## CLI

```bash
opf <command> [input] [output]

# examples
opf sarif library.opf.json library.sarif.json
opf defectdojo library.opf.json | curl -F 'file=@-' ...        # into DefectDojo
opf jira-csv library.opf.json > jira-import.csv                # Jira CSV import wizard
opf markdown library.opf.json > FINDINGS.md
opf validate library.opf.json                                  # non-zero exit if invalid
cat scan.sarif.json | opf from-sarif > scan.opf.json           # scanner → OPF

# create issues in a live Jira instance
export JIRA_BASE_URL=https://acme.atlassian.net JIRA_EMAIL=you@acme.com JIRA_TOKEN=... JIRA_PROJECT=SEC
opf jira-push library.opf.json

# create issues in a live GitHub repository
export GITHUB_OWNER=cairnsec GITHUB_REPO=findings GITHUB_TOKEN=ghp_...
opf github-push library.opf.json
```

### Issue-tracker coverage

Every finding maps to a neutral `IssueDraft`; each tracker is a thin adapter over it. All push commands print a JSON preview (`*-rest`) so you can review what will be created before sending it.

> New in 0.2.0: the REST/GraphQL push adapters are built against each API's documented contract and unit-tested with mocked transports, but not yet exercised against live instances. Preview with the `*-rest` command and start on a scratch project. Please report any real-world payload mismatches.

| Tracker | CSV import | REST push | Push env vars |
|---------|:----------:|:---------:|---------------|
| Jira | `jira-csv` | `jira-push` | `JIRA_BASE_URL`, `JIRA_EMAIL`, `JIRA_TOKEN`, `JIRA_PROJECT` |
| GitHub | `github-csv` | `github-push` | `GITHUB_OWNER`, `GITHUB_REPO`, `GITHUB_TOKEN` |
| GitLab | — | `gitlab-issues-push` | `GITLAB_PROJECT`, `GITLAB_TOKEN`, `GITLAB_URL`* |
| Linear | `linear-csv` | `linear-push` | `LINEAR_API_KEY`, `LINEAR_TEAM_ID` |
| Azure Boards | `azure-csv` | `azure-push` | `AZURE_ORG`, `AZURE_PROJECT`, `AZURE_TOKEN` |
| ServiceNow | — | `servicenow-push` | `SN_INSTANCE`, `SN_USER`, `SN_PASSWORD`, `SN_TABLE`* |
| generic | `issues-csv` | — | — |

\* optional (self-managed GitLab base URL; ServiceNow table defaults to `incident`).

Reads a file argument or stdin; writes a file argument or stdout.

## Library

```ts
import {
  opfToSarif,
  opfToDefectDojo,
  opfToIssues,
  opfToIssuesCsv,
  opfToJiraRest,
  pushToJira,
  pushToGitHub,
  pushToGitLabIssues,
  pushToLinear,
  pushToAzure,
  pushToServiceNow,
  sarifToOpf,
  validateOpf,
} from '@cairnsec/opf-tools'

const sarif = opfToSarif(opfDocument)
const dd = opfToDefectDojo(opfDocument)
const opf = sarifToOpf(sarifLog)
const { valid, errors } = validateOpf(opfDocument)

// issue trackers
const drafts = opfToIssues(opfDocument)                        // tracker-neutral tickets
const csv = opfToIssuesCsv(opfDocument, 'linear')              // any tracker profile
const payload = opfToJiraRest(opfDocument, { projectKey: 'SEC' })
await pushToJira(opfDocument, { baseUrl, email, apiToken, projectKey: 'SEC' })
await pushToGitHub(opfDocument, { owner: 'cairnsec', repo: 'findings', token })
await pushToGitLabIssues(opfDocument, { projectId: 'group/app', token })
await pushToLinear(opfDocument, { apiKey, teamId })
await pushToAzure(opfDocument, { org: 'acme', project: 'Security', token })
await pushToServiceNow(opfDocument, { instanceUrl, user, password })
```

Every `push*` takes an injectable `fetch` for testing, and each has a pure counterpart (`opfTo*`) that builds the request without sending it.

## Mapping notes

- **Severity → tool severity.** OPF `critical/high/medium/low/informational` maps to each target's scale (SARIF `error/warning/note`, DefectDojo/GitLab `Critical…Info`).
- **CVSS carries through.** The score becomes SARIF `security-severity` (what GitHub ranks alerts on), DefectDojo `cvssv3_score`, and so on. When a finding has no CVSS score, one is synthesised from its severity so it still buckets correctly.
- **Identifiers travel.** CWE, CVE, OWASP and MITRE ATT&CK map to each format's native identifier or tag (`external/cwe/cwe-89` for SARIF, integer `cwe` for DefectDojo, typed `identifiers[]` for GitLab).
- **Text is normalised.** OPF text is often HTML (`textFormat: "html"`); it is stripped to plain text for text fields and lightly formatted for Markdown/HTML.
- **Round trips keep structure.** OPF → CSV → OPF and OPF → SARIF → OPF preserve the fields those formats can represent, so a finding survives as a finding, not a flattened paragraph.
- **One issue model, many trackers.** Each finding maps once to a neutral `IssueDraft` (summary, priority, labels, a Markdown body, and structured CVSS/CWE/CVE fields). Severity becomes each tracker's priority scale, and every tracker is then a thin adapter over that draft: a CSV column profile (Jira, GitHub, Linear, Azure Boards, generic) or a REST/GraphQL payload builder plus a live pusher (Jira, GitHub, GitLab, Linear, Azure Boards, ServiceNow). Adding another API-backed tracker is a small file modelled on the existing adapters.

## Why

A finding library is an asset a team builds over years. It should not be trapped in one vendor's database. OPF makes it portable; `opf-tools` makes that portability real by connecting OPF to the tools findings actually flow through.

## See also

- [**cairnsec/opf**](https://github.com/cairnsec/opf) — the OPF specification, JSON Schema and examples.

## License

MIT.
