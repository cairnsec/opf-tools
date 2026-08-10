#!/usr/bin/env node
/**
 * opf — convert Open Pentest Format files to and from other formats.
 *
 * Usage:
 *   opf <command> [input] [output]
 *   cat lib.opf.json | opf sarif > lib.sarif.json
 *
 * Commands:
 *   sarif        OPF  -> SARIF 2.1.0
 *   from-sarif   SARIF -> OPF
 *   markdown     OPF  -> Markdown
 *   html         OPF  -> standalone HTML
 *   csv          OPF  -> CSV
 *   from-csv     CSV  -> OPF
 *   defectdojo   OPF  -> DefectDojo Generic Findings Import JSON
 *   gitlab       OPF  -> GitLab SAST security report JSON
 *   validate     Check an OPF document; non-zero exit if invalid
 */
import { readFileSync, writeFileSync } from 'node:fs'
import {
  opfToSarif,
  sarifToOpf,
  opfToMarkdown,
  opfToHtml,
  opfToCsv,
  csvToOpf,
  opfToDefectDojo,
  opfToGitLab,
  opfToIssuesCsv,
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
  validateOpf,
  type TrackerId,
} from './index.js'

type Kind = 'json' | 'text'
const COMMANDS = new Set([
  'sarif',
  'from-sarif',
  'markdown',
  'md',
  'html',
  'csv',
  'from-csv',
  'defectdojo',
  'dd',
  'gitlab',
  'jira-csv',
  'github-csv',
  'linear-csv',
  'azure-csv',
  'issues-csv',
  'jira-rest',
  'jira-push',
  'github-rest',
  'github-push',
  'gitlab-issues-rest',
  'gitlab-issues-push',
  'linear-rest',
  'linear-push',
  'azure-rest',
  'azure-push',
  'servicenow-rest',
  'servicenow-push',
  'validate',
])

/** Map a *-csv command to its tracker profile. */
const CSV_TRACKER: Record<string, TrackerId> = {
  'jira-csv': 'jira',
  'github-csv': 'github',
  'linear-csv': 'linear',
  'azure-csv': 'azure-devops',
  'issues-csv': 'generic',
}

function requireEnv(name: string): string {
  const v = process.env[name]
  if (!v) {
    process.stderr.write(`opf: ${name} is required for this command (set it in the environment)\n`)
    process.exit(1)
  }
  return v
}

function usage(code: number): never {
  process.stderr.write(
    [
      'opf — Open Pentest Format converters',
      '',
      'Usage: opf <command> [input] [output]',
      '       cat lib.opf.json | opf sarif > lib.sarif.json',
      '',
      'Commands:',
      '  sarif        OPF  -> SARIF 2.1.0',
      '  from-sarif   SARIF -> OPF',
      '  markdown     OPF  -> Markdown   (alias: md)',
      '  html         OPF  -> standalone HTML',
      '  csv          OPF  -> CSV',
      '  from-csv     CSV  -> OPF',
      '  defectdojo   OPF  -> DefectDojo Generic Findings Import  (alias: dd)',
      '  gitlab       OPF  -> GitLab SAST report',
      '  jira-csv     OPF  -> Jira-importable CSV',
      '  github-csv   OPF  -> GitHub Issues CSV',
      '  linear-csv   OPF  -> Linear CSV',
      '  azure-csv    OPF  -> Azure Boards CSV',
      '  issues-csv   OPF  -> generic issue CSV',
      '  jira-rest    OPF  -> Jira bulk-create JSON      (env: JIRA_PROJECT)',
      '  jira-push    Create issues in a live Jira        (env: JIRA_BASE_URL,',
      '               instance via the bulk API           JIRA_EMAIL, JIRA_TOKEN, JIRA_PROJECT)',
      '  github-rest  OPF  -> GitHub create-issue JSON',
      '  github-push  Create issues in a live GitHub repo (env: GITHUB_OWNER,',
      '                                                    GITHUB_REPO, GITHUB_TOKEN)',
      '  gitlab-issues-rest  OPF -> GitLab create-issue JSON',
      '  gitlab-issues-push  Create issues in a live GitLab (env: GITLAB_PROJECT,',
      '                      project                         GITLAB_TOKEN, [GITLAB_URL])',
      '  linear-rest  OPF  -> Linear IssueCreateInput JSON  (env: LINEAR_TEAM_ID)',
      '  linear-push  Create issues in a live Linear team   (env: LINEAR_API_KEY,',
      '                                                      LINEAR_TEAM_ID)',
      '  azure-rest   OPF  -> Azure Boards work-item JSON',
      '  azure-push   Create work items in Azure Boards     (env: AZURE_ORG,',
      '                                                      AZURE_PROJECT, AZURE_TOKEN)',
      '  servicenow-rest  OPF -> ServiceNow record JSON',
      '  servicenow-push  Insert records into ServiceNow    (env: SN_INSTANCE,',
      '                                                      SN_USER, SN_PASSWORD, [SN_TABLE])',
      '  validate     Check an OPF document (non-zero exit if invalid)',
      '',
    ].join('\n'),
  )
  process.exit(code)
}

function read(path?: string): string {
  try {
    return path ? readFileSync(path, 'utf-8') : readFileSync(0, 'utf-8')
  } catch (err) {
    process.stderr.write(`opf: cannot read input: ${(err as Error).message}\n`)
    process.exit(1)
  }
}

function parseJson(raw: string): unknown {
  try {
    return JSON.parse(raw)
  } catch (err) {
    process.stderr.write(`opf: input is not valid JSON: ${(err as Error).message}\n`)
    process.exit(1)
  }
}

function emit(out: string, outputPath?: string): void {
  if (outputPath) writeFileSync(outputPath, out.endsWith('\n') ? out : out + '\n')
  else process.stdout.write(out.endsWith('\n') ? out : out + '\n')
}

async function run(command: string, inputPath?: string, outputPath?: string): Promise<void> {
  const raw = read(inputPath)
  const json = () => parseJson(raw)
  const stringify = (o: unknown) => JSON.stringify(o, null, 2)

  let output: string
  let outKind: Kind = 'json'

  switch (command) {
    case 'sarif':
      output = stringify(opfToSarif(json() as never))
      break
    case 'from-sarif':
      output = stringify(sarifToOpf(json()))
      break
    case 'markdown':
    case 'md':
      output = opfToMarkdown(json() as never)
      outKind = 'text'
      break
    case 'html':
      output = opfToHtml(json() as never)
      outKind = 'text'
      break
    case 'csv':
      output = opfToCsv(json() as never)
      outKind = 'text'
      break
    case 'from-csv':
      output = stringify(csvToOpf(raw))
      break
    case 'defectdojo':
    case 'dd':
      output = stringify(opfToDefectDojo(json() as never))
      break
    case 'gitlab':
      output = stringify(opfToGitLab(json() as never))
      break
    case 'jira-csv':
    case 'github-csv':
    case 'linear-csv':
    case 'azure-csv':
    case 'issues-csv':
      output = opfToIssuesCsv(json() as never, CSV_TRACKER[command])
      outKind = 'text'
      break
    case 'jira-rest':
      output = stringify(opfToJiraRest(json() as never, { projectKey: requireEnv('JIRA_PROJECT') }))
      break
    case 'jira-push': {
      const result = await pushToJira(json() as never, {
        baseUrl: requireEnv('JIRA_BASE_URL'),
        email: requireEnv('JIRA_EMAIL'),
        apiToken: requireEnv('JIRA_TOKEN'),
        projectKey: requireEnv('JIRA_PROJECT'),
      })
      output = stringify(result)
      break
    }
    case 'github-rest':
      output = stringify(opfToGitHubIssues(json() as never))
      break
    case 'github-push': {
      const result = await pushToGitHub(json() as never, {
        owner: requireEnv('GITHUB_OWNER'),
        repo: requireEnv('GITHUB_REPO'),
        token: requireEnv('GITHUB_TOKEN'),
      })
      output = stringify(result)
      break
    }
    case 'gitlab-issues-rest':
      output = stringify(opfToGitLabIssues(json() as never))
      break
    case 'gitlab-issues-push': {
      const result = await pushToGitLabIssues(json() as never, {
        projectId: requireEnv('GITLAB_PROJECT'),
        token: requireEnv('GITLAB_TOKEN'),
        baseUrl: process.env.GITLAB_URL,
      })
      output = stringify(result)
      break
    }
    case 'linear-rest':
      output = stringify(opfToLinearInputs(json() as never, { teamId: requireEnv('LINEAR_TEAM_ID') }))
      break
    case 'linear-push': {
      const result = await pushToLinear(json() as never, {
        apiKey: requireEnv('LINEAR_API_KEY'),
        teamId: requireEnv('LINEAR_TEAM_ID'),
      })
      output = stringify(result)
      break
    }
    case 'azure-rest':
      output = stringify(opfToAzureWorkItems(json() as never))
      break
    case 'azure-push': {
      const result = await pushToAzure(json() as never, {
        org: requireEnv('AZURE_ORG'),
        project: requireEnv('AZURE_PROJECT'),
        token: requireEnv('AZURE_TOKEN'),
      })
      output = stringify(result)
      break
    }
    case 'servicenow-rest':
      output = stringify(opfToServiceNowRecords(json() as never))
      break
    case 'servicenow-push': {
      const result = await pushToServiceNow(json() as never, {
        instanceUrl: requireEnv('SN_INSTANCE'),
        user: requireEnv('SN_USER'),
        password: requireEnv('SN_PASSWORD'),
        table: process.env.SN_TABLE,
      })
      output = stringify(result)
      break
    }
    case 'validate': {
      const result = validateOpf(json())
      for (const w of result.warnings) process.stderr.write(`warning ${w.path}: ${w.message}\n`)
      if (result.valid) {
        process.stderr.write('OPF document is valid.\n')
        process.exit(0)
      }
      for (const e of result.errors) process.stderr.write(`error ${e.path}: ${e.message}\n`)
      process.stderr.write(`OPF document is INVALID (${result.errors.length} error(s)).\n`)
      process.exit(1)
    }
    default:
      usage(2)
  }

  void outKind
  emit(output!, outputPath)
}

async function main(argv: string[]): Promise<void> {
  const args = argv.slice(2)
  if (!args.length || args[0] === '-h' || args[0] === '--help') usage(args.length ? 0 : 2)
  const command = args[0]
  if (!COMMANDS.has(command)) {
    process.stderr.write(`opf: unknown command "${command}"\n`)
    usage(2)
  }
  try {
    await run(command, args[1], args[2])
  } catch (err) {
    process.stderr.write(`opf: ${(err as Error).message}\n`)
    process.exit(1)
  }
}

main(process.argv)
