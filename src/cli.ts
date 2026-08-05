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
  validateOpf,
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
  'validate',
])

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

function run(command: string, inputPath?: string, outputPath?: string): void {
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

function main(argv: string[]): void {
  const args = argv.slice(2)
  if (!args.length || args[0] === '-h' || args[0] === '--help') usage(args.length ? 0 : 2)
  const command = args[0]
  if (!COMMANDS.has(command)) {
    process.stderr.write(`opf: unknown command "${command}"\n`)
    usage(2)
  }
  try {
    run(command, args[1], args[2])
  } catch (err) {
    process.stderr.write(`opf: ${(err as Error).message}\n`)
    process.exit(1)
  }
}

main(process.argv)
