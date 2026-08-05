# opf-tools

Converters between the [Open Pentest Format](https://github.com/cairnsec/opf) (OPF) and the formats security teams already use.

OPF is a small, portable JSON format for pentest findings and finding libraries. On its own a portable format is only half the story, it has to reach the tools people actually run. `opf-tools` is that bridge: it turns an OPF library into SARIF, DefectDojo, GitLab, Markdown, HTML or CSV, and reads SARIF and CSV back into OPF.

Zero runtime dependencies. Library + `opf` CLI. MIT.

## Converters

| Command | From → To | Use it for |
|---------|-----------|------------|
| `sarif` | OPF → SARIF 2.1.0 | GitHub code scanning, Azure DevOps, VS Code SARIF Viewer |
| `from-sarif` | SARIF → OPF | Bring scanner output into an OPF library |
| `defectdojo` | OPF → DefectDojo Generic Findings Import | Import a library into DefectDojo, no custom parser |
| `gitlab` | OPF → GitLab SAST report | Surface findings on GitLab MRs / security dashboard |
| `markdown` | OPF → Markdown | A readable, diffable finding document |
| `html` | OPF → standalone HTML | A self-contained page to open or share |
| `csv` | OPF → CSV | Spreadsheets, triage, bulk edit |
| `from-csv` | CSV → OPF | Turn a spreadsheet back into a library |
| `validate` | OPF → pass/fail | Check a document in CI or a pre-commit hook |

## Install

```bash
npm install @cairnsecurity/opf-tools
```

## CLI

```bash
opf <command> [input] [output]

# examples
opf sarif library.opf.json library.sarif.json
opf defectdojo library.opf.json | curl -F 'file=@-' ...        # into DefectDojo
opf markdown library.opf.json > FINDINGS.md
opf validate library.opf.json                                  # non-zero exit if invalid
cat scan.sarif.json | opf from-sarif > scan.opf.json           # scanner → OPF
```

Reads a file argument or stdin; writes a file argument or stdout.

## Library

```ts
import { opfToSarif, opfToDefectDojo, sarifToOpf, validateOpf } from '@cairnsecurity/opf-tools'

const sarif = opfToSarif(opfDocument)
const dd = opfToDefectDojo(opfDocument)
const opf = sarifToOpf(sarifLog)
const { valid, errors } = validateOpf(opfDocument)
```

## Mapping notes

- **Severity → tool severity.** OPF `critical/high/medium/low/informational` maps to each target's scale (SARIF `error/warning/note`, DefectDojo/GitLab `Critical…Info`).
- **CVSS carries through.** The score becomes SARIF `security-severity` (what GitHub ranks alerts on), DefectDojo `cvssv3_score`, and so on. When a finding has no CVSS score, one is synthesised from its severity so it still buckets correctly.
- **Identifiers travel.** CWE, CVE, OWASP and MITRE ATT&CK map to each format's native identifier or tag (`external/cwe/cwe-89` for SARIF, integer `cwe` for DefectDojo, typed `identifiers[]` for GitLab).
- **Text is normalised.** OPF text is often HTML (`textFormat: "html"`); it is stripped to plain text for text fields and lightly formatted for Markdown/HTML.
- **Round trips keep structure.** OPF → CSV → OPF and OPF → SARIF → OPF preserve the fields those formats can represent, so a finding survives as a finding, not a flattened paragraph.

## Why

A finding library is an asset a team builds over years. It should not be trapped in one vendor's database. OPF makes it portable; `opf-tools` makes that portability real by connecting OPF to the tools findings actually flow through.

## See also

- [**cairnsec/opf**](https://github.com/cairnsec/opf) — the OPF specification, JSON Schema and examples.

## License

MIT.
