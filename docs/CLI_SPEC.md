# CLI Specification

## 1. Program

```text
secret-guard [GLOBAL OPTIONS] [COMMAND]
```

No command means staged scan.

## 2. Global options

```text
--config <FILE>       Explicit TOML configuration file
--format <FORMAT>     console | json; default console
--output <FILE>       Write report to a file instead of stdout
--fail-on <SEVERITY>  low | medium | high | critical
--quiet               Suppress clean-success console output
-h, --help
-V, --version
```

Global options must work before or after subcommands where Clap supports them.

## 3. Scan command

```text
secret-guard scan [PATH] [--staged]
```

Rules:

- no `PATH` and no `--staged`: staged scan;
- `--staged`: staged scan;
- `PATH`: folder scan;
- `PATH` and `--staged`: CLI usage error, exit `2`.

Examples:

```text
secret-guard
secret-guard scan
secret-guard scan --staged
secret-guard scan .
secret-guard --format json scan .
secret-guard --fail-on medium scan --staged
```

## 4. Hook command

```text
secret-guard hook install [--global | --local] [--repository <PATH>]
secret-guard hook status [--global | --local] [--repository <PATH>]
secret-guard hook uninstall [--global | --local] [--repository <PATH>]
```

Scope rules:

- no scope option means global user scope;
- `--global` explicitly selects the same global scope;
- global commands may run outside a repository;
- `--local` selects one repository;
- `--repository <PATH>` requires `--local` and otherwise the current directory is used.

Installing the binary alone never changes Git configuration. Invoking `hook install` explicitly authorizes Secret Guard to create the required scope-specific `core.hooksPath`; installation proceeds without an additional prompt in both interactive and non-interactive environments. Existing-path adoption, conflict refusal, ownership tracking, and rollback rules still apply.

### Install output states

- installed;
- already installed;
- updated managed hook;
- refused because an unrelated hook exists;
- failed because repository or executable path could not be resolved.

### Status output states

Stable status identifiers:

```text
absent
installed
stale-executable
modified-managed
unrelated
covered-by-global
shadowed
```

Human-readable text may accompany the identifier.

Operational hook failures are not stable status identifiers. They are written to stderr and return exit `2`.

`covered-by-global` applies to local status when the effective managed global hook already protects the repository. `shadowed` means a recognized managed hook exists but the effective Git configuration does not select it.

### Uninstall

Only an exact recognized managed hook may be removed. Any unrelated or modified file is preserved and returns exit `2`.

## 5. Rules command

```text
secret-guard rules list
```

Console columns:

```text
RULE ID | SEVERITY | FAMILY | DESCRIPTION
```

JSON shape:

```json
{
  "schemaVersion": 1,
  "rules": [
    {
      "id": "private-key-pem",
      "severity": "critical",
      "family": "private-key",
      "description": "PEM encoded private key block"
    }
  ]
}
```

## 6. Console scan output

### Clean default output

```text
Secret Guard: no blocking secrets found.
Scanned 7 files; 0 findings; 2 skipped.
```

With `--quiet`, emit nothing for a clean completed scan.

### Findings

```text
Secret Guard blocked the commit.

[HIGH] github-token
Path: src/config.rs:18:24
Reason: Value matches a GitHub token structure.
Value: gh••••9z

[MEDIUM] generic-secret-assignment
Path: appsettings.json:12:17
Reason: Sensitive assignment contains a high-confidence literal value.
Value: pa••••rd

Summary: 2 findings; 1 blocking; 8 files scanned; 1 file skipped.
```

For folder scans, the first line is:

```text
Secret Guard found blocking secrets.
```

The tool must never print the source line.

### Warnings below threshold

A completed scan with only findings below threshold returns `0` but still prints them unless `--quiet` is interpreted only for clean success. In v0.1, `--quiet` does not suppress findings.

## 7. JSON scan output

```json
{
  "schemaVersion": 1,
  "mode": "staged",
  "root": ".",
  "threshold": "high",
  "summary": {
    "filesConsidered": 8,
    "filesScanned": 7,
    "findingsTotal": 2,
    "findingsBlocking": 1,
    "skipped": {
      "binary": 1,
      "invalidUtf8": 0,
      "oversized": 0,
      "symlink": 0,
      "submodule": 0,
      "excluded": 0,
      "ignored": 0
    }
  },
  "findings": [
    {
      "ruleId": "github-token",
      "severity": "high",
      "confidence": 98,
      "path": "src/config.rs",
      "line": 18,
      "column": 24,
      "endLine": 18,
      "endColumn": 63,
      "redacted": "gh••••9z",
      "message": "Value matches a GitHub token structure."
    }
  ]
}
```

Contract rules:

- no timestamp;
- no absolute path in `root` or findings unless the scan target cannot be represented relative to itself; use `.` for the root;
- no raw candidate;
- findings sorted deterministically;
- UTF-8 without BOM;
- trailing newline permitted and recommended.

## 8. Streams

- Completed report: stdout or `--output` file.
- Operational errors: stderr.
- When `--output` is used, stdout may contain a short success location message in console format; in JSON format stdout must remain empty.

## 9. Exit codes

```text
0  Scan completed and no finding met or exceeded threshold
1  Scan completed and at least one finding met or exceeded threshold
2  Usage, configuration, Git, filesystem, hook, output, or internal error
```

The reducer must evaluate severity exactly. An empty finding list is success only after the scan completed without fatal errors.
