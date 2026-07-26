# Staged Secret Guard

`staged-secret-guard` provides the `secret-guard` executable, a deterministic, offline Rust CLI that prevents likely credentials and private keys from entering a Git commit.

## Quick start

See [Quick start](docs/QUICKSTART.md) for installation, staged and folder scans, report options, and complete Git pre-commit hook configuration.

## Staged-index behavior

Staged mode discovers the repository through Git, enumerates NUL-delimited staged paths, resolves each stage-0 index entry, and reads each blob by object ID with `git cat-file`. It never reads the working-tree copy. Full staged text is scanned so multiline matches can be found, then findings are retained only when their line span intersects an added or modified new-side hunk. Exact rename-only entries run path rules without content rules.

All Git processes are started directly with argument arrays. No shell is used for Git operations, and the program performs no network requests.

## Detection and safety

The built-in catalog covers provider-shaped tokens, PEM private-key blocks, contextual cloud secrets, credential-bearing HTTP headers, URLs and connection strings, JWT warnings, context-scored generic assignments, and suspicious paths. Every non-empty literal Bearer/API-key/token credential and credential-like session cookie is high severity regardless of length; scheme-only authorization headers, placeholders, and environment references remain valid source. Use `secret-guard rules list` for the complete stable catalog.

A report finding contains only location metadata, severity, confidence, a safe message, and a redacted preview. It never contains the complete candidate or a source line. Values shorter than eight characters become `[REDACTED]`; longer values reveal at most two leading and two trailing ASCII characters.

## Configuration

Configuration is discovered at `.secret-guard.toml` in the repository or folder-scan root. `--config FILE` selects an explicit file. Missing discovered configuration uses defaults; a missing explicit file or invalid configuration returns `2`.

See [.secret-guard.example.toml](.secret-guard.example.toml) and [docs/CONFIGURATION.md](docs/CONFIGURATION.md). Unknown fields, invalid globs, unknown allowlist rules, and empty allowlist reasons are errors. Configured exclusions are additive to the safe default exclusions.

Inline suppression requires an exact rule ID and a non-empty reason on the same or immediately preceding physical line:

```text
// secret-guard:allow(generic-secret-assignment) reason="Synthetic value assembled at runtime"
let value = build_test_value();
```

## Hook safety

The installed hook is a small, versioned, fully managed script that invokes the absolute current executable path with `scan --staged`. `secret-guard hook install` installs it globally for the current operating-system user by default and can run outside a repository; `--local` selects one repository instead. The explicit install command automatically applies any required scoped `core.hooksPath` change, with no second confirmation option; installing or updating the binary alone never changes Git configuration. Installation remains idempotent and never overwrites or automatically chains an unrelated hook. See [Configure the Git pre-commit hook](docs/QUICKSTART.md#configure-the-git-pre-commit-hook), [global Windows setup](docs/GLOBAL_HOOKS_WINDOWS.md), or [global Linux setup](docs/GLOBAL_HOOKS_LINUX.md).

## Development

Run the platform verification script:

```text
sh ./scripts/verify.sh
```

```text
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify.ps1
```

The scripts run formatting checks, Clippy with warnings denied, and all tests. Release readiness additionally requires `cargo build --release` and a release-binary self-scan.

## Documented limitations

Version 0.2 intentionally does not scan Git history, archives, binary files, UTF-16 files, or obfuscated/split credentials. It does not verify credentials with providers, download rules, accept custom regular expressions, chain unrelated hooks automatically, rotate secrets, run as a daemon, or scan in parallel. Users can bypass local hooks with `git commit --no-verify`; CI scanning is recommended as a second layer.
