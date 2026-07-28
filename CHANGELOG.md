# Changelog

All notable changes will be documented in this file.

## 0.3.0 - 2026-07-27

- Stopped treating configuration-file with `MASKED`/`*MASKED*` placeholders.

## 0.2.0 - 2026-07-26

- Made hook commands global for the current user by default, with explicit `--local` repository targeting, ownership-aware uninstall, and isolated scope status.
- Invoking `hook install` now authorizes the required scoped `core.hooksPath` change.
- Sanitized invalid exclusion-glob diagnostics so configured pattern text is never echoed.
- Blocked non-empty credential-header literals of every length while allowing authorization schemes without a credential value.
- Added a tag/manual release workflow that packages Linux, Windows, and macOS binaries with the license and SHA-256 checksums.
- Stopped treating unquoted runtime calls and index lookups assigned to sensitive variables as literal secrets.


## 0.1.0 - 2026-07-25

- Implemented the complete offline `secret-guard` CLI for staged-index and recursive folder scanning.
- Added the 19-rule built-in catalog, including high-confidence literal HTTP credential headers, safe redaction, strict configuration, deterministic console/JSON reports, and stable exit codes.
- Added provider/header/JWT overlap precedence so literal Bearer credentials block without duplicate findings.
- Added conservative worktree-aware pre-commit hook management.
- Added cross-platform, MSRV, release-build, self-scan, unit, component, and temporary-Git-repository verification.
