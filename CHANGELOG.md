# Changelog

All notable changes will be documented in this file.

## 0.2.0 - 2026-07-26

- Made hook commands global for the current user by default, with explicit `--local` repository targeting, safe confirmation, ownership-aware uninstall, and isolated scope status.

## 0.1.0 - 2026-07-25

- Implemented the complete offline `secret-guard` CLI for staged-index and recursive folder scanning.
- Added the 19-rule built-in catalog, including high-confidence literal HTTP credential headers, safe redaction, strict configuration, deterministic console/JSON reports, and stable exit codes.
- Added provider/header/JWT overlap precedence so literal Bearer credentials block without duplicate findings.
- Added conservative worktree-aware pre-commit hook management.
- Added cross-platform, MSRV, release-build, self-scan, unit, component, and temporary-Git-repository verification.