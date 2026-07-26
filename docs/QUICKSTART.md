# Quick start

This guide installs `secret-guard`, scans staged Git-index content, and configures the optional pre-commit hook.

## Prerequisites

- Git available on `PATH`;
- Rust 1.85.0 or newer;
- a local clone of this repository for installation from source.

The scanner is offline at runtime and does not contact credential providers or download rules.

## Install

From the `staged-secret-guard` source directory, install the executable into Cargo's binary directory:

```text
cargo +stable install --locked --path .
secret-guard --version
```

If Cargo's binary directory is not on `PATH`, invoke `secret-guard` by its absolute path. Hook installation records the absolute path of the executable that performs the installation.

## Scan staged content

Run the scanner anywhere inside a Git worktree:

```text
secret-guard
```

The following forms are equivalent:

```text
secret-guard scan
secret-guard scan --staged
```

Staged mode reads blob bytes from the Git index. An unstaged working-tree edit cannot change the scan result. Findings from content rules are limited to added or modified new-side line ranges.

The default blocking threshold is `high`. A completed scan returns:

- `0` when no finding meets the threshold;
- `1` when at least one finding meets the threshold;
- `2` for usage, configuration, Git, filesystem, hook, report, or scanner failures.

## Scan a folder

Pass a directory to scan its eligible regular files recursively:

```text
secret-guard scan .
secret-guard scan ../another-project
```

Hidden files are eligible, `.git` and generated dependency/build directories are excluded, Git ignore rules are respected by default, and symlinks are not followed.

## Configure reports and thresholds

Global options may select JSON, write a report, or override the blocking threshold:

```text
secret-guard --format json scan --staged
secret-guard --format json --output report.json scan .
secret-guard --fail-on medium scan --staged
secret-guard --quiet scan .
```

Configuration is discovered in `.secret-guard.toml` at the repository or scan root. Start from [the example configuration](../.secret-guard.example.toml) and see the [configuration reference](CONFIGURATION.md) for exclusions, allowlists, and inline suppression.

## Configure the Git pre-commit hook

### Install globally by default

Run this once from any directory:

```text
secret-guard hook install
```

The explicit install command immediately creates the required user-level `core.hooksPath`; Installing or updating the executable alone never changes Git configuration.

After a global path is created, Git stops selecting repository-local hook directories. Review the existing-hooks section in the [Windows guide](GLOBAL_HOOKS_WINDOWS.md#existing-hooks-and-overrides) or [Linux guide](GLOBAL_HOOKS_LINUX.md#existing-hooks-and-overrides) when that matters; Secret Guard still refuses to overwrite an unrelated hook in the selected shared directory.

Check the global state from any directory:

```text
secret-guard hook status
```

The installer adopts an existing global hooks directory when its `pre-commit` slot is absent or already managed. Otherwise it creates an absolute user-owned hooks directory and records ownership in the managed hook. It never overwrites or automatically chains unrelated hook content.

Platform-specific examples:

- [Global Git client hook on Windows](GLOBAL_HOOKS_WINDOWS.md)
- [Global Git client hook on Linux](GLOBAL_HOOKS_LINUX.md)

### Protect only one repository

```text
secret-guard hook install --local
secret-guard hook status --local
```

Run those commands inside the repository, or select it from another directory:

```text
secret-guard hook install --local --repository /path/to/repository
```

If the effective managed global hook already protects the selected repository, local installation reports `covered-by-global` and creates no redundant override. A local override is created only when it will not silently disable unrelated global hooks.

### Managed hook behavior

The installed POSIX-compatible `pre-commit` script contains the managed scope, Git-configuration ownership, and safely quoted absolute executable path. It runs `secret-guard scan --staged`. On Unix it is executable. Scan result `1` and operational result `2` both block the commit.

Installation is idempotent. If the executable moves, status reports `stale-executable`; installing again updates only an otherwise canonical managed hook. Generated hooks are machine-specific and must not be committed as portable project files.

### Existing hooks and manual chaining

`secret-guard` owns only its exact generated hook. If `pre-commit` already contains an unrelated hook or a modified managed hook, installation exits with code `2` and does not overwrite it. The error prints a safely quoted command for manual chaining.

Add that printed command to the existing hook so a non-zero scanner result stops the commit. A typical POSIX hook shape is:

```sh
#!/bin/sh
'/absolute/path/to/secret-guard' scan --staged || exit $?

# Existing project checks follow.
```

Use the exact command printed by `secret-guard hook install`, especially when the executable path contains spaces or quotes. Manual chained hooks remain user-owned: `secret-guard hook status` reports them as `unrelated` or `modified-managed`, and the tool will not update or remove them.

### Inspect or remove the hook

Check the current state with:

```text
secret-guard hook status
```

Possible states are:

- `absent`;
- `installed`;
- `stale-executable`;
- `modified-managed`;
- `unrelated`.
- `covered-by-global`;
- `shadowed`.

Remove an exact recognized managed hook with:

```text
secret-guard hook uninstall
secret-guard hook uninstall --local --repository /path/to/repository
```

Hook actions are global by default. Uninstalling an absent hook reports `absent`. Uninstall refuses to delete unrelated or modified hook content. It unsets `core.hooksPath` only when the managed hook records that Secret Guard created that exact scoped value.

### Verify commit behavior

After installation, stage an ordinary change and make a normal test commit. The hook should run automatically and allow the commit when the scan completes below the configured threshold. When staged content produces a blocking finding, Git aborts the commit and the scanner prints only a redacted value.

Git permits bypassing client-side hooks with `git commit --no-verify`. The tool intentionally does not prevent that bypass. Run `secret-guard scan --staged` in CI as a second enforcement layer when required by project policy.

## Inspect the rule catalog

List the stable built-in detector metadata in console or JSON form:

```text
secret-guard rules list
secret-guard --format json rules list
```

For the full command contract, see [CLI specification](CLI_SPEC.md).
