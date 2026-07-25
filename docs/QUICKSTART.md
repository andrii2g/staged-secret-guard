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

### Install the managed hook

From inside the repository that should be protected, run:

```text
secret-guard hook install
secret-guard hook status
```

Successful status output is `installed`. Installation creates a POSIX-compatible `pre-commit` script containing the managed marker and a safely quoted absolute executable path. The script runs:

```text
secret-guard scan --staged
```

The actual generated hook uses the absolute executable path. On Unix it is made executable. A scan result of `1` blocks the commit, and an operational failure with result `2` also blocks it.

Installation is idempotent. Repeating `secret-guard hook install` reports `already installed`. If the executable has moved, status reports `stale-executable`; running install again updates a recognized, otherwise unchanged managed hook to the current executable path.

Install the hook separately in each clone or environment because its executable path is machine-specific.

### Hook location, custom hooks paths, and worktrees

The tool asks Git for the effective hook location with:

```text
git rev-parse --git-path hooks/pre-commit
```

This respects Git's effective hooks directory, including `core.hooksPath`, and resolves the correct Git path from a linked worktree. To use a repository-specific hooks directory, configure Git before installing:

```text
git config core.hooksPath .githooks
secret-guard hook install
```

Run status, install, and uninstall after changing `core.hooksPath`; each command operates on the hook path Git currently reports. Because the generated managed hook contains an absolute, machine-specific executable path, do not treat it as a portable hook to commit and share. Each developer or CI environment should install its own hook.

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

Remove an exact recognized managed hook with:

```text
secret-guard hook uninstall
```

Uninstalling an absent hook reports `absent`. Uninstall refuses to delete unrelated or modified hook content. A stale but otherwise canonical managed hook can be removed safely.

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
