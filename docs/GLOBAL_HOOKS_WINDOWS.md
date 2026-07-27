# Global Git client hook on Windows

This guide installs `secret-guard` once and configures one pre-commit hook for all repositories used by the current Windows account.

**You do not enumerate repositories and you do not install a hook in every repository.** Git redirects all ordinary repositories for this account to one shared hook file.

## Prerequisites

- Git for Windows available on `PATH`;
- Rust installed through Rustup;
- PowerShell;
- the `staged-secret-guard` source directory.

## Install the executable once

Open PowerShell in the `staged-secret-guard` source directory:

```powershell
rustup update stable
cargo +stable install --locked --path .
secret-guard --version
```

Cargo normally installs `secret-guard.exe` under `%USERPROFILE%\.cargo\bin`. If PowerShell cannot find it, add that directory to the user `PATH`, open a new terminal, and verify with:

```powershell
Get-Command secret-guard
```

## Install the global hook once

Run the default global installation from any directory:

```powershell
secret-guard hook install
```

The explicit install command immediately creates the required user-level `core.hooksPath`; there is no secondary prompt or automation flag. Installing or updating the executable alone never changes Git configuration.

Once configured, Git stops selecting repository-local hook directories for repositories without their own override. Review [existing hooks and overrides](#existing-hooks-and-overrides) before installation when those hooks must be preserved.

Verify the managed hook and Git setting:

```powershell
secret-guard hook status
git config --show-origin --get core.hooksPath
```

Expected status:

```text
installed
```

When no path existed, the resolved hook is normally `%USERPROFILE%\.config\secret-guard\hooks\pre-commit`. If a global hooks directory already existed, Secret Guard adopts it only when its `pre-commit` slot is absent or already managed.

The hook contains the absolute installed executable path and runs `secret-guard scan --staged`. Other repositories automatically use it unless they explicitly override `core.hooksPath`.

```text
repository A ---\
repository B ----+--> %USERPROFILE%\.config\secret-guard\hooks\pre-commit
repository C ---/
```
## Verify another repository

```powershell
Set-Location C:\path\to\another-repository
secret-guard hook status
git add .
git commit -m "Verify global secret guard"
```

The same hook runs from the second repository's worktree and scans only its staged Git-index content. A blocking finding returns `1`; an operational failure returns `2`. Either result prevents the commit.

## Configure individual repositories

To protect only one repository instead of configuring the account-wide hook:

```powershell
secret-guard hook install --local --repository C:\path\to\repository
secret-guard hook status --local --repository C:\path\to\repository
```

If the managed global hook is already effective there, the local command reports `covered-by-global` and makes no redundant change.

Each repository can keep its own `.secret-guard.toml` in its root. For example, to block medium and higher findings:

```toml
version = 1

[scan]
fail_on = "medium"
```

The shared hook discovers this configuration from the repository where the commit is running.

## Existing hooks and overrides

`core.hooksPath` redirects Git away from each repository's normal `.git/hooks` directory; Git does not merge the two locations. Existing repository-local hooks stop running unless they are moved or manually chained into the shared hook.

Before enabling the global path, inspect any existing setting:

```powershell
git config --show-origin --get-all core.hooksPath
```

A repository-local `core.hooksPath`, including one configured by tools such as Husky, can override the global value. Check the effective value inside that repository:

```powershell
git config --show-origin --get core.hooksPath
git rev-parse --git-path hooks/pre-commit
```

If the shared directory already contains an unrelated or modified `pre-commit` hook, `secret-guard hook install` refuses to overwrite it and prints a safely quoted command for manual chaining.

## Update or move the executable

After reinstalling `secret-guard` at a different path, enter a repository that uses the global hook and run:

```powershell
secret-guard hook status
secret-guard hook install
```

Status reports `stale-executable` when the recognized managed hook points to another executable path. Installation updates only an otherwise canonical managed hook.

## Remove the global setup

Remove the managed global hook from any directory:

```powershell
secret-guard hook uninstall
```

Secret Guard unsets `core.hooksPath` only when its hook metadata proves that Secret Guard created that exact value. An adopted hooks path is preserved. The directory can be removed if it is empty; never delete it when it contains other hooks.

## Limitations

- `git commit --no-verify` bypasses all client-side hooks.
- A GUI or IDE running as another Windows account uses that account's Git configuration.
- A GUI bundled with a different Git executable may use different configuration discovery; verify its effective `core.hooksPath`.
- This setup protects local commits, not pushes made from other machines or accounts. Use a required CI scan for centralized enforcement.
