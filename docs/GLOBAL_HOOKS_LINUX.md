# Global Git client hook on Linux

This guide installs `secret-guard` once and configures one pre-commit hook for all repositories used by the current Linux account.

**You do not enumerate repositories and you do not install a hook in every repository.** Git redirects all ordinary repositories for this account to one shared hook file.

## Prerequisites

- Git available on `PATH`;
- Rust installed through Rustup;
- a POSIX-compatible shell;
- the `staged-secret-guard` source directory.

## Install the executable once

From the `staged-secret-guard` source directory:

```sh
rustup update stable
cargo +stable install --locked --path .
secret-guard --version
```

Cargo normally installs the executable under `$HOME/.cargo/bin`. If the command is unavailable, add it to `PATH` for the current session:

```sh
export PATH="$HOME/.cargo/bin:$PATH"
```

Add the same export to `~/.profile`, `~/.bashrc`, `~/.zshrc`, or the appropriate shell startup file for future sessions.

## Install the global hook once

Run the default global installation from any directory:

```sh
secret-guard hook install
```

The explicit install command immediately creates the required user-level `core.hooksPath`; there is no secondary prompt or automation flag. Installing or updating the executable alone never changes Git configuration.

Once configured, Git stops selecting repository-local hook directories for repositories without their own override. Review [existing hooks and overrides](#existing-hooks-and-overrides) before installation when those hooks must be preserved.

Verify the managed hook and Git setting:

```sh
secret-guard hook status
git config --show-origin --get core.hooksPath
```

Expected status:

```text
installed
```

When no path existed, the resolved hook is normally `${XDG_CONFIG_HOME:-$HOME/.config}/secret-guard/hooks/pre-commit`. If a global hooks directory already existed, Secret Guard adopts it only when its `pre-commit` slot is absent or already managed.

The installer gives the hook executable permissions, embeds the absolute installed executable path, and runs `secret-guard scan --staged`. Other repositories automatically use it unless they explicitly override `core.hooksPath`.

```text
repository A ---\
repository B ----+--> $HOME/.config/secret-guard/hooks/pre-commit
repository C ---/
```
## Verify another repository

```sh
cd /path/to/another-repository
secret-guard hook status
git add .
git commit -m "Verify global secret guard"
```

The same hook runs from the second repository's worktree and scans only its staged Git-index content. A blocking finding returns `1`; an operational failure returns `2`. Either result prevents the commit.

## Configure individual repositories

To protect only one repository instead of configuring the account-wide hook:

```sh
secret-guard hook install --local --repository /path/to/repository
secret-guard hook status --local --repository /path/to/repository
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

```sh
git config --show-origin --get-all core.hooksPath
```

A repository-local `core.hooksPath`, including one configured by tools such as Husky, can override the global value. Check the effective value inside that repository:

```sh
git config --show-origin --get core.hooksPath
git rev-parse --git-path hooks/pre-commit
```

If the shared directory already contains an unrelated or modified `pre-commit` hook, `secret-guard hook install` refuses to overwrite it and prints a safely quoted command for manual chaining.

## Update or move the executable

After reinstalling `secret-guard` at a different path, enter a repository that uses the global hook and run:

```sh
secret-guard hook status
secret-guard hook install
```

Status reports `stale-executable` when the recognized managed hook points to another executable path. Installation updates only an otherwise canonical managed hook.

## Remove the global setup

Remove the managed global hook from any directory:

```sh
secret-guard hook uninstall
```

Secret Guard unsets `core.hooksPath` only when its hook metadata proves that Secret Guard created that exact value. An adopted hooks path is preserved. The directory can be removed if it is empty; never delete it when it contains other hooks.

## Multi-user machines

Global Git configuration is per operating-system account. Repeat the setup for each developer account that needs local protection. Installing a system-wide hook under `/etc` requires administrator-controlled ownership, upgrades, hook chaining, and Git system configuration; it is intentionally outside the managed per-user workflow described here.

## Limitations

- `git commit --no-verify` bypasses all client-side hooks.
- Commands run through `sudo` may use root's Git configuration rather than the developer's configuration.
- Repositories owned by another account use that account's Git configuration.
- This setup protects local commits, not pushes made from other machines or accounts. Use a required CI scan for centralized enforcement.
