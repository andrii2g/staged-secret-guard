# Sources and Version Notes

Reviewed on 2026-07-25.

Primary references used to prepare this implementation pack:

- Rust 1.97.1 release announcement: `https://blog.rust-lang.org/2026/07/16/Rust-1.97.1/`
- Cargo manifest and `rust-version`: `https://doc.rust-lang.org/cargo/reference/manifest.html`
- Cargo Rust version contract: `https://doc.rust-lang.org/cargo/reference/rust-version.html`
- Git hooks: `https://git-scm.com/docs/githooks`
- Git configuration: `https://git-scm.com/docs/git-config`
- HTTP semantics and Authorization fields: `https://www.rfc-editor.org/rfc/rfc9110.html`
- HTTP cookies: `https://www.rfc-editor.org/rfc/rfc6265.html`
- Git diff: `https://git-scm.com/docs/git-diff`
- Git diff format: `https://git-scm.com/docs/diff-format`
- Git index file listing: `https://git-scm.com/docs/git-ls-files`
- Clap crate: `https://crates.io/crates/clap`
- Regex crate: `https://crates.io/crates/regex`

Dependency version policy:

- Pin the current intended direct dependency line in `Cargo.toml`.
- Generate `Cargo.lock` during implementation and commit it because this is an application.
- Do not update dependencies opportunistically while implementing unrelated behavior.
- Any dependency addition or major-version change requires an ADR entry.

Provider token formats evolve. Before changing a provider detector after v0.1, consult the provider’s official documentation and add positive/negative tests without committing a complete realistic token literal.
