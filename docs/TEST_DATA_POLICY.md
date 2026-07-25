# Test Data Policy

## Goal

Test detectors rigorously without committing complete realistic credential-shaped values that could trigger hosting-provider secret scanners or be copied accidentally.

## Rules

1. Do not place a complete provider-shaped token in a tracked source, fixture, comment, Markdown example, snapshot, or configuration file.
2. Construct positive candidates at runtime from separately stored fragments.
3. Keep fragments individually too short or structurally incomplete for the detector.
4. Use obviously nonfunctional domains such as `.test` for URL tests.
5. Never use an actual credential, revoked credential, production secret, or user data.
6. For every rendered output, assert the complete runtime candidate is absent.
7. Do not globally allowlist the repository’s tests from the scanner. The repository should be able to scan itself cleanly.

## Rust construction pattern

Preferred:

```text
let prefix = ["g", "hp", "_"].concat();
let body = "A".repeat(REQUIRED_TEST_LENGTH);
let candidate = format!("{prefix}{body}");
```

Avoid compile-time concatenation that may place the complete result into source diagnostics or compiled constants when not necessary.

For a PEM test, assemble markers from fragments:

```text
let begin = ["-----BEGIN ", "PRIVATE", " KEY-----"].concat();
let end = ["-----END ", "PRIVATE", " KEY-----"].concat();
```

## Fixture files

Static fixture files should contain only safe ordinary text, malformed prefixes, placeholders, or split fragments. Tests that require a full candidate must create a temporary file at runtime and delete it with the temporary directory.

## Self-scan gate

The final release workflow must run the built binary against the repository root. A finding in tracked test data is a release failure unless it is an explicitly documented product source false positive fixed through detector refinement, not a broad allowlist.
