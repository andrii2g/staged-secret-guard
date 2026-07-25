# Configuration

## 1. Discovery

Resolution order:

1. `--config <FILE>` exactly;
2. staged mode: `<repository-root>/.secret-guard.toml`;
3. folder mode: `<scan-root>/.secret-guard.toml`;
4. built-in defaults when the expected file does not exist.

An explicitly requested missing file is an error. An implicitly discovered missing file is not an error.

Relative paths inside configuration are interpreted relative to the directory containing the configuration file.

## 2. Schema

```toml
version = 1

[scan]
fail_on = "high"
max_file_size_bytes = 1048576
respect_gitignore = true
fail_on_read_error = true

[exclude]
paths = [
  ".git/**",
  "target/**",
  "node_modules/**",
  "bin/**",
  "obj/**",
  ".idea/**",
  ".vs/**",
  "dist/**",
  "build/**",
  "coverage/**",
  "**/*.min.js",
  "**/*.map"
]

[[allowlist]]
rule = "generic-secret-assignment"
path = "tests/fixtures/**"
reason = "Synthetic test values assembled from fragments"
```

## 3. Strictness

All config structs must use strict unknown-field rejection.

Errors:

- `version` other than `1`;
- missing required field inside an explicitly present allowlist item;
- unknown table or key;
- invalid severity;
- zero `max_file_size_bytes`;
- invalid glob;
- empty or whitespace-only reason;
- invalid rule ID;
- allowlist rule not present in the built-in catalog.

Do not permit arbitrary custom regular expressions in v0.1.

## 4. Defaults

```text
version                 1
fail_on                 high
max_file_size_bytes     1048576
respect_gitignore       true
fail_on_read_error      true
```

Default exclusions are the paths shown in the schema example. User configuration replaces the default `exclude.paths` list only when the list is explicitly present. Codex may instead choose additive semantics, but must document that decision before implementation and keep the example synchronized. The preferred behavior is additive to avoid accidentally scanning generated trees.

## 5. Allowlist semantics

An allowlist item matches only when all specified dimensions match:

- exact rule ID;
- normalized relative path matches the glob.

No value-based allowlisting exists in v0.1. This avoids storing candidate values or hashes in configuration.

An allowlist is applied after detection and changed-range filtering but before report construction. A suppressed candidate must still never be logged.

## 6. Inline suppression

Syntax:

```text
secret-guard:allow(<rule-id>) reason="human explanation"
```

Examples are shown without a complete secret:

```text
// secret-guard:allow(generic-secret-assignment) reason="Documentation placeholder assembled at runtime"
const value = build_example_value();
```

Scope:

- marker on the same line as the match; or
- marker on the immediately preceding physical line.

Requirements:

- exact rule ID;
- non-empty quoted reason;
- malformed markers do not suppress;
- `allow(all)` is not supported;
- a marker applies to only one following physical line, not an entire block;
- for PEM, a marker immediately before the `BEGIN` line suppresses that block.

## 7. Environment/reference values

The generic detector must reject values that are clearly references rather than literals, including:

```text
${PASSWORD}
$PASSWORD
%PASSWORD%
{{ secret }}
env:PASSWORD
ENV[PASSWORD]
process.env.PASSWORD
configuration["Password"]
getenv("PASSWORD")
```

Provider-shaped detectors may still report a literal provider token even if it appears inside a larger expression.

## 8. Placeholder values

Case-insensitive placeholder words and patterns include:

```text
example
dummy
fake
placeholder
changeme
change-me
replace-me
your-token-here
your-api-key
not-a-secret
redacted
<password>
<secret>
xxxxx
********
```

A value composed entirely of repeated punctuation or one repeated character is not a secret finding.

## 9. Sanitized configuration errors

A configuration error message may state:

```text
Invalid configuration at .secret-guard.toml:12:5: unknown field.
```

It must not print the source line or a TOML diagnostic excerpt because configuration files can themselves be mishandled.
