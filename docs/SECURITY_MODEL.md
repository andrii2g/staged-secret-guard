# Security Model

## 1. Assets protected

- credentials not yet committed;
- source content being scanned;
- local repository integrity;
- existing Git hook behavior;
- deterministic, trustworthy commit gating.

## 2. Trust boundaries

Untrusted or potentially sensitive inputs:

- staged file bytes;
- working directory names and Git paths;
- configuration file content;
- Git process output;
- candidate matches;
- output destination paths.

Trusted code:

- built-in rule catalog;
- compiled regexes;
- fixed managed hook template.

## 3. Threats and controls

### Secret disclosure through output

Controls:

- raw candidates never enter `Finding`;
- source lines are never printed;
- short candidates become `[REDACTED]`;
- long candidates reveal at most two leading and two trailing characters;
- JSON contains only redacted values;
- errors do not include file contents.

### Secret disclosure through debugging

Controls:

- internal candidate type does not derive `Debug`;
- no logging framework in v0.1;
- no debug dumps of regex captures;
- tests assert candidate absence from stdout and stderr.

### Shell injection

Controls:

- all Git commands use direct process argument arrays;
- file paths are never embedded in shell command strings;
- only the generated hook template is shell text;
- executable path in the hook uses a dedicated POSIX single-quote escaping function with tests.

### Hook destruction

Controls:

- managed marker and complete template recognition;
- unrelated hooks are never overwritten;
- uninstall removes only a recognized managed hook;
- writes use temporary sibling plus rename;
- no `--force` option.

### Scanner bypass through operational errors

Controls:

- fatal errors return `2`;
- hook propagates non-zero exit status;
- missing or moved scanner executable causes the hook to fail;
- malformed configuration is not treated as defaults.

### Catastrophic regex behavior

Controls:

- Rust `regex` engine;
- bounded patterns;
- no user-defined regex;
- maximum file size;
- rule boundary tests.

### Data exfiltration

Controls:

- no HTTP client dependency;
- no DNS/network calls;
- no telemetry or update checks;
- CI dependency review recommended but not required for local runtime.

### Path confusion

Controls:

- Git path lists use NUL delimiters;
- paths normalized only for reporting and matching, not for locating staged blobs;
- object content read by object ID;
- output path excluded from traversal;
- symlinks not followed.

## 4. Raw candidate lifetime

A detector necessarily observes a borrowed slice of prepared file text. The implementation should:

1. keep it borrowed;
2. calculate offsets and confidence;
3. evaluate suppression and changed-range relevance;
4. create redacted text;
5. construct `Finding` without the candidate;
6. drop the file buffer after the file is processed.

Adding a zeroization dependency is not required because immutable source buffers and borrowed slices cannot be reliably guaranteed to have no copies. The primary guarantee is non-persistence and non-output.

## 5. Configuration diagnostics

TOML parsers often include a source excerpt in their formatted error. Do not directly expose the parser error’s full `Display` value. Convert it to a sanitized category and line/column using its span where available.

## 6. False negatives and bypasses

Documented limitations:

- users can invoke `git commit --no-verify`;
- obfuscated or split credentials may not match;
- binary and UTF-16 files are not scanned;
- ignored files are skipped in folder mode unless behavior changes later;
- tokens with unknown future formats may not match;
- no live provider verification is performed.

A CI scan is recommended as a second layer, but v0.1 remains a local tool.

## 7. Security review gates

Before release verify:

- no network-capable crates were added;
- no raw candidate fields exist;
- no production debug formatting can include source text;
- test fixtures contain no complete realistic tokens;
- hook conflict behavior is conservative;
- operational errors are non-zero;
- release binary self-scan succeeds.
