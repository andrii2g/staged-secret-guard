# Architecture

## 1. Overview

The design separates acquisition of bytes from detection and reporting. Git-specific behavior must not leak into the rule engine, and rules must not perform I/O.

```text
arguments
   |
   v
CLI parser -------------------------+
   |                                |
   v                                v
config loader                   hook manager
   |
   v
scan source
   +-- staged Git source
   +-- folder source
   |
   v
FileInput stream
   |
   v
ScannerEngine
   +-- path rules
   +-- text preparation
   +-- content rules
   +-- changed-range filter
   +-- suppression/allowlist filter
   +-- safe Finding conversion
   |
   v
sorted findings + ScanSummary
   |
   +-- console reporter
   +-- JSON reporter
   |
   v
exit reducer
```

## 2. Core domain types

### Severity

```text
Low < Medium < High < Critical
```

Must support parsing from lowercase CLI/config text and serialization as lowercase JSON.

### RuleId

A validated lower-kebab-case identifier. Allowed characters are ASCII lowercase letters, digits, and single hyphens between non-empty segments.

### LineRange

Inclusive, one-based range:

```text
start_line >= 1
end_line >= start_line
```

`intersects(other)` must be a pure function.

### FileInput

Conceptual fields:

```text
relative_path: normalized path with '/'
source_kind: staged | folder
bytes: bounded file bytes
changed_ranges: inclusive new-side ranges
path_only: whether content rules must be skipped
index_mode: optional Git mode for diagnostics
```

Directory mode assigns one range covering every line. An empty file has no content range but still runs path rules.

### CandidateMatch

Internal-only borrowed match data:

```text
rule_id
severity
confidence: 0..=100
byte_start
byte_end
message
candidate: borrowed slice or string
```

It must not implement `Debug`, `Serialize`, or `Clone` in a way that unnecessarily copies candidate text.

### Finding

Safe public/report type:

```text
rule_id
severity
confidence
path
line
column
end_line
end_column
redacted
message
```

There is deliberately no raw value, matched line, or source excerpt.

### ScanSummary

Counts:

```text
files_considered
files_scanned
findings_total
findings_blocking
skipped_binary
skipped_invalid_utf8
skipped_oversized
skipped_symlink
skipped_submodule
skipped_excluded
skipped_ignored
```

## 3. Module responsibilities

### `cli`

- Clap data structures only.
- No scanning logic.
- Convert command-line values to domain requests.

### `application`

- Orchestrates configuration, source, engine, reporting, and exit code.
- Owns no detector details.

### `config`

- Strict TOML schema.
- Defaults.
- Path resolution.
- Glob validation.
- Effective threshold.
- Sanitized parse errors.

### `git`

- Direct Git process execution.
- Repository discovery.
- NUL-delimited staged path parsing.
- Stage-0 index entry parsing.
- Blob loading by object ID.
- Diff hunk parsing.
- No rule logic.

### `scan`

- `ScanSource` abstraction or equivalent explicit source types.
- Folder traversal.
- Staged-file conversion to `FileInput`.
- Text validation, line index, skip reasons.
- Scanner engine orchestration.

### `rules`

- Rule trait.
- Static rule metadata.
- Provider regexes.
- PEM matching.
- Generic scoring.
- Suspicious path rules.
- No filesystem, Git, CLI, or report output.

### `report`

- Deterministic console rendering.
- JSON DTO/schema.
- Atomic file writing.
- No detector logic.

### `hook`

- Managed hook template.
- Hook status classification.
- Atomic installation/removal.
- No scan implementation.

## 4. Detector interface

A suitable contract is:

```text
trait ContentRule {
    fn metadata(&self) -> &'static RuleMetadata;
    fn detect<'a>(&self, input: &'a PreparedText, sink: &mut Vec<CandidateMatch<'a>>);
}
```

Path rules use a separate interface because they must execute even when content is skipped:

```text
trait PathRule {
    fn metadata(&self) -> &'static RuleMetadata;
    fn detect(&self, normalized_path: &str) -> Option<PathMatch>;
}
```

Avoid boxed trait objects if a static catalog enum is clearer. The contract matters more than the specific dispatch mechanism.

## 5. Rule execution order

1. Normalize the path.
2. Apply source-level exclusions.
3. Run suspicious path rules.
4. Validate file size and content eligibility.
5. Build text and line index.
6. Run provider rules.
7. Run PEM rules.
8. Run URL/connection-string rules.
9. Run JWT rules.
10. Run generic assignment rules.
11. Deduplicate raw match coordinates.
12. Map offsets to lines and columns.
13. Filter staged matches by changed-range intersection.
14. Apply inline suppression.
15. Apply configured allowlists.
16. Redact immediately and construct `Finding`.
17. Sort findings globally.

Provider-specific findings should win over a generic finding at the same or contained span. Implement containment-based suppression of the generic result.

## 6. Error model

Use typed error categories:

- CLI usage: handled by Clap, process exit `2`.
- Configuration error.
- Git unavailable or failed.
- Repository not found.
- Invalid Git output.
- Unmerged index entry.
- File traversal/read error.
- Report write error.
- Hook conflict or invalid state.
- Internal invariant failure.

Errors may include safe paths, command names, exit status, and line/column. They must not include file contents, diff bodies, raw TOML source lines, or candidate values.

## 7. Determinism

Sort findings by:

1. severity descending;
2. normalized path ascending by raw UTF-8 byte order;
3. line ascending;
4. column ascending;
5. rule ID ascending;
6. redacted preview ascending only as a final tie-breaker.

Sort rule listing by rule ID. Do not include timestamps or random IDs in JSON.

## 8. Atomic output

When `--output FILE` is used:

1. render complete bytes in memory;
2. create a sibling temporary file with a process-specific suffix;
3. write and flush;
4. replace the destination atomically when supported;
5. remove the temporary file on failure where possible.

The output file itself must not be scanned during the same traversal if it is created inside the scan root. Resolve and exclude the target path before traversal.
