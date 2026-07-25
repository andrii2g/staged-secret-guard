# Git Index Scanning Algorithm

## 1. Required property

Staged mode must inspect exactly what Git would commit, not what currently exists in the working tree.

The working tree may differ because of partial staging, edits after `git add`, deleted local content, or generated files. Reading the working-tree path is therefore forbidden in staged mode.

## 2. Repository discovery

Execute directly:

```text
git rev-parse --show-toplevel
```

Use the returned path as the process working directory for subsequent Git calls. Strip only the final line terminator. A missing Git executable, non-zero status, empty root, or non-UTF-8 root path unsupported by the platform abstraction is an operational error.

## 3. Staged path enumeration

Execute:

```text
git diff --cached --name-only --diff-filter=ACMR -z --no-ext-diff --no-textconv --ignore-submodules=all
```

Properties:

- `--cached` compares the index with `HEAD` or the empty tree on an initial commit;
- `A`, `C`, `M`, and `R` include content that exists in the new index;
- deleted files are omitted;
- `-z` returns verbatim NUL-terminated paths.

Parse output as bytes split on NUL. Ignore one final empty segment. Do not decode a path by parsing line-oriented output.

## 4. Resolve the staged index entry

For each path, execute:

```text
git ls-files --stage -z -- <path>
```

Parse records shaped as:

```text
<mode> <object-id> <stage><TAB><path><NUL>
```

Requirements:

- exactly one stage-0 entry is expected;
- stage 1, 2, or 3 indicates an unresolved merge and is an operational error;
- object IDs must be validated as non-empty lowercase or uppercase hexadecimal of the repository hash length;
- mode `160000` is a submodule and is skipped;
- mode `120000` is a symlink and is skipped in v0.1;
- regular blob modes continue.

Do not build `:<path>` object expressions. Reading by object ID avoids ambiguity and keeps unusual path names out of revision syntax.

## 5. Read staged bytes

Execute:

```text
git cat-file blob <object-id>
```

Capture stdout as bytes. Do not decode Git stderr into a message that includes arbitrary content; a safe truncated diagnostic without file contents is sufficient.

The bytes returned here are the only content bytes used for staged detection.

## 6. Compute changed new-side ranges

For each staged path, execute:

```text
git diff --cached --unified=0 --no-color --no-ext-diff --no-textconv --ignore-submodules=all -- <path>
```

Read output line by line only to find hunk header lines beginning with `@@ `.

Traditional hunk shape:

```text
@@ -<old-start>[,<old-count>] +<new-start>[,<new-count>] @@
```

Parse only the new range.

Rules:

- omitted count means `1`;
- new count `0` contributes no changed line range;
- otherwise create inclusive range `new-start ..= new-start + new-count - 1`;
- merge overlapping or adjacent ranges;
- ignore file headers, index lines, mode lines, rename metadata, and patch body;
- do not parse filenames from `---` or `+++` lines.

A newly added file normally produces a full new-side range. As a defensive fallback, if Git status is `A` and no hunk range is emitted for a non-empty blob, mark all lines changed.

A rename-only entry with no hunk has no changed content ranges. It still runs path rules for the new path.

## 7. Match relevance

Each content match maps to inclusive start and end line numbers. Retain it when:

```text
match_range intersects any changed_range
```

Examples:

- provider token entirely on changed line: retain;
- PEM block starts on unchanged line but changed body line intersects: retain;
- old secret elsewhere in file with no changed line overlap: drop;
- generic assignment on unchanged line next to changed comment: drop.

## 8. Initial commit

The algorithm must not call `git rev-parse HEAD` as a prerequisite. `git diff --cached` already supports comparing the index against the empty tree when no commit exists. Integration tests must initialize a repository, stage files before the first commit, and scan successfully.

## 9. Partial staging tests

At least two inverse cases are required:

1. working tree contains a fake secret, index contains clean content: no finding;
2. index contains a fake secret, working tree has been edited clean: finding remains.

These tests prove the scanner does not read the working-tree file.

## 10. Process safety

- Set Git working directory explicitly.
- Use `Command::new("git").args([...])` or equivalent typed argument calls.
- Pass paths as individual `OsStr` arguments after `--`.
- Never quote arguments manually for Git process execution.
- Never invoke `sh -c`, `cmd /C`, or PowerShell.
- Bound captured stderr length before displaying it.

## 11. Error behavior

Fatal:

- Git missing;
- not inside a repository in staged mode;
- Git command non-zero where success is required;
- malformed stage record;
- unresolved merge stages;
- malformed hunk header emitted by Git for a selected file;
- blob read failure.

Non-fatal skip:

- submodule;
- symlink;
- oversized blob;
- binary heuristic;
- invalid UTF-8.
