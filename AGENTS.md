## Security Rules

- Never write files outside the selected project directory.
- Treat all user-provided paths as untrusted input.
- Resolve and normalize paths before writing files.
- Reject path traversal attempts such as `../`, `..\\`, absolute paths, symlinks, junctions, or paths that escape the selected project root.
- Only allow Glacial to create or overwrite `AGENTS.md` in the selected project root unless a future feature explicitly requires otherwise.
- Always require explicit user confirmation before overwriting an existing `AGENTS.md`.
- Never read, print, log, commit, or expose secrets, tokens, API keys, `.env` files, SSH keys, cookies, browser data, or credential files.
- Never add real secrets to examples, tests, README files, or fixtures.
- Do not run package install scripts unless explicitly approved by the user.
- Prefer dependency changes that minimize new packages.
- Before adding a dependency, explain why the built-in platform or existing dependency is not enough.
- Validate backend inputs defensively; frontend validation is helpful but never sufficient.
- Keep backend file-writing logic small, boring, and easy to audit.
- Fail closed: if a path or write operation is ambiguous, reject it rather than trying to be clever.
- Avoid shell execution for file operations. Use filesystem APIs instead.
- If shell execution becomes necessary, never interpolate unsanitized user input.
- Do not weaken `.gitignore`.
- Do not commit generated junk, logs, build folders, `node\_modules`, or local config files.
- Do not follow symlinks or junctions when resolving write targets.
- Do not execute generated AGENTS.md content as code or shell commands.



## Dependency Security Rules

- Do not use loose dependency ranges for production dependencies.
- Prefer exact dependency versions in `package.json`.
- Do not introduce `^` or `~` version ranges unless explicitly approved.
- Do not run `pnpm update` unless explicitly approved.
- Prefer `pnpm install --frozen-lockfile` over an unlocked install when installing from the existing lockfile.
- Treat `pnpm-lock.yaml` as security-relevant and commit it.
- Review dependency diffs before accepting changes to `package.json` or `pnpm-lock.yaml`.
- Do not add new dependencies for trivial utilities that can be implemented safely with built-in APIs.
- Keep pnpm dependency build scripts blocked unless a package is explicitly reviewed and narrowly allowed in `pnpm-workspace.yaml`.
- If a dependency requires install scripts, explain why it is needed and ask before enabling scripts.



## Glacial Golden Rule

Glacial is allowed to generate and write project instructions, not to become a general-purpose filesystem. Keep file writes narrowly scoped, predictable, and reviewable.



## Security Test Expectations

When changing file-writing or path-handling code, include tests for:

- Normal valid project paths.
- Existing `AGENTS.md` overwrite confirmation.
- `../` traversal attempts.
- Windows-style `..\\` traversal attempts.
- Absolute path injection.
- Symlink or junction escape attempts where practical.
- Empty, malformed, or suspicious path input.




## Test-efficiency policy

Use the smallest test set capable of validating the change.

Validation levels are `targeted` for directly relevant checks (the default), `broad` for wider affected-area suites when the exceptions below apply, and `release` for complete release-candidate validation.

- Begin with tests directly covering changed files or behavior.
- Do not run the complete frontend, backend, packaging, signing, or release suites unless:
  - the change is cross-cutting or security-critical;
  - a targeted test indicates broader risk;
  - this is an explicit release-candidate validation;
  - the user explicitly requests the full suite.
- Do not rerun an unchanged passing suite within the same task unless new changes could affect it.
- Prefer quiet or summary test output. Write verbose logs to disk and report only failures and aggregate results.
- Stop diagnostic investigation once the root cause is proven unless additional evidence is needed to choose or verify a fix.
- Do not recompute hashes or inventories for immutable historical artifacts unless the task could have modified them.
- Separate implementation validation from release validation.
- Before running unusually broad or expensive validation, explain why it is necessary.




## Numbered Google Drive handoffs

Glacial handoff IDs use the Glacial-specific `G###` namespace. `G030` is the first
namespaced handoff and the current transition handoff. Every subsequent Glacial
handoff ID must be exactly `G` followed by three digits, beginning at `G030`
(for example, `G031`). Reject malformed or out-of-sequence identifiers such as
`G30`, `GG030`, `030G`, bare `030`, or `G001`.

Legacy bare identifiers `001` through `029` remain valid only as immutable
historical records. Never rename, move, modify, recreate, or reinterpret those
handoffs as `G001` through `G029`.

Each Glacial handoff ID is unique and must never be reused. Unrelated Icefields
repositories may use separate prefixes and numbering sequences; do not apply the
Glacial namespace or sequence to them.

When a valid Glacial handoff ID is present:

1. Complete the task according to the task-specific prompt.
2. Compose the normal final response that will be shown to the user.
3. Before submitting that final response, create:
   `My Drive/Icefields/Glacial/<HANDOFF_ID>/`
4. Write the exact final-response Markdown, verbatim, as the machine-readable handoff at:
   `My Drive/Icefields/Glacial/<HANDOFF_ID>/result.md`
5. The contents of `result.md` and the final response shown to the user must be identical. Do not summarize, expand, omit, or reformat either version.
6. Write to `result.tmp` first, then atomically rename it to `result.md`.
7. Never overwrite or reuse an existing handoff ID or handoff folder.
8. Never include credentials, tokens, private keys, signing secrets, or other sensitive values.

These requirements are additive only. They must not alter, broaden, reinterpret, or override the task-specific prompt.
