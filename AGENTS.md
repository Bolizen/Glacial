## Security Rules

- Never write files outside the selected project directory.
- Treat all user-provided paths as untrusted input.
- Resolve and normalize paths before writing files.
- Reject path traversal attempts such as `../`, `..\\`, absolute paths, symlinks, junctions, or paths that escape the selected project root.
- Only allow CodexForge to create or overwrite `AGENTS.md` in the selected project root unless a future feature explicitly requires otherwise.
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
- Do not run `npm update` unless explicitly approved.
- Prefer `npm ci` over `npm install` when installing from an existing lockfile.
- Treat `package-lock.json` as security-relevant and commit it.
- Review dependency diffs before accepting changes to `package.json` or `package-lock.json`.
- Do not add new dependencies for trivial utilities that can be implemented safely with built-in APIs.
- Keep `npm config get ignore-scripts` set to `true` unless a package script is explicitly reviewed and approved.
- If a dependency requires install scripts, explain why it is needed and ask before enabling scripts.



## CodexForge Golden Rule

CodexForge is allowed to generate and write project instructions, not to become a general-purpose filesystem gremlin. Keep file writes narrowly scoped, predictable, and reviewable.



## Security Test Expectations

When changing file-writing or path-handling code, include tests for:

- Normal valid project paths.
- Existing `AGENTS.md` overwrite confirmation.
- `../` traversal attempts.
- Windows-style `..\\` traversal attempts.
- Absolute path injection.
- Symlink or junction escape attempts where practical.
- Empty, malformed, or suspicious path input.