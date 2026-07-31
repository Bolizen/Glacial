# G058 repository debloat and scan boundary

## Starting boundary

The accepted starting state was `fa435d1068ee9b6f2acfb5da5ad9c79ca4ab0a51` on `main`. `HEAD`, local `main`, `origin/main`, and direct `origin` `main` all matched. The tracked worktree was clean and the product version was `0.9.11`.

Before cleanup, the worktree contained 28,544 files totaling 13,084,745,856 bytes: 340 tracked files, no untracked files, and 28,204 ignored files totaling 13,075,401,868 bytes. The dominant sources were `frontend/src-tauri/target` (11,896,191,693 bytes), `.desktop-build` (1,035,309,958 bytes), `frontend/node_modules`, `backend/.venv`, staged sidecar files, and frontend build output.

## Classification and retention

- Tracked source, tests, dependency locks, release scripts, readiness records, manifests, and concise Markdown evidence were retained.
- No untracked raw evidence required preservation: the pre-cleanup untracked-file count was zero.
- Reproducible output was removed only after confirming that each selected path was ignored, contained no tracked file, stayed beneath the repository root, and contained no reparse point.
- Dependency trees, Python environments, bytecode, test state, and temporary handoff artifacts were treated as cache or temporary state.
- `.desktop-build/g052-private-evidence` was retained as unclear (10 files, 251,321 bytes). Its contents were not inspected or relocated. Seven historical handoff-result files directly under `.desktop-build` were also retained as unclear (7 files, 30,449 bytes). They are small and not part of the future clean scan target.

No evidence was preserved outside the repository. No `rank_input.jsonl` or `deep_review_input.jsonl` was copied into the repository.

## Deleted paths

The following verified generated directories were deleted:

- `.desktop-build/acceptance`, `g049-evidence`, `g049-prior-pyinstaller`, `g050-evidence`, `g052-accessibility-projects`, `guided-review-acceptance`, `handoff`, `handoff-019`, `portable`, `portable-zip-tests`, `pyinstaller`, `release`, `release-acceptance`, `release-candidates`, `release-publication`, `release-publication-verification`, `release-work`, `signer-preflight`, `signing`, `signing-preflight`, `tauri-dev-smoke-016-20260723T005355`, `tauri-sidecar`, `validation`, `venv`, and `zip-compat-diagnostics`.
- `backend/.venv`, `backend/app/__pycache__`, and `backend/tests/__pycache__`.
- `frontend/.desktop-build`, `frontend/dist`, `frontend/node_modules`, `frontend/src-tauri/binaries`, `frontend/src-tauri/gen`, and `frontend/src-tauri/target`.

This removed 28,180 files and reclaimed 13,074,392,082 bytes.

## Prevention and future scan target

`.gitignore` now consolidates generated desktop-build output, nested `.desktop-build` directories, virtual environments, dependency trees, generic build/dist/target output, Tauri generation and staging, Python/test/coverage caches, temporary diagnostics, and local SQLite state. Existing tracked files remain unaffected by these rules.

`.glacialignore`, `.codex/config.toml`, and `.codex/environments/environment.toml` were inspected but not changed. The installed Codex Security workflow documents target-and-scope selection but no supported project-local exclusion setting. No unverified exclusion key was added, and authored source, tests, manifests, release scripts, and security configuration were not excluded.

`scripts/security/Prepare-CleanSecurityScanWorktree.ps1` is the future clean-scan preparation method. It has one fixed sibling destination, `Z:\CodexProjects\Glacial-security-scan-target`, refuses an existing destination, a dirty source worktree, a branch other than `main`, or disagreement among `HEAD`, local `main`, `origin/main`, and direct remote `main`. It then creates a detached Git worktree at the aligned commit and verifies its commit, clean status, tracked-file count, and absence of untracked or ignored files. `-DryRun` performs the boundary checks without creating the target. The script does not run Codex Security.

## After state and validation

After-state metrics, including this report and the preparation script, are recorded as:

- Files: `366`
- Bytes: `10362898`
- Tracked files after commit: `342`
- Untracked files after commit: `0`
- Ignored files after commit: `24`

Validation performed for the cleanup selected only explicit paths and confirmed zero tracked candidates, zero paths outside the root, and zero selected reparse points. The final validation also checks the updated ignore rules, parses the preparation script, runs the script with `-DryRun`, creates and validates the clean target after the focused commit is pushed, runs `git diff --check`, and verifies the final aligned and clean `main` worktree.

No Deep Security Scan was run. The prior `spawn EPERM` worker-spawn failure was not claimed fixed. This handoff does not change product behavior. Version `0.9.11` remains unchanged, `V1-SEC-007` remains `FAIL`, and Glacial remains `NOT READY`. No release candidate, tag, release, signing action, or publication occurred.
