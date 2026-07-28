# G051 documentation, legal, privacy, and support closure

Status: completed documentation implementation and focused source validation on 2026-07-28. Glacial is version 0.9.8 and remains `NOT READY`. No installer, release candidate, tag, GitHub Release, or v1 authorization was created.

## Source and scope

- Starting source commit: `3e042eae47289b44e9cf206419159162c0c215b2`
- Audited version: `0.9.8`
- Product boundary: current-user Windows x64 NSIS installation
- Installed behavior evidence: G049 and [G050 installed lifecycle acceptance](g050-installed-lifecycle-acceptance.md)
- Privacy behavior evidence: [G048 data privacy boundary](data-privacy-boundary.md)

Public documents created:

- [Evidence and remediation interpretation](../evidence-and-remediation.md)
- [Supported environments](../supported-environments.md)
- [Privacy and network disclosure](../privacy-and-network.md)
- [Support policy](../support.md)
- [Third-party notices](../../THIRD_PARTY_NOTICES.md)

The [installed lifecycle guide](../installed-windows-lifecycle.md), [security policy](../../SECURITY.md), [contribution policy](../../CONTRIBUTING.md), README, changelog, release notes, signing guide, lifecycle policy, remediation sequence, and readiness Markdown/JSON were revised. The public structure keeps task instructions outside release evidence and links them from README.

## Clean-reader walkthrough

No independent human reader was available. The acceptance was a deliberately context-restricted author review: each task began at README's user-documentation list, used only the linked public guides, and compared the resulting action or decision with G048–G050 evidence after the task was complete. This is not independent human acceptance.

| # | Reader task | Result |
| ---: | --- | --- |
| 1 | Locate installation requirements | Found current-user Windows x64 NSIS scope, non-elevated install, WebView2 prerequisite, and unsupported layouts. |
| 2 | Identify install and data paths | Found the install, database, log, backup, WebView, roaming-state, and uninstaller paths in one table. |
| 3 | Simulate first-run verification | Followed shortcut launch, backend wait, Settings path readback, process-location checks, and first-project registration; matched G050. |
| 4 | Find update behavior | Found manual verified in-place NSIS update, same-user requirement, state retention, migration backup, same-version reinstall, updater absence, and downgrade prohibition. |
| 5 | Identify reset deletion | Found the Settings control, exact phrase, database and two-key WebView deletion scope, retained logs/backups, and project-file preservation. |
| 6 | Locate a recovery backup | Found both backup directories and distinct migration/reset filename patterns. |
| 7 | Follow manual restoration | Followed stop, displaced-state preservation, integrity/schema checks, same-directory temporary copy, atomic replacement, relaunch, readback, and rollback steps. |
| 8 | Distinguish uninstall modes | Found default binary removal with retained local/roaming bundle state and checked removal of only the two Glacial application-data roots. |
| 9 | Find startup troubleshooting | Found separate actions for no window, missing backend, startup screen, unavailable data, backend unavailability, repeated launch, and process persistence. |
| 10 | Identify privacy/network boundary | Found local reads/stores/exports, authenticated loopback, offline scanning, WebView2 installer traffic, user/developer/release network workflows, and redaction limits. |
| 11 | Locate private security reporting | Reached the GitHub private vulnerability-reporting destination, reporting fields, response targets, coordinated disclosure terms, and fallback. |
| 12 | Classify a hypothetical environment | Windows 11 Pro x64 build 26200 in the recorded VMware setup is the tested internal baseline; Windows on ARM is unsupported; physical Windows and other builds are untested and have no current support claim. |

The walkthrough exposed and corrected these ambiguities:

- the lifecycle guide did not state the exact reset phrase;
- backup filename patterns and backup-selection criteria were missing;
- same-version reinstall did not say clearly that retained state remains;
- reinstall troubleshooting did not distinguish damaged binaries from retained-state failure;
- the WebView2 download-bootstrapper network exception was absent from the privacy boundary;
- reset wording did not separate Glacial UI keys from other WebView runtime/cache files;
- the environment matrix needed to say that no display-resolution or scaling range has passed yet; and
- ordinary support, private security, and fallback routing were not separated.

No unresolved material ambiguity remained in the lifecycle tasks. Final-candidate repetition and the incomplete environment/legal gates below remain release evidence work, not hidden reader assumptions.

## Environment-matrix derivation

The matrix uses:

- Tauri configuration for NSIS-only packaging, `currentUser`, updater disabled, WebView2 default download-bootstrapper mode, 1280 × 800 default window, and 960 × 640 minimum window;
- Rust and release configuration for x64 Windows targeting and installed layout;
- G050 for Windows 11 Pro x64 version `10.0.26200` build `26200` in VMware and the native lifecycle results; and
- G049/G050 lifecycle and schema evidence for clean install, same-version reinstall, predecessor upgrade, reset, restore, and uninstall.

G050 explicitly does not prove a clean operating-system image, physical hardware, other Windows builds, other hypervisors, display resolution, or scaling. Those environments are untested or unsupported rather than promised. G052 owns the minimum-window and scaling acceptance; the frozen candidate owns the final environment matrix.

## Link and channel verification

Verification date: 2026-07-28.

- The G051 documentation validator checked project Markdown targets and found no missing or escaping internal link.
- The public GitHub repository Security page displayed **Report a vulnerability** with destination `https://github.com/Bolizen/Glacial/security/advisories/new`.
- Opening the destination without a signed-in session reached GitHub sign-in for that exact return path. No report was created or sent.
- The GitHub issue destination and repository were publicly reachable.
- The verification browser was explicitly blocked from accessing `https://icefields.dev`; no alternate access path was used. Repository configuration and GitHub metadata identify it as the project homepage. The owner confirms that the domain is intentionally inactive much of the time, so live HTTP availability is unconfirmed and is not a product defect or G051 blocker.
- The RustSec advisory, GitHub advisory, upstream `glib` pull request, and both upstream commit references resolved.
- The DigiCert timestamp URL rejected ordinary page navigation. It is a timestamp service endpoint rather than a documentation page; the release-tool URL and signing-preflight tests cover that endpoint boundary.
- Local project-license, glib license/copyright/provenance, public-guide, release-evidence, and third-party inventory links resolved.

The private channel is therefore present and publicly discoverable. Receiving a report requires a reporter to sign in to GitHub, which the security policy states.

## Third-party notice review

Inventory sources were `frontend/package-lock.json`, `backend/requirements.lock.txt`, installed Python metadata, the locked offline Windows-target Cargo runtime graph, Tauri/NSIS configuration, the PyInstaller payload, and G050 installed readback. The generator records:

- 4 frontend runtime packages;
- 15 Python runtime packages;
- 225 Windows-target Rust runtime crates with no `NOASSERTION` license result;
- 7 bundled native/runtime families; and
- WebView2 as a prerequisite acquired when absent rather than a Glacial-owned redistributed runtime.

The review distinguishes runtime code from Vite, Tauri CLI, most PyInstaller tooling, package managers, compilers, and test dependencies. It retains the vendored `glib` license, copyright, patch, and provenance. MIT, BSD, Apache, PSF, OpenSSL, Unicode, MPL, zlib, Microsoft redistributable, PyInstaller bootloader-exception, and other inventory expressions require their applicable upstream terms.

`V1-DOC-005` remains `PARTIAL`: no frozen installer exists for notice/license readback and no maintainer or legal owner has signed off the complete obligation set. This review is not legal advice.

## Prose review

A sentence-level read-through covered README, `CONTRIBUTING.md`, `SECURITY.md`, `THIRD_PARTY_NOTICES.md`, the four new public guides, the revised lifecycle guide, the v0.9.8 release-note/changelog entries, and this evidence record.

The pass removed generic introductions, repeated warnings, promotional terms, unnecessary transitions, duplicated lifecycle instructions, implied commercial-service language, unsupported reassurance, and vague references to “the system” or “the process.” It replaced them with named controls, paths, states, commands, outcomes, and limits. Warnings about relocation, reinstall, reset, redaction, and security controls appear where a user acts rather than in repeated summaries.

## Readiness reconciliation

Changed classifications:

- `V1-SEC-006`: `FAIL` → `PASS`
- `V1-DOC-002`: `PARTIAL` → `PASS`
- `V1-DOC-003`: `PARTIAL` → `PASS`
- `V1-DOC-004`: `UNKNOWN` → `PARTIAL`
- `V1-DOC-006`: `FAIL` → `PASS`

`V1-DOC-005` remains `PARTIAL` for frozen-artifact readback and owner/legal sign-off. No unrelated classification changed. The reconciled totals are 44 `PASS`, 13 `PARTIAL`, 3 `FAIL`, 1 `UNKNOWN`, and 17 non-passing P1 requirements. The overall verdict remains `NOT READY`.

Remaining documentation-related blockers:

- G052 display resolution, minimum-window, and scaling acceptance;
- representative final-candidate environment execution;
- frozen-installer notice and license readback; and
- maintainer or legal owner sign-off on the exact shipped notice set.

Other P1 blockers, including native privacy-sink acceptance, deep security scanning and finding closure, public trust/signing, candidate construction, release rollback/withdrawal, remaining desktop failures, interruption coverage, accessibility, and final authorization, are unchanged.

## Focused validation

- `node scripts/release/validate-g051-documentation.mjs`
- `node scripts/release/validate-v1-readiness-audit.mjs`
- `node --test scripts/desktop/windows-signing.test.mjs`
- backend `py_compile` for version and changelog modules
- production frontend build
- `git diff --check`
