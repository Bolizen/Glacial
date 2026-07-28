# G052 accessibility and window-management acceptance

Status: completed on 2026-07-28 against exact implementation commit
`b1ac54f0661425b111293c58176a76dc708fdf18`. Glacial is version 0.9.9 and
remains `NOT READY`. This is a pragmatic Windows desktop baseline, not a claim
of WCAG conformance or formal accessibility certification.

## Scope and environment

The acceptance covered `V1-DESKTOP-006`, `V1-UX-001`, `V1-UX-004`, and
`V1-UX-005`.

| Item | Accepted value |
| --- | --- |
| Operating system | Windows 11 Pro x64, version `10.0.26200`, build `26200` |
| Virtual machine | VMware `20,1`, VMware SVGA 3D |
| Desktop resolution | 1276 × 1284 |
| Windows display scaling | 100% |
| Windows text size | Default |
| Web runtime | Microsoft Edge WebView2 150.0.4078.99 |
| Default application window | 1280 × 800 |
| Minimum application window | 960 × 640 outer window |
| Test state | Disposable Glacial state and projects; pre-existing state restored exactly |

Before implementation, local `HEAD`, `origin/main`, and direct remote `main`
all matched G051 commit `fc07ef67a33817b578f39c61e3189f85ddb86568`.
The installed acceptance used only the committed and pushed G052
implementation hash above.

The pre-existing application-data tree was moved aside before mutation. After
acceptance it was restored with the same 433-file inventory and database
SHA-256
`006C7EA4BFFEC1993E326608F6E6C37F05F6B97392486FC322A93E903B9CEE91`.
Registered project files were not deleted or modified by cleanup.

## Supported boundary

Glacial v1 supports 100% Windows display scaling at the enforced 960 × 640
minimum outer window on the tested VMware configuration. Tauri prevents
resizing below 960 × 640; a native `MoveWindow` request measured the resulting
outer window as exactly 960 × 640.

The accepted range does not include 125%, 150%, 175%, or 200% scaling, custom
DPI, increased Windows text size, high-contrast themes, multiple-monitor
movement, rotated displays, other resolutions, other Windows builds, physical
hardware, or other hypervisors. Those configurations are untested and
unsupported rather than assumed to work. Every environment proposed for the
frozen candidate still requires its own acceptance run.

## Acceptance inventory

The primary screens are:

1. Workspace Overview
2. Projects
3. Review
4. Project Expectations
5. Activity
6. Scan Comparison
7. Reports
8. Changelog
9. Settings

The persistent navigation regions are the dashboard navigation, the local
project selector, the top-level project/action area, and screen-local review,
history, filter, and settings controls. The inspected interaction inventory
included hyperlinks, buttons, text inputs, text areas, selectors, cards,
history rows, finding controls, and disclosure buttons. The application has no
drag-only control, hover-only action, application checkbox, runtime toggle, or
menu. The NSIS uninstaller's data-removal checkbox is installer-managed and is
outside the running application's primary interface.

Custom dialogs are Add Project, Agent Remediation Brief preview, review
checkpoint confirmation, and trusted-scan-baseline confirmation. Native
confirmation flows cover workspace-root changes, project unregistration,
existing `AGENTS.md` overwrite, trusted-baseline replacement or clearing, and
application-state reset. Each destructive operation retains its existing
explicit confirmation boundary.

The state inventory covered:

- no-project and no-scan empty states;
- scan loading, completion, and duplicate-disabled actions;
- textual high-risk and incomplete-coverage warnings;
- outside-workspace validation failure;
- long project paths, project names, findings, remediation text, and settings
  path inventory;
- populated report, history, activity, review, and changelog lists;
- generated remediation preview and export controls;
- native confirmation cancellation;
- owned-backend startup failure.

## Keyboard-only acceptance

The installed application exposed this exact Tab sequence from the first
dashboard link:

`Workspace Overview → Projects → Review → Project Expectations → Activity → Scan Comparison → Reports → Changelog → Settings`

All nine targets were unique and visibly focused. The installed workflow then
covered:

- changing to a disposable workspace after Escape-cancelling the first native
  confirmation;
- registering and selecting a disposable existing folder;
- running a scan that reported `Risk: HIGH`, `Coverage: Incomplete`, two
  findings, and one dependency-analysis gap;
- opening Review, the finding disclosure, the remediation brief, Projects,
  Reports, and Settings;
- Enter activation on navigation;
- Space activation on a review disclosure;
- Alt+Down, Down, and Enter on the Severity selector, changing `All` to
  `Critical / high`;
- Tab and Shift+Tab modal wrapping;
- Escape cancellation of Add Project, remediation preview, workspace-root
  change, and Unregister;
- trigger-focus restoration after custom dialogs and native confirmations;
- an outside-workspace registration error that stayed visible inside the
  active Add Project dialog.

The Add Project dialog initially focused `Existing folder path`. Shift+Tab
from Close wrapped to the final `Create New Folder` action and scrolled it into
view. Escape closed the dialog and returned focus to the Add Project trigger.
The remediation dialog stayed within the viewport and returned focus to
Generate brief. No focus trap, accidental activation, unreachable primary
control, or focus movement behind an active dialog remained after the fixes.

## Focus, names, semantics, and state

UI Automation exposed meaningful names for all nine navigation links, project
selection, scan and report actions, Add Project fields, selectors, findings,
settings actions, and confirmation buttons. Add Project now uses explicit
labels instead of placeholder-only names. Its backend validation error is a
visible in-dialog alert associated with the active modal.

Risk, coverage, progress, review state, selected state, warnings, errors, and
success are communicated with text in addition to color. Disabled controls
retain distinguishable text, background, border, and disabled semantics.
Expanded review content remains attached to its disclosure. Modal backdrops
are presentational; active panels use dialog semantics, modal association,
headings, descriptions, named actions, and contained focus.

Focus indicators use a high-contrast outline or inset ring and remained visible
on links, buttons, inputs, selectors, and dialog actions. Unregister and
workspace-root confirmations were Escape-cancelled without state mutation;
focus returned to `Unregister` and `Apply Workspace Root`, respectively.

## Contrast measurements

`node scripts/release/validate-g052-accessibility.mjs` performs repeatable sRGB
relative-luminance and contrast calculations. Text pairs use 4.5:1 and focus
indicators use 3:1 as pragmatic WCAG-derived thresholds.

| Representative pair | Result |
| --- | ---: |
| Body text on page | 17.63:1 |
| Secondary text on surface | 8.12:1 |
| Muted text on hover surface | 4.51:1 |
| Link text on page | 8.05:1 |
| Primary button text | 8.05:1 |
| Secondary button text | 15.15:1 |
| Form value on inset surface | 16.73:1 |
| Disabled control text | 5.03:1 |
| Selected-card text | 14.52:1 |
| Dialog text | 15.15:1 |
| Success text on surface | 8.62:1 |
| Warning text on surface | 9.28:1 |
| Error text on surface | 6.29:1 |
| Information text on surface | 7.94:1 |
| Focus ring on page | 10.88:1 |
| Alpha-composited sidebar focus ring | 3.92:1 |
| Startup-error text | 16.30:1 |

All 17 pairs pass their assigned threshold. The validator also checks the
modal viewport-containment rules. This calculation does not constitute a
formal audit or certification.

## Minimum-window and hostile-content results

Every primary screen was opened in the installed application at 960 × 640.
UI Automation found the expected heading and named navigation on each screen.
The screen-by-screen visible interactive-control check found zero controls
extending past the usable horizontal bounds:

| Screen | Visible interactive controls | Horizontal outliers |
| --- | ---: | ---: |
| Workspace Overview | 10 | 0 |
| Projects | 13 | 0 |
| Review | 11 | 0 |
| Project Expectations | 13 | 0 |
| Activity | 13 | 0 |
| Scan Comparison | 13 | 0 |
| Reports | 13 | 0 |
| Changelog | 13 | 0 |
| Settings | 13 | 0 |

Vertical off-screen controls were reachable through the document or modal
scroll container. Long Windows paths wrapped or scrolled without creating
horizontal page overflow. Long finding and remediation content retained its
disclosure or scroll mechanism. Empty and populated lists, validation text,
the Settings path inventory, scan warnings, and generated output actions
remained distinguishable.

The real installed missing-backend case was also resized to 960 × 640. UI
Automation exposed `Glacial could not start`, the owned-backend failure
explanation, and the recovery instruction within the visible window. The
backend executable was restored immediately with its original SHA-256
`AEE894C82A7C5C6694ACD0C9817E98F56223ED5897DC353EB4DC1897C92CDB08`.

## Confirmed defects and fixes

| Confirmed defect | Evidence before | Exact fix | Evidence after |
| --- | --- | --- | --- |
| Add Project exceeded the 960 × 640 usable viewport. Its heading and actions could be clipped. | Native pre-fix screenshot and UI Automation bounds. | General modal panels now have a viewport-relative maximum height and vertical scrolling; the remediation dialog retains its intentional nested layout. | Installed panel measured 572 × 550 inside the 960 × 640 window; top content, scrollbar, and actions were reachable. |
| Add Project left focus on the obscured page, allowed Shift+Tab behind the dialog, ignored Escape, and lost focus on close. | Native keyboard/UI Automation pass. | Added one shared modal focus hook with initial focus, Tab/Shift+Tab containment, Escape close, and connected-trigger restoration. | Installed initial focus, wrap, Escape, and Add Project trigger restoration passed. |
| Review-checkpoint and trusted-baseline custom confirmations lacked the same focus containment and restoration contract. | Source and targeted interaction inspection. | Applied the shared modal focus behavior to both confirmations. | Targeted integration tests pass for wrap, Escape, and restoration. |
| Add Project fields depended on placeholders and errors appeared only in the obscured page notice. | UI Automation and source inspection. | Added explicit labels, modal description association, and a local `role="alert"` while retaining the global notice. | Installed fields expose names; the outside-workspace error remained visible inside the active dialog. |
| Muted and disabled text and the sidebar focus ring fell below the selected pragmatic thresholds. | Pre-change ratios: 4.32:1 muted text, 2.95:1 disabled text before opacity, and 2.79:1 alpha-composited sidebar focus. | Raised muted/disabled tokens, removed legibility-reducing disabled opacity, retained borders/backgrounds, and strengthened the inset focus ring. | 4.51:1 muted text, 5.03:1 disabled text, and 3.92:1 sidebar focus. |

No visual redesign, framework change, dependency change, or broad aesthetic
polish was introduced.

## Artifact provenance

| Item | Value |
| --- | --- |
| Source commit | `b1ac54f0661425b111293c58176a76dc708fdf18` |
| Backend build | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\desktop\Build-DesktopBackend.ps1` |
| NSIS build | `npm.cmd --prefix frontend run tauri:build` |
| Installer | `Glacial_0.9.9_x64-setup.exe` |
| Installer size | 16,115,932 bytes |
| Installer SHA-256 | `33E20D7D115B8C1BB45726E352739A2633CEADFAE23F97F8080399FA9106725B` |
| Installer signing state | Unsigned (`NotSigned`) |
| Installed executable | Product version 0.9.9; 11,186,176 bytes |
| Installed executable SHA-256 | `4D70A647B4D4E996EA85EF52A32208FA1E6525D443665A2508EEE7036AB039B6` |

The artifact is internal acceptance evidence only. It was not published,
publicly signed, tagged, uploaded to a GitHub Release, or authorized as a v1
candidate.

## Validation

- Focused frontend integration selection: 3 passed, 0 failed.
- G052 contrast and modal-containment validator: 17 pairs passed.
- Production frontend build: 51 modules transformed.
- G051 documentation/version consistency validator: passed for seven public
  documents, eight version sources, support boundaries, links, and runtime
  inventory.
- Targeted Windows release version-source test: 1 passed.
- V1 readiness Markdown/JSON consistency validator: passed for 61 unique
  requirements before final reconciliation and repeated afterward.
- Locked PyInstaller backend build: passed.
- Tauri release and NSIS build: passed.
- Installed primary-screen, keyboard, minimum-window, hostile-content,
  validation, scan/review/remediation, confirmation, and startup-failure
  acceptance: passed within the declared environment.
- `git diff --check`, source alignment, version consistency, and final
  repository integrity: passed.

The full repository, backend, packaging, and release suites were not run
because this handoff changed frontend accessibility behavior and authoritative
version/documentation sources only. A diagnostic run of the full frontend
integration file encountered a test-process array-buffer allocation failure
and the established unrelated `Copy Markdown` notice-timer expectation
failure. The three changed-behavior tests pass together.

## Readiness conclusions

| Contract | G052 classification | Basis |
| --- | --- | --- |
| `V1-DESKTOP-006` | PASS | All primary installed screens, long/error states, custom dialogs, and the real startup-failure surface passed at the enforced 960 × 640 minimum and declared 100% scaling boundary. |
| `V1-UX-001` | PASS | The installed critical workflow passed keyboard-only navigation, registration, scan, review, remediation, settings, selectors, disclosures, confirmations, and focus checks. |
| `V1-UX-004` | PASS | The declared scaling/minimum boundary, all-screen installed inspection, hostile-content cases, and repeatable contrast measurements are complete. |
| `V1-UX-005` | PASS | The full primary interaction/state inventory found no remaining color-only, hover-only, drag-only, or fine-pointer-only critical meaning or action. |

The overall verdict remains `NOT READY`. Remaining release blockers include
runtime identity, exact production dependency declarations, installed privacy
sink closure, interruption/startup variants, public signer trust, the mandatory
G054/G055 deep-security assessment and closure, final-candidate provenance and
multi-environment acceptance, notice/legal sign-off, rollback, and owner
authorization. G053 is the next exact handoff.
