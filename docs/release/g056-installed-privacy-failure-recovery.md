# G056 installed privacy-sink and failure-recovery closure

Status: completed internal Windows x64 NSIS acceptance on 2026-07-28/29.
This is bounded pre-release evidence, not a Codex Security Deep Security Scan,
publicly trusted build, release candidate, tag, GitHub Release, v1
authorization, or publication. Glacial remains `NOT READY`.

## Provenance and artifact

- Required source baseline: `d3dcec7036732811c81f2080b1b5295cb3222d62`.
  Local `HEAD`, local `main`, `origin/main`, and direct remote `main` all
  matched before work began; the tree was clean.
- Version-preparation commit:
  `3a3c5413ffe4e0c07b62cc6be292719d200304d7`.
- Exact clean implementation commit:
  `83d6a351c21228a1a397fe51a251f47b4550e6fe`.
- Product/runtime version: `0.9.11`; build profile and lifecycle stage:
  `internal-evidence`; signing/trust: `unsigned`; signer evidence:
  `not-applicable`.
- Host: Windows 11 Pro x64 build 26200 in the existing VMware acceptance
  environment, current-user NSIS installation, WebView2
  `150.0.4078.105`, 100% display scaling.

The locked PyInstaller backend, ignored Tauri sidecar stage, production Vite
frontend, Rust application, and NSIS installer were built from the clean
implementation commit. The final artifact inventory was:

| Artifact | Bytes | SHA-256 | Signature |
| --- | ---: | --- | --- |
| `Glacial_0.9.11_x64-setup.exe` | 16,118,987 | `7FC46DF694C45F4AE95183D33E20A74A882DCCE585035F1FDD5900D4AA2067BF` | `NotSigned` |
| Pre-bundle `glacial.exe` | 11,179,008 | `7E6142D77B2ED0E54825CE9CBEFCEAB9A04D9B832A3FEE0ADD3989CFE5A7C264` | `NotSigned` |
| Packaged backend | 6,546,302 | `DB962C050365657739C57D33F260CCC605FA63366A7B8FBDE7391943FB4AAD80` | `NotSigned` |
| Installed `glacial.exe` | 11,179,008 | `EB65B47A6CA44C542636787039CC42752F6F9FCC8A1FD36218E0EC9DB432264B` | `NotSigned` |
| Installed backend | 6,546,302 | `DB962C050365657739C57D33F260CCC605FA63366A7B8FBDE7391943FB4AAD80` | `NotSigned` |
| Installed uninstaller | 148,424 | `4E07D00432BE652A5657166AA8EFE285E063116087D5AA11C1052590AF1E0EF3` | `NotSigned` |

Tauri's expected NSIS bundle patching makes the installed application hash
different from the pre-bundle executable. The installed backend is
byte-identical to the packaged backend.

Native Settings readback showed version `0.9.11`, source
`83d6a351c21228a1a397fe51a251f47b4550e6fe`, `internal-evidence`,
`unsigned`, frontend/Tauri `0.9.11 / 0.9.11`, owned backend `0.9.11`, and
`Matches frontend/Tauri version`.

## Disposable hostile fixture

The accepted fixture was an ignored in-repository project under
`.desktop-build/g056-evidence/project`. It contained only synthetic
credential-shaped values, Windows/UNC/repository paths, HTML and Markdown,
control characters, traversal strings, a long error, a lifecycle script, and
an encoded-command pattern. No real credential or private user file was used.

The installed UI registered the fixture under an explicitly confirmed
disposable workspace, completed a six-file scan with three findings and
complete supported-check coverage, exercised finding review input, generated
an AGENTS preview, generated an existing-root `AGENTS.md` replacement with
explicit overwrite confirmation, and exercised report, clipboard, brief,
package, database, log, WebView, temporary-file, and failure surfaces.

Before acceptance, the user's existing Glacial state and installation were
atomically isolated without inspection:

- application state: 433 files; aggregate inventory SHA-256
  `362FB31B119B9A11BD9F3776C2ABDA1C80F50DA70085F7C8317D4769855D8EB8`;
- installation: 43 files; aggregate inventory SHA-256
  `922632EE50EA0099CC47355256CAFA6F4EC7C618EC3ADFABC8454053AB694C71`.

Only disposable state was mutated during G056. The cleanup section records
the byte/inventory restoration check.

## Native privacy-sink acceptance

Twelve canonical canary classes covered API keys, bearer values, passwords,
GitHub-shaped tokens, random credential-shaped values, private-key material,
host usernames/paths, environment values, repository/absolute/UNC paths, and
hostile markup. Every result below was produced by the exact final
implementation.

| Sink | Result | Safe evidence retained |
| --- | --- | --- |
| Installed SQLite | `integrity_check = ok`, schema 2, ten application tables, zero canonical-canary hits | `[REDACTED]`, relative fixture path, scan/finding structure |
| WebView/application state | 289 files searched as binary/text after the final workflow; zero match files across all 12 canary classes | Product UI state and normal WebView runtime data |
| Startup log | Synthetic diagnostic variant produced a bounded 64-byte log; credential, password, host, private-key, and full-token canaries were absent | Bounded generic diagnostic outcome |
| Visible UI/errors | Project metadata, review input, and AGENTS preview suppressed credential/host canaries | Redaction markers, relative project evidence, actionable bounded errors |
| Report download | 8,671 bytes; SHA-256 `71CCC832607A4A3934B0D17BF577E21B6AA0F2D590B2E1A2873C0B5F72FB59BA`; zero canonical-canary hits | Redaction marker, relative path, scanner rule |
| Report clipboard | 8,896 UTF-8 bytes; SHA-256 `0D31CFFAC6E9163BA92E065D17D4CA3391A85401F5186A8BCC386A4C571C8879`; zero canonical-canary hits | Redaction marker, relative path, scanner rule |
| Remediation Brief download | 5,024 bytes; SHA-256 `EE5510CFC7A62F97076CE6D9E1BEBE9679709A50C9F37C3C35C2B40A749D8F20`; zero canonical-canary hits | Redaction marker, relative paths, scanner rules |
| Remediation Brief clipboard | 5,129 UTF-8 bytes; SHA-256 `310AE9B2CC146CAD3290A98580A53F75047F6B72B064450FA4CE908B917D3BE8`; zero canonical-canary hits | Redaction marker, relative paths, scanner rules |
| Remediation Package | 5,634 bytes; SHA-256 `1D3E306068BB32F3A21C4B820777260F62C9EA2060EE0331ED6DBD81A9E9B0B8`; zero canonical-canary hits across every member | Fixed five-member inventory, relative paths, rules, checksums |
| Root `AGENTS.md` | 717 bytes; SHA-256 `F7E7777376BC4C8279B75640C2C14D343941B4FBE15835D70464DE56157915A4`; first write and confirmed replacement completed | Redaction marker, explicit inert user-provided build/test labels |
| Temporary/backup files | No native export or AGENTS temporary residue remained after success/failure; existing-file exports used non-overwriting names | Atomic publication and retained prior downloads |

Every package member was read, hashed, and inspected without extraction:

| Member | Bytes | SHA-256 |
| --- | ---: | --- |
| `README.md` | 998 | `0E338CA6A6F07939601476724B8766E4E83DE64EA385D8C713B3E2037CDCFAFE` |
| `AGENT_TASK.md` | 5,990 | `99253CD5640F86D30DD6C6906977365662D386CA6DFB2EE998524BB263A22ADD` |
| `findings.json` | 4,866 | `60F75B5291ECD598470B486FCF47EED1FF03189CF97477BC31D412E9E9BB1D65` |
| `manifest.json` | 1,589 | `4DD154B63004EF43BA084C022CDFB6B51E3C3CA301334CAB38AA106476102259` |
| `CHECKSUMS.sha256` | 316 | `11B7BC1630BF4DEB51199EF287B394AC79291B9EC964522B99DAC4553682F13E` |

Project-derived shell/Markdown/traversal labels were retained only as inert,
bounded scanner evidence or explicit user-provided instruction labels. They
were not executed and were not treated as credential leaks.

## Defects found and corrected

Two installed-runtime defects were found before acceptance:

1. WebView2 accepted the first browser download but suppressed later
   same-session report/brief/package downloads while the UI reported that
   they had started. Final exports now use a Tauri-native Downloads writer
   with allowlisted generated names, a 16 MiB bound, nonempty content,
   same-directory temporary publication, `sync_all`, non-overwrite collision
   names, bounded errors, and temporary cleanup. Sequential report, brief, and
   package exports passed on the final install.
2. WebView2 general autofill copied synthetic project/review/AGENTS form
   values into its `Web Data` profile database even though application
   persistence and exports were redacted. The main window now explicitly
   disables general autofill. A fresh final profile repeated all sensitive
   forms and then produced zero matches for every canonical canary across the
   complete installed profile.

No dependency was added and no existing safety boundary was weakened.

## Installed startup-failure matrix

A 7,168-byte, SHA-256
`11ED7BC2C643207E618DD8E2E50005412C655D1E333EAA14F8418BABDC72EABA`
local-only C# `winexe` fixture temporarily replaced only the disposable
installed backend. It opened no console window, accepted no external input,
and was removed after testing. The final backend hash was verified before and
after the batch.

| Variant | Installed result |
| --- | --- |
| Backend early exit, code 17 | Bounded exact-code startup error; no backend at readback; clean close |
| Malformed startup message | Bounded invalid-message error; no orphan |
| Oversized startup message | Bounded invalid-message error; no orphan |
| Duplicate startup message | Bounded duplicate-message error; no orphan |
| No startup message | Bounded 15-second owned-port timeout; fixture terminated |
| Unhealthy loopback endpoint | Bounded 15-second authenticated-health timeout; fixture terminated |
| Hostile diagnostic plus malformed message | Bounded error; 64-byte persisted log with all synthetic credential/host canaries absent |
| Missing sidecar | Bounded owned-backend start error; database unchanged; sidecar restored |
| Data directory unavailable | Bounded private-data-directory error; exact directory restored |
| Log directory unavailable | Bounded private-data-directory error; exact directory restored |
| Parent terminated during startup | No console window; owned backend ended through the Windows job in 74 ms |
| Normal retry after all restorations | Main UI reached `Backend reachable`; clean close |

All failure windows used inert text rendering. Every application and backend
process stopped, no fixture backup/mode file remained, the installed backend
returned to SHA-256
`DB962C050365657739C57D33F260CCC605FA63366A7B8FBDE7391943FB4AAD80`,
and the disposable database was byte-identical across the startup matrix at
SHA-256
`065EE2B5123FD2245CDCFEDFD01CC61714E2F64775F1E13AD6FE60BFE1E67397`.

## State interruption and corruption

- G050's installed reset interruption remains valid supporting evidence: the
  process was terminated after verified recovery-backup publication and before
  the exclusive reset transaction; current state remained unchanged, retry
  succeeded, and SQLite integrity passed.
- G056 terminated the parent during startup and observed owned-backend cleanup
  in 74 ms with the database byte-identical, then completed a normal retry.
- A 43-byte intentionally malformed disposable `glacial.db`, SHA-256
  `506867A32E43FA2661715F6354FA2F70E187533A889DEDD263D8B26EB6995CF5`,
  produced the bounded startup-error surface. Glacial left those bytes
  unchanged rather than presenting partial state as current. The isolated
  valid database remained `integrity_check = ok`; after exact restoration its
  SHA-256 was unchanged and `integrity_check = ok`.
- Focused database, AGENTS writer, native export, backend supervisor, and
  release-publication tests cover transaction rollback, database locks,
  disk-full/short-write/fsync/replace failures, temporary cleanup, bounded
  diagnostics, and retry behavior.

Physical power loss, kernel/filesystem crash timing, real media failure,
antivirus filter-driver interference, and arbitrary low-level corruption were
not manufactured. Therefore `V1-DATA-002` remains `PARTIAL`.

## Validation and rejected attempts

The final targeted source validation passed:

- backend privacy, AGENTS writer, installed lifecycle, database lifecycle,
  desktop runtime, and runtime identity: 52 passed;
- frontend native-download, privacy, and report Markdown: 22 passed;
- focused installed-flow integration (Add Project, reset, remediation brief,
  report-copy notices, identity, and checkpoint): 7 passed;
- Rust bridge, supervisor, job, diagnostic, compiled-identity, native-export,
  startup-error, and autofill controls: 14 passed;
- Windows release/signing and exact production dependency tests: 42 passed;
- exact production dependency graph, G051 documentation/version consistency,
  61-requirement readiness reconciliation, JSON parsing, `py_compile`, and
  `git diff --check`: passed;
- production Vite build: 54 modules transformed; locked PyInstaller backend
  and Tauri/NSIS build: passed.

One attempted combined frontend integration run was stopped after 180 seconds
under concurrent test load. It exposed a stale report-copy test that had not
navigated back from the intentional post-scan Review route, and a checkpoint
case exceeded the combined-run timeout. The report-copy fixture was corrected;
both cases then passed individually under serial targeted execution. The
timed-out aggregate is not counted as passing and the complete frontend suite
was not rerun because the directly affected selections passed.

Rejected installed artifacts were not accepted as G056 evidence:

- an initial 16,120,224-byte installer, SHA-256
  `36452F3636013E9CE01121944AF10E29FDCD01CF09A70BBE0174E9EF062AD7AA`,
  reproduced WebView2's suppression of later same-session downloads;
- a later 16,119,512-byte installer, SHA-256
  `64E39B923D52219D82B02BB9B90E87E5BE7B20820E2DC9EE01A0EBF56C1A1379`,
  passed sequential native exports but retained synthetic form values in
  WebView `Web Data` through general autofill.

Only the final 16,118,987-byte installer from
`83d6a351c21228a1a397fe51a251f47b4550e6fe` is accepted.

## Readiness reconciliation

| Contract | Result | Reason |
| --- | --- | --- |
| `V1-FS-006` | `PASS` | Exact installed WebView, SQLite, state, log, visible UI/error, clipboard, report, brief, package, generated-file, download, and temporary surfaces passed hostile canary inspection while retaining bounded useful evidence. |
| `V1-DESKTOP-004` | `PASS` | Eleven controlled failure/interruption variants plus normal retry proved bounded actionable errors, redacted logs, resource restoration, no orphan, and no fixture console window. |
| `V1-DATA-002` | `PARTIAL` | Installed process interruption, fail-closed malformed-state handling, restoration, retry, and integrity are evidenced; physical power-loss and low-level filesystem classes remain unproven. |
| `V1-SEC-007` | `FAIL` | G054 failed before discovery because the required security worker could not spawn, and G055 was cancelled before discovery. There is no canonical threat model, discovery/validation ledger, reportable finding count, or closure evidence. |

The reconciled audit has 51 `PASS`, 7 `PARTIAL`, 3 `FAIL`, 0 `UNKNOWN`, 0
`NOT_APPLICABLE`, and 10 P1 items. The overall verdict remains `NOT READY`.

G054's failed pre-discovery attempt and G055's cancellation cannot be
reinterpreted as a zero-finding result. A fresh clean whole-repository Codex
Security Deep Security Scan and any required remediation/closure remain
mandatory before release-candidate construction.

## Cleanup and user-state restoration

After acceptance:

- every Glacial frontend/backend process was stopped;
- the disposable NSIS edition was silently uninstalled with exit code 0 and
  its uninstall registry key was absent;
- the 288-file final disposable profile and 290-file rejected-autofill profile
  were removed by exact verified paths;
- nine enumerated G056 report/brief/package downloads were removed, while the
  pre-existing `scan-report.md` and `scan-report (1).md` remained;
- the synthetic clipboard was cleared and the 14-file ignored G056 fixture
  root was removed;
- the same atomically preserved original application-state and installation
  directory objects were moved back without inspecting or mutating their
  contents.

Final readback found 433 restored application-state files and 43 restored
installation files, matching the pre-test inventories and their recorded
aggregate SHA-256 values
`362FB31B119B9A11BD9F3776C2ABDA1C80F50DA70085F7C8317D4769855D8EB8`
and
`922632EE50EA0099CC47355256CAFA6F4EC7C618EC3ADFABC8454053AB694C71`.
No `.g056-*` local root, install fixture/mode/backup, roaming state, uninstall
key, G056 download, fixture root, frontend process, or backend process
remained.

## Explicit exclusions

G056 did not run or manufacture a Deep Security Scan, obtain/configure a
public signer, build or sign a public release candidate, create release
metadata for publication, tag a commit, create a GitHub Release, publish an
artifact, declare v1 ready, or authorize stable release.
