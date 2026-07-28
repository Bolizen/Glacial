# G053 runtime identity, exact dependencies, and signer readiness

Status: completed on 2026-07-28 against implementation commit
`1d580221a1275aec5f355131028c9911e30c7191`. Glacial is version `0.9.10`
and remains `NOT READY`.

## Source and scope

The handoff started from clean, pushed `main` at
`1cb0811f93cae85f1ce51413338be1412e98bdcb`. The implementation commit is
`1d580221a1275aec5f355131028c9911e30c7191`.

The inspected identity and release sources included:

- `frontend/package.json`, `package-lock.json`, `vite.config.js`, Settings UI,
  API transport, Tauri configuration, `build.rs`, Rust host commands, and
  backend supervision;
- `backend/app/version.py`, authenticated API middleware, desktop startup,
  PyInstaller specification, and installed-path behavior;
- `scripts/desktop/Build-SignedWindowsRelease.mjs`,
  `windows-signing.mjs`, their focused tests, and Windows signing guidance;
- the v1 readiness contract, Markdown/JSON audit, remediation sequence, G052
  evidence, current release notes, changelog, lifecycle policy, and version
  validators.

No G054 Deep Security Scan or G055 remediation was performed. No updater,
portable edition, telemetry, remote runtime, candidate, tag, GitHub Release,
publication, or stable-release path was introduced.

## Runtime identity contract

`frontend/src/buildIdentityContract.js` defines schema version `1` and the
single build-identity model consumed by build injection, Tauri compilation,
frontend validation/rendering, release manifests, and tests. The authenticated
backend endpoint provides the bounded owned-component subset needed for
frontend/backend agreement.

| Field | Contract |
| --- | --- |
| `productName` | Exactly `Glacial` |
| `productVersion` | Exact semantic version; `0.9.10` in this handoff |
| `sourceCommit` | Lowercase 40-character Git commit; development alone may report `null` and mark it unavailable |
| `buildProfile` / `lifecycleStage` | `development`, `internal-evidence`, `signed-preview`, `public-rc`, or `stable` |
| `trustClassification` | `unsigned`, `self-signed`, `publicly-trusted`, or `unknown` |
| `signingState` | `unsigned`, `verified`, or `unverified` |
| `signerSubject` / `signerThumbprint` | Present only for structurally valid, observed, verified signer evidence |
| `signerVerification` | `verified`, `unverified`, or `not-applicable` |
| `frontendVersion` / `tauriVersion` | Must equal the product version |
| `unavailableFields` | Explicit allowlisted unavailable values |

Development and internal-evidence builds must be unsigned. Signed preview
requires a verified self-signed or publicly trusted signer. Public RC and
stable require a verified publicly trusted signer. Production construction
requires injected identity, an exact source commit, and component/source
version agreement before Rust product construction. Stable is schema-complete
but unused and is not a bypass around the public-RC gate.

Settings now exposes a Build Identity section with product/version, profile,
lifecycle stage, commit, signing/trust state, signer verification and identity,
frontend/Tauri versions, owned-backend version, and explicit match/mismatch
state. Missing values render as `Unknown` or `Unavailable`. Configured signer
values never become observed evidence.

The backend `GET /api/runtime-identity` response is authenticated and contains
only schema version, product name, product version, and component name. It
does not return paths, environment values, usernames, hostnames, commands,
tokens, or interpreter details.

## Runtime readback

The focused frontend development readback showed profile `development`,
version `0.9.10`, unsigned trust, unavailable source commit and signer fields,
and matching owned-backend version. A deterministic mismatch fixture using
backend `0.9.9` displayed an unhealthy mismatch alert.

The unsigned internal native application was built from clean implementation
commit `1d580221a1275aec5f355131028c9911e30c7191`. Windows UI Automation:

- resized the native window to exactly 960 × 640;
- found Settings keyboard-focusable and observed focus before activation;
- found Build Identity and scrolled it into the visible window;
- read `Glacial`, `0.9.10`, `internal-evidence`, the exact implementation
  commit, `unsigned`, `not-applicable`, unavailable signer values, frontend and
  Tauri `0.9.10`, backend `0.9.10`, and matching agreement.

One owned backend was present while the application ran. Graceful close ended
the frontend and backend with no orphan.

The existing local application-data tree was isolated before native readback
and restored afterward with the same 433-file inventory and aggregate
inventory SHA-256
`B39BC361E33CF1DCF5329F2D08377D080662326F45C5E4F3483158B843DBDBE3`.
The disposable run created 171 files. A bounded scan found zero repository
path matches, signing-configuration names, persisted authentication material,
or host paths in logs. Clipboard and download actions were not invoked.
Disposable readback state was removed after the original tree was restored.

This was an internal unpacked native readback, not installed-candidate or
frozen-candidate acceptance. Actual signed-preview, public-RC, and stable
identity readback remains deferred.

## Exact production dependencies

Only the four loose declarations changed:

| Dependency | Before | After / locked package |
| --- | --- | --- |
| `@vitejs/plugin-react` | `^5.0.0` | `5.2.0` |
| `react` | `^19.0.0` | `19.2.7` |
| `react-dom` | `^19.0.0` | `19.2.7` |
| `vite` | `^7.0.0` | `7.3.6` |

`@tauri-apps/api` remains exactly `2.11.1`. The PostCSS override remains
exactly `8.5.18`. Package-lock changes are limited to application version and
root declaration metadata. The normalized resolved-tree fingerprint was
`42CB63A73AEC7BC7F58A4FC02018E9C020A8C89E9AD452575A8DD02D3319A06F`
before and after.

The validator rejects non-exact semantic versions, range operators, tags,
wildcards, Git sources, URLs, file/workspace aliases, package/lock root
mismatch, missing or mismatched locked packages, version disagreement,
PostCSS override drift, and unrelated resolved-graph churn. It validates only
Glacial's direct production declarations, not upstream transitive metadata.

## Signer preflight

The signer-only commands reuse the existing redacted configuration loader and
disposable PE signing implementation:

```powershell
npm.cmd --prefix frontend run release:windows:signed-preview:signer-preflight
npm.cmd --prefix frontend run release:windows:public-rc:signer-preflight
```

They validate the exact configured subject and thumbprint, current
certificate validity, Code Signing EKU, accessible private key or approved
provider, disposable PE signing, Authenticode verification, observed trust,
signer identity, RFC 3161 timestamp, profile trust, and cleanup. Output is
bounded to public identity, provider/profile, validity, trust, timestamp
origin/presence, verification, and cleanup.

The local environment had no configured signing provider. Both real commands
exited `1` with
`GLACIAL_WINDOWS_SIGNING_PROVIDER must be store or command.` Cleanup passed
and product construction did not begin. No self-signed success was claimed
without configured runtime evidence.

Deterministic fixtures prove a valid public-trust result, public-RC rejection
of self-signed trust, signer subject/thumbprint mismatch rejection, missing
private key, expired validity, missing Code Signing EKU, missing timestamp,
invalid chain/trust, and disposable cleanup across signing/timestamp failure.

Signer tooling is ready to evaluate a future signer. Public signer
possession/configuration is not complete.

## Internal artifact evidence

These artifacts are internal, unsigned evidence only and were not published:

| Artifact | Bytes | SHA-256 | Signing state |
| --- | ---: | --- | --- |
| `Glacial_0.9.10_x64-setup.exe` | 16,119,401 | `31E4ADC72ED8E32A68069865A2CE9D7EBA98CC1ADBC6E64FC55DE964DF0FFF03` | `NotSigned` |
| `glacial.exe` | 11,182,080 | `8B5C40FA2DBA8EFFA22B05227B9E2BA1E4BE33D39BE629385D68F258441C2652` | `NotSigned` |
| `glacial-backend.exe` | 6,545,892 | `072902D669A0B59776379971454A6145284E4E966E4353CAB32F639984CDF650` | `NotSigned` |

No release-candidate manifest or public hashes file was created because this
was not a candidate workflow.

## Validation

- Runtime-identity schema/agreement unit tests: 4 passed.
- Frontend identity rendering and mismatch tests: 2 passed.
- Authenticated backend/runtime selection: 15 passed.
- Rust compile-time build-identity selection: 1 passed.
- Exact-production-dependency validator tests: 4 passed.
- Standalone signer-preflight tests: 3 passed.
- Existing Windows signing/release suite: 38 passed.
- `npm ls --ignore-scripts --all`: passed with exact direct versions.
- Production Vite build: 53 modules transformed.
- Locked PyInstaller backend and unsigned internal Tauri/NSIS build: passed.
- G051 documentation/version validator: passed.
- V1 Markdown/JSON consistency validator: passed for 61 requirements.
- `git diff --check`: passed.

The complete repository, backend, frontend, packaging, signing, and release
suites were not run. The selections above cover changed identity,
authentication, dependency, signer, version, documentation, build, and audit
behavior.

## Readiness reconciliation

| Contract | G053 classification | Basis |
| --- | --- | --- |
| `V1-REL-001` | `PASS` | Exact direct declarations, package/lock parity, expected locked packages, unchanged normalized graph, PostCSS `8.5.18`, `npm ls`, negative fixtures, and release-preflight integration pass. |
| `V1-VER-004` | `PARTIAL` | Development and internal-evidence identity are visible and fail closed; actual signed-preview, public-RC, and stable candidate readback is absent. |
| `V1-REL-004` | `FAIL` | No signing provider is configured and no publicly trusted signer is possessed. |
| `V1-SEC-005` | `PARTIAL` | Tooling validates identity, EKU, validity, timestamp, trust, redaction, and cleanup, but no signed public candidate evidence exists. |
| `V1-SEC-007` | `FAIL` | G054/G055 have not occurred. |

The reconciled counts are 49 `PASS`, 9 `PARTIAL`, 3 `FAIL`, 0 `UNKNOWN`,
0 `NOT_APPLICABLE`, and 12 P1 items. The overall verdict remains `NOT READY`.

Remaining blockers include installed privacy-sink closure, OS/filesystem
interruption and startup-failure variants, actual signed-profile identity,
public signer possession, G054/G055 security assessment and remediation,
frozen candidate construction and multi-environment acceptance, public
signature/timestamp/manifest/hash evidence, notice/legal sign-off, rollback,
and explicit owner authorization.

No Deep Security Scan, public candidate, public signing, final signing, tag,
GitHub Release, publication, or v1 authorization occurred.

