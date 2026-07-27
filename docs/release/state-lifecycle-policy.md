# Glacial State Lifecycle and Recovery Policy

Status: v1 policy baseline for Glacial 0.9.4. This document describes source-level behavior and required future acceptance. It is not evidence that installed, crash, power-loss, upgrade, reset, or uninstall behavior has passed.

## Ownership boundary

### Application-owned persistent state

| State family | Storage | Contents and ownership |
| --- | --- | --- |
| SQLite database | `<Glacial data directory>/glacial.db` | The authoritative application database. Release desktop builds pass Tauri's application-local data directory plus `data`; development builds use the separated `development/data` directory. |
| Database schema version | SQLite database header through `PRAGMA user_version` | The sole authoritative relational schema version. `DATABASE_SCHEMA_VERSION` is `1` in Glacial 0.9.4. It is not duplicated as an authoritative setting or JSON field. |
| Settings | `settings` | Workspace-root selection. |
| Projects and metadata | `projects` | Registration path, display name, description, type, and registration time. A row is a registration; it does not make the project directory application-owned. |
| Immutable scans and scan metadata | `scans` | Append-only scan identity, time, risk, findings JSON, bounded counts, summary, coverage, reviewed/ignored-file metadata, dependency analysis, and related scanner metadata. |
| Notes | `notes` | User-entered project-scoped note bodies and timestamps. |
| Trust Profiles / Project Expectations | `project_trust_profiles` | Sanitized project-scoped expectations, risk tolerance, provenance, dismissals, notes, and update time in bounded JSON. |
| Finding reviews | `finding_reviews` | Project/fingerprint review or expected status, note, and timestamps. Reviews remain separate from immutable scan rows. |
| Trusted dependency baselines | `trusted_dependency_baselines` | Sanitized dependency snapshot, format versions, fingerprint, source scan identity/date, note, and timestamps. |
| Trusted scan baselines | `trusted_scan_baselines` | Project-to-scan reference, manual provenance, and pin time. Scan contents remain in `scans`. |
| Activity events | `project_activity_events` | Bounded project-scoped event type, time, optional scan reference, details JSON, and optional dedupe identity. Registration and scan-completed activity are reconstructed from their primary rows rather than duplicated. |
| Review checkpoints | `project_review_checkpoints` | Immutable normalized evidence identities, baseline/review/coverage state, evaluator/schema versions, provenance, and time. |
| SQLite internal metadata | SQLite-managed objects such as `sqlite_sequence` | SQLite-owned metadata supporting application tables. Glacial does not treat it as an independently editable state family. |
| Desktop UI session state | WebView local storage key `glacial.ui-state.v1` | Bounded workspace, selected project/scan, active section, and panel state. It is convenience state, not security evidence. |
| Guided-review dismissal state | WebView local storage key `glacial.guided-review.dismissed.v1` | At most 100 normalized project-path dismissals. It is convenience state, not review completion or approval. |
| Application log | Tauri application log directory, `backend-startup.log` | Bounded, token-redacted startup diagnostics. The current implementation truncates the file at each startup rather than keeping a historical rotating log. |
| Verified migration backups | `<Glacial data directory>/migration-backups/*.db` | Complete SQLite-safe pre-migration recovery artifacts. They may contain every state family already present in the source database. |
| Migration backup temporary files | The migration-backup directory, dot-prefixed `*.tmp` plus SQLite sidecars | Operation-owned transient files. They are never accepted as backups and are removed after success or handled failure. |

### Not application-owned state

The following are outside the application-state lifecycle even when Glacial reads or produces them:

- Scanned project directories and every source, manifest, lockfile, script, secret-designated file, or other project file in them.
- A generated project-root `AGENTS.md`. It is an explicit, confirmation-gated project-file write governed by the separate root-only writer contract.
- Downloaded scan reports, remediation briefs, and remediation package ZIPs. Browser downloads are user-selected exports, not an application database or managed backup.
- NSIS installer, release-candidate, signing, manifest, checksum, and other release-build artifacts.
- Source-controlled fixtures and disposable test databases under test-owned temporary directories.
- Developer build outputs, caches, and local tool state.

Unregister, migration, backup, future reset, or uninstall logic must never reinterpret these external files as disposable application state.

## Schema lifecycle

### Supported versions and shapes

Schema version `1` is the smallest honest first version: every database before Glacial 0.9.3 was unversioned and therefore reports `user_version = 0`.

Glacial 0.9.4 supports:

- a nonexistent, zero-byte, or valid table-empty database as new state;
- schema version `0` when the database contains the historically evidenced core tables (`settings`, `projects`, `scans`, and `notes`), no unknown application tables, and only recognized later Glacial tables with their required historical columns and constraints;
- early core databases before scan-history columns;
- databases with scan-history columns and recognized later tables before the two later checkpoint columns;
- the complete unversioned 0.9.2 schema;
- schema version `1`, which must already pass the complete schema, constraint, index, foreign-key, JSON-shape, foreign-key-check, and integrity checks.

An arbitrary partial schema, unknown table, missing historical invariant, malformed persisted JSON envelope, or invalid relationship is not promoted merely because `user_version` is zero.

### New database sequence

For new or table-empty state Glacial:

1. Opens the configured database path and enables foreign-key enforcement and a 5,000 ms busy timeout.
2. Confirms SQLite integrity and that the state is table-empty.
3. Begins `BEGIN IMMEDIATE`.
4. Creates the complete current schema and the default workspace-root setting.
5. Verifies required tables, columns, constraints, indexes, foreign keys, JSON envelopes, and integrity inside the transaction.
6. Sets `PRAGMA user_version = 1` as the final migration publication statement.
7. Commits, closes, reopens read-only, and verifies the published version and complete schema.

No migration backup is created because there is no predecessor state to recover.

### Legacy migration sequence

For a nonempty supported version-0 database Glacial:

1. Opens deliberately with foreign keys enabled and a 5,000 ms busy timeout.
2. Reads `PRAGMA user_version`, rejects unsupported/future versions, runs `PRAGMA integrity_check`, inventories the schema, validates the supported legacy shape and constraints, and validates recognized persisted JSON envelopes.
3. Records SQLite schema/data change counters.
4. Creates and verifies the pre-migration backup without changing the source.
5. Begins `BEGIN IMMEDIATE`, then confirms the version and schema/data counters did not change during preparation.
6. Applies the ordered `0 -> 1` migration once: creates missing recognized objects, adds only the known scan-history and checkpoint predecessor columns, and preserves or creates the workspace-root setting.
7. Verifies the complete current schema, constraints, indexes, foreign keys, JSON envelopes, `foreign_key_check`, and `integrity_check`.
8. Sets `PRAGMA user_version = 1` last.
9. Commits and closes.
10. Reopens read-only and verifies the published version and complete state before startup may continue.

Any exception before commit rolls back the whole migration. A verified pre-migration backup remains available. Normal startup does not continue on a partial result.

### Connection and durability decisions

- Foreign keys: enabled on application connections and during initialization. Existing relationships are compatible with supported fixtures.
- Busy timeout: 5,000 ms. A bounded lock wait is preferable to immediate spurious failure, but Glacial does not wait indefinitely.
- Write transactions: `BEGIN IMMEDIATE` for migrations and state families that couple multiple writes or require stale-state revalidation.
- Journal mode: not changed by Glacial 0.9.4. The existing database/runtime mode is retained because G046 found no artifact evidence justifying a mode migration.
- Synchronous mode: not changed by Glacial 0.9.4. SQLite's existing/runtime default remains in force; G046 does not claim power-loss acceptance from this decision.
- Read/write connection context: normal single-statement writes use SQLite's implicit transaction and commit/rollback context. A Python `with connection:` block is not treated as proof; the fault tests exercise the effective transaction.

## Migration backups

The dedicated location is `<Glacial data directory>/migration-backups`. The data directory and backup directory must be real directories, not symlinks, junctions, or other reparse points, and the backup directory must remain directly inside the selected data directory.

Names follow:

`glacial-pre-migration-v0-to-v1-<UTC timestamp>-<random suffix>.db`

Publication is:

1. Create a unique dot-prefixed temporary file exclusively inside the backup directory.
2. Use SQLite's online backup API from the opened source connection.
3. Verify that the temporary output is a regular non-reparse file, reports the source `user_version`, matches a supported legacy shape, and passes `integrity_check`.
4. Publish through an atomic no-overwrite filesystem link to the final unique name.
5. Remove the temporary name.
6. Reopen and verify the published backup again.

An existing final name is never overwritten. Backup failure prevents migration. Incomplete temporary files and their exact journal/WAL/shared-memory sidecars are removed after success or handled failure. A published backup is retained when a later pre-commit migration failure occurs.

Verified migration backups are retained indefinitely in the v1 policy unless a future explicit, reviewed retention feature changes that contract. Startup does not automatically prune or restore them. A backup proves that SQLite can open and validate that recovery artifact; it does not prove every row is semantically correct or safe.

## Future, corrupt, malformed, and downgrade behavior

- A `user_version` greater than `1` fails closed with an instruction to use the newer Glacial version. Glacial does not modify, reset, downgrade, or replace the file.
- A nonzero version for which no ordered migration exists fails closed and preserves the file.
- SQLite open, schema inspection, integrity, constraint, foreign-key, or recognized JSON-envelope failure stops normal startup. Glacial does not delete, truncate, recreate, or silently repair the database.
- Unsupported unversioned shapes fail before backup or migration because Glacial cannot claim to understand them.
- Automatic restore is prohibited. Recovery requires an explicit documented user action.
- Downgrading application binaries is unsupported. An older Glacial version is not guaranteed to understand schema version `1`, and a backup from a newer schema is not guaranteed to open in an older version.

## Persistent mutation inventory

“Later artifact evidence” is deliberately separate from source-level tests.

| Operation | API or internal entrypoint | Tables/files touched | Cardinality | Transaction mode | Rollback expectation | Duplicate/stale/concurrency behavior | Existing evidence | Missing evidence | Required G046 evidence | Later artifact evidence |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Initialize new database | startup `init_db` | All schema objects, default `settings`, `user_version` | Multi-object | Explicit immediate | No partial schema/version publication | Repeated v1 startup is read-only/idempotent | Prior startup tests | No prior explicit version evidence | New/current idempotency, schema/FK/index/integrity checks | Installed-edition first run in G049 |
| Migrate supported legacy database | startup `initialize_database` | Recognized schema objects/columns, setting if absent, `user_version`, backup file | Multi-object/file | Verified backup, then explicit immediate | Every schema/data change and version publication rolls back pre-commit | Version/counters rechecked after lock; retry safe | Historical source shapes | No prior migration registry or rollback proof | All predecessor fixtures, preserved records, injected pre-publication failure, retry recovery | Installed-edition upgrade and forced-process acceptance in G049/G056 |
| Publish migration backup | `_create_verified_backup` | Temporary and final backup files | Multi-file publication | SQLite backup plus atomic no-overwrite link | Failure removes incomplete temp/final; source unchanged | Unique name; collision fails closed | None before G046 | Power-loss publication acceptance | Verification, atomic observation, collision, failed cleanup tests | Filesystem interruption on artifact hosts |
| Set workspace root | `PUT /api/config/project-root`; `set_setting` | One `settings` row | Single record | Implicit single-write | Row unchanged on exception | Upsert; path validated before write; last committed update wins | `test_project_lifecycle`, desktop startup tests | Concurrent desktop acceptance | Inventory and retained targeted test | Installed-edition path persistence in G049 |
| Create project and register it | `POST /api/projects` | New external project directory, one `projects` row | Cross-resource | Directory creation then implicit DB write; no shared transaction | DB write rolls back; an already-created empty directory can remain if DB registration fails | Existing folder rejects; DB key rejects duplicate path | Source inspection and frontend flow tests | Dedicated cross-resource failure cleanup evidence | Explicitly record the non-atomic boundary; do not overclaim `V1-DATA-001` | Desktop create failure/retry acceptance |
| Register existing project | `POST /api/projects/register` | One `projects` row | Single record | Implicit upsert | Row unchanged on exception | Same path updates description/type; validated current root | Project lifecycle/source evidence | Direct duplicate/stale test is limited | Inventory | Desktop registration/restart acceptance |
| Update project metadata | `PUT /api/projects/metadata` | One `projects` row | Single record | Implicit single-write | Row unchanged on exception | Missing registration fails; last committed update wins | `test_project_lifecycle` | Concurrent UI acceptance | Retained targeted test | G049 |
| Unregister project | `DELETE /api/projects` | Project row and all project rows in scans, notes, profiles, reviews, both baselines, activity, checkpoints | Multi-table | Explicit immediate | Every deletion rolls back; project files untouched | Missing registration is 404; serialized writer lock | Existing unregister retention tests | Process-kill/power-loss evidence | Inject failure after early deletes; exact all-table before/after equality | G049/G056 desktop interruption and uninstall distinction |
| Persist scan | `POST /api/scans` | One immutable `scans` row | Single record | Scan happens before one implicit insert | Failed insert creates no scan row; earlier scans unchanged | Every successful request appends; stale prior dependency context is read before scan | Scan completeness/history tests | Forced termination at commit | Inventory; verify other rollback actions do not alter scan rows | G049/G056 |
| Add note | `POST /api/notes` | One `notes` row | Single record | Implicit single-write | No partial row | Each request appends; no dedupe contract | Source and frontend integration | Focused backend failure test | Inventory | G049 |
| Create/update finding review | `PUT /api/finding-reviews` | One `finding_reviews` row; optionally one required activity row | Multi-table when completion event is required | Explicit immediate | Review and required completion event commit/rollback together; scan unchanged | Latest/current fingerprint revalidated; completion event deduped by scan | Finding-review/activity tests | Process interruption | Inject activity failure and compare review/activity/scan state | G049/G056 |
| Reopen/delete finding review | `DELETE /api/finding-reviews` | One `finding_reviews` row | Single record | Implicit single-write | No partial row; scan unchanged | Missing review is idempotent success | Finding-review tests | Desktop retry acceptance | Inventory | G049 |
| Create/update Trust Profile | `PUT /api/trust-profile` | One profile row; one activity row for material update/adoption | Multi-table | Explicit immediate | Profile and event commit/rollback together; scans/baselines unchanged | Normalized no-op returns without write; observed adoption revalidated in transaction | Activity and lifecycle tests | Process interruption | Inject activity failure after profile write | G049/G056 |
| Create/replace trusted dependency baseline | `PUT /api/trusted-dependency-baseline` | One baseline row; optionally one required activity row | Multi-table | Explicit immediate | Baseline/event commit/rollback together; source scan unchanged | Latest scan and fingerprint revalidated; replacement confirmation; event dedupe | Baseline/activity tests | Process interruption | Inject activity failure; exact baseline/event/scan comparison | G049/G056 |
| Update dependency baseline note | `PATCH /api/trusted-dependency-baseline` | One baseline row | Single record | Implicit single-write | Old note remains on exception | Missing baseline is 404; last committed write wins | Baseline API tests | Desktop retry acceptance | Inventory | G049 |
| Clear dependency baseline | `DELETE /api/trusted-dependency-baseline` | One baseline row | Single record | Implicit single-write | Row remains on exception | Repeated clear is safe | Baseline API tests | Desktop retry acceptance | Inventory | G049 |
| Set/replace trusted scan baseline | `PUT /api/trusted-scan-baseline` | One baseline reference; one required activity row | Multi-table | Explicit immediate | Reference and event commit/rollback together; scans unchanged | Scan ownership/eligibility revalidated; same scan is no-op; replacement confirmation | Trusted-scan baseline tests | Process interruption | Existing injected event failure retained | G049/G056 |
| Clear trusted scan baseline | `DELETE /api/trusted-scan-baseline` | One baseline reference; one required activity row | Multi-table | Explicit immediate | Delete and event commit/rollback together; scan unchanged | Missing reference is no-op | Trusted-scan baseline tests | Dedicated injected clear-event failure | Family covered by strongest replacement boundary; inventory records remaining variant | G049/G056 |
| Create review checkpoint | `POST /api/review-checkpoints` | One immutable checkpoint row; one required activity row | Multi-table | Explicit immediate | Checkpoint and event commit/rollback together; underlying evidence unchanged | Evidence/fingerprint revalidated; identical checkpoint is no-op; event dedupe | Review-checkpoint tests | Process interruption | Existing injected event failure and immutable evidence checks | G049/G056 |
| Append activity event | `append_activity_event` called only by owning mutation | One activity row | Dependent record | Owner's transaction | Never commits independently of required primary mutation | `(project_id, dedupe_key)` suppresses defined duplicates | Activity tests | Artifact interruption | Exercised through representative owner families | G049/G056 |
| Save/clear UI session state | `writeSessionState`, `clearSessionState` | WebView local storage key | Single value | Web storage operation | Failure returns false and does not become security evidence | Versioned parser; malformed/cross-workspace values ignored | `sessionState.test.js` | Real WebView persistence/reset | Inventory | G049 |
| Dismiss guided review | `dismissGuidedReview` | WebView local storage key | Single bounded value | Web storage operation | Storage failure retains prior in-memory list | Normalized, deduped, capped at 100; not review evidence | `guidedReview.test.js` | Real WebView persistence/reset | Inventory | G049 |
| Write startup diagnostics | Rust `StartupDiagnostics` | `backend-startup.log` | One bounded file | Truncate on startup; bounded atomicity is not claimed | Diagnostic failure blocks owned-backend startup rather than exposing token | Full token redacted; output capped | Rust diagnostics test | Installed log location/permissions | Inventory and source decision | G049/G056 |
| Write generated `AGENTS.md` | `POST /api/agents/write` | External project-root `AGENTS.md` and operation temp | Single external file | Separate atomic writer contract | Existing file requires confirmation; failures clean owned temp | Stale/link/hardlink/path checks; explicit overwrite | `test_agents.py` | Desktop dialog acceptance | Classified outside application-state reset/unregister | G049 |
| Download report/brief/package | Frontend download actions | User download destination | External export | Browser download boundary | Failed download does not mutate SQLite/project | Explicit user action; stale package rejected | Remediation/report tests | Installed-edition download acceptance | Classified outside managed state | G049/G056 |

## Retention

- SQLite state, UI convenience state, and the current startup log survive ordinary backend process restart according to their storage contracts.
- SQLite state is intended to survive application upgrade. A supported schema migration happens before normal startup and retains the verified pre-migration backup.
- Scans, reviews, profiles, baselines, activity, checkpoints, settings, and notes otherwise persist indefinitely. There is no age-based pruning in v1.
- Project unregister removes only that project's database rows. It does not remove the global workspace setting, migration backups, UI storage, logs, the project directory, or any file in it.
- Migration backups persist indefinitely until a future explicit reviewed retention flow exists.
- Operation-owned migration temporary files are removed after success or handled failure. A verified published backup is not temporary.
- The startup log is replaced at each launch and bounded to the implementation maximum; no multi-day log-retention period is currently promised.
- Installed-edition upgrade and exact application-owned state locations still require G049/G056 artifact evidence. There is no supported cross-edition or relocation contract.

## Reset contract

Glacial 0.9.4 does not expose a reset route or prominent reset UI. Any future supported reset must satisfy all of the following:

1. It is an explicit user action, never a response to startup, schema, integrity, migration, or content failure.
2. Glacial and all concurrent state mutations are stopped before replacement.
3. It affects only application-owned state and never deletes, modifies, traverses, or “cleans” registered project directories or downloaded exports.
4. It offers or requires a verified backup unless the user explicitly declines in an approved future flow.
5. It removes or archives only the exact documented application-state targets selected by that flow.
6. The next startup creates a new schema-version-1 database.
7. Old state is not automatically merged into the new database.
8. Reset of WebView convenience state and logs is explicit about those separate stores.

Installed-edition reset UX, permissions, interrupted reset, path readback, and clean-machine acceptance remain G049/G056 work.

## Backup and manual restore contract

- Automatic backups occur only before migration of a nonempty supported predecessor database.
- A future user-requested backup must use SQLite-safe backup semantics, the same safe-destination and verification principles, and explicit user intent.
- Glacial must be fully closed before manually replacing `glacial.db`.
- Preserve the displaced database separately; do not overwrite the only recovery copy.
- Restore only a database whose schema version the target Glacial version supports.
- A newer-schema backup is not guaranteed to open with older Glacial.
- Startup rejects future versions rather than downgrading them.
- Restore is replacement, not merge. Glacial provides no automatic merge of two databases.
- After replacement, startup must pass version, schema, constraint, relationship, JSON-envelope, and integrity checks before normal use.

## Uninstall boundary

Application uninstallation must never remove scanned project files, generated project instructions, or downloaded exports. G046 does not claim what the current NSIS uninstaller retains or removes from application-local data, WebView storage, or logs because no current installed artifact was exercised. Exact installed paths, upgrade retention, reset, and uninstall retention/removal behavior remain mandatory G049/G056 acceptance evidence.

## Evidence boundary

The G046 tests prove controlled source-level behavior: recognized schema migrations, version publication, logical rollback, backup verification/publication/collision handling, future/corrupt/malformed rejection, and representative multi-record transaction coupling. They do not prove sudden process termination, parent crash, OS crash, power loss, disk-full behavior at every statement, antivirus interference, filesystem corruption, installer upgrade, unsupported relocation, reset UX, or uninstall behavior. Those claims remain blocked until their assigned desktop and release-candidate handoffs produce artifact evidence.
