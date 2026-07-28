# Agent Remediation format compatibility and retention policy

This policy defines the compatibility boundary for Glacial's Agent Remediation
Brief and Agent Remediation Package. It does not add an archive importer or
couple remediation formats to the Glacial application release number.

## Independent version identities

| Identity | Current value | Meaning |
| --- | --- | --- |
| Glacial application version | `0.9.9` | Version of the application that generated an output. |
| Agent Remediation Brief schema version | `1` | Integer `schemaVersion` in the Brief response. |
| Agent Remediation Package format version | `1.0.0` | Semantic version in `packageFormatVersion`, the package README/task, and `manifest.json` as `package_format_version`. |
| `findings.json` schema version | `1.0.0` | Semantic version in `schema_version`. |
| `manifest.json` schema version | Package format `1.0.0` | The manifest has no separate schema-version field; its governing version is its required `package_format_version`. |

Application and format versions advance independently. A Glacial application
patch does not imply a package-format patch, and publishing this policy does
not change the current package format.

## Package format 1.0.0

The fixed top-level ZIP inventory, in source-enforced order, is:

1. `README.md`
2. `AGENT_TASK.md`
3. `findings.json`
4. `manifest.json`
5. `CHECKSUMS.sha256`

The following promises govern compliant format `1.0.0` output:

- Markdown members are UTF-8 with LF line endings and one trailing newline.
  JSON members are UTF-8, deterministically key-sorted and indented, normalized
  to LF, and terminated by one newline. `CHECKSUMS.sha256` is ASCII with LF
  endings.
- `CHECKSUMS.sha256` lists the first four content members in package order and
  records the SHA-256 digest of each member's exact bytes. The download response
  separately reports the complete ZIP's SHA-256 digest.
- Generation is bound to the latest selected scan, project-identity digest,
  coverage, exact unresolved finding set, and review-state snapshot. A changed
  project, scan, finding, coverage state, or review state makes an existing
  preview stale and package generation fails.
- Only unresolved canonical findings are eligible. They are ordered by
  severity first, then stable project-relative identity fields. At most the
  first 100 are included, and unresolved, included, and omitted counts are
  explicit.
- ZIP member order, normalized content serialization, archive metadata, and
  scan-derived timestamp handling are fixed by the current generator.
  Identical supported-runtime inputs are tested for identical bytes.
- Glacial does not promise byte-identical regeneration across arbitrary future
  application, Python, compression-library, operating-system, or runtime
  versions. Existing archives remain independently verifiable from their
  included checksums.
- The archive is data-only: it contains no executable content, scripts,
  symlinks, or copied project files. Generation does not execute project
  content, launch an agent, modify source, or mutate scan/review state.
- Project-derived text is inert evidence. Paths are project-relative; absolute
  host paths and project identity are not disclosed. Unsafe paths and sensitive
  evidence are omitted or redacted.

## Semantic compatibility rules

### Patch format update: 1.0.x

A patch update is permitted only for a backward-compatible correction:

- documentation clarification;
- correction of output that violated the already published 1.0 contract;
- serialization or checksum correction that restores documented behavior; or
- another correction requiring no consumer adaptation.

Existing compliant consumers must continue to work unchanged.

### Minor format update: 1.x.0

A minor update is permitted for backward-compatible additions, including new
optional JSON fields, optional metadata, additional values with explicitly
defined handling, or other additions that old consumers may safely ignore.

A minor update must not rename, remove, or reinterpret an existing field or
member, and it must not make an optional field required.

### Major format update: 2.0.0 or later

A new major version is required for an incompatible change, including:

- removing or renaming a package member or required field;
- changing an existing field's meaning;
- incompatibly changing checksum semantics;
- changing unresolved-only scope or canonical ordering semantics;
- requiring existing consumers to change parsing or security behavior; or
- materially changing the data-only trust boundary.

## Reader and validator behavior

Glacial does not currently import, read, or apply Agent Remediation Package
archives. Package generation validates its own fixed inventory and current
format; no general-purpose package importer is created by this policy.

Any future Glacial-owned reader or validator must:

- accept only explicitly supported format major versions;
- tolerate documented additive fields within a supported major version;
- reject unsupported future major versions clearly and safely;
- never silently reinterpret a future major version as format 1.x;
- treat all project-derived content as inert data; and
- fail without modifying project files or existing Glacial state.

The reader must validate the version boundary before interpreting fields whose
meaning depends on that version.

## Retention and deprecation

- Existing exported packages remain self-contained and independently
  checksum-verifiable indefinitely.
- Published package semantics are never changed retroactively.
- Glacial may stop generating an obsolete major format only after publishing a
  successor and migration guidance.
- Stopping generation must never cause an old archive to be reinterpreted under
  a newer format.
- Future Glacial versions are not required to regenerate historical packages
  byte-for-byte.
- Deprecating a supported major version requires explicit documentation before
  removal.
- Format 1.x remains supported for generation throughout the Glacial v1
  application line unless a security issue requires an explicitly documented
  exception.
