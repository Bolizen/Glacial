# Support policy

Glacial is maintained as an early-stage project, not as a staffed commercial support service.

## Requesting help

Use [GitHub Issues](https://github.com/Bolizen/Glacial/issues/new) for ordinary bugs, documentation problems, and feature requests. Search existing issues first and keep one reproducible problem per issue.

Include:

- Glacial version and whether it is an installed NSIS build or a development checkout;
- Windows edition, build, architecture, display resolution, and scaling;
- installation scope and whether files were moved or modified;
- the exact task, expected result, and observed result;
- the smallest safe reproduction;
- relevant bounded messages from the startup screen or log; and
- whether reinstall, reset, or restore was attempted.

Do not post a database, project archive, remediation package, full log, screenshot, or path inventory without reviewing it. Replace usernames and private paths, remove project content that is not needed, and redact credentials, tokens, private URLs, personal data, and proprietary names.

Suspected undisclosed vulnerabilities use the private process in [SECURITY.md](../SECURITY.md), not a public issue.

## Version and environment boundary

Pre-v1 assistance is limited to the current repository version and the latest explicitly documented installed build, when one exists. Older versions may be asked to reproduce on the current version. No long-term support window or backport commitment exists yet.

The installed product boundary is the current-user Windows x64 NSIS edition described in the [support matrix](supported-environments.md). Modified, copied, relocated, unpacked, unofficial, or unsigned builds are outside the supported distribution boundary. Source-development questions are best-effort and do not convert a development checkout into a supported installed product.

An issue may be closed as unsupported when it depends on an unsupported operating system, architecture, privilege level, remote deployment, relocated installation, modified binary, unsafe workspace authority, obsolete version, or disabled security control. A report can be reopened with evidence from a supported configuration.

## Response targets

For ordinary issues, the maintainer aims to acknowledge actionable reports within 14 calendar days. Status updates depend on availability, reproducibility, severity, and current release work. These are targets, not service-level guarantees.

Security reports use the shorter acknowledgement target and coordinated-disclosure process in `SECURITY.md`. Feature requests can be declined or deferred without a delivery date.
Reinstalling is appropriate when verified installed binaries or the packaged backend are missing or damaged. Default uninstall retains application state, so reinstalling does not repair a corrupt or incompatible retained database. Preserve the database and backups before reset, checked data deletion, or manual restoration.
