# Privacy and network disclosure

Glacial operates locally by default. Its installed application uses a Tauri frontend and an owned FastAPI backend on authenticated loopback. Ordinary scans do not upload registered project files or query package registries.

## Data Glacial reads and stores

When a project is registered, Glacial reads supported files and metadata below that project root for scanning and review. This can include paths, filenames, manifests, lockfiles, configuration, project instructions, file attributes, bounded text evidence, and user-provided project notes or expectations. Linked or unsafe paths are rejected rather than followed.

Application-owned state includes:

- the SQLite database containing registrations, operational absolute project paths, scan records, findings, notes, reviews, expectations, baselines, activity, and checkpoints;
- bounded WebView convenience state for the selected workspace, project, scan, section, layout, and guided-review dismissal;
- the current bounded backend startup log;
- verified migration and reset-recovery database backups; and
- operation-owned temporary files while an atomic write, backup, build, or export is in progress.

The installed locations are listed in the [lifecycle guide](installed-windows-lifecycle.md). Registered project directories and downloaded exports are not application database backups.

Reports, remediation briefs, remediation packages, generated `AGENTS.md` files, and other exports can contain project-relative paths, findings, bounded evidence, notes, expectations, dependency identities, review decisions, counts, timestamps, and integrity hashes. They may disclose information about the project even when no source file is included.

## Network-capable workflows

| Workflow | Network behavior |
| --- | --- |
| Installed application runtime | Authenticated loopback traffic between the Tauri process and its owned backend only |
| Project scanning and Dependency Trust | Offline; no registry, reputation, package-download, or cloud lookup |
| Update checking | None; no runtime updater is configured |
| NSIS installation when WebView2 is missing | Tauri's WebView2 download bootstrapper may contact Microsoft before the application runs |
| Links in repository documentation | A user's browser contacts the selected site when the link is opened |
| Source setup and dependency acquisition | Developer-invoked Git, pnpm, pip, Cargo, or OS tooling can contact their configured services |
| Signed release tooling | An explicitly invoked signer or RFC 3161 timestamp service can create outbound traffic |
| GitHub release and support workflows | Maintainer- or user-invoked browser and release tooling contacts GitHub |

The installer bootstrapper, dependency tools, signing tools, and GitHub workflows are not ordinary Glacial scanning traffic. Project content is not an input to the configured signing or timestamp step. Network policy, proxies, endpoint protection, and the contacted service still govern those external operations.

Glacial's production content-security policy permits Tauri IPC and does not permit public web origins. The development policy also permits the local Vite server and its WebSocket. Remote backend deployment, LAN binding, reverse proxies, and public service operation are unsupported.

## Redaction and disclosure limits

Glacial sanitizes project-derived and user-authored text before persistence and again at major disclosure sinks. It removes control characters, bounds excerpts, presents safe relative paths where operational absolute paths are not required, and redacts common credential-shaped values. Standalone 40–128 character hexadecimal values are redacted in generic text unless a strict structured field requires a validated commit, checksum, fingerprint, or public signing identity.

Redaction is a risk reduction, not a guarantee. Unrecognized secret formats, business-sensitive names, source excerpts, notes, filenames, and information that is sensitive only in context can remain. Structured hashes and identifiers can also be sensitive even when they are valid.

Review every report, brief, package, generated file, diagnostic, screenshot, and log before copying, exporting, attaching, or sharing it. Remove information the recipient does not need. Do not send credentials, private keys, tokens, personal data, or proprietary source merely because Glacial did not redact it.

The detailed source-backed data inventory is the [data privacy and disclosure boundary](release/data-privacy-boundary.md).
