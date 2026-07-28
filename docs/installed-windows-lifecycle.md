# Installed Windows lifecycle guide

Glacial supports one Windows x64 product edition: the current-user NSIS installation. It does not support a portable edition or relocation by copying installed files.

This guide describes Glacial 0.9.9. The application remains pre-v1 and `NOT READY`; these instructions do not make an unsigned or unapproved installer trustworthy.

## Install and first run

1. Obtain the intended `Glacial_<version>_x64-setup.exe` and its independently published SHA-256 from Icefields.
2. Verify that the filename, byte size, hash, version, and signing state match the release record you intend to use. Do not bypass SmartScreen, Smart App Control, organization policy, or signature failures.
3. Run the installer as the current Windows user without elevation. Glacial installs under `%LOCALAPPDATA%\Glacial`.
4. Start Glacial from its shortcut.
5. Wait for the packaged backend to start. The first launch creates a schema-version-2 database when no prior Glacial state exists. It may take longer while Windows and WebView2 initialize.
6. In **Settings → Installed paths and application state**, confirm the running executable, packaged backend, runtime, database, logs, backups, and temporary directory match the paths shown below.
7. Confirm that `glacial.exe` and `glacial-backend.exe` run below `%LOCALAPPDATA%\Glacial`. A repository path, build staging directory, copied folder, missing `_internal` runtime, or backend outside the install directory is not a valid installed layout.
8. Choose a workspace root, create or select a project folder below that root, and register it through Glacial. Registration does not transfer ownership of project files to Glacial.

Glacial packages its backend, Python runtime, and SQLite support. Node.js, Python, Rust, a database server, and developer tools are not separate installed prerequisites. Microsoft Edge WebView2 Evergreen Runtime is required. If it is absent, the installer may contact Microsoft to acquire it.

Windows may show User Account Control, SmartScreen, Smart App Control, antivirus, organization-policy, or WebView2 installation prompts. Check the artifact record and publisher state. Do not disable a security control or accept an unexpected publisher to force installation.

## Installed state locations

| State | Windows location |
| --- | --- |
| Application and backend | `%LOCALAPPDATA%\Glacial` |
| SQLite database and settings | `%LOCALAPPDATA%\com.glacial.desktop\data\glacial.db` |
| Startup log | `%LOCALAPPDATA%\com.glacial.desktop\logs\backend-startup.log` |
| Migration backups | `%LOCALAPPDATA%\com.glacial.desktop\data\migration-backups` |
| Reset recovery backups | `%LOCALAPPDATA%\com.glacial.desktop\data\recovery-backups` |
| WebView data | `%LOCALAPPDATA%\com.glacial.desktop\EBWebView` |
| Optional roaming bundle state | `%APPDATA%\com.glacial.desktop` |
| Uninstaller | `%LOCALAPPDATA%\Glacial\uninstall.exe` |

Registered projects, generated project-root `AGENTS.md` files, and downloaded exports are not stored below those bundle roots and are never uninstall targets.

## Update or same-version reinstall

1. Close Glacial and confirm `glacial.exe` and `glacial-backend.exe` have exited.
2. Preserve a separate copy of `glacial.db` when the state is important, before an unusual upgrade, or before any manual recovery attempt.
3. Verify the new installer's version, hash, and signing state.
4. Run the NSIS installer as the same Windows user. Supported schema migration runs at first startup and writes a verified migration backup before changing supported predecessor state.
5. Start Glacial, open Settings, and confirm the version-specific installer and the same application-data paths are in use.
6. Confirm registered projects and recognizable notes/review state remain available.

Running the same verified installer again replaces the installed application payload while retaining application data. It does not create a second application-data root and does not clear a retained database. Glacial has no automatic updater or background update check.

If installation fails, keep Glacial closed, preserve the installer result and current state, and retry only after verifying free space, permissions, artifact integrity, and security-software disposition. Do not manually copy a newer `glacial.exe`, backend, `_internal` runtime, or WebView file over an installation. Those files are tested and versioned as one payload.

Downgrades are unsupported. A previous application version may not understand the current schema or generated formats. Do not move an installed payload to simulate another edition.

## Reset application state

1. Open **Settings → Installed paths and application state**.
2. Select **Reset application state**.
3. Read the confirmation carefully. Reset deletes active Glacial database state and saved Glacial UI preferences. It does not traverse or modify registered project directories.
4. Enter the exact phrase `RESET GLACIAL APPLICATION DATA`.
5. Confirm only if you intend to reset. When an existing database is available, Glacial creates a verified recovery backup first.
6. After reset, confirm the success message and restart Glacial.

Reset recreates the active database with schema version 2 and the default workspace setting. It clears project registrations, scans, findings, notes, reviews, expectations, baselines, activity, checkpoints, and the two Glacial WebView convenience-state keys. It preserves WebView runtime/cache files outside those keys, the startup log, migration backups, recovery backups, downloaded exports, and every registered project file.

If reset fails, do not delete the active database or backup directories. Close Glacial, preserve the startup log and the newest recovery backup, and use the manual recovery procedure or request support.

## Restore a migration or recovery backup manually

Restoration is replacement, not merge. Use only a verified Glacial database backup from a supported schema.

1. Close Glacial. In Task Manager, confirm neither `glacial.exe` nor `glacial-backend.exe` is running.
2. Locate `glacial.db` and the intended backup through the Settings paths above. Migration backups use `glacial-pre-migration-v<SOURCE>-to-v2-<UTC timestamp>-<random suffix>.db`; reset backups use `glacial-before-reset-<UTC timestamp>-<random suffix>.db`.
3. Copy the current `glacial.db` to a separately named displaced-state backup outside the two managed backup directories. Never overwrite the only copy.
4. Select the backup by operation time and source schema. Verify that it is a regular file from the expected Glacial directory, opens as SQLite, returns `ok` from `PRAGMA integrity_check`, and reports a `PRAGMA user_version` supported by the installed Glacial version.
5. Copy the selected backup to a uniquely named temporary file in the same `data` directory as `glacial.db`.
6. Atomically replace `glacial.db` with that temporary copy while preserving the displaced database. On PowerShell/.NET, `System.IO.File.Replace(temporary, database, displacedBackup, $true)` provides this same-volume replacement.
7. Start Glacial. Confirm expected recognizable state, open Settings, and verify the database path.
8. If startup fails, close Glacial, preserve the failing bytes and startup log, restore the displaced database, and seek support. Do not delete or silently recreate the only valid backup.

Do not replace the database while either Glacial process is running. Do not copy a backup from a newer schema into an older version. Database backups contain application-owned state, not registered project folders, project files, generated project instructions, or downloaded exports.

## Uninstall

Close Glacial before uninstalling.

- Leave **Delete the application data** unchecked to remove installed binaries, shortcuts, uninstaller, and installer registration while retaining `%LOCALAPPDATA%\com.glacial.desktop` and `%APPDATA%\com.glacial.desktop`. This includes the database, logs, WebView data, migration backups, recovery backups, and optional roaming bundle state.
- Explicitly check **Delete the application data** to additionally remove `%LOCALAPPDATA%\com.glacial.desktop` and `%APPDATA%\com.glacial.desktop`.

Before checking data deletion, close Glacial and copy any database backup you need to a separate safe location. Neither uninstall option removes registered project directories, project files, generated project instructions, or downloaded exports. Data deletion is intentionally limited to Glacial's two bundle-identifier application-data roots.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| Application does not open | Check Task Manager for an existing `glacial.exe`, then verify the installed shortcut and `%LOCALAPPDATA%\Glacial\glacial.exe`. Check Windows security history and the artifact record without bypassing policy. |
| Backend is missing or blocked | Keep Glacial closed. Verify `glacial-backend.exe` and `_internal` under the install directory against the intended installer. Reinstall the complete verified payload; do not replace one file. |
| Startup error screen | Record the exact bounded message, close the window, preserve `backend-startup.log`, and check installed paths and retained database state before retrying. |
| Application-data directory is unavailable or corrupt | Do not grant broad permissions or delete it. Preserve the directory, check that it is a normal current-user directory rather than a link or redirected object, and restore only from a verified backup. |
| Update or migration fails | Keep the pre-migration backup and active database. Do not downgrade. Verify disk space, directory access, schema version, and the new installer before seeking support. |
| Reset fails | Keep the active database and any newly created recovery backup. Close both processes, preserve the log, and retry only after identifying the lock or storage failure. |
| Window opens but backend is unavailable | Use the startup message and log; confirm one owned backend should run below the install directory. A browser-opened development page is not an installed client. |
| Repeated launch | A second launch should activate the existing window. If multiple frontends or backends remain, close them, preserve diagnostics, and report the process names and times. |
| Application remains after close | Allow the loaded window time to close. If a process remains, record its name and PID before ending it. Relaunch only after both owned processes exit. |
| Restore does not pass integrity or startup | Stop, retain the failing and displaced databases, and try another verified backup. Do not reset or delete the only recovery copy. |

Reinstall when installed binaries or the packaged backend are missing or damaged. Default uninstall and same-version reinstall retain application data, so they do not repair a corrupt, future, or otherwise incompatible retained database.

Do not disable antivirus, SmartScreen, Smart App Control, code-signing checks, controlled-folder access, or organization policy. Verify the artifact and report suspected false positives through the support or private security channel.

For support, provide the Glacial version, Windows build, symptom, exact safe error text, installed-path readback, and the smallest relevant log excerpt. Remove usernames, private project names, credentials, tokens, and personal data first. See the [support policy](support.md).
