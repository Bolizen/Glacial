# Installed Windows lifecycle guide

Glacial supports one Windows x64 product edition: the current-user NSIS installation. It does not support a portable edition or relocation by copying installed files.

This guide describes Glacial 0.9.7. The application remains pre-v1 and `NOT READY`; these instructions do not make an unsigned or unapproved installer trustworthy.

## Install and first run

1. Obtain the intended `Glacial_<version>_x64-setup.exe` and its independently published SHA-256 from Icefields.
2. Verify that the filename, byte size, hash, version, and signing state match the release record you intend to use. Do not bypass SmartScreen, Smart App Control, organization policy, or signature failures.
3. Run the installer as the current Windows user. Glacial installs under `%LOCALAPPDATA%\Glacial`; it does not require a portable extraction directory.
4. Start Glacial from its shortcut.
5. In **Settings → Installed paths and application state**, confirm the running executable, database, logs, backups, and temporary directory match the paths shown below.
6. Choose a workspace root, create or select a project folder below that root, and register it through Glacial. Registration does not transfer ownership of project files to Glacial.

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
2. Preserve a separate copy of `glacial.db` when the state is important.
3. Verify the new installer's version, hash, and signing state.
4. Run the NSIS installer as the same Windows user. Supported schema migration runs at first startup and writes a verified migration backup before changing supported predecessor state.
5. Start Glacial, open Settings, and confirm the version-specific installer and the same application-data paths are in use.
6. Confirm registered projects and recognizable notes/review state remain available.

Do not downgrade or move an installed payload to simulate another edition.

## Reset application state

1. Open **Settings → Installed paths and application state**.
2. Select **Reset application state**.
3. Read the confirmation carefully. Reset deletes active Glacial database state and saved Glacial UI preferences. It does not traverse or modify registered project directories.
4. Confirm only if you intend to reset. When an existing database is available, Glacial creates a verified recovery backup first.
5. After reset, confirm the success message and restart Glacial.

Migration backups, recovery backups, and logs are retained by reset.

## Restore a migration or recovery backup manually

Restoration is replacement, not merge. Use only a verified Glacial database backup from a supported schema.

1. Close Glacial. In Task Manager, confirm neither `glacial.exe` nor `glacial-backend.exe` is running.
2. Locate `glacial.db` and the intended backup through the Settings paths above.
3. Copy the current `glacial.db` to a separately named displaced-state backup. Never overwrite the only copy.
4. Verify the selected backup opens as SQLite, `PRAGMA integrity_check` returns `ok`, and `PRAGMA user_version` is supported by the installed Glacial version.
5. Copy the selected backup to a uniquely named temporary file in the same `data` directory as `glacial.db`.
6. Atomically replace `glacial.db` with that temporary copy while preserving the displaced database. On PowerShell/.NET, `System.IO.File.Replace(temporary, database, displacedBackup, $true)` provides this same-volume replacement.
7. Start Glacial. Confirm expected recognizable state, open Settings, and verify the database path.
8. If startup fails, close Glacial, preserve the failing bytes and startup log, restore the displaced database, and seek support. Do not delete or silently recreate the only valid backup.

## Uninstall

Close Glacial before uninstalling.

- Leave **Delete the application data** unchecked to remove installed binaries, shortcuts, uninstaller, and installer registration while retaining the database, logs, WebView data, and migration/recovery backups for reinstall or recovery.
- Explicitly check **Delete the application data** to additionally remove `%LOCALAPPDATA%\com.glacial.desktop` and `%APPDATA%\com.glacial.desktop`.

Neither option removes registered project directories, project files, generated project instructions, or downloaded exports.

## Troubleshooting startup

- A missing or blocked backend produces a bounded Glacial startup-error window and no usable partial application state.
- Do not disable Windows security controls or antivirus policy to force startup.
- Confirm the installed application and backend exist under `%LOCALAPPDATA%\Glacial`, then verify their hashes/signatures against the intended release record.
- Preserve `%LOCALAPPDATA%\com.glacial.desktop\logs\backend-startup.log`, the active database, and available backups before reinstalling or restoring.
- If a second launch is attempted, Glacial should activate the existing instance rather than create a second backend. If multiple backends remain, close Glacial and treat the state as unsafe until investigated.
