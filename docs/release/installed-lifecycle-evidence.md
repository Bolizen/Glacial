# Glacial 0.9.6 installed lifecycle evidence

Status: internal G049 evidence recorded 2026-07-27 on the Windows x64 development host. This is focused installed-edition evidence, not a public release candidate, clean-machine matrix, signing report, or v1 authorization.

## Authoritative Windows path contract

Glacial uses Tauri's `currentUser` NSIS mode. The running desktop application resolves and displays these paths:

| Purpose | Windows installed path |
| --- | --- |
| Installation directory | `%LOCALAPPDATA%\Glacial` |
| Application executable | `%LOCALAPPDATA%\Glacial\glacial.exe` |
| Owned backend executable | `%LOCALAPPDATA%\Glacial\glacial-backend.exe` |
| Owned backend runtime | `%LOCALAPPDATA%\Glacial\_internal` |
| Application-data root | `%LOCALAPPDATA%\com.glacial.desktop` |
| Active backend data | `%LOCALAPPDATA%\com.glacial.desktop\data` |
| SQLite database | `%LOCALAPPDATA%\com.glacial.desktop\data\glacial.db` |
| Configuration | The `settings` table in `glacial.db`; there is no separate configuration file |
| Startup log | `%LOCALAPPDATA%\com.glacial.desktop\logs\backend-startup.log` |
| Migration backups | `%LOCALAPPDATA%\com.glacial.desktop\data\migration-backups\*.db` |
| Reset recovery backups | `%LOCALAPPDATA%\com.glacial.desktop\data\recovery-backups\*.db` |
| WebView-owned data | `%LOCALAPPDATA%\com.glacial.desktop\EBWebView` |
| Temporary files | The current user's Windows temporary directory returned by Tauri |
| Installer metadata | `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Glacial` |
| Uninstaller | `%LOCALAPPDATA%\Glacial\uninstall.exe` |

Release startup derives these values from Tauri path APIs and the running executable. It passes absolute owned-runtime paths to the packaged backend. It does not use the repository, build-machine source path, current working directory, writable installation storage, portable-layout inference, or development-only environment values.

## Internal artifacts

Both artifacts were unsigned, internal NSIS installers. They were not published.

| Artifact | Source | Bytes | SHA-256 |
| --- | --- | ---: | --- |
| `Glacial_0.9.5_x64-setup.exe` | Detached exact predecessor commit `4c8a4e67ab151b12f4615186eab49de647733111` | 16,100,493 | `A91B5B7CCA5C525BE930A1DE783D220A4B9F66FA035CCEA9356288B46EE31D19` |
| `Glacial_0.9.6_x64-setup.exe` | Final G049 behavior before documentation/audit commits | 16,113,410 | `E432914E96F31BB9F586B5D14BBF5ACDB2C179C52E93FC6DE8FDFB8A742E47A8` |

The v0.9.6 artifact is lifecycle evidence only. It is not represented as a commit-provenanced release candidate.

## Scenario record

The host had no Glacial installation or uninstall registration. It did have an existing development data root. That root was atomically moved aside before the matrix and restored afterward with its original database SHA-256 `006C7EA4BFFEC1993E326608F6E6C37F05F6B97392486FC322A93E903B9CEE91`.

1. **Clean application-state install:** silent v0.9.5 installation succeeded in `currentUser` mode. HKCU metadata reported `0.9.5`; `glacial.exe`, `glacial-backend.exe`, `_internal`, and `uninstall.exe` existed under `%LOCALAPPDATA%\Glacial`.
2. **First launch and paths:** the installed application, owned backend, schema-v1 database, and startup log appeared at the documented locations. `CloseMainWindow()` did not close this predecessor instance within 10 seconds; forced parent termination removed the owned backend. This predecessor observation is retained as a limitation, not converted to a pass.
3. **Predecessor persistence:** a disposable project marker plus one representative project registration, scan, note, and Project Expectations / Trust Profile record were placed in the v0.9.5 schema-v1 database. A second installed v0.9.5 launch succeeded with that state.
4. **Upgrade:** the v0.9.6 installer updated HKCU metadata in place and retained the database and project marker. First v0.9.6 startup migrated schema `1 -> 2`, produced one verified migration backup, preserved all four representative row families, retained the cautious trust profile and expectations, and passed `integrity_check`.
5. **Migration idempotence:** a repeated v0.9.6 startup left the database SHA-256 unchanged at `14447BF1BD1FA903BE3117CCA19EDAC93D9B3D696F294C2359A579EF7716A07E`, kept schema version 2, and created no second migration backup.
6. **Installed path readback:** the installed Settings page displayed the actual application executable, SQLite database, and log paths listed above.
7. **Reset:** the installed confirmation identified the exact application state being deleted, said registered project files would not be modified, and promised a recovery backup. The first implementation created its backup but Windows rejected the database rename while the backend held SQLite; that preliminary artifact was rejected. The corrected final implementation reset valid SQLite state transactionally under an exclusive lock. Projects, scans, notes, and trust profiles each changed from one row to zero; schema version 2 and `integrity_check = ok` remained; one migration backup and two recovery backups were retained; the project marker SHA-256 remained `EAA1E232B38C3B8C7E9523EB0B4BE2CE4CBC7663F3ECD6FEBC788070226DD30C`.
8. **Post-reset start:** the installed application reopened successfully with the same clean database hash and zero representative rows.
9. **Reinstall:** silent same-version reinstall succeeded, retained the clean database, migration and recovery backups, and project marker.
10. **Default uninstall:** silent uninstall removed `%LOCALAPPDATA%\Glacial` and the HKCU uninstall registration. It retained the application-data root, SQLite database, logs, migration backups, recovery backups, and WebView data. The project marker was unchanged.
11. **Optional uninstall removal:** generated final NSIS source confirms that checking **Delete the application data** removes `%APPDATA%\com.glacial.desktop` and `%LOCALAPPDATA%\com.glacial.desktop`. That checked GUI variant was not exercised in G049. Neither path includes registered project directories.

## Reset and recovery contract

The Settings reset is an explicit authenticated action with an exact backend confirmation phrase. It clears the active SQLite schema and both known Glacial WebView preference keys. It does not traverse, open, modify, or delete registered project paths or downloaded exports.

For a valid or partially initialized SQLite file, reset first publishes a recovery backup, obtains an exclusive transaction, recreates only Glacial's schema and default setting, publishes schema version 2, and rolls back on failure. A lock failure retains the original database and reports the problem. For a malformed SQLite file, reset preserves a verified byte-for-byte raw recovery copy before replacing it with clean state. An unavailable database is initialized cleanly without pretending a backup was created.

Migration backups, recovery backups, and logs are retained by reset. Restore is manual replacement while Glacial is closed; it is not merge or automatic rollback.

## Uninstall contract

The default uninstaller removes installed binaries, owned runtime files, shortcuts, installer metadata, and the uninstaller. It preserves application data for reinstall and recovery.

If the user explicitly checks **Delete the application data**, NSIS additionally removes the Glacial roaming and local bundle-ID roots, including settings, SQLite state, logs, WebView state, migration backups, and recovery backups. Registered project files, generated project instructions, and downloaded exports are never installer-owned and are never uninstall targets.

## Evidence limits

- This was a clean application-state matrix on one Windows x64 development host, not a clean Windows machine or supported-OS matrix.
- Artifacts were unsigned and internal. Public trust, RFC 3161 timestamps, release manifests, final candidate provenance, and GitHub Release procedures remain unproven.
- The checked **Delete the application data** GUI path was source-inspected but not natively exercised.
- Recovery backups were created and validated, but manual restore from a recovery backup was not exercised.
- Graceful close through `CloseMainWindow()` failed for the v0.9.5 predecessor. Forced parent termination stopped its backend; G049 did not complete the broader graceful/crash/startup-failure/console-flash matrix.
- No power-loss, disk-full, antivirus-interference, filesystem-corruption, or clean-machine acceptance was performed.
- G049 did not run the Codex Security Deep Security Scan, accessibility matrix, legal/notices review, public release-candidate construction, or final authorization.
