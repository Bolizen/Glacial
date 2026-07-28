# G050 installed lifecycle acceptance

Status: completed internal Windows x64 NSIS acceptance on 2026-07-27/28. The accepted artifact is unsigned internal evidence, not a public release candidate, publicly trusted build, tag, GitHub Release, or v1 authorization. Glacial remains `NOT READY`.

## Environment and clean-state method

- Host: Icefields VMware guest, VMware model `VMware20,1`.
- Operating system: Windows 11 Pro x64, version `10.0.26200`, build `26200`.
- Windows user: `Fidel`; NSIS installation mode: `currentUser`.
- Starting repository: clean `main` at `2ee6f9018f786d169e9d2cd13ad487742cbb7952`.
- Exact artifact source: clean committed state `518cf498929152799d656ee6e27cfedc81b98cbe`.
- Clean application state: no installed Glacial directory, uninstall registration, running frontend, or running backend. The pre-existing local Glacial bundle root was atomically renamed to `com.glacial.desktop.g050-preserved`, retaining 419 files and database SHA-256 `006C7EA4BFFEC1993E326608F6E6C37F05F6B97392486FC322A93E903B9CEE91`. After acceptance, it was atomically restored to its original name with the same file count and database hash.
- Test data: only the disposable G050 application state, one disposable registered-project directory under `.desktop-build/g050-evidence/project`, one local AppData neighboring marker, one roaming AppData neighboring marker, and one disposable roaming Glacial-state marker.
- Cleanup: the exact neighbor markers were removed, the tested installation was uninstalled, no Glacial frontend/backend remained, and the pre-existing Glacial state was restored.

## Accepted artifact provenance

| Field | Accepted value |
| --- | --- |
| Source commit | `518cf498929152799d656ee6e27cfedc81b98cbe` |
| Installer | `Glacial_0.9.7_x64-setup.exe` |
| Bytes | `16,116,199` |
| SHA-256 | `8BB1627DA3E41993763E9DF147BC6AC34D03F8B0F30C9D899796B4B1C0F38003` |
| Build timestamp | `2026-07-28T03:28:47Z` |
| Signing state | `NotSigned`; no signer |
| Backend build | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\desktop\Build-DesktopBackend.ps1` |
| Sidecar staging | `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\desktop\Stage-DesktopSidecar.ps1` |
| NSIS build | `npm.cmd --prefix frontend run tauri:build` |
| Installed application | `C:\Users\Fidel\AppData\Local\Glacial\glacial.exe` |
| Installed application SHA-256 | `3C9BB6F49F8C38EDB8C216C3F7671B89E0ECC00CA744E34F864838DE23A37A38` |
| Installed backend | `C:\Users\Fidel\AppData\Local\Glacial\glacial-backend.exe` |
| Installed backend SHA-256 | `AEE894C82A7C5C6694ACD0C9817E98F56223ED5897DC353EB4DC1897C92CDB08` |

The pre-bundle Rust executable hash was `95C07B03950075EE09BEAC7BB0413B8DD13C513EE0915B11EA7037AA5C63EACF`. Tauri patched the application executable with NSIS bundle-type information before packaging, so the installed application hash differs as expected. The backend hash remained identical to the staged PyInstaller executable.

No runtime defect required a rebuild, no installer was rejected, and the artifact above is the only accepted G050 installer. PyInstaller emitted a future-version deprecation warning about the existing cross-environment `pathex`; it did not fail or change the locked build result.

## Observed installed paths

Settings displayed the actual running values:

| Purpose | Observed path |
| --- | --- |
| Installation | `C:\Users\Fidel\AppData\Local\Glacial` |
| Application | `C:\Users\Fidel\AppData\Local\Glacial\glacial.exe` |
| Backend | `C:\Users\Fidel\AppData\Local\Glacial\glacial-backend.exe` |
| Backend runtime | `C:\Users\Fidel\AppData\Local\Glacial\_internal` |
| Application data | `C:\Users\Fidel\AppData\Local\com.glacial.desktop\data` |
| Database/configuration | `C:\Users\Fidel\AppData\Local\com.glacial.desktop\data\glacial.db`; configuration is the `settings` table |
| Logs | `C:\Users\Fidel\AppData\Local\com.glacial.desktop\logs` |
| Migration backups | `C:\Users\Fidel\AppData\Local\com.glacial.desktop\data\migration-backups` |
| Recovery backups | `C:\Users\Fidel\AppData\Local\com.glacial.desktop\data\recovery-backups` |
| WebView data | `C:\Users\Fidel\AppData\Local\com.glacial.desktop\EBWebView` |
| Temporary directory | `C:\Users\Fidel\AppData\Local\Temp` |
| Installer metadata | `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Glacial` |
| Uninstaller | `C:\Users\Fidel\AppData\Local\Glacial\uninstall.exe` |

No repository/build path was reported as runtime mutable state.

## Required acceptance matrix

Acceptance ran from approximately `2026-07-28T03:31Z` through `2026-07-28T03:55Z`.

| # | Case | Status | Evidence |
| ---: | --- | --- | --- |
| 1 | Clean-state installation and first run | PASS | Silent install exited 0; HKCU reported 0.9.7 at the current-user location. The visible window opened with PID `12736`; backend PID `16988` was its only owned backend; 50 ms window sampling observed zero new visible console windows. Settings reported every path above. Fresh schema version was 2 and `integrity_check` was `ok`; restart retained the same valid first-run database. |
| 2 | Concurrent two-launch behavior | PASS | First PID `15304` remained; immediate second PID `3760` exited 0. One effective frontend, one visible window, and one backend PID `1532` remained. Recognizable project/note state persisted and SQLite integrity was `ok`. |
| 3 | Graceful shutdown | PASS | Stable installed close requested through `CloseMainWindow()` removed frontend PID `15304` and backend PID `1532` in 279 ms; orphan count was zero. Relaunch produced one window/backend and unchanged recognizable state. An earlier first-run close completed in 10,059 ms; a post-reinstall close attempted before the UI had fully loaded did not complete within 15 seconds, then the stable loaded window closed normally in 259 ms. |
| 4 | Forced parent termination | PASS | Forced parent PID `5892` caused job-owned backend PID `14780` to disappear in 213 ms. No orphan remained. Relaunch preserved the exact database hash, recognizable state, schema version 2, and `integrity_check = ok`. |
| 5 | Controlled startup failure and recovery | PASS | With Glacial closed, `glacial-backend.exe` was reversibly renamed. The frontend showed: “Glacial could not start its owned backend process. Close this window, correct the problem, and run Glacial again.” No backend existed, the bounded startup log was zero bytes, and the database hash was unchanged. Restoring the backend produced its original SHA-256 and normal startup with one backend. |
| 6 | Interrupted reset recovery | PASS | A disposable external SQLite `BEGIN IMMEDIATE` writer allowed the verified recovery backup to publish, then blocked reset at Glacial's `BEGIN EXCLUSIVE` boundary. Parent termination removed the backend in 122 ms. The backup hash was `9D68CA15DC5BB711AA3ED64CC3F81AB4D3A3505280FA003D1BF4C03119B9F0CB`; no pending reset file existed; the original recognizable database remained current and valid. Relaunch succeeded, and a later normal reset produced clean schema version 2, zero project/note rows, two retained recovery backups, and `integrity_check = ok`. |
| 7 | Manual backup restoration | PASS | With Glacial closed, the verified recovery backup was copied to a same-directory temporary and atomically installed with `File.Replace`; the displaced clean database was preserved as `g050-displaced-clean-before-manual-restore.db`. Restored database SHA-256 matched the backup exactly. Recognizable project/note rows returned, integrity was `ok`, and the installed app relaunched with one backend. |
| 8 | Same-version reinstall | PASS | Reinstall of the exact accepted artifact exited 0, kept one `Glacial` install directory and one uninstall key, preserved database SHA-256 `9D68…F0CB`, retained the marker, started one backend, and showed the correct installed paths after the WebView finished loading. |
| 9 | Default uninstall retention | PASS | Uninstall with data deletion unchecked exited 0 and removed installed binaries and the uninstall key. Local/roaming bundle roots, database, logs, WebView data, recovery backups, and their exact hashes/counts remained. No backend remained. |
| 10 | Checked uninstall-data removal | PASS | The native NSIS checkbox text was identified, explicitly set, and read back as state `1` before invoking **Uninstall**. The GUI completed and exited through **Close**. Installed binaries, the uninstall key, `%LOCALAPPDATA%\com.glacial.desktop`, and `%APPDATA%\com.glacial.desktop` were removed. Both parent AppData directories and neighboring markers remained unchanged; no frontend/backend/uninstaller process remained. |
| 11 | Project-file non-deletion invariant | PASS | `PROJECT_MARKER.txt` remained byte-identical across every case with SHA-256 `273022740CEC9EBFA01368827740EAB13EA8BD24ADFFC166BD894FEB575C98E1`. |

## Retained-versus-removed inventory

Default uninstall retained:

- `%LOCALAPPDATA%\com.glacial.desktop\data\glacial.db`, hash `9D68CA15DC5BB711AA3ED64CC3F81AB4D3A3505280FA003D1BF4C03119B9F0CB`;
- `%LOCALAPPDATA%\com.glacial.desktop\logs`;
- `%LOCALAPPDATA%\com.glacial.desktop\EBWebView`;
- `%LOCALAPPDATA%\com.glacial.desktop\data\recovery-backups`, three verified database files at that point;
- `%APPDATA%\com.glacial.desktop\G050_ROAMING_STATE.txt`;
- the registered-project marker and both neighboring AppData markers.

Default uninstall removed:

- `%LOCALAPPDATA%\Glacial`, including application, backend, runtime, and uninstaller;
- `HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\Glacial`.

Checked uninstall removed:

- `%LOCALAPPDATA%\Glacial`;
- `%LOCALAPPDATA%\com.glacial.desktop`;
- `%APPDATA%\com.glacial.desktop`;
- the HKCU uninstall key.

Checked uninstall retained:

- `%LOCALAPPDATA%` and `%APPDATA%` parent directories;
- local neighboring marker SHA-256 `58DB3AA44741CD295C13DFF990D76D6796279CC24288F4C2CDDB5B91323D66A4`;
- roaming neighboring marker SHA-256 `6B0BFA1E8DEA163AD80BC15BDAC9151DEF47A7AF0B8F19C81B0B1911F8323AA7`;
- registered-project marker SHA-256 `273022740CEC9EBFA01368827740EAB13EA8BD24ADFFC166BD894FEB575C98E1`.

## Defects, rejected artifacts, and limitations

- Product defects discovered: none.
- Rejected installers: none. The two initial checked-uninstall automation attempts stopped on the confirmation page before uninstalling because the custom NSIS checkbox is not exposed through .NET UI Automation; native control readback completed the required GUI case against the same artifact.
- The accepted artifact is unsigned and internal. No public trust, signer, timestamp, candidate manifest, GitHub Release, tag, or authorization is claimed.
- This is one Windows 11 x64 VMware guest with a genuinely clean Glacial installed/user state, not a newly provisioned operating-system image or a multi-version Windows support matrix.
- The controlled reset interruption is process-boundary evidence, not a power-loss, disk-full, antivirus, or filesystem-corruption simulation.
- Native installed hostile privacy-sink acceptance, whole-product accessibility, deep security scanning, public candidate construction, rollback/withdrawal, and final release authorization remain separate blockers.
