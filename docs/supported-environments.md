# Supported environments

Glacial v1 is limited to a current-user Windows x64 installation produced by the NSIS installer. The repository is still `NOT READY`; this matrix records the tested boundary and the work still required before v1 authorization.

| Area | v0.9.11 boundary |
| --- | --- |
| Product edition | Installed NSIS edition only |
| Processor architecture | x64 |
| Install scope | Current Windows user, non-elevated |
| Install location | `%LOCALAPPDATA%\Glacial` |
| Installed application data | `%LOCALAPPDATA%\com.glacial.desktop` and optional `%APPDATA%\com.glacial.desktop` state |
| Language | English installer and application |
| Web runtime | Microsoft Edge WebView2 Evergreen Runtime |
| Application window | Enforced minimum outer window is 960 × 640; default is 1280 × 800 |
| Windows display scaling | 100% only |
| Windows text size | Default only; increased accessibility text-size settings are untested |
| Update method | Close Glacial and run a verified newer NSIS installer as the same user |
| Automatic updater | None; updater artifacts and runtime update checks are disabled |
| Downgrade | Unsupported |

## Tested Windows boundary

G050 completed the installed lifecycle on one VMware guest running Windows 11 Pro x64, OS version `10.0.26200`, build `26200`. It covered clean Glacial state, first run, same-version reinstall, in-place schema migration, reset, manual restore, both uninstall modes, concurrent launch, process cleanup, and one missing-backend failure.

That one run is evidence for the tested configuration, not a multi-version Windows support claim. The frozen candidate must repeat the lifecycle on every environment that will be declared supported.

| Environment | Status |
| --- | --- |
| Windows 11 Pro x64 build 26200 in the tested VMware configuration | Tested internal baseline; final-candidate acceptance still required |
| Other Windows 11 editions or builds | Untested; not yet in the v1 support set |
| Windows 10 | Untested and unsupported |
| Windows Server | Untested and unsupported |
| Windows on ARM, including x64 emulation | Unsupported |
| Linux and macOS | Unsupported as installed products |
| Physical Windows hardware | Untested; no support claim yet |
| Other hypervisors, sandbox products, remote-app delivery, or VDI | Untested; no support claim |
| Copied, manually relocated, or unpacked installed files | Unsupported |
| Source checkouts and development builds | Development inputs, not supported installed products |

## WebView, display, and scaling

The application requires Microsoft Edge WebView2 Evergreen Runtime. The NSIS configuration uses Tauri's default download-bootstrapper mode: when WebView2 is absent, installation may contact Microsoft to acquire it. Users normally should not install a separate backend, Python runtime, Node.js, Rust toolchain, or database engine.

The application refuses to size its outer main window below 960 × 640; this is an enforced Tauri constraint, not merely a documented recommendation. G052 accepted every primary screen and the critical keyboard workflow at that minimum on the tested VMware guest with a 1276 × 1284 desktop, 100% Windows display scaling, and default Windows text size.

The v1 support boundary is therefore conservative: 100% Windows display scaling only. Scaling at 125%, 150%, 175%, or 200%, custom DPI, increased Windows text size, high-contrast themes, multiple-monitor movement, rotation, and resolutions other than the tested 1276 × 1284 desktop are untested and unsupported. They may work, but G052 does not make that claim. The final frozen candidate must repeat acceptance on every environment proposed for support.

## Installation and upgrade assumptions

The supported installation is run by the interactive user without elevation. Glacial expects a stable application-data directory and a stable, current-user-controlled workspace root. Do not use a workspace that another principal can replace or modify while Glacial is operating.

Clean installation and same-version reinstall are proven on the tested G050 environment. In-place upgrade is supported only through the current-user NSIS installer and the documented schema path. Schema versions 0 and 1 are recognized predecessors for the current schema version 2 when their structure is supported. A newer, unknown, corrupt, or malformed database fails closed. Glacial does not automatically downgrade or restore it.

Do not replace `glacial.exe`, `glacial-backend.exe`, WebView files, or individual runtime files by hand. The installed application, backend, resources, installer registration, and data paths are one tested unit.
