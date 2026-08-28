# Windows release signing

Glacial v0.9.12 is intended to use an Authenticode certificate with the subject `CN=Icefields Development`. The existing certificate is self-signed and is not publicly trusted. Its signature proves byte integrity and publisher-key continuity only; it does not establish Windows reputation or public trust.

Windows Smart App Control, SmartScreen, or organization-managed Application Control may still block Glacial. Do not disable those controls, add exclusions, restore blocked files, or instruct users to bypass warnings. Treat a block as failed or incomplete acceptance.

Users should independently verify the Git commit, release manifest, `SHA256SUMS.txt`, artifact hashes, signer subject, signer thumbprint, and a thumbprint published through an independent Icefields channel.

## Development and release workflows

Unsigned development is independent of release signing and never requires a certificate:

```powershell
pnpm --dir frontend run desktop:backend:plan
pnpm --dir frontend run desktop:backend
```

These pnpm commands invoke Node directly to plan or build the internal PyInstaller backend. They do not use `-ExecutionPolicy Bypass`, do not read signing configuration, and do not create a user-distributable application. Normal Tauri development and internal staging remain development workflows, not product distributions.

### Signed preview

The signed-preview profile is for internal development, local testing, and release-pipeline validation. It accepts either the existing valid self-signed certificate or a publicly trusted signer, but self-signed output is not automatically appropriate for public distribution.

```powershell
pnpm --dir frontend run release:windows:signed-preview:plan
pnpm --dir frontend run release:windows:signed-preview -- --python C:\Path\To\Python313\python.exe
```

The legacy commands remain exact signed-preview aliases and never select the public-release profile:

```powershell
pnpm --dir frontend run release:windows:plan
pnpm --dir frontend run release:windows:signed -- --python C:\Path\To\Python313\python.exe
```

### Public release candidate

The public-rc profile is for a candidate that may be publicly distributed. It fails closed unless the disposable signer preflight derives `trustClassification` exactly equal to `publicly-trusted`; the existing self-signed certificate cannot satisfy this gate.

```powershell
pnpm --dir frontend run release:windows:public-rc:plan
pnpm --dir frontend run release:windows:public-rc -- --python C:\Path\To\Python313\python.exe
```

Both profiles retain the established RFC 3161 timestamp, exact signer identity, signature, installer-payload, restoration, hash, and atomic-publication checks. Actual signed construction runs in a detached checkout and consumes only a frozen fresh pnpm installation, an isolated locked Cargo home, and build/runtime Python trees reconstructed from the repository-pinned Python.org embeddable archive plus SHA-256-verified wheels. The operator-selected Python is bootstrap transport only and is not the interpreter executed by PyInstaller or packaged into the backend. Persistent `frontend/node_modules`, Cargo state, `backend/.venv`, and `.desktop-build/venv` in the primary checkout are not release inputs. Each profile produces only the installed NSIS artifact and its release metadata. Glacial does not currently claim to possess or configure a publicly trusted code-signing certificate.

### Signer preflight only

The signer-only commands load the same redacted configuration and sign no Glacial product file. They validate the expected subject and exact thumbprint, current certificate validity, Code Signing EKU, usable private key or approved provider, disposable PE signature, RFC 3161 timestamp, observed Authenticode chain classification, profile trust gate, and disposable cleanup:

```powershell
pnpm --dir frontend run release:windows:signed-preview:signer-preflight
pnpm --dir frontend run release:windows:public-rc:signer-preflight
```

The result is bounded to profile, provider type, expected and observed public signer identity, observed trust, validity dates, Code Signing EKU, timestamp origin/presence, verification, and cleanup. It excludes credentials, private-key locations, raw environment values, provider credential responses, and host paths. A plan command remains a plan and is not signer verification. The public-RC signer preflight must fail when only the existing self-signed signer is available.

## Signing providers

`store` mode selects exactly one certificate by normalized thumbprint from `Cert:\CurrentUser\My`. The pipeline canonicalizes the expected and actual distinguished names, requires an exact match, verifies the chain, signs and RFC 3161 timestamps in separate checked SignTool operations, proves private-key usability by verifying a disposable PE before any expensive build, and deletes the probe directory.

`command` mode invokes one absolute reviewed executable directly, without a shell. Its JSON argument array contains exactly one `{file}` placeholder. Only explicitly named provider environment variables are forwarded. Credentials must not appear in command arguments, paths, logs, manifests, or tracked files. Prefer managed identity or an HSM/provider session over long-lived environment secrets.

Tauri receives an ignored generated overlay whose object-form `signCommand` calls the same wrapper. Before provider delegation, the broker freezes a release-scoped signing plan containing the artifact role, canonical path, pre-signing digest, and Windows handle-derived filesystem object identity. Reparse objects and artifacts with multiple hardlinks are rejected. Identity and signed bytes are revalidated after signing/capture and during final evidence verification when the object remains present. Signing audit JSONL records are authenticated with a release-scoped HMAC key that is shared only by the coordinator and broker, not the Tauri build client. Tauri patches and signs Glacial.exe for the NSIS bundle, then restores its unsigned working executable after bundling. The wrapper atomically preserves the verified NSIS application signing result in confined release signing state so it can be checked against the authenticated signing audit and generated NSIS source evidence. Glacial.exe is never signed a second time after Tauri finishes. Existing valid vendor-signed files are hashed before and after verification and are never re-signed.

## Repeat-safe self-signed provisioning

Do not run this during review. Run it only after certificate provisioning is separately approved. It touches only `CurrentUser\My` and `CurrentUser\Root`, creates a non-exportable RSA key, and refuses an existing exact publisher identity instead of silently rotating it.

```powershell
$ErrorActionPreference = "Stop"
$subject = "CN=Icefields Development"
$friendlyName = "Icefields Development Glacial Code Signing"
$flags = [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseCommas `
    -bor [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::Reversed `
    -bor [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::DoNotUseQuotes `
    -bor [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::DoNotUsePlusSign `
    -bor [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseUTF8Encoding

function ConvertTo-CanonicalSubject(
    [System.Security.Cryptography.X509Certificates.X500DistinguishedName] $Name
) {
    $Name.Decode($flags).Trim().ToUpperInvariant()
}

$expectedName = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new($subject)
$expectedCanonical = ConvertTo-CanonicalSubject $expectedName
$existing = @(
    foreach ($storeName in @("My", "Root")) {
        Get-ChildItem -LiteralPath "Cert:\CurrentUser\$storeName" |
            Where-Object {
                (ConvertTo-CanonicalSubject $_.SubjectName) -eq $expectedCanonical
            } |
            ForEach-Object {
                [pscustomobject]@{ Store = $storeName; Thumbprint = $_.Thumbprint }
            }
    }
)
if ($existing.Count -ne 0) {
    $locations = ($existing | ForEach-Object { "$($_.Store):$($_.Thumbprint)" }) -join ", "
    throw "Refusing duplicate provisioning. Existing Icefields certificate(s): $locations"
}

$certificate = New-SelfSignedCertificate `
    -Type CodeSigningCert `
    -Subject $subject `
    -FriendlyName $friendlyName `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -KeyAlgorithm RSA `
    -KeyLength 3072 `
    -HashAlgorithm SHA256 `
    -KeyExportPolicy NonExportable `
    -NotAfter (Get-Date).ToUniversalTime().AddYears(2)

$thumbprint = ($certificate.Thumbprint -replace "\s", "").ToUpperInvariant()
$duplicateRoot = @(
    Get-ChildItem -LiteralPath "Cert:\CurrentUser\Root" |
        Where-Object { (($_.Thumbprint -replace "\s", "").ToUpperInvariant()) -eq $thumbprint }
)
if ($duplicateRoot.Count -ne 0) {
    throw "The new certificate thumbprint already exists in CurrentUser\Root. Stop and investigate."
}

$publicCertificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new(
    $certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert)
)
$currentUserRoot = [System.Security.Cryptography.X509Certificates.X509Store]::new(
    "Root",
    [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
)
$currentUserRoot.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
try {
    $currentUserRoot.Add($publicCertificate)
}
finally {
    $currentUserRoot.Close()
}

$thumbprint
```

Adding the public certificate to the release account's `CurrentUser\Root` makes verification meaningful only on that account. It does not install machine-wide trust and does not make the certificate publicly trusted.

### Exact certificate removal

Removal is a separate destructive operation. Supply the independently verified thumbprint and run only when retirement is explicitly approved. The commands refuse missing, duplicate, wrong-subject, or malformed candidates before touching either CurrentUser store.

```powershell
$ErrorActionPreference = "Stop"
$subject = "CN=Icefields Development"
$thumbprint = ("<40-character-thumbprint>" -replace "\s", "").ToUpperInvariant()
if ($thumbprint -notmatch "^[0-9A-F]{40}$") {
    throw "The certificate thumbprint is malformed."
}

$flags = [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseCommas `
    -bor [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::Reversed `
    -bor [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::DoNotUseQuotes `
    -bor [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::DoNotUsePlusSign `
    -bor [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags]::UseUTF8Encoding
$expectedName = [System.Security.Cryptography.X509Certificates.X500DistinguishedName]::new($subject)
$expectedCanonical = $expectedName.Decode($flags).Trim().ToUpperInvariant()

function Get-ExactIcefieldsCertificate([string] $StoreName) {
    $storePath = "Cert:\CurrentUser\$StoreName"
    $matches = @(
        Get-ChildItem -LiteralPath $storePath |
            Where-Object { (($_.Thumbprint -replace "\s", "").ToUpperInvariant()) -eq $thumbprint }
    )
    if ($matches.Count -ne 1) {
        throw "Expected exactly one $storePath certificate with thumbprint $thumbprint; found $($matches.Count)."
    }
    $actualCanonical = $matches[0].SubjectName.Decode($flags).Trim().ToUpperInvariant()
    if ($actualCanonical -ne $expectedCanonical) {
        throw "Refusing to remove an unexpected certificate subject from $storePath."
    }
    return $matches[0]
}

$personalCertificate = Get-ExactIcefieldsCertificate "My"
$trustedRootCertificate = Get-ExactIcefieldsCertificate "Root"
Remove-Item -LiteralPath $personalCertificate.PSPath
Remove-Item -LiteralPath $trustedRootCertificate.PSPath
```

## Key continuity and recovery

`KeyExportPolicy NonExportable` means losing the Icefields VM, user profile, DPAPI state, or private-key container loses the ability to sign with the same thumbprint. A repository backup does not preserve signing continuity.

Do not weaken or export the current key. Outside this repository, keep encrypted, access-controlled full-VM recovery snapshots and periodically test restoration. For public signing, prefer a provider-managed HSM or Azure signing identity with managed identity, least-privilege roles, dual control, audit logs, and provider disaster recovery.

## Release authority and build-time configuration

Every non-plan signed operation first loads the two caller-supplied detached statement files and the artifact signer's public certificate, but verifies them against one fixed machine trust anchor:

`C:\Program Files\Icefields\Glacial Release Policy\release-authority-public-key.pem`

Provision that RSA public key from the offline authority as an administrator before granting the non-elevated release account read access. Keep the directory and file non-writable by that account. The path is compiled into the release verifier; no environment variable, command argument, manifest field, or sibling helper can select another authority key. A missing, redirected, malformed, or inaccessible anchor fails closed. Replacing the anchor requires a separately reviewed repository change plus controlled-host reprovisioning. Administrator, kernel, weakened-ACL, and arbitrary active same-user process compromise remain outside the repository threat model.

Actual signed modes require:

| Variable | Purpose |
| --- | --- |
| `GLACIAL_WINDOWS_RELEASE_AUTHORITY_PATH` | Absolute path outside the repository to the exact UTF-8 JSON release-authority manifest |
| `GLACIAL_WINDOWS_RELEASE_AUTHORITY_SIGNATURE_PATH` | Absolute path outside the repository to its raw RSA PKCS#1 SHA-256 signature |
| `GLACIAL_WINDOWS_ARTIFACT_SIGNER_CERTIFICATE_PATH` | Absolute path outside the repository to the artifact signer's public certificate; its thumbprint and SPKI SHA-256 must match the signed authority statement and its key must differ from the machine authority key |

Command-provider credential values may be present only for the exact environment-variable names authorized inside the signed statement. The provider type, expected signer subject/thumbprint/SPKI, PowerShell, SignTool, provider executable, provider argument template, environment-name allowlist, and HTTPS timestamp endpoint all come from the authenticated statement, not from invocation environment.

Plan commands are non-signing diagnostics and continue to accept these environment values only to print a proposed configuration:

| Variable | Purpose |
| --- | --- |
| `GLACIAL_WINDOWS_SIGNING_PROVIDER` | Proposed `store` or `command` provider |
| `GLACIAL_WINDOWS_EXPECTED_SUBJECT` | Proposed exact signer DN |
| `GLACIAL_WINDOWS_SIGNTOOL_PATH` | Proposed absolute Windows SDK `signtool.exe` path |
| `GLACIAL_WINDOWS_REQUIRE_TIMESTAMP` | Must be `1` for a plan |
| `GLACIAL_WINDOWS_TIMESTAMP_URL` | Proposed credential-free timestamp endpoint |
| `GLACIAL_WINDOWS_CERTIFICATE_THUMBPRINT` | Exact 40-hex certificate thumbprint in `CurrentUser\My` |
| `GLACIAL_WINDOWS_EXPECTED_THUMBPRINT` | Exact signer thumbprint expected after signing |
| `GLACIAL_WINDOWS_SIGN_COMMAND` | Absolute reviewed provider executable |
| `GLACIAL_WINDOWS_SIGN_COMMAND_ARGS` | JSON string array with exactly one `{file}` placeholder and no secrets |
| `GLACIAL_WINDOWS_SIGN_COMMAND_ENV` | JSON array naming only provider environment variables that may be forwarded |

There is no operator-supplied trust label. The pipeline derives `self-signed` or `publicly trusted` from the actual verified signer chain. It rejects invalid, ambiguous, or privately rooted non-self-signed chains.

The release-authority manifest is the independent approval for source, producer identity, signing identity, and time/profile scope. It has `schemaVersion: 2`, a unique `authorityId`, canonical `issuedAtUtc` and `expiresAtUtc` values no more than fourteen days apart, one or more authorized profiles, source repository `https://github.com/Bolizen/Glacial.git`, the exact approved 40-hex commit, and exactly thirteen tool records named `node`, `python`, `git`, `tar`, `cargo`, `rustc`, `linker`, `resourceCompiler`, `cCompiler`, `librarian`, `powerShell`, `signTool`, and `signingProvider`. Each tool record contains its approved absolute `path` and lowercase SHA-256. Store mode records SignTool as both `signTool` and `signingProvider`; command mode records the exact external provider. The signed `signing` object also fixes provider type, signer subject/thumbprint/SPKI SHA-256, timestamp URL, command arguments, and provider environment-name allowlist. Cargo and Rustc records must identify actual toolchain binaries, not rustup proxies.

Create the manifest only after the immutable release commit and complete tool/signing selection exist, keep it outside the checkout and Git common directory, and sign its exact bytes with the offline key corresponding to the machine-provisioned public anchor. Keep the authority private key unavailable to the release host. An expired, not-yet-valid, wrong-profile, wrong-repository, wrong-commit, wrong-signer, or tool-modified statement fails before signing capability is reached.

The fourteen-day maximum is the replay/revocation bound: a statement may authorize repeat canonical builds only inside its signed window. Emergency invalidation inside that window requires controlled-host removal or replacement of the protected machine anchor (or denial of signer/provider access); there is no repository-managed one-use ledger. The release host's protected UTC clock is therefore part of the controlled-host boundary. Glacial does not claim resistance to administrator-equivalent clock or anchor manipulation.

On the separate authorization system, an authorized operator can create the detached signature without exporting the private key:

```powershell
$manifestPath = "C:\ReleaseAuthority\Glacial-G120.json"
$signaturePath = "C:\ReleaseAuthority\Glacial-G120.sig"
$certificate = Get-Item -LiteralPath "Cert:\CurrentUser\My\<offline-authorization-thumbprint>"
$privateKey = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($certificate)
$manifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)
$signature = $privateKey.SignData($manifestBytes, [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
[System.IO.File]::WriteAllBytes($signaturePath, $signature)
$privateKey.Dispose()

$env:GLACIAL_WINDOWS_RELEASE_AUTHORITY_PATH = $manifestPath
$env:GLACIAL_WINDOWS_RELEASE_AUTHORITY_SIGNATURE_PATH = $signaturePath
$env:GLACIAL_WINDOWS_ARTIFACT_SIGNER_CERTIFICATE_PATH = $artifactSignerCertificatePath
```

The coordinator verifies the detached signature with the fixed machine public key, statement freshness/profile, artifact-signer identity and key separation before the first signing-capable child launch. It then requires Node and bootstrap Python to match their signed records, uses only signed absolute producer paths, and rechecks canonical path, SHA-256, and filesystem identity immediately before direct launches. PowerShell, SignTool, and the configured provider are reauthenticated before their signing or verification results are trusted. Authenticated authority, tool, signing-configuration, and artifact-plan objects are private in-process capabilities; copying their visible properties cannot mint a signing capability. The broker and Tauri wrapper independently reload the same statement, verify the exact checkout, authenticate the same tools, reject Node runtime-injection variables, and prove that their authenticated Node parent is the canonical clean-release coordinator. The public command first relaunches that coordinator with its absolute script path so relative package-script invocation cannot weaken the parent proof. Tauri reconstructs Cargo, Rust, and MSVC executable variables from authenticated tool records instead of forwarding caller-selected values. Direct `sign-one` is disabled; signer preflight and release-verification CLIs also require current authority. A source, tool, signer, provider, profile, or authorization-window change requires a new externally signed manifest.

This boundary does not claim resistance to an already malicious Node runtime, arbitrary active same-user process interference, or a race that swaps and restores an approved file or tracked source between checks. Node is the verifier's bootstrap runtime, so release operations should invoke the authority-approved absolute Node path from a controlled host rather than rely on an unreviewed shell resolution. Persistent tool replacement is detected before direct use and after descendant packaging; persistent source mutation is detected by the existing clean-tree and final source checks. Stronger guarantees against a hostile process already executing as the release user require host isolation or code-integrity enforcement outside this repository.

Example signed-preview store-mode plan:

```powershell
$env:GLACIAL_WINDOWS_SIGNING_PROVIDER = "store"
$env:GLACIAL_WINDOWS_CERTIFICATE_THUMBPRINT = "<40-character-thumbprint>"
$env:GLACIAL_WINDOWS_EXPECTED_SUBJECT = "CN=Icefields Development"
$env:GLACIAL_WINDOWS_SIGNTOOL_PATH = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
$env:GLACIAL_WINDOWS_TIMESTAMP_URL = "http://timestamp.digicert.com"
$env:GLACIAL_WINDOWS_REQUIRE_TIMESTAMP = "1"

pnpm --dir frontend run release:windows:signed-preview:plan
```

After separate certificate provisioning, a signed release-authority manifest for the immutable commit and approved tools, a clean `main`, and `HEAD == origin/main`, produce an internal signed preview with:

```powershell
pnpm --dir frontend run release:windows:signed-preview -- --python C:\Path\To\Python313\python.exe
```

Plan or produce a public release candidate only after configuring a publicly trusted signer:

```powershell
pnpm --dir frontend run release:windows:public-rc:plan
pnpm --dir frontend run release:windows:public-rc -- --python C:\Path\To\Python313\python.exe
```

The coordinator performs this order:

1. Verify the externally signed exact repository, commit, and release-tool identities; then verify branch, clean status, `HEAD == origin/main`, canonical origin identity, and v0.9.12 metadata.
2. Select one exact CurrentUser certificate or external signer and sign/verify a disposable timestamped PE probe.
3. Enforce the selected profile immediately from the verified `trustClassification`: signed preview accepts `self-signed` or `publicly-trusted`; public RC accepts exactly `publicly-trusted`.
4. Create a detached checkout at the authenticated commit; provision frozen pnpm state and both Python environments from pinned authenticated repository inputs; bind their complete executed trees to the build and revalidate them after use.
5. Build the backend once from those retained disposable inputs, preserve valid vendor bytes, and sign every unsigned PE.
6. Stage the signed backend and pass the coordinator-retained source inventory as authority outside the stage; Tauri rejects missing, stale, copied, or recomputed colocated receipts before and after packaging. The broker then handles Glacial.exe, supported NSIS components, uninstaller, and final installer signing, rejecting reparse/multi-link objects and binding each request to an immutable role/path/digest/object/release plan before provider delegation.
7. Verify the final installer, captured application, authenticated object-and-byte-bound signing audit events, retained object identities, restored working-file state, and generated NSIS main-binary source.
8. Copy only the verified NSIS installer into release-candidate state.
9. Generate final manifest and hashes only after all binary mutation is complete, recording the selected profile, required signer trust, verified signer trust classification, independent source authority, and dependency-input provenance.
10. Recheck the detached source identity, tracked state, and current signed authorization immediately before and after the inner atomic publication; copy and reverify the candidate, recheck authorization immediately before and after the outer primary publication, then remove the checkout and its inputs. Expiry at either publication boundary rolls the rename back and fails closed.

The failed unsigned candidate `Glacial-0.4.0-fbf96d568350-20260719T065059Z` is historical evidence and must never be overwritten or removed.

## Independent verification

```powershell
$signTool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
& $signTool verify /pa /all /tw /v "<path-to-file>"
Get-AuthenticodeSignature -LiteralPath "<path-to-file>" |
    Select-Object Status, StatusMessage, SignerCertificate, TimeStamperCertificate
Get-FileHash -Algorithm SHA256 -LiteralPath "<installer-path>"
```

Verify every executable PE included in the installed application, including `.pyd` files. After installation in a disposable acceptance environment, obtain the actual uninstaller path from the uninstall registry entry and verify it the same way.

Glacial v1 does not publish a portable binary archive. Internal unpacked Tauri/PyInstaller outputs are staging inputs only, and GitHub-generated source archives are source snapshots rather than Glacial binary distributions.

## Migration to publicly trusted signing

Glacial does not currently claim to possess a publicly trusted code-signing certificate. Before a public release candidate can be produced, obtain and configure an appropriate publicly trusted signer, publish its certificate outside the checkout, and issue a fresh authority statement that binds its thumbprint, public-key digest, exact subject, provider, and `public-rc` profile. The pipeline derives public trust from the actual verified chain and the public-rc gate rejects every other classification.

For Azure Artifact Signing or another remote signer, set command mode, expected production subject/thumbprint, reviewed executable, non-secret argument template, and the minimal provider environment-name allowlist. Prefer managed identity. Artifact names, layout, signing order, manifest location, and release semantics remain unchanged.
