# Windows release signing

Glacial v0.6.4 is intended to use an Authenticode certificate with the subject `CN=Icefields Development`. The initial certificate is self-signed and is not publicly trusted. Its signature proves byte integrity and publisher-key continuity only; it does not establish Windows reputation or public trust.

Windows Smart App Control, SmartScreen, or organization-managed Application Control may still block Glacial. Do not disable those controls, add exclusions, restore blocked files, or instruct users to bypass warnings. Treat a block as failed or incomplete acceptance.

Users should independently verify the Git commit, release manifest, `SHA256SUMS.txt`, artifact hashes, signer subject, signer thumbprint, and a thumbprint published through an independent Icefields channel.

## Development and release workflows

Unsigned development is independent of release signing and never requires a certificate:

```powershell
npm.cmd --prefix frontend run desktop:backend:plan
npm.cmd --prefix frontend run desktop:portable:plan
npm.cmd --prefix frontend run desktop:backend
npm.cmd --prefix frontend run desktop:portable
```

These npm commands invoke Node directly. They do not use `-ExecutionPolicy Bypass` and do not read signing configuration.

Signed release candidates use only:

```powershell
npm.cmd --prefix frontend run release:windows:plan
npm.cmd --prefix frontend run release:windows:signed
```

## Signing providers

`store` mode selects exactly one certificate by normalized thumbprint from `Cert:\CurrentUser\My`. The pipeline canonicalizes the expected and actual distinguished names, requires an exact match, verifies the chain, signs and RFC 3161 timestamps in separate checked SignTool operations, proves private-key usability by verifying a disposable PE before any expensive build, and deletes the probe directory.

`command` mode invokes one absolute reviewed executable directly, without a shell. Its JSON argument array contains exactly one `{file}` placeholder. Only explicitly named provider environment variables are forwarded. Credentials must not appear in command arguments, paths, logs, manifests, or tracked files. Prefer managed identity or an HSM/provider session over long-lived environment secrets.

Tauri receives an ignored generated overlay whose object-form `signCommand` calls the same wrapper. Tauri patches and signs Glacial.exe for each bundle type, then restores its unsigned working executable after bundling. The wrapper atomically preserves the one verified NSIS application signing result in the confined release signing state; that exact capture is verified against the signing audit and NSIS staging evidence, then reused byte-for-byte for portable packaging. Glacial.exe is never signed a second time after Tauri finishes. Existing valid vendor-signed files are hashed before and after verification and are never re-signed.

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

## Required build-time configuration

All signed modes require:

| Variable | Purpose |
| --- | --- |
| `GLACIAL_WINDOWS_SIGNING_PROVIDER` | `store` or `command` |
| `GLACIAL_WINDOWS_EXPECTED_SUBJECT` | Exact expected signer DN, currently `CN=Icefields Development` |
| `GLACIAL_WINDOWS_SIGNTOOL_PATH` | Absolute path to the reviewed Windows SDK `signtool.exe` |
| `GLACIAL_WINDOWS_REQUIRE_TIMESTAMP` | Must be `1` |
| `GLACIAL_WINDOWS_TIMESTAMP_URL` | Credential-free HTTPS RFC 3161 endpoint, or the exact `http://timestamp.digicert.com` endpoint, with no query or fragment |

Store mode also requires:

| Variable | Purpose |
| --- | --- |
| `GLACIAL_WINDOWS_CERTIFICATE_THUMBPRINT` | Exact 40-hex certificate thumbprint in `CurrentUser\My` |

Command mode also requires:

| Variable | Purpose |
| --- | --- |
| `GLACIAL_WINDOWS_EXPECTED_THUMBPRINT` | Exact signer thumbprint expected after signing |
| `GLACIAL_WINDOWS_SIGN_COMMAND` | Absolute reviewed provider executable |
| `GLACIAL_WINDOWS_SIGN_COMMAND_ARGS` | JSON string array with exactly one `{file}` placeholder and no secrets |
| `GLACIAL_WINDOWS_SIGN_COMMAND_ENV` | JSON array naming only provider environment variables that may be forwarded |

There is no operator-supplied trust label. The pipeline derives `self-signed` or `publicly trusted` from the actual verified signer chain. It rejects invalid, ambiguous, or privately rooted non-self-signed chains.

Example store-mode plan:

```powershell
$env:GLACIAL_WINDOWS_SIGNING_PROVIDER = "store"
$env:GLACIAL_WINDOWS_CERTIFICATE_THUMBPRINT = "<40-character-thumbprint>"
$env:GLACIAL_WINDOWS_EXPECTED_SUBJECT = "CN=Icefields Development"
$env:GLACIAL_WINDOWS_SIGNTOOL_PATH = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
$env:GLACIAL_WINDOWS_TIMESTAMP_URL = "http://timestamp.digicert.com"
$env:GLACIAL_WINDOWS_REQUIRE_TIMESTAMP = "1"

npm.cmd --prefix frontend run release:windows:plan
```

After separate certificate provisioning, a clean `main`, and `HEAD == origin/main`:

```powershell
npm.cmd --prefix frontend run release:windows:signed
```

The coordinator performs this order:

1. Verify repository identity, branch, clean status, `HEAD == origin/main`, and v0.6.4 metadata.
2. Select one exact CurrentUser certificate or external signer and sign/verify a disposable timestamped PE probe.
3. Verify build/runtime environments, build the backend once, preserve valid vendor bytes, and sign every unsigned PE.
4. Stage the signed backend and let Tauri sign Glacial.exe, supported NSIS components, uninstaller, and final installer; the custom signer atomically captures the one verified NSIS-patched Glacial.exe before Tauri restores its working file.
5. Verify the final installer, captured application, exact signing audit event, restored working-file state, and generated NSIS main-binary source; reuse only the captured signed Glacial.exe bytes for portable assembly.
6. Create the portable ZIP with Windows-compatible root entry names, validate Explorer visibility, re-extract it with both Windows `Expand-Archive` and `tar.exe`, compare every source/archive file, and reverify every PE.
7. Generate final manifest and hashes only after all binary mutation is complete.
8. Recheck branch, HEAD, origin/main, clean status, and release metadata.
9. Atomically publish a new unique candidate directory.

The failed unsigned candidate `Glacial-0.4.0-fbf96d568350-20260719T065059Z` is historical evidence and must never be overwritten or removed.

## Independent verification

```powershell
$signTool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"
& $signTool verify /pa /all /tw /v "<path-to-file>"
Get-AuthenticodeSignature -LiteralPath "<path-to-file>" |
    Select-Object Status, StatusMessage, SignerCertificate, TimeStamperCertificate
Get-FileHash -Algorithm SHA256 -LiteralPath "<installer-path>"
Get-FileHash -Algorithm SHA256 -LiteralPath "<portable-zip-path>"
```

Verify every executable PE, including `.pyd` files and extracted portable contents. After installation in a disposable acceptance environment, obtain the actual uninstaller path from the uninstall registry entry and verify it the same way.

## Migration to publicly trusted signing

For a publicly trusted certificate in `CurrentUser\My`, change only the build-time thumbprint and exact expected subject. The pipeline derives public trust from the actual chain.

For Azure Artifact Signing or another remote signer, set command mode, expected production subject/thumbprint, reviewed executable, non-secret argument template, and the minimal provider environment-name allowlist. Prefer managed identity. Artifact names, layout, signing order, manifest location, and release semantics remain unchanged.
