# Signs the Windows files of a GitHub release on your own computer with a code signing certificate that never leaves
# its token (a YubiKey PIV slot or any smart card the Windows certificate store sees), and uploads them back to the
# same release. See docs/release.md, "Windows code signing".
#
# Full (default): unpack the MSI (administrative install), sign every unsigned .exe and .dll of the app image and
# the project's own native libraries inside its jars (zk/native/windows-x86_64/*.dll: diw_zk, diw_bb5, with their
# .sha256 rewritten, since ZkNative checks the library against it), build the MSI again with jpackage from that image
# (same name, version, upgrade UUID and install options as the CI build) and sign the MSI. The Windows release jar
# (DIW-MY-WALLET-windows-x64-<version>-release.jar) gets the same native library signatures and is uploaded too.
# Needs JDK 21 or later (jpackage) and WiX Toolset 3.14 (JDK 21 and 22) or WiX 4 / 5 (JDK 23+).
# MsiOnly: sign the MSI as it is; the launcher and the native libraries inside stay unsigned. Needs only signtool.
# Native: the experimental GraalVM executable (the desktop-native-windows artifact of a CI run, as its .zip or
# unpacked folder): sign diw-desktop.exe and every unsigned .exe and .dll beside it (the JDK libraries native-image
# copies there, jawt.dll), then zip the folder as DIW-MY-WALLET-<version>-windows-x64-native.zip. The ZK libraries are
# compiled into the executable as resources and cannot be signed afterwards; the executable unpacks them only when
# their SHA-256, pinned inside the signed executable, matches.
# Third-party libraries that jars unpack at run time (Skiko, SQLite, JNA) are left as they are: their loaders check
# their own digests, and they are not this project's code.
#
# Both need signtool (Windows SDK) and, to download and upload, the GitHub CLI (gh auth login). With a YubiKey, the
# YubiKey Smart Card Minidriver puts the certificate into Cert:\CurrentUser\My while the key is inserted; Windows
# asks for the PIV PIN when signing.
#
#   .\tools\windows-sign.ps1 -Tag v0.5.3
#   .\tools\windows-sign.ps1 -Tag v0.5.3 -Thumbprint 0123ABCD... -Mode MsiOnly
#   .\tools\windows-sign.ps1 -Msi .\DIW-MY-WALLET-0.5.3.msi -NoUpload
#   .\tools\windows-sign.ps1 -Mode Native -Path .\desktop-native-windows.zip -Tag v0.5.3
[CmdletBinding()]
param(
    [string]$Tag,
    [string]$Msi,
    [string]$Path,
    [string]$Repo = "mctea01/my-Bonds-fork-android",
    [ValidateSet("Full", "MsiOnly", "Native")] [string]$Mode = "Full",
    [string]$Thumbprint,
    [string]$TimestampUrl = "http://timestamp.digicert.com",
    [string]$WorkDir = (Join-Path $env:TEMP "diw-windows-sign"),
    [switch]$NoUpload,
    [switch]$NoNotes
)
$ErrorActionPreference = "Stop"
[Console]::OutputEncoding = [Text.Encoding]::UTF8
$OutputEncoding = [Text.Encoding]::UTF8

# Same values as compose.desktop.nativeDistributions in app/build.gradle.kts; keep them in step.
$PackageName = "DIW-MY-WALLET"
$Vendor = "DIW MY WALLET"
$Description = "DIW MY WALLET"
$MenuGroup = "DIW MY WALLET"
$UpgradeUuid = "5d0f4a52-8a3e-4b8e-9f0c-6c1d2b7e3a41"

function Find-Tool([string]$name, [string[]]$roots) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    foreach ($root in $roots) {
        if (Test-Path $root) {
            $hit = Get-ChildItem $root -Recurse -Filter $name -ErrorAction SilentlyContinue |
                Where-Object { $_.FullName -match "\\x64\\" } | Sort-Object FullName -Descending | Select-Object -First 1
            if ($hit) { return $hit.FullName }
        }
    }
    return $null
}

function Invoke-Checked([string]$exe, [string[]]$arguments) {
    # Out-Host keeps the tool output off the pipeline, so functions that sign still return only their result.
    & $exe @arguments | Out-Host
    if ($LASTEXITCODE -ne 0) { throw "$([IO.Path]::GetFileName($exe)) failed with exit code $LASTEXITCODE" }
}

$signtool = Find-Tool "signtool.exe" @("${env:ProgramFiles(x86)}\Windows Kits\10\bin", "$env:ProgramFiles\Windows Kits\10\bin")
if (-not $signtool) { throw "signtool.exe not found: install the Windows SDK (Signing Tools for Desktop Apps)" }

# The certificate: the one given, or the only code signing certificate with a private key in the user's store.
if ($Thumbprint) {
    $Thumbprint = ($Thumbprint -replace "\s", "").ToUpperInvariant()
    $cert = Get-ChildItem Cert:\CurrentUser\My | Where-Object { $_.Thumbprint -eq $Thumbprint }
    if (-not $cert) { throw "No certificate $Thumbprint in Cert:\CurrentUser\My (is the YubiKey inserted?)" }
} else {
    $certs = @(Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object { $_.HasPrivateKey -and $_.NotAfter -gt (Get-Date) })
    if ($certs.Count -ne 1) {
        $certs | ForEach-Object { Write-Host ("  {0}  {1}  until {2:yyyy-MM-dd}" -f $_.Thumbprint, $_.Subject, $_.NotAfter) }
        throw "Found $($certs.Count) usable code signing certificates: pass -Thumbprint"
    }
    $cert = $certs[0]
}
Write-Host "Signing with $($cert.Subject) ($($cert.Thumbprint)), valid until $($cert.NotAfter.ToString('yyyy-MM-dd'))"

function Sign-File([string]$path) {
    Invoke-Checked $signtool @("sign", "/sha1", $cert.Thumbprint, "/fd", "SHA256", "/tr", $TimestampUrl, "/td", "SHA256",
        "/d", $Description, $path)
}

# The project's native libraries inside a jar: extract, sign, put back with a new .sha256 (lowercase hex and a
# newline, as native/build.sh writes it). Returns how many were signed.
Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem
function Sign-JarLibraries([string]$jar) {
    $temp = Join-Path $WorkDir ("jar-" + [Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $temp | Out-Null
    $zip = [IO.Compression.ZipFile]::Open($jar, [IO.Compression.ZipArchiveMode]::Update)
    $count = 0
    try {
        $entries = @($zip.Entries | Where-Object { $_.FullName -match "^zk/native/windows-[^/]+/[^/]+\.dll$" })
        foreach ($entry in $entries) {
            $name = $entry.FullName
            $file = Join-Path $temp ([IO.Path]::GetFileName($name))
            [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $file, $true)
            if ((Get-AuthenticodeSignature $file).Status -ne "Valid") { Sign-File $file }
            $hash = (Get-FileHash $file -Algorithm SHA256).Hash.ToLowerInvariant()
            $entry.Delete()
            [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $file, $name, [IO.Compression.CompressionLevel]::Optimal) | Out-Null
            $old = $zip.GetEntry("$name.sha256")
            if ($old) { $old.Delete() }
            $writer = New-Object IO.StreamWriter(($zip.CreateEntry("$name.sha256")).Open(), (New-Object Text.UTF8Encoding $false))
            try { $writer.Write("$hash`n") } finally { $writer.Dispose() }
            Write-Host "  $([IO.Path]::GetFileName($jar)): $name"
            $count++
        }
    } finally {
        $zip.Dispose()
        Remove-Item $temp -Recurse -Force
    }
    return $count
}

if (Test-Path $WorkDir) { Remove-Item $WorkDir -Recurse -Force }
New-Item -ItemType Directory -Path $WorkDir | Out-Null

$output = Join-Path $WorkDir "signed"
New-Item -ItemType Directory -Path $output | Out-Null
if ($Tag -eq "nightly") { Write-Warning "nightly is replaced by every push to main; the signed files last until then" }

if ($Mode -eq "Native") {
    if (-not $Path) { throw "Native needs -Path: the desktop-native-windows artifact of a CI run (.zip or its folder)" }
    $Path = (Resolve-Path $Path).Path
    $folder = Join-Path $WorkDir "native"
    if (Test-Path $Path -PathType Leaf) {
        [IO.Compression.ZipFile]::ExtractToDirectory($Path, $folder)
    } else {
        Copy-Item $Path $folder -Recurse
    }
    $exe = Get-ChildItem $folder -Recurse -Filter "diw-desktop.exe" | Select-Object -First 1
    if (-not $exe) { throw "diw-desktop.exe not found in $Path" }
    $root = $exe.Directory.FullName
    $binaries = @(Get-ChildItem $root -Recurse -Include "*.exe", "*.dll" | Where-Object { (Get-AuthenticodeSignature $_.FullName).Status -ne "Valid" })
    Write-Host "Signing $($binaries.Count) files of the native executable folder"
    foreach ($b in $binaries) { Sign-File $b.FullName }
    foreach ($b in $binaries) { Invoke-Checked $signtool @("verify", "/pa", $b.FullName) }
    $zipName = if ($Tag -match "^v(\d+\.\d+\.\d+)$") { "$PackageName-$($Matches[1])-windows-x64-native.zip" } else { "$PackageName-windows-x64-native.zip" }
    $signed = Join-Path $output $zipName
    [IO.Compression.ZipFile]::CreateFromDirectory($root, $signed, [IO.Compression.CompressionLevel]::Optimal, $false)
    $uploads = @($signed)
    $what = "Windows 原生版（實驗，$zipName）的執行檔與其旁的程式庫"
} else {
    # The installer: a local file, or the one .msi of the release.
    if ($Msi) {
        $Msi = (Resolve-Path $Msi).Path
    } else {
        if (-not $Tag) { throw "Pass -Tag (a release such as v0.5.3) or -Msi (a local file)" }
        Invoke-Checked "gh" @("release", "download", $Tag, "--repo", $Repo, "--pattern", "*.msi", "--dir", (Join-Path $WorkDir "download"))
        $found = @(Get-ChildItem (Join-Path $WorkDir "download") -Filter "*.msi")
        if ($found.Count -ne 1) { throw "Release $Tag has $($found.Count) .msi files, expected one" }
        $Msi = $found[0].FullName
    }
    $msiName = [IO.Path]::GetFileName($Msi)
    if ($msiName -notmatch "^$PackageName-(\d+\.\d+\.\d+)\.msi$") { throw "Unexpected installer name $msiName (expected $PackageName-<version>.msi)" }
    $version = $Matches[1]
    $existing = Get-AuthenticodeSignature $Msi
    if ($existing.Status -eq "Valid") { Write-Warning "$msiName is already signed by $($existing.SignerCertificate.Subject); signing again replaces it" }
    $signed = Join-Path $output $msiName

    if ($Mode -eq "MsiOnly") {
        Copy-Item $Msi $signed
    } else {
        $jpackage = Find-Tool "jpackage.exe" @("$env:JAVA_HOME\bin")
        if (-not $jpackage) { throw "jpackage.exe not found: install JDK 21 or later and set JAVA_HOME" }
        if (-not ((Get-Command candle.exe -ErrorAction SilentlyContinue) -or (Get-Command wix.exe -ErrorAction SilentlyContinue))) {
            throw "WiX Toolset not found on PATH: install WiX 3.14 (candle.exe, light.exe) for JDK 21 and 22, or WiX 4 / 5 for JDK 23+"
        }

        # Administrative install: the files of the MSI without installing it.
        $extracted = Join-Path $WorkDir "extracted"
        $log = Join-Path $WorkDir "msiexec.log"
        $p = Start-Process msiexec.exe -ArgumentList @("/a", "`"$Msi`"", "/qn", "TARGETDIR=`"$extracted`"", "/l*v", "`"$log`"") -Wait -PassThru
        if ($p.ExitCode -ne 0) { throw "msiexec /a failed with exit code $($p.ExitCode), see $log" }
        $launcher = Get-ChildItem $extracted -Recurse -Filter "$PackageName.exe" | Select-Object -First 1
        if (-not $launcher) { throw "$PackageName.exe not found in the unpacked installer" }
        $image = $launcher.Directory.FullName
        foreach ($dir in @("app", "runtime")) {
            if (-not (Test-Path (Join-Path $image $dir))) { throw "The unpacked installer has no $dir folder next to $PackageName.exe" }
        }

        $libraries = 0
        foreach ($jar in Get-ChildItem (Join-Path $image "app") -Filter "*.jar") { $libraries += Sign-JarLibraries $jar.FullName }
        if ($libraries -eq 0) { Write-Warning "No zk/native/windows-*/ library found in the app's jars: the zero-knowledge library stays unsigned" }

        # Every .exe and .dll that has no valid signature yet; the Java runtime's own files are already signed.
        $binaries = @(Get-ChildItem $image -Recurse -Include "*.exe", "*.dll" | Where-Object { (Get-AuthenticodeSignature $_.FullName).Status -ne "Valid" })
        Write-Host "Signing $($binaries.Count) files of the app image"
        foreach ($b in $binaries) { Sign-File $b.FullName }

        $arguments = @("--type", "msi", "--app-image", $image, "--dest", $output, "--name", $PackageName,
            "--app-version", $version, "--vendor", $Vendor, "--description", $Description,
            "--win-menu", "--win-menu-group", $MenuGroup, "--win-shortcut", "--win-per-user-install", "--win-upgrade-uuid", $UpgradeUuid)
        $icon = Join-Path $PSScriptRoot "..\app\icons\app-icon.ico"
        if (Test-Path $icon) { $arguments += @("--icon", (Resolve-Path $icon).Path) }
        Invoke-Checked $jpackage $arguments
        if (-not (Test-Path $signed)) {
            $built = Get-ChildItem $output -Filter "*.msi" | Select-Object -First 1
            if (-not $built) { throw "jpackage produced no .msi" }
            Move-Item $built.FullName $signed
        }
    }

    Sign-File $signed
    Invoke-Checked $signtool @("verify", "/pa", $signed)
    $uploads = @($signed)

    # The Windows release jar carries the same native libraries.
    if ($Mode -eq "Full" -and $Tag) {
        $jarDir = Join-Path $WorkDir "jar"
        Invoke-Checked "gh" @("release", "download", $Tag, "--repo", $Repo, "--pattern", "$PackageName-windows-*-release.jar", "--dir", $jarDir)
        foreach ($jar in Get-ChildItem $jarDir -Filter "*.jar") {
            if ((Sign-JarLibraries $jar.FullName) -gt 0) { $uploads += $jar.FullName }
        }
    }
    $what = if ($Mode -eq "Full") { "Windows 安裝檔、其中的程式與零知識原生程式庫，以及 Windows 版 jar 內的原生程式庫" } else { "Windows 安裝檔" }
}
$hash = (Get-FileHash $signed -Algorithm SHA256).Hash.ToLowerInvariant()
Write-Host "Signed: $signed"
Write-Host "SHA-256: $hash"

if ($NoUpload -or -not $Tag) {
    Write-Host "Not uploaded (-NoUpload or no -Tag). Upload with: gh release upload <tag> `"$signed`" --clobber --repo $Repo"
    exit 0
}
Invoke-Checked "gh" (@("release", "upload", $Tag) + $uploads + @("--clobber", "--repo", $Repo))
Write-Host "Replaced in release ${Tag}: $(($uploads | ForEach-Object { [IO.Path]::GetFileName($_) }) -join ', ')"

# One line in the release body under the download guide (tools/release-notes.py writes the marker line).
if (-not $NoNotes) {
    $bodyFile = Join-Path $WorkDir "notes.md"
    $body = (& gh release view $Tag --repo $Repo --json body --jq .body | Out-String)
    if ($LASTEXITCODE -ne 0) { throw "gh release view failed" }
    $subject = $cert.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)
    $line = "$what 已以 $subject 的程式碼簽章憑證簽署（Authenticode）。"

    # The guide ends with the marker sentence; a line from an earlier run of the same mode is replaced.
    $marker = "每個檔案的 SHA-256 列在本頁最下方的檔案清單。"
    $lines = @($body.TrimEnd() -split "`r?`n" | Where-Object { -not $_.StartsWith("$what 已以 ") })
    $at = -1
    for ($i = 0; $i -lt $lines.Count; $i++) { if ($lines[$i].EndsWith($marker)) { $at = $i; break } }
    if ($at -ge 0) {
        $rest = if ($at + 1 -lt $lines.Count) { $lines[($at + 1)..($lines.Count - 1)] } else { @() }
        $lines = $lines[0..$at] + @("", $line) + $rest
    } else {
        $lines = @($line, "") + $lines
    }
    [IO.File]::WriteAllText($bodyFile, ($lines -join "`n"), (New-Object Text.UTF8Encoding $false))
    Invoke-Checked "gh" @("release", "edit", $Tag, "--repo", $Repo, "--notes-file", $bodyFile)
    Write-Host "Release notes updated"
}
