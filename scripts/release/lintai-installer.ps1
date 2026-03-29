$ErrorActionPreference = "Stop"

param(
    [string]$Target,
    [string]$InstallDir = (Join-Path $env:USERPROFILE ".local\bin"),
    [string]$BaseUrl = $env:LINTAI_INSTALL_BASE_URL
)

$ReleaseTag = if ($env:LINTAI_INSTALL_RELEASE_TAG) { $env:LINTAI_INSTALL_RELEASE_TAG } else { "__RELEASE_TAG__" }
$ReleaseRepository = if ($env:LINTAI_INSTALL_RELEASE_REPOSITORY) { $env:LINTAI_INSTALL_RELEASE_REPOSITORY } else { "__RELEASE_REPOSITORY__" }

function Fail([string]$Message) {
    throw $Message
}

function Resolve-Target {
    if (-not $IsWindows) {
        Fail "This installer is intended for Windows PowerShell hosts."
    }

    switch ($env:PROCESSOR_ARCHITECTURE) {
        "AMD64" { return "x86_64-pc-windows-msvc" }
        default { Fail "Unsupported Windows architecture: $($env:PROCESSOR_ARCHITECTURE)" }
    }
}

if ($ReleaseTag -like "*__RELEASE_TAG__*" -or [string]::IsNullOrWhiteSpace($ReleaseTag)) {
    Fail "This installer is a template. Download lintai-installer.ps1 from a published GitHub Release asset."
}

if ($ReleaseRepository -like "*__RELEASE_REPOSITORY__*" -or [string]::IsNullOrWhiteSpace($ReleaseRepository)) {
    Fail "This installer is a template. Download lintai-installer.ps1 from a published GitHub Release asset."
}

if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
    $BaseUrl = "https://github.com/$ReleaseRepository/releases/download/$ReleaseTag"
}

if ([string]::IsNullOrWhiteSpace($Target)) {
    $Target = Resolve-Target
}

if ($Target -ne "x86_64-pc-windows-msvc") {
    Fail "Unsupported target: $Target"
}

$AssetBaseName = "lintai-$ReleaseTag-$Target"
$ArchiveName = "$AssetBaseName.zip"
$TempDir = Join-Path ([System.IO.Path]::GetTempPath()) ("lintai-install-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $TempDir | Out-Null

try {
    $ArchivePath = Join-Path $TempDir $ArchiveName
    $ChecksumPath = Join-Path $TempDir "SHA256SUMS"

    Invoke-WebRequest -Uri "$BaseUrl/$ArchiveName" -OutFile $ArchivePath
    Invoke-WebRequest -Uri "$BaseUrl/SHA256SUMS" -OutFile $ChecksumPath

    $ExpectedLine = Get-Content $ChecksumPath | Where-Object { $_ -match ("  " + [regex]::Escape($ArchiveName) + "$") } | Select-Object -First 1
    if (-not $ExpectedLine) {
        Fail "Checksum for $ArchiveName not found in SHA256SUMS."
    }

    $ExpectedHash = ($ExpectedLine -split "\s+")[0].ToLowerInvariant()
    $ActualHash = (Get-FileHash -Path $ArchivePath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ExpectedHash -ne $ActualHash) {
        Fail "Checksum mismatch for $ArchiveName."
    }

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Expand-Archive -Path $ArchivePath -DestinationPath $TempDir -Force

    $InstalledBinary = Join-Path $InstallDir "lintai.exe"
    Copy-Item (Join-Path $TempDir $AssetBaseName "lintai.exe") $InstalledBinary -Force

    & $InstalledBinary help | Out-Null

    Write-Host "Installed lintai to $InstalledBinary"

    $ResolvedInstallDir = [System.IO.Path]::GetFullPath($InstallDir)
    $PathEntries = ($env:Path -split ';') | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    $OnPath = $false
    foreach ($Entry in $PathEntries) {
        if ([System.IO.Path]::GetFullPath($Entry).TrimEnd('\') -ieq $ResolvedInstallDir.TrimEnd('\')) {
            $OnPath = $true
            break
        }
    }

    if ($OnPath) {
        Write-Host "lintai is already on PATH."
    }
    else {
        Write-Host "Add '$InstallDir' to PATH, then open a new shell."
        Write-Host "Example:"
        Write-Host "[Environment]::SetEnvironmentVariable('Path', `"$env:Path;$InstallDir`", 'User')"
    }

    Write-Host "Verify with: lintai help"
}
finally {
    if (Test-Path $TempDir) {
        Remove-Item -Path $TempDir -Recurse -Force
    }
}
