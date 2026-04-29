#Requires -Version 7.0
<#
.SYNOPSIS
    Installs SilkETW environment dependencies and starts a local Elastic stack.

.DESCRIPTION
    1.  Verifies the script is running as Administrator (re-launches elevated if not).
    2.  Installs winget (App Installer) when it is not found in PATH.
    3.  Installs jq and Docker Desktop via winget (skipped when already present).
    4.  Registers deviantony/docker-elk as a git submodule at ./docker-elk.
    5.  Waits for the Docker daemon to become available.
    6.  Runs 'docker compose up setup' to initialise Elasticsearch users.
    7.  Starts the full ELK stack in detached mode.
    8.  Polls http://localhost:9200 and reports Elasticsearch status.

.PARAMETER SubmodulePath
    Repository-relative path where the docker-elk submodule is placed.
    Defaults to 'docker-elk'.

.PARAMETER ElasticUrl
    Elasticsearch base URL used for the readiness check.
    Defaults to 'http://localhost:9200'.

.PARAMETER SkipInstall
    Skip winget package installation (jq + Docker Desktop).
    Use when both are already installed.

.PARAMETER SkipElkStart
    Skip ELK stack startup; only install dependencies and register the submodule.

.EXAMPLE
    # Full setup from scratch
    ./Setup-Environment.ps1

    # Dependencies already installed, just start ELK
    ./Setup-Environment.ps1 -SkipInstall

    # Install dependencies only, do not start containers
    ./Setup-Environment.ps1 -SkipElkStart

.NOTES
    Requires Windows 10 1903+ or Windows 11.
    Docker Desktop may require a sign-out/reboot on first install (WSL 2 integration).
    Elasticsearch default credentials: elastic / changeme — change them before any real use.
#>
[CmdletBinding()]
param(
    [string]$SubmodulePath = 'docker-elk',
    [string]$ElasticUrl    = 'http://localhost:9200',
    [switch]$SkipInstall,
    [switch]$SkipElkStart
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ─── Helpers ────────────────────────────────────────────────────────────────

function Write-Step([string]$Message) {
    Write-Host "`n==> $Message" -ForegroundColor Cyan
}

function Write-Ok([string]$Message) {
    Write-Host "    [OK]  $Message" -ForegroundColor Green
}

function Write-Warn([string]$Message) {
    Write-Host "    [!!]  $Message" -ForegroundColor Yellow
}

function Test-Admin {
    $id        = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$id
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Merges machine + user PATH registry values into the current session.
function Update-SessionPath {
    $machine = [System.Environment]::GetEnvironmentVariable('PATH', 'Machine') ?? ''
    $user    = [System.Environment]::GetEnvironmentVariable('PATH', 'User')    ?? ''
    $env:PATH = ($machine + ';' + $user) -replace ';;+', ';'
}

# ─── 1. Elevation ───────────────────────────────────────────────────────────

Write-Step 'Checking for Administrator privileges'
if (-not (Test-Admin)) {
    Write-Warn 'Not running as Administrator — re-launching elevated...'
    $passThrough = @()
    if ($SkipInstall)  { $passThrough += '-SkipInstall'  }
    if ($SkipElkStart) { $passThrough += '-SkipElkStart' }
    $argList = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $($passThrough -join ' ')"
    Start-Process pwsh -Verb RunAs -ArgumentList $argList
    exit 0
}
Write-Ok 'Running as Administrator'

# ─── 2. winget ──────────────────────────────────────────────────────────────

Write-Step 'Checking winget (Windows Package Manager)'
if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
    Write-Warn 'winget not found — attempting installation...'

    # Attempt 1: register the existing App Installer package by family name
    try {
        Add-AppxPackage -RegisterByFamilyName -MainPackage Microsoft.DesktopAppInstaller_8wekyb3d8bbwe
        Update-SessionPath
    }
    catch {
        Write-Warn "Family-name registration failed: $_"
    }

    # Attempt 2: download from Microsoft's official redirect URL
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        $vcLibsPath     = Join-Path $env:TEMP 'Microsoft.VCLibs.x64.14.00.Desktop.appx'
        $msixBundlePath = Join-Path $env:TEMP 'Microsoft.DesktopAppInstaller.msixbundle'
        Write-Host '    Downloading VCLibs...' -ForegroundColor Gray
        Invoke-WebRequest 'https://aka.ms/Microsoft.VCLibs.x64.14.00.Desktop.appx' `
            -OutFile $vcLibsPath -UseBasicParsing -NoProxy
        Write-Host '    Downloading App Installer...' -ForegroundColor Gray
        Invoke-WebRequest 'https://aka.ms/getwinget' `
            -OutFile $msixBundlePath -UseBasicParsing -NoProxy
        Add-AppxPackage $vcLibsPath  -ErrorAction SilentlyContinue
        Add-AppxPackage $msixBundlePath
        Update-SessionPath
    }

    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw 'winget installation failed. Install App Installer manually from the Microsoft Store and re-run.'
    }
}
Write-Ok "winget $(winget --version)"

# ─── 3. jq and Docker Desktop ───────────────────────────────────────────────

if (-not $SkipInstall) {
    $packages = @(
        [pscustomobject]@{ Id = 'jqlang.jq';           Name = 'jq'             },
        [pscustomobject]@{ Id = 'Docker.DockerDesktop'; Name = 'Docker Desktop' }
    )

    foreach ($pkg in $packages) {
        Write-Step "Installing $($pkg.Name)"

        winget install `
            --id                        $pkg.Id `
            --accept-source-agreements `
            --accept-package-agreements `
            --silent `
            2>&1 | ForEach-Object { Write-Verbose $_ }

        # winget exit codes:
        #   0            – installed successfully
        #   0x8A150021   – no applicable update (already at same/newer version)
        #   other        – warn but continue; the binary may still be present
        switch ($LASTEXITCODE) {
            0           { Write-Ok "$($pkg.Name) installed" }
            -1978335199 { Write-Ok "$($pkg.Name) is already installed (no update available)" }
            default     { Write-Warn "$($pkg.Name): winget exited with code $LASTEXITCODE — continuing" }
        }
    }

    Update-SessionPath
}

# Confirm jq is accessible
if (Get-Command jq -ErrorAction SilentlyContinue) {
    Write-Ok "jq $(jq --version)"
}
else {
    Write-Warn 'jq not found in PATH after installation. You may need to open a new terminal.'
}

# ─── 4. docker-elk git submodule ────────────────────────────────────────────

Write-Step "Registering docker-elk submodule at '$SubmodulePath'"
$repoRoot   = $PSScriptRoot
$gitModules = Join-Path $repoRoot '.gitmodules'

Push-Location $repoRoot
try {
    $alreadyRegistered = (Test-Path $gitModules) -and
        (Select-String -Path $gitModules -Pattern 'docker-elk' -Quiet)

    if ($alreadyRegistered) {
        Write-Ok 'Submodule already registered — updating...'
        git submodule update --init --recursive -- $SubmodulePath
    }
    else {
        git submodule add https://github.com/deviantony/docker-elk.git $SubmodulePath
        git submodule update --init --recursive -- $SubmodulePath
    }
    Write-Ok "docker-elk submodule ready at '$SubmodulePath'"
}
finally {
    Pop-Location
}

# ─── 5. Docker daemon readiness ─────────────────────────────────────────────

if (-not $SkipElkStart) {
    Write-Step 'Waiting for Docker daemon'

    Update-SessionPath

    if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
        Write-Warn @'
docker CLI not found in PATH.
Docker Desktop was likely just installed and requires a new terminal (or a reboot on some systems).
After reopening a terminal, re-run:  ./Setup-Environment.ps1 -SkipInstall
'@
        exit 1
    }

    $dockerReady = $false
    $desktopExe  = "${env:ProgramFiles}\Docker\Docker\Docker Desktop.exe"
    $launchSent  = $false

    for ($i = 0; $i -lt 60; $i++) {
        $null = docker info 2>&1
        if ($LASTEXITCODE -eq 0) { $dockerReady = $true; break }

        if (-not $launchSent -and (Test-Path $desktopExe)) {
            Write-Host '    Launching Docker Desktop...' -ForegroundColor Gray
            Start-Process $desktopExe
            $launchSent = $true
        }

        $elapsed = ($i + 1) * 5
        Write-Host "    Waiting for Docker daemon... ${elapsed}s elapsed" -ForegroundColor Gray
        Start-Sleep -Seconds 5
    }

    if (-not $dockerReady) {
        throw 'Docker daemon did not become available within 5 minutes. Start Docker Desktop manually and re-run.'
    }
    Write-Ok 'Docker daemon is ready'

    # ─── 6. ELK setup + start ─────────────────────────────────────────────

    $elkDir = Join-Path $repoRoot $SubmodulePath
    if (-not (Test-Path (Join-Path $elkDir 'docker-compose.yml'))) {
        throw "docker-compose.yml not found in '$elkDir'. Submodule may not have been initialised correctly."
    }

    Push-Location $elkDir
    try {
        Write-Step 'Initialising Elasticsearch users (docker compose up setup)'
        docker compose up setup
        if ($LASTEXITCODE -ne 0) {
            throw "docker compose up setup failed with exit code $LASTEXITCODE"
        }
        Write-Ok 'Setup container finished'

        Write-Step 'Starting ELK stack in detached mode (docker compose up -d)'
        docker compose up -d
        if ($LASTEXITCODE -ne 0) {
            throw "docker compose up -d failed with exit code $LASTEXITCODE"
        }
        Write-Ok 'Containers started'
    }
    finally {
        Pop-Location
    }

    # ─── 7. Verify Elasticsearch ──────────────────────────────────────────

    Write-Step "Polling Elasticsearch at $ElasticUrl"
    $b64Creds = [Convert]::ToBase64String(
        [Text.Encoding]::ASCII.GetBytes('elastic:changeme')
    )
    $esReady = $false

    for ($i = 0; $i -lt 24; $i++) {
        try {
            $resp = Invoke-WebRequest `
                -Uri                  $ElasticUrl `
                -Headers              @{ Authorization = "Basic $b64Creds" } `
                -UseBasicParsing `
                -NoProxy `
                -TimeoutSec           5 `
                -SkipCertificateCheck

            if ($resp.StatusCode -eq 200) { $esReady = $true; break }
        }
        catch [Microsoft.PowerShell.Commands.HttpResponseException] {
            # 401 Unauthorized — Elasticsearch is up, credentials may have been changed
            if ($_.Exception.Response.StatusCode.value__ -eq 401) {
                $esReady = $true; break
            }
        }
        catch {
            # Connection refused / timeout — not ready yet
        }

        $elapsed = ($i + 1) * 5
        Write-Host "    Waiting for Elasticsearch... ${elapsed}s elapsed" -ForegroundColor Gray
        Start-Sleep -Seconds 5
    }

    if ($esReady) {
        Write-Ok "Elasticsearch is responding at $ElasticUrl"
        Write-Host ''
        Write-Host '  ┌────────────────────────────────────────────────┐' -ForegroundColor White
        Write-Host '  │  Kibana        : http://localhost:5601          │' -ForegroundColor White
        Write-Host '  │  Elasticsearch : http://localhost:9200          │' -ForegroundColor White
        Write-Host '  │  Login         : elastic / changeme             │' -ForegroundColor White
        Write-Host '  │                                                  │' -ForegroundColor White
        Write-Host '  │  Change default passwords before real use!      │' -ForegroundColor Yellow
        Write-Host '  └────────────────────────────────────────────────┘' -ForegroundColor White
    }
    else {
        Write-Warn "Elasticsearch did not respond within 2 minutes."
        Write-Warn "Check container logs:  docker compose -f '$elkDir\docker-compose.yml' logs elasticsearch"
    }
}

Write-Host "`nSetup complete." -ForegroundColor Green
