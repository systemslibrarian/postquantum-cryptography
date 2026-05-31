# Runs the packaged-consumption smoke test end-to-end:
#   1. Packs the library to ./artifacts/packages.
#   2. Restores the smoke project against that local feed (NuGet.config in this dir).
#   3. Runs the smoke checks against the packaged DLL.
#
# Usage:
#   pwsh tests/PostQuantum.Cryptography.SmokeTest/run-smoke-test.ps1
#   pwsh tests/PostQuantum.Cryptography.SmokeTest/run-smoke-test.ps1 -Version 0.1.0-preview.1

[CmdletBinding()]
param(
    [string]$Version = "0.2.0-preview.1",
    [string]$Configuration = "Release"
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "../..")).Path
$smokeDir = $PSScriptRoot

Push-Location $repoRoot
try {
    Write-Host "[1/4] Packing PostQuantum.Cryptography $Version..." -ForegroundColor Cyan
    Remove-Item -Recurse -Force ./artifacts/packages -ErrorAction SilentlyContinue
    dotnet pack src/PostQuantum.Cryptography/PostQuantum.Cryptography.csproj `
        -c $Configuration `
        -p:Version=$Version `
        -o ./artifacts/packages
    if ($LASTEXITCODE -ne 0) { throw "dotnet pack failed." }

    Write-Host "[2/4] Cleaning smoke test caches..." -ForegroundColor Cyan
    Remove-Item -Recurse -Force (Join-Path $smokeDir "bin"), (Join-Path $smokeDir "obj") -ErrorAction SilentlyContinue

    Write-Host "[3/4] Restoring smoke test against local feed..." -ForegroundColor Cyan
    dotnet restore $smokeDir/PostQuantum.Cryptography.SmokeTest.csproj `
        -p:SmokeTestPackageVersion=$Version `
        --configfile $smokeDir/NuGet.config
    if ($LASTEXITCODE -ne 0) { throw "dotnet restore failed." }

    Write-Host "[4/4] Running smoke test..." -ForegroundColor Cyan
    dotnet run --project $smokeDir/PostQuantum.Cryptography.SmokeTest.csproj `
        -c $Configuration `
        --no-restore `
        -p:SmokeTestPackageVersion=$Version
    if ($LASTEXITCODE -ne 0) { throw "Smoke test reported failures." }

    Write-Host ""
    Write-Host "Smoke test passed for PostQuantum.Cryptography $Version" -ForegroundColor Green
}
finally {
    Pop-Location
}
