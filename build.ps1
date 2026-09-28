<#
  Builds the plugin and stages the deployable files.
  Run from the folder containing HashiCorpVaultLockbox.SecureStore.csproj.

    .\build.ps1                      # build only
    .\build.ps1 -RunHarness          # build, then run the offline logic checks
    .\build.ps1 -Deploy              # build, then copy into the proxy plugins folder (needs admin)
#>
param(
    [switch]$RunHarness,
    [switch]$Deploy,
    [string]$ProxyPath = "C:\Program Files\UiPath\OrchestratorCredentialsProxy"
)

$ErrorActionPreference = "Stop"

# A stale obj\ from an earlier build is the usual cause of CS0579 duplicate-attribute errors.
Remove-Item -Recurse -Force -ErrorAction SilentlyContinue `
    (Join-Path $PSScriptRoot "obj"), (Join-Path $PSScriptRoot "bin"), `
    (Join-Path $PSScriptRoot "tools\Harness\obj"), (Join-Path $PSScriptRoot "tools\Harness\bin")

Write-Host "== restore ==" -ForegroundColor Cyan
dotnet restore
if ($LASTEXITCODE -ne 0) { throw "restore failed - check access to nuget.org or your internal feed" }

Write-Host "== build ==" -ForegroundColor Cyan
dotnet build -c Release --nologo
if ($LASTEXITCODE -ne 0) { throw "build failed" }

$dll = Join-Path $PSScriptRoot "bin\Release\UiPath.Orchestrator.Extensions.SecureStores.HashiCorpVaultLockbox.dll"
if (-not (Test-Path $dll)) { throw "expected output not found: $dll" }

Write-Host "`nBuilt: $dll" -ForegroundColor Green
Get-Item $dll | Select-Object Name, Length, LastWriteTime | Format-List

if ($RunHarness) {
    Write-Host "== harness ==" -ForegroundColor Cyan
    dotnet run -c Release --project (Join-Path $PSScriptRoot "tools\Harness\Harness.csproj")
}

if ($Deploy) {
    $target = Join-Path $ProxyPath "plugins"
    if (-not (Test-Path $target)) { throw "plugins folder not found: $target" }
    Copy-Item $dll $target -Force
    Write-Host "Copied DLL to $target" -ForegroundColor Green

    # Deliberately copied under its .merge.json name so it can never clobber the live config.
    foreach ($f in @("appsettings.Production.merge.json", "DEPLOY.txt")) {
        $src = Join-Path $PSScriptRoot "bin\Release\$f"
        if (Test-Path $src) {
            Copy-Item $src $ProxyPath -Force
            Write-Host "Copied $f to $ProxyPath" -ForegroundColor Green
        }
    }

    Write-Host ""
    Write-Host "NOT done automatically, on purpose:" -ForegroundColor Yellow
    Write-Host "  1. Merge the keys from appsettings.Production.merge.json into the live" -ForegroundColor Yellow
    Write-Host "     appsettings.Production.json (append to Plugins.SecureStores; do not replace)." -ForegroundColor Yellow
    Write-Host "  2. Grant the app pool identity read access to the cert private key." -ForegroundColor Yellow
    Write-Host "  3. Restart the OrchestratorCredentialsProxy site in IIS." -ForegroundColor Yellow
    Write-Host "See DEPLOY.txt for the full sequence and rollback." -ForegroundColor Yellow
}
