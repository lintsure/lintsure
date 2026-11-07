# Publishes the three packages in dependency order. npm runs the full test suite first
# (prepublishOnly). If npm asks for a one-time password, type your 2FA code.
$ErrorActionPreference = "Stop"
$env:NODE_OPTIONS = "--use-system-ca"   # Avast intercepts TLS on this machine
Set-Location (Join-Path $PSScriptRoot "..")
foreach ($p in "core", "cli", "mcp") {
  Write-Host "`n=== Publishing packages/$p ===" -ForegroundColor Green
  Push-Location "packages/$p"
  npm publish --access public
  if ($LASTEXITCODE -ne 0) { Pop-Location; throw "npm publish failed for $p" }
  Pop-Location
}
Write-Host "`nAll three packages published." -ForegroundColor Green
