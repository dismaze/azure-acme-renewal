#Requires -Version 5.1
<#
.SYNOPSIS
    Deploys the Azure Function code after terraform apply.
    Reads all values from Terraform outputs automatically.
.USAGE
    .\deploy_function.ps1
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Read values from Terraform outputs ────────────────────────────────────────
Write-Host "=== Reading Terraform outputs ===" -ForegroundColor Cyan
$FuncName = terraform output -raw function_app_name
$RgName   = terraform output -raw resource_group_name

Write-Host "Function App : $FuncName"
Write-Host "Resource Group: $RgName"

# ── Zip function code ──────────────────────────────────────────────────────────
Write-Host "`n=== Zipping function code ===" -ForegroundColor Cyan
$ZipPath = Join-Path $PSScriptRoot "deploy.zip"

if (Test-Path $ZipPath) { Remove-Item $ZipPath -Force }

Compress-Archive -Path (Join-Path $PSScriptRoot "function_code\*") `
                 -DestinationPath $ZipPath `
                 -Force

Write-Host "Created: $ZipPath"

# ── Deploy to Azure ────────────────────────────────────────────────────────────
Write-Host "`n=== Deploying to Azure ===" -ForegroundColor Cyan
az functionapp deployment source config-zip `
    --src $ZipPath `
    --name $FuncName `
    --resource-group $RgName `
    --build-remote true

if ($LASTEXITCODE -ne 0) {
    Write-Error "Deployment failed with exit code $LASTEXITCODE"
    exit $LASTEXITCODE
}

Write-Host "`n=== Done! Function code deployed successfully. ===" -ForegroundColor Green