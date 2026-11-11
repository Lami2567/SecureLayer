#!/usr/bin/env pwsh
<#
.SYNOPSIS
    SecureLayer Local Docker Demonstration Runner
.DESCRIPTION
    Validates the local Docker Compose demonstration environment and invokes all
    security objective verifications against the running microservices.
#>

param(
    [string]$GatewayUrl = "http://localhost:8080",
    [string]$BankingUrl = "http://localhost:3001",
    [string]$PythonUrl  = "http://localhost:3002",
    [string]$DashboardUrl = "http://localhost:3000",
    [string]$CoreUrl    = "http://localhost:8090"
)

$ErrorActionPreference = "Stop"

Write-Host "`n===============================================================================" -ForegroundColor Cyan
Write-Host "       SECURELAYER LOCAL DOCKER DEMONSTRATION VERIFIER" -ForegroundColor Cyan
Write-Host "===============================================================================`n" -ForegroundColor Cyan

# 1. Check health of services
$services = @(
    @{ Name = "Demo Banking API"; Url = "$BankingUrl/health" },
    @{ Name = "Demo Python App";  Url = "$PythonUrl/health" },
    @{ Name = "Security Gateway"; Url = "$GatewayUrl/actuator/health" }
)

Write-Host "[1/4] Probing Service Health Endpoints..." -ForegroundColor Yellow
foreach ($svc in $services) {
    try {
        $resp = Invoke-RestMethod -Uri $svc.Url -Method Get -TimeoutSec 3 -ErrorAction SilentlyContinue
        Write-Host "  ✓ $($svc.Name) is healthy ($($svc.Url))" -ForegroundColor Green
    } catch {
        Write-Host "  ⚠ $($svc.Name) not reachable at $($svc.Url) (Container may still be building or starting)" -ForegroundColor DarkYellow
    }
}

# 2. Run Banking Scenario
Write-Host "`n[2/4] Triggering Protected Banking Scenario..." -ForegroundColor Yellow
try {
    $scenario = Invoke-RestMethod -Uri "$BankingUrl/demo/scenario" -Method Post -TimeoutSec 5
    Write-Host "  ✓ Banking Scenario Completed: $($scenario.scenario)" -ForegroundColor Green
    foreach ($step in $scenario.steps) {
        $outcome = if ($step.result) { $step.result } else { $step.outcome }
        Write-Host "    - Step $($step.step): $($step.action) -> $outcome" -ForegroundColor Gray
    }
} catch {
    Write-Host "  ⚠ Could not trigger $BankingUrl/demo/scenario: $_" -ForegroundColor DarkYellow
}

# 3. Run Python Cryptographic Verification
Write-Host "`n[3/4] Triggering Cross-Language Python Verification..." -ForegroundColor Yellow
try {
    $pyCheck = Invoke-RestMethod -Uri "$PythonUrl/demo/run" -Method Post -TimeoutSec 5
    Write-Host "  ✓ Python SDK Suite: $($pyCheck.suite)" -ForegroundColor Green
    foreach ($chk in $pyCheck.checks) {
        Write-Host "    - $($chk.check): $($chk.status)" -ForegroundColor Gray
    }
} catch {
    Write-Host "  ⚠ Could not trigger $PythonUrl/demo/run: $_" -ForegroundColor DarkYellow
}

# 4. Summary & Links
Write-Host "`n[4/4] Environment Summary:" -ForegroundColor Yellow
Write-Host "  • Developer Dashboard: $DashboardUrl" -ForegroundColor White
Write-Host "  • Gateway Proxy:       $GatewayUrl" -ForegroundColor White
Write-Host "  • Security Core REST:  $CoreUrl" -ForegroundColor White
Write-Host "  • Banking Core:        $BankingUrl" -ForegroundColor White
Write-Host "  • Python Verifier:     $($PythonUrl)" -ForegroundColor White
Write-Host ""
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host "             DEMONSTRATION RUN COMPLETE" -ForegroundColor Cyan
Write-Host "===============================================================================" -ForegroundColor Cyan
Write-Host ""
