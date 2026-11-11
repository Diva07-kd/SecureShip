<#
.SYNOPSIS
  SecureScan 1-Click Launch & Quick Tunnel Script (Option A)
.DESCRIPTION
  Launches the SecureScan multi-scanner platform via Docker Compose
  and automatically extracts and displays the public Cloudflare Quick Tunnel URL.
#>

$ErrorActionPreference = "Stop"

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "  SecureScan 1-Click Launch (Option A - Cloudflare Tunnel)" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host ""

# Verify Docker is running
try {
    docker info > $null 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "Docker is not running"
    }
} catch {
    Write-Host "[ERROR] Docker is not running. Please start Docker Desktop first." -ForegroundColor Red
    exit 1
}

Write-Host "[1/3] Building and starting SecureScan containers with Cloudflare Quick Tunnel..." -ForegroundColor Yellow
docker compose --profile tunnel up --build -d

Write-Host "[2/3] Waiting for Cloudflare Tunnel to establish public HTTPS route..." -ForegroundColor Yellow
$timeoutSeconds = 30
$elapsed = 0
$tunnelUrl = ""

while ($elapsed -lt $timeoutSeconds) {
    Start-Sleep -Seconds 2
    $elapsed += 2
    $logs = docker compose logs tunnel 2>&1 | Out-String
    if ($logs -match 'https://[a-zA-Z0-9-]+\.trycloudflare\.com') {
        $tunnelUrl = $matches[0]
        break
    }
    Write-Host "  Waiting for tunnel route... ($elapsed/$timeoutSeconds s)" -ForegroundColor Gray
}

Write-Host ""
Write-Host "[3/3] SecureScan Platform is LIVE!" -ForegroundColor Green
Write-Host "----------------------------------------------------------" -ForegroundColor Gray
if ($tunnelUrl) {
    Write-Host "  Public HTTPS Tunnel URL : $tunnelUrl" -ForegroundColor Green
} else {
    Write-Host "  Public Tunnel           : Check with 'docker compose logs tunnel'" -ForegroundColor Yellow
}
Write-Host "  Local Frontend Dashboard: http://localhost:3000" -ForegroundColor Cyan
Write-Host "  Local Backend REST API  : http://localhost:8000/api/health" -ForegroundColor Cyan
Write-Host "  Interactive Swagger Docs: http://localhost:8000/docs" -ForegroundColor Cyan
Write-Host "----------------------------------------------------------" -ForegroundColor Gray
Write-Host ""
Write-Host "Tip: Use 'tests/fixtures/valid_vulnerable.zip' for testing the dashboard." -ForegroundColor Magenta
Write-Host "To stop the stack: docker compose --profile tunnel down" -ForegroundColor Gray
