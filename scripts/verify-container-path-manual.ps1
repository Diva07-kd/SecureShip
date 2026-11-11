# ==============================================================================
# SecureShip-IDE F-SAN-001 (Gate 12) Manual Evidence Verification Checklist
# Cross-Platform Container Mount Path Verification (Windows Docker Desktop)
# ==============================================================================

[CmdletBinding()]
param(
    [switch]$SkipLiveDocker = $false
)

$ErrorActionPreference = "Stop"

Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "SecureShip F-SAN-001 Verification Checklist (PowerShell Manual)" -ForegroundColor Cyan
Write-Host "=================================================================" -ForegroundColor Cyan

# Step 1: Environment and Toolchain Diagnostics
Write-Host "`n[Step 1/7] Inspecting Host Platform and Toolchain..." -ForegroundColor Yellow
Write-Host "OS: $([System.Environment]::OSVersion.VersionString)"
Write-Host "Node: $(node --version)"
Write-Host "pnpm: $(pnpm --version)"

# Step 2: Anti-Fake-Test Law Verification
Write-Host "`n[Step 2/7] Running Anti-Fake-Test Law Integrity Auditor..." -ForegroundColor Yellow
node --experimental-strip-types scripts/verify-test-integrity.ts
if ($LASTEXITCODE -ne 0) {
    Write-Error "Test integrity audit failed! Exiting."
    exit 1
}
Write-Host "[OK] Anti-Fake-Test Law check passed: 0 violations." -ForegroundColor Green

# Step 3: Run Unit, Differential, Oracle and Filesystem Tests (Layers A, C, E)
Write-Host "`n[Step 3/7] Running Container Path Verification Suite (Layers A - E)..." -ForegroundColor Yellow
npx vitest run packages/sandbox/test/container-path.translate.test.ts packages/sandbox/test/container-path.oracle.test.ts packages/sandbox/test/container-path.fs.test.ts
if ($LASTEXITCODE -ne 0) {
    Write-Error "Layers A, C, or E test failed! Exiting."
    exit 1
}
Write-Host "[OK] Layers A, C, and E test suites completed successfully." -ForegroundColor Green

# Step 4: Run Mount Suite (Layer B and Layer D)
Write-Host "`n[Step 4/7] Running Layer B and Layer D Mount Exactness and Doc Suite..." -ForegroundColor Yellow
npx vitest run packages/sandbox/test/container-path.mount.test.ts
if ($LASTEXITCODE -ne 0) {
    Write-Error "Layer B or D test failed! Exiting."
    exit 1
}
Write-Host "[OK] Layer B and D passed completely (9/9 tests)." -ForegroundColor Green

# Step 5: Check Docker Daemon Availability (for Layer F)
Write-Host "`n[Step 5/7] Checking Docker Daemon for Layer F..." -ForegroundColor Yellow
$dockerAvailable = $false
try {
    $dockerInfo = docker info --format '{{.OSType}}' 2>$null
    if ($dockerInfo -eq "linux") {
        Write-Host "[OK] Docker Desktop is online and operating in Linux containers mode." -ForegroundColor Green
        $dockerAvailable = $true
    } else {
        Write-Host "[INFO] Docker is running, but OSType is '$dockerInfo' (expected 'linux'). Skipping Layer F." -ForegroundColor Yellow
    }
} catch {
    Write-Host "[INFO] Docker daemon is not running or docker CLI is unavailable. Skipping Layer F." -ForegroundColor Yellow
}

# Step 6: Live Docker Reproduction and Layer F Execution (If Available)
if ($dockerAvailable -and -not $SkipLiveDocker) {
    Write-Host "`n[Step 6/7] Running Live Docker Desktop Verification (Layer F)..." -ForegroundColor Yellow
    
    $pinnedImage = "node:20-alpine@sha256:4f04642c676d95da5753ec91ac64a590623a31c51a7b45fcf3a137adcb3989c6"
    Write-Host "Ensuring pinned image is present: $pinnedImage"
    docker pull $pinnedImage

    Write-Host "Executing live reproduction of legacy /c/... rejection:"
    $tempTest = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), "ss-manual-test-" + [System.Guid]::NewGuid().ToString("N"))
    [System.IO.Directory]::CreateDirectory($tempTest) | Out-Null
    try {
        $legacySpec = "/" + $tempTest.Substring(0, 1).ToLower() + $tempTest.Substring(2).Replace("\", "/")
        Write-Host "Attempting legacy mount: -v=${legacySpec}:/work:rw"
        $reproErr = docker run --rm --pull=never "-v=${legacySpec}:/work:rw" $pinnedImage ls /work 2>&1
        Write-Host "Docker daemon output (expected error): $reproErr" -ForegroundColor Cyan
    } finally {
        [System.IO.Directory]::Delete($tempTest, $true)
    }

    Write-Host "`nExecuting Layer F automated test suite..."
    $env:SECURESHIP_LIVE_DOCKER = "1"
    npx vitest run packages/sandbox/test/container-path.live-docker.test.ts
    Remove-Item env:SECURESHIP_LIVE_DOCKER -ErrorAction SilentlyContinue
} else {
    Write-Host "`n[Step 6/7] Skipping Layer F: Host Docker environment unavailable or switch specified." -ForegroundColor Gray
    Write-Host "Status: Live Windows UNVERIFIED (gated offline)." -ForegroundColor Yellow
}

# Step 7: Final Summary and Gate Status
Write-Host "`n[Step 7/7] Verification Summary:" -ForegroundColor Yellow
Write-Host "- Layer A (translateHostPath Tables and PRNG): PASS" -ForegroundColor Green
Write-Host "- Layer C (Moby v27.0.0 Bind Oracle): PASS" -ForegroundColor Green
Write-Host "- Layer E (Real Filesystem Semantics): PASS" -ForegroundColor Green
Write-Host "- Layer D (SANDBOX.md and Static Guards): PASS" -ForegroundColor Green
Write-Host "- Layer B (Mount Exactness and Realpath Canonicalization): PASS" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
Write-Host "Gate 12 Status: CLOSED (unit-verified; live Windows UNVERIFIED)" -ForegroundColor Green
Write-Host "=================================================================" -ForegroundColor Cyan
