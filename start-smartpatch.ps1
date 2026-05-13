# SmartPatch Launcher - Starts backend API + HTML5UP frontend
# Run: powershell -ExecutionPolicy Bypass -File start-smartpatch.ps1

$ErrorActionPreference = "Stop"

# Configuration
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$apiPort = 8888
$frontendPort = 8000
$apiModule = "src.api.backend_api_fixed"
$frontendDir = Join-Path $scriptDir "html5up-spectral"

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "         SmartPatch - AI-Driven Security Mitigation             " -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

# Verify Python is available
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ Python found: $pythonVersion" -ForegroundColor Green
}
catch {
    Write-Host "✗ Python not found. Please install Python 3.9+" -ForegroundColor Red
    Write-Host "  Download from: https://www.python.org/downloads/" -ForegroundColor Yellow
    exit 1
}

# Verify required files
Write-Host ""
Write-Host "Checking dependencies..." -ForegroundColor Yellow

$requiredFiles = @(
    "src/api/backend_api_fixed.py",
    "html5up-spectral/index.html"
)

$missingFiles = @()
foreach ($file in $requiredFiles) {
    $fullPath = Join-Path $scriptDir $file
    if (Test-Path $fullPath) {
        Write-Host "  ✓ $file" -ForegroundColor Green
    }
    else {
        Write-Host "  ✗ $file (MISSING)" -ForegroundColor Red
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host ""
    Write-Host "✗ Missing required files:" -ForegroundColor Red
    $missingFiles | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
    exit 1
}

Write-Host "✓ All required files found" -ForegroundColor Green

# Check if ports are in use
Write-Host ""
Write-Host "Checking if ports are available..." -ForegroundColor Yellow

$apiPortInUse = netstat -ano 2>$null | findstr ":$apiPort"
$frontendPortInUse = netstat -ano 2>$null | findstr ":$frontendPort"

if ($apiPortInUse) {
    Write-Host "⚠ Port $apiPort is already in use" -ForegroundColor Yellow
    $response = Read-Host "Continue anyway? (y/n)"
    if ($response -ne 'y') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        exit 0
    }
}
else {
    Write-Host "✓ Port $apiPort is available" -ForegroundColor Green
}

if ($frontendPortInUse) {
    Write-Host "⚠ Port $frontendPort is already in use" -ForegroundColor Yellow
    $response = Read-Host "Continue anyway? (y/n)"
    if ($response -ne 'y') {
        Write-Host "Cancelled." -ForegroundColor Yellow
        exit 0
    }
}
else {
    Write-Host "✓ Port $frontendPort is available" -ForegroundColor Green
}

# Start backend API
Write-Host ""
Write-Host "Starting SmartPatch Backend API (port $apiPort)..." -ForegroundColor Cyan
Write-Host "  Command: python -m $apiModule" -ForegroundColor Gray

$pythonCmd = "cd '$scriptDir'; python -m $apiModule"
$apiProcess = Start-Process powershell -ArgumentList "-NoExit", "-Command", $pythonCmd -PassThru

if (-not $apiProcess) {
    Write-Host "✗ Failed to start backend API" -ForegroundColor Red
    exit 1
}

Write-Host "✓ Backend API started (PID: $($apiProcess.Id))" -ForegroundColor Green

# Wait for API to initialize
Write-Host ""
Write-Host "Waiting for API to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# Verify API is responding
Write-Host "Testing API connectivity..." -ForegroundColor Yellow
$maxAttempts = 10
$attempt = 0
$apiReady = $false

while ($attempt -lt $maxAttempts) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:$apiPort/api/health" -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            Write-Host "✓ API is responding" -ForegroundColor Green
            $apiReady = $true
            break
        }
    }
    catch {
        # API not ready yet
    }
    
    $attempt++
    if ($attempt -lt $maxAttempts) {
        Start-Sleep -Seconds 1
    }
}

if (-not $apiReady) {
    Write-Host "⚠ API did not respond after waiting (may still be initializing)" -ForegroundColor Yellow
}

# Start frontend HTTP server
Write-Host ""
Write-Host "Starting HTML5UP Frontend HTTP Server (port $frontendPort)..." -ForegroundColor Cyan
Write-Host "  Directory: $frontendDir" -ForegroundColor Gray

$frontendCmd = "cd '$frontendDir'; python -m http.server $frontendPort"
$frontendProcess = Start-Process powershell -ArgumentList "-NoExit", "-Command", $frontendCmd -PassThru

if (-not $frontendProcess) {
    Write-Host "✗ Failed to start frontend" -ForegroundColor Red
    exit 1
}

Write-Host "✓ Frontend started (PID: $($frontendProcess.Id))" -ForegroundColor Green

# Wait for frontend to start
Write-Host ""
Write-Host "Waiting for frontend server to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 2

# Verify frontend is responding
Write-Host "Testing frontend connectivity..." -ForegroundColor Yellow
$maxAttempts = 10
$attempt = 0
$frontendReady = $false

while ($attempt -lt $maxAttempts) {
    try {
        $response = Invoke-WebRequest -Uri "http://localhost:$frontendPort" -ErrorAction Stop
        if ($response.StatusCode -eq 200) {
            Write-Host "✓ Frontend is responding" -ForegroundColor Green
            $frontendReady = $true
            break
        }
    }
    catch {
        # Frontend not ready yet
    }
    
    $attempt++
    if ($attempt -lt $maxAttempts) {
        Start-Sleep -Seconds 1
    }
}

if (-not $frontendReady) {
    Write-Host "⚠ Frontend did not respond after waiting (may still be starting)" -ForegroundColor Yellow
}

# Open dashboard
Write-Host ""
Write-Host "Opening SmartPatch Dashboard..." -ForegroundColor Cyan
Start-Process "http://localhost:$frontendPort/dashboard_overview.html"
Write-Host "✓ Dashboard opened in default browser" -ForegroundColor Green

# Summary
Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "                    SmartPatch is Running!                      " -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Dashboard:     http://localhost:$frontendPort/dashboard_overview.html" -ForegroundColor Cyan
Write-Host "  Scanner:       http://localhost:$frontendPort/scanner.html" -ForegroundColor Cyan
Write-Host "  Mitigations:   http://localhost:$frontendPort/mitigation.html" -ForegroundColor Cyan
Write-Host "  API Base:      http://localhost:$apiPort/api" -ForegroundColor Cyan
Write-Host ""
Write-Host "To stop SmartPatch, close both terminal windows or press Ctrl+C" -ForegroundColor Gray
Write-Host ""

# Keep the launcher running
Write-Host "Launcher monitoring... (Press Ctrl+C to stop)" -ForegroundColor Gray

try {
    # Monitor both processes
    while (($apiProcess -and -not $apiProcess.HasExited) -or ($frontendProcess -and -not $frontendProcess.HasExited)) {
        if ($apiProcess -and $apiProcess.HasExited) {
            Write-Host ""
            Write-Host "✗ Backend API has stopped" -ForegroundColor Red
            break
        }
        
        if ($frontendProcess -and $frontendProcess.HasExited) {
            Write-Host ""
            Write-Host "✗ Frontend has stopped" -ForegroundColor Red
            break
        }
        
        Start-Sleep -Seconds 5
    }
}
catch {
    # User cancelled (Ctrl+C)
}

Write-Host ""
Write-Host "SmartPatch shutdown." -ForegroundColor Yellow

# Cleanup
if ($apiProcess -and -not $apiProcess.HasExited) {
    $apiProcess.Kill()
}

if ($frontendProcess -and -not $frontendProcess.HasExited) {
    $frontendProcess.Kill()
}
