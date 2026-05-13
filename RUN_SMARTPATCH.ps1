# SmartPatch Launcher - Simple PowerShell Script
# Just starts the backend and opens the frontend

Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host "         SmartPatch - AI-Driven Security Mitigation" -ForegroundColor Cyan
Write-Host "=====================================================================" -ForegroundColor Cyan
Write-Host ""

# Get script directory
$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Check Python
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ Python found: $pythonVersion" -ForegroundColor Green
}
catch {
    Write-Host "✗ Python not found. Please install Python 3.9+" -ForegroundColor Red
    exit 1
}

Write-Host ""
Write-Host "Starting SmartPatch Backend API (port 8888)..." -ForegroundColor Cyan

# Start backend in new window
$backendCmd = "cd '$scriptDir'; python -m src.api.backend_api_fixed"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $backendCmd

Write-Host "✓ Backend started in new window" -ForegroundColor Green

Write-Host ""
Write-Host "Waiting 3 seconds for backend to initialize..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

Write-Host ""
Write-Host "Starting HTTP Server for HTML5UP Frontend (port 8000)..." -ForegroundColor Cyan

# Start simple HTTP server for frontend
$frontendDir = Join-Path $scriptDir "html5up-spectral"
$httpCmd = "cd '$frontendDir'; python -m http.server 8000"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $httpCmd

Write-Host "✓ Frontend HTTP server started (port 8000)" -ForegroundColor Green

Write-Host ""
Write-Host "Waiting 2 seconds, then opening frontend..." -ForegroundColor Yellow
Start-Sleep -Seconds 2

Write-Host ""
Write-Host "Opening HTML5UP Spectra Frontend..." -ForegroundColor Cyan
Write-Host ""

# Open frontend in browser
Start-Process "http://localhost:8000"

Write-Host "✓ Frontend opened in default browser" -ForegroundColor Green
Write-Host ""
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host "SmartPatch is running!" -ForegroundColor Green
Write-Host "=====================================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Backend API: http://localhost:8888/api" -ForegroundColor Yellow
Write-Host "Frontend:    http://localhost:8000" -ForegroundColor Yellow
Write-Host ""
Write-Host "Files:" -ForegroundColor Gray
Write-Host "  Backend:  python running in first window" -ForegroundColor Gray
Write-Host "  Frontend: $frontendDir" -ForegroundColor Gray
Write-Host ""
Write-Host "To stop: Close both command windows" -ForegroundColor Gray
Write-Host ""
