@echo off
REM SmartPatch Launcher - Simple Batch Script
REM This starts the backend API and opens the HTML5UP frontend

echo ======================================================================
echo         SmartPatch - AI-Driven Security Mitigation
echo ======================================================================
echo.

REM Get the script directory
set SCRIPT_DIR=%~dp0

REM Check if Python is available
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found. Please install Python 3.9+
    pause
    exit /b 1
)

echo Starting SmartPatch Backend API...
echo.

REM Start the backend in a new window
start "SmartPatch Backend" cmd /k "cd /d "%SCRIPT_DIR%" && python -m src.api.backend_api_fixed"

echo Waiting for backend to start...
timeout /t 3 /nobreak

echo.
echo Starting HTTP Server for Frontend...
echo.

REM Start HTTP server for frontend on port 8000
start "SmartPatch Frontend" cmd /k "cd /d "%SCRIPT_DIR%html5up-spectral" && python -m http.server 8000"

echo Waiting for frontend server to start...
timeout /t 2 /nobreak

echo.
echo Opening SmartPatch Dashboard in browser...
echo.

REM Open the frontend in browser at port 8000
start http://localhost:8000

echo.
echo ======================================================================
echo SmartPatch is running!
echo.
echo Backend API: http://localhost:8888/api
echo Frontend:    http://localhost:8000
echo Dashboard:   http://localhost:8000/dashboard_overview.html
echo.
echo To stop: Close both command windows
echo ======================================================================
echo.
pause
pause
