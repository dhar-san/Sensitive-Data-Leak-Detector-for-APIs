@echo off
title Sensitive Data Leak Detector for APIs
echo ===================================================================
echo   Sensitive Data Leak Detector for APIs (T1-PS7) - Web Server
echo ===================================================================
echo.

:: Check Python installation
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python is not found in PATH. Please install Python 3.10+ and try again.
    pause
    exit /b 1
)

:: Install dependencies if needed
echo [*] Checking dependencies...
pip install -r requirements.txt --quiet

:: Launch web application
echo [*] Starting web server on http://localhost:5000 ...
start http://localhost:5000
python app.py

pause
