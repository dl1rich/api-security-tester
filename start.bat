@echo off
REM API Security Tester - Windows Startup Script
REM This script automatically sets up and starts the entire application

echo.
echo ========================================
echo   API Security Tester - Auto Setup   
echo ========================================
echo.

REM Check if Python is available
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.9+ from https://python.org
    pause
    exit /b 1
)

REM Run the Python setup script
echo Starting automated setup and launch...
echo.
python start.py

REM Keep window open if there's an error
if errorlevel 1 (
    echo.
    echo Setup failed. Press any key to exit...
    pause >nul
)
