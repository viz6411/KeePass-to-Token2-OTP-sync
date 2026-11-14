@echo off
setlocal enabledelayedexpansion
title KeePassXC to Token2 PIN+ Sync

cd /d "%~dp0"

REM 1. Check for standalone compiled binary
set "EXE_FILE=%~dp0t2-kpxc-sync.exe"
if exist "%EXE_FILE%" (
    "%EXE_FILE%" %*
    set "EXIT_CODE=!ERRORLEVEL!"
    goto :finish
)

REM 2. Fallback to Python environment
set "PYTHON_BIN="
if exist "%~dp0.venv\Scripts\python.exe" (
    set "PYTHON_BIN=%~dp0.venv\Scripts\python.exe"
) else if exist "%~dp0venv\Scripts\python.exe" (
    set "PYTHON_BIN=%~dp0venv\Scripts\python.exe"
) else (
    where python >nul 2>nul
    if not errorlevel 1 (
        set "PYTHON_BIN=python"
    ) else (
        where py >nul 2>nul
        if not errorlevel 1 (
            set "PYTHON_BIN=py -3"
        )
    )
)

if "%PYTHON_BIN%"=="" (
    echo [ERROR] Neither standalone executable 't2-kpxc-sync.exe' nor Python was found.
    echo Please download the standalone Windows release or install Python 3.11+.
    set "EXIT_CODE=1"
    goto :finish
)

set "PYTHONDONTWRITEBYTECODE=1"
if exist "%~dp0src" (
    if defined PYTHONPATH (
        set "PYTHONPATH=%~dp0src;%PYTHONPATH%"
    ) else (
        set "PYTHONPATH=%~dp0src"
    )
)

%PYTHON_BIN% -m t2_kpxc_sync %*
set "EXIT_CODE=!ERRORLEVEL!"

:finish
REM Pause only when launched via double-click without arguments and no suppression flag
if "%~1"=="" if "%T2_NO_PAUSE%"=="" (
    pause
)
exit /b %EXIT_CODE%
