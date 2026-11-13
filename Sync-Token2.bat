@echo off
title KeePassXC -> Token2 PIN+ R3.3 Sync
set PYTHONDONTWRITEBYTECODE=1
set PYTHONPATH=%~dp0src;%PYTHONPATH%
cd /d "%~dp0"
python -m t2_kpxc_sync %*
pause
