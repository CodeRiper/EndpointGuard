@echo off
setlocal
title EndpointGuard Agent Uninstaller
cls
echo ==========================================================
echo  EndpointGuard Enterprise Agent - Anti-Tamper Uninstaller
echo ==========================================================
echo.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0uninstall.ps1"
echo.
pause
