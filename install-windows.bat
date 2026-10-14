@echo off
title EndpointGuard Server Setup
echo =======================================================================
echo        EndpointGuard Enterprise Control Server - Windows Setup
echo =======================================================================
echo.

:: Launch the Graphical Installer
if exist "EndpointGuard-Server-Setup.exe" (
    echo Starting graphical setup wizard...
    start "" "EndpointGuard-Server-Setup.exe"
    exit /b 0
)

if exist "server\EndpointGuard-Server-Setup.exe" (
    echo Starting graphical setup wizard...
    start "" "server\EndpointGuard-Server-Setup.exe"
    exit /b 0
)

echo Warning: EndpointGuard-Server-Setup.exe not found, launching direct application...
if exist "server\EndpointGuardServer.exe" (
    start "" "server\EndpointGuardServer.exe"
) else (
    echo Error: Server binaries not found.
    pause
)
