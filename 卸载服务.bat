@echo off
chcp 65001 >nul
title 卸载系统服务

cd /d "%~dp0"

echo ==============================================
echo    农田数字化台账系统 - 卸载服务
echo ==============================================
echo.

set SERVICE_NAME=SmartFarmService

echo 正在停止服务...
net stop "%SERVICE_NAME%" 2>nul

echo 正在删除服务...
sc delete "%SERVICE_NAME%"

echo.
echo ==============================================
echo    卸载完成！
echo ==============================================
echo.
pause
