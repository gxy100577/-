@echo off
chcp 65001 >nul
title 农田数字化台账系统 - 服务启动

cd /d "%~dp0"

echo ==============================================
echo    农田数字化台账系统 - 服务启动中...
echo ==============================================
echo.
echo 服务地址: http://localhost:3001
echo 按 Ctrl+C 停止服务
echo.
echo ==============================================
echo.

node server.js

pause
