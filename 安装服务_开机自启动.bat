@echo off
chcp 65001 >nul
title 安装系统服务 - 开机自启动

cd /d "%~dp0"

echo ==============================================
echo    农田数字化台账系统 - 安装开机自启动
echo ==============================================
echo.

set SERVICE_NAME=SmartFarmService
set DISPLAY_NAME=农田数字化台账系统
set DESCRIPTION=农田数字化台账系统后端服务
set NODE_PATH=%cd%\node.exe
set SCRIPT_PATH=%cd%\server.js
set WORK_DIR=%cd%

echo [1/3] 检查Node.js...
if not exist "%NODE_PATH%" (
    echo 未找到 node.exe，使用系统Node.js
    set NODE_PATH=node
)
echo 完成
echo.

echo [2/3] 创建服务...
sc create "%SERVICE_NAME%" binPath= "\"%NODE_PATH%\" \"%SCRIPT_PATH%\"" DisplayName= "%DISPLAY_NAME%" start= auto
if %errorlevel% neq 0 (
    echo 创建服务失败，请以管理员身份运行此脚本
    pause
    exit /b 1
)
echo 完成
echo.

echo [3/3] 启动服务...
sc description "%SERVICE_NAME%" "%DESCRIPTION%"
net start "%SERVICE_NAME%"
if %errorlevel% neq 0 (
    echo 服务启动失败，请检查日志
    pause
    exit /b 1
)
echo 完成
echo.

echo ==============================================
echo    安装成功！
echo ==============================================
echo.
echo 服务名称: %SERVICE_NAME%
echo 访问地址: http://localhost:3001
echo.
echo 服务已设置为开机自动启动
echo.
pause
