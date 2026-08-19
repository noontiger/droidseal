@echo off
rem DroidSeal 双击启动器:在真实控制台内运行 droidseal.exe,解决资源管理器
rem 双击 exe 时无交互终端导致 TUI 闪退的问题。把本文件与 droidseal.exe 放在同一目录。
cd /d "%~dp0"
droidseal.exe %*
pause
