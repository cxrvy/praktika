@echo off
rem Запуск окна помощника SOC без чёрного окна консоли
cd /d "%~dp0"
if exist ".venv\Scripts\pythonw.exe" (
    start "" ".venv\Scripts\pythonw.exe" gui.py
) else (
    start "" pythonw gui.py
)
