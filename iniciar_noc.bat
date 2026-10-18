@echo off
title NOC Syslog Inteligente
cd /d "%~dp0"
echo ============================================
echo   NOC Syslog Inteligente - iniciando...
echo   No cierres esta ventana mientras lo uses.
echo   Para apagarlo: Ctrl + C
echo ============================================
call venv\Scripts\activate.bat
start "" cmd /c "timeout /t 5 >nul & start http://127.0.0.1:8000"
python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
pause