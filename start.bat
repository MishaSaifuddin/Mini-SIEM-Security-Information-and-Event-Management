@echo off
REM Start the Mini SIEM backend and frontend
echo ========================================
echo  Mini SIEM - Starting Services
echo ========================================
echo.

REM Start backend
start "Mini SIEM Backend" cmd /k "cd /d C:\Users\Misha\mini-siem\backend && venv\Scripts\python.exe -m uvicorn app.main:app --reload --port 8000"

REM Start frontend
start "Mini SIEM Frontend" cmd /k "cd /d C:\Users\Misha\mini-siem\frontend && npm start"

echo Backend: http://localhost:8000  (API docs at /docs)
echo Frontend: http://localhost:3000
echo.
echo Default login: admin / admin123
echo.
pause
