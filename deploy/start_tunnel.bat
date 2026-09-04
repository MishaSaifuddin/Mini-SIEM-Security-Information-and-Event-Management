@echo off
REM ============================================================
REM  Mini SIEM - Cloudflare Quick Tunnel launcher
REM  Starts cloudflared, waits, extracts the current public URL,
REM  and saves it to tunnel-url.txt
REM  Requires the backend running on 127.0.0.1:8000
REM ============================================================
setlocal
cd /d "%~dp0"

REM Kill any existing cloudflared
taskkill /F /IM cloudflared.exe >nul 2>&1

echo Starting Cloudflare Quick Tunnel...
start "cloudflared" /min cloudflared.exe tunnel --url http://127.0.0.1:8000 --no-autoupdate > tunnel.log 2>&1

echo Waiting for tunnel to connect...
timeout /t 12 /nobreak >nul

REM Extract the public URL
for /f "delims=" %%i in ('findstr /r "https://[a-z0-9-]*\.trycloudflare\.com" tunnel.log') do set LINE=%%i
echo %LINE% > tunnel-url.txt

echo ===========================================
echo  Tunnel URL:
type tunnel-url.txt
echo ===========================================
endlocal
pause