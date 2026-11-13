@echo off
echo ==========================================================
echo    PHISHGUARD - Threat Intelligence & Detection Platform   
echo ==========================================================

echo [1/2] Starting Backend in new window...
start "PhishGuard Backend" cmd /k "cd backend && py -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload"

echo [2/2] Starting Frontend in current window...
cd frontend
npm.cmd run dev

