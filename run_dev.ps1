# PhishGuard Development Launch Script
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "   PHISHGUARD - Threat Intelligence & Detection Platform   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Start Backend Server
Write-Host "`n[1/2] Starting FastAPI Backend on http://127.0.0.1:8000..." -ForegroundColor Green
$backendJob = Start-Job -ScriptBlock {
    Set-Location "$using:PWD\backend"
    py -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
}

# Start Frontend Dev Server
Write-Host "[2/2] Starting Vite Frontend on http://localhost:5173..." -ForegroundColor Green
Set-Location "$PSScriptRoot\frontend"
npm.cmd run dev

