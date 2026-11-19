@echo off
title SafeInbox AI Cloud Intelligence Backend
echo ======================================================================
echo   SafeInbox AI Backend - Connected to Neon Lakebase Postgres
echo   Target Database: ep-summer-union-a134dbgc.ap-southeast-1.aws.neon.tech
echo   API Server:      http://localhost:8080
echo   API Docs:        http://localhost:8080/docs
echo ======================================================================
cd /d "%~dp0"
if exist ".venv\Scripts\python.exe" (
  set "PYTHON_EXE=.venv\Scripts\python.exe"
) else (
  set "PYTHON_EXE=python"
)
"%PYTHON_EXE%" -m uvicorn app.main:app --app-dir backend --port 8080 --reload
pause

