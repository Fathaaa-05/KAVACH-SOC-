@echo off
REM Start KAVACH on Windows: http://localhost:8000
cd /d %~dp0
python -m pip install -q -r requirements.txt
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
