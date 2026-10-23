@echo off
cd /d "%~dp0"
echo Installing requirements...
python -m pip install -r requirements.txt
echo Starting Visitor Management System on http://127.0.0.1:5000
python main.py
pause
