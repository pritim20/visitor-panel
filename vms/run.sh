#!/usr/bin/env bash
cd "$(dirname "$0")"
python3 -m pip install -r requirements.txt
echo "Starting Visitor Management System on http://127.0.0.1:5000"
python3 main.py
