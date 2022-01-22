#!/usr/bin/bash
python3 -m venv venv-run
venv-run/bin/python3 -m pip install -r requirements.txt
useradd --system --no-create-home dl-jwtserver-operator
chmod +x start.sh
venv-run/bin/python3 systemdhelper.py
