#!/bin/bash
rm -rf dist
rm -rf build
python -m venv .venv
source .venv/bin/activate
pip install -r cli_client/requirements.txt
pip install pyinstaller
pyinstaller --onefile --paths="." --paths="deps" --distpath "dist/cli_client/" --copy-metadata readchar ./cli_client/main.py 
cp -R shared/* dist/cli_client
cp -R shared/.storage dist/cli_client/