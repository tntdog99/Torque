rmdir /s /q dist
python -m venv .venv
call .venv\Scripts\activate.bat
pip install -r cli_client\requirements.txt
pip install pyinstaller
pyinstaller --onefile --paths="." --paths="deps" --distpath "dist/cli_client/" --copy-metadata readchar .\cli_client\main.py 
xcopy shared dist\cli_client /e /h /r /y