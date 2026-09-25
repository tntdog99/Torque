rmdir /s /q dist\windows
rmdir /s /q build
python -m venv .venv
call .venv\Scripts\activate.bat
pip install -r cli_client\requirements.txt
pip install pyinstaller
pyinstaller --onefile --paths="." --paths="deps" --distpath "dist/windows/cli_client/" --copy-metadata readchar .\cli_client\main.py 
xcopy shared dist\windows\cli_client /e /h /r /y