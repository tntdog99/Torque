Remove-Item -Recurse -Force client1
Remove-Item -Recurse -Force client2

mkdir client1
mkdir client2


Copy-Item -Path "cli_client/*" -Destination "./client1" -Recurse -Force
Copy-Item -Path "cli_client/*" -Destination "./client2" -Recurse -Force


Copy-Item -Path "shared/*" -Destination "./client1" -Recurse -Force
Copy-Item -Path "shared/*" -Destination "./client2" -Recurse -Force
Copy-Item -Path "deps/*" -Destination "./client1" -Recurse -Force
Copy-Item -Path "deps/*" -Destination "./client2" -Recurse -Force

if ((Get-Command wt.exe -ErrorAction SilentlyContinue)) {
    wt -d client1
    wt -d client2
    exit
}
if ((Get-Command pwsh.exe -ErrorAction SilentlyContinue)) {
    Start-Process pwsh -WorkingDirectory $PWD/client1
    Start-Process pwsh -WorkingDirectory $PWD/client2
    exit
}
if ((Get-Command powershell.exe -ErrorAction SilentlyContinue)) {
    Start-Process powershell -WorkingDirectory $PWD/client1
    Start-Process powershell -WorkingDirectory $PWD/client2
    exit
}
