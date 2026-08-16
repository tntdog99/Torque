Remove-Item -Recurse -Force client1
Remove-Item -Recurse -Force client2
Remove-Item -Recurse -Force client3

mkdir client1
mkdir client2
mkdir client3


Copy-Item -Path "cli_client/*" -Destination "./client1" -Recurse -Force
Copy-Item -Path "cli_client/*" -Destination "./client2" -Recurse -Force
Copy-Item -Path "kivy_client/*" -Destination "./client3" -Recurse -Force


Copy-Item -Path "shared/*" -Destination "./client1" -Recurse -Force
Copy-Item -Path "shared/*" -Destination "./client2" -Recurse -Force
Copy-Item -Path "shared/*" -Destination "./client3" -Recurse -Force


if ((Get-Command wt.exe -ErrorAction SilentlyContinue)) {
    wt -d client1
    wt -d client2
    wt -d client3
}
