cmd.exe /c start cmd.exe /c wsl.exe python3 receiver.py password password 5003
cmd.exe /c start cmd.exe /c wsl.exe python3 receiver.py password1 salt1 5000
cmd.exe /c start cmd.exe /c wsl.exe python3 receiver.py password2 salt2 5001
cmd.exe /c start cmd.exe /c wsl.exe python3 mix.py 1
cmd.exe /c start cmd.exe /c wsl.exe python3 mix.py 2
cmd.exe /c start cmd.exe /c wsl.exe python3 mix.py 3

sleep 1

cmd.exe /c start cmd.exe /c wsl.exe python3 sender.py 1
cmd.exe /c start cmd.exe /c wsl.exe python3 sender.py 2
cmd.exe /c start cmd.exe /c wsl.exe python3 sender.py 3
