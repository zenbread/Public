$ErrorActionPreference = 'SilentlyContinue'

Remove-Item C:\windows\system32\psexec.exe -force
start-sleep -s 1

Remove-Item C:\windows\system32\setup1.ps1 -force
start-sleep -s 1

Remove-Item C:\windows\system32\setup2.ps1 -force
start-sleep -s 3

Write-Output "The password for the next level is the Powershell build version. Please be sure to include all periods" -n > C:\Users\Apprentice01\Desktop\challenge.txt
icacls "C:\Users\Apprentice01\Desktop\challenge.txt" /grant Apprentice01:F /T /C

restart-computer
