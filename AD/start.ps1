$ErrorActionPreference = 'SilentlyContinue'

Remove-Item C:\windows\system32\setup1.ps1 -force
start-sleep -s 1

Remove-Item C:\windows\system32\setup2.ps1 -force
start-sleep -s 3

net user Administrator ReallyStrongPassword!!
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon" -Name "DefaultPassword" -PropertyType String -Value 'ReallyStrongPassword!!'

restart-computer
