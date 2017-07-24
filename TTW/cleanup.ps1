$ErrorActionPreference = 'SilentlyContinue'

icacls "C:\windows\system32\psexec.exe" /deny BUILTIN\Users:RX
start-sleep -s 1
icacls "C:\windows\system32\setup1.ps1" /deny BUILTIN\Users:RX
start-sleep -s 1
icacls "C:\windows\system32\setup2.ps1" /deny BUILTIN\Users:RX
start-sleep -s 1
icacls "C:\windows\system32\setup2.ps1" /deny BUILTIN\Users:RX
start-sleep -s 1
Remove-Item C:\windows\system32\psexec.exe
start-sleep -s 1
Remove-Item C:\windows\system32\setup1.ps1
start-sleep -s 1
Remove-Item C:\windows\system32\setup1.ps1 -force
start-sleep -s 1
Remove-Item C:\windows\system32\setup2.ps1
start-sleep -s 1
Remove-Item C:\windows\system32\setup2.ps1 -force
start-sleep -s 3
restart-computer
