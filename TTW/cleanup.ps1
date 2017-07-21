$ErrorActionPreference = 'SilentlyContinue'
icacls "C:\windows\system32\psexec.exe" /deny BUILTIN\Users:RX
icacls "C:\windows\system32\setup1.ps1" /deny BUILTIN\Users:RX
icacls "C:\windows\system32\setup2.ps1" /deny BUILTIN\Users:RX
Remove-Item C:\windows\system32\psexec.exe
Remove-Item C:\windows\system32\setup1.ps1
Remove-Item C:\windows\system32\setup2.ps1
