$ErrorActionPreference = 'SilentlyContinue'
icacls C:\windows\system32\psexec.exe /deny BUILTIN\Users:RX
icacls C:\windows\system32\setup1.ps1 /deny BUILTIN\Users:RX
icacls C:\windows\system32\setup2.ps1 /deny BUILTIN\Users:RX
