$ErrorActionPreference = 'SilentlyContinue'
icacls C:\windows\system32\psexec.exe /deny BUILTIN\Users:RX
