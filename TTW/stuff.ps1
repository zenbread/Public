
New-Item $PROFILE.AllUsersAllHosts -ItemType File -Force
echo "$ProfileRoot = (Split-Path -Parent $MyInvocation.MyCommand.Path)" > "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"
echo '$env:path += "$ProfileRoot"' >> "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"
icacls C:\WINDOWS\system32\WindowsPowerShell\v1.0\start.ps1 /grant Everyone:F /T /C
icacls C:\Windows\System32\setup2.ps1 /grant Everyone:F /T /C
icacls C:\Windows\System32\PsExec.exe /grant Everyone:F /T /C

Restart-Computer
