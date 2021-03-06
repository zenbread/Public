$ErrorActionPreference = 'SilentlyContinue'
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
Install-ADDSForest `
-CreateDnsDelegation:$false `
-DatabasePath 'C:\Windows\NTDS' `
-DomainMode 'Win2012R2' `
-DomainName 'army.warriors' `
-DomainNetbiosName 'ARMY' `
-ForestMode 'Win2012R2' `
-SafeModeAdministratorPassword (ConvertTo-SecureString -String 'PassWord12345!!' -AsPlainText -Force) `
-InstallDns:$true `
-LogPath 'C:\Windows\NTDS' `
-NoRebootOnCompletion:$true `
-SysvolPath 'C:\Windows\SYSVOL' `
-Force:$true
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" "setup2" 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -noprofile -sta -File "C:\windows\system32\setup2.ps1"'
Restart-Computer -Force
