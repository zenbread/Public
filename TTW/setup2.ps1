$ErrorActionPreference = 'SilentlyContinue'

#----- LOCK OUT Administrator from that which was set on yaml / Instructor ACCESS ONLY ---
net user Administrator ReallyStrongPassword!!
Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon" -Name "DefaultPassword" -PropertyType String -Value 'ReallyStrongPassword!!'

#----- OUs ---
dsadd ou "OU=WARRIORS,DC=army,DC=warriors"
dsadd ou "OU=Apprentice,OU=WARRIORS,DC=army,DC=warriors"
dsadd ou "OU=Fighter,OU=WARRIORS,DC=army,DC=warriors"
dsadd ou "OU=Paladin,OU=WARRIORS,DC=army,DC=warriors"
dsadd ou "OU=Wizard,OU=WARRIORS,DC=army,DC=warriors"
dsadd ou "OU=OSsassin,OU=WARRIORS,DC=army,DC=warriors"
dsadd ou "OU=SYNmurai,OU=WARRIORS,DC=army,DC=warriors"

#----- Security Groups ---
dsadd group "CN=Apprentices,CN=Users,DC=army,DC=warriors" -secgrp yes -scope u -desc "Apprentice"
dsadd group "CN=Fighters,CN=Users,DC=army,DC=warriors" -secgrp yes -scope g -desc "Fighter" -memberof "CN=Apprentices,CN=Users,DC=army,DC=warriors"
dsadd group "CN=Paladins,CN=Users,DC=army,DC=warriors" -secgrp yes -scope g -desc "Paladin" -memberof "CN=Fighters,CN=Users,DC=army,DC=warriors"
dsadd group "CN=Wizards,CN=Users,DC=army,DC=warriors" -secgrp yes -scope g -desc "Wizard" -memberof "CN=Paladins,CN=Users,DC=army,DC=warriorss"
dsadd group "CN=OSsassins,CN=Users,DC=army,DC=warriors" -secgrp yes -scope g -desc "OSsassin" -memberof "CN=Wizards,CN=Users,DC=army,DC=warriors"
dsadd group "CN=SYNmurais,CN=Users,DC=army,DC=warriors" -secgrp yes -scope g -desc "SYNmurai" -memberof "CN=OSsassins,CN=Users,DC=army,DC=warriors"
dsadd group "CN=Rangers,CN=Users,DC=army,DC=warriors" -secgrp yes -scope g -desc "Ranger" -memberof "CN=SYNmurais,CN=Users,DC=army,DC=warriors"
dsadd group "CN=CodeSlingers,CN=Users,DC=army,DC=warriors" -secgrp yes -scope g -desc "CodeSlinger" -memberof "CN=SYNmurais,CN=Users,DC=army,DC=warriors"
dsadd group "CN=MASTERS,CN=Users,DC=army,DC=warriors" -secgrp yes -scope g -desc "MASTER" -memberof "CN=SYNmurais,CN=Users,DC=army,DC=warriors"


#----- Share Drive Setup ---

#----- Creates Share Folders for all Levels ---  10990 folders
set-variable -name ROOT -value "C:\share"
set-variable -name TOP -value "WARRIORS"
new-item -ItemType Directory -Path "$ROOT\$TOP\" -Force

$CLASSES = @("Apprentice","Fighter","Paladin","Wizard","OSsassin","SYNmurai","MASTER","Ranger","CodeSlinger")
$1STFOLDER = @("1","2","3","4","5","6","7","8","9","10")
$2NDFOLDER = @("10","9","8","7","6","5","4","3","2","1")
$3RDFOLDER = @("1","2","3","4","5","6","7","8","9","10")
$4THFOLDER = @("10","9","8","7","6","5","4","3","2","1")

foreach ($CLASS in $CLASSES) {
	echo $CLASS
	foreach ($3RD in $3RDFOLDER) {
		echo $3RD
		foreach ($2ND in $2NDFOLDER) {
			echo $2ND
			foreach ($1ST in $1STFOLDER) {
				new-item -ItemType Directory -Path "$ROOT\$TOP\$CLASS\$3RD\HOME\$2ND\HOME\$1ST" -Force
			}
		}
	}
}

   
    foreach ($4TH in $4THFOLDER) {
        echo $4TH
        foreach ($3RD in $3RDFOLDER) {
            new-item -ItemType Directory -Path "$CLASS\$1ST\$4TH\$3RD"
            }
        }
start-sleep -s 1
	
# ----- creates SMB share for folders created above ---
new-SMBshare -path "C:\share" `
-Name "The Share" `
-Desc "A Share Drive"

Add-NTFSAccess -Path C:\share -Account 'Everyone' -AccessRights Read

icacls "C:\share\WARRIORS" /grant Everyone:R /C
icacls "C:\share\WARRIORS\MASTER" /grant MASTER:F /T /C
icacls "C:\share\WARRIORS\CodeSlinger" /grant CodeSlinger:F /T /C
icacls "C:\share\WARRIORS\Ranger" /grant Ranger:F /T /C
icacls "C:\share\WARRIORS\SYNmurai" /grant SYNmurais:F /T /C
icacls "C:\share\WARRIORS\OSsassins" /grant OSsassins:F /T /C
icacls "C:\share\WARRIORS\Wizards" /grant Wizards:F /T /C
icacls "C:\share\WARRIORS\Paladins" /grant Paladins:F /T /C
icacls "C:\share\WARRIORS\Fighters" /grant Fighters:F /T /C
icacls "C:\share\WARRIORS\Apprentices" /grant Apprentices:F /T /C

#----- DISABLES PASSWORD COMPLEXITY REQ AND ENABLES LOCAL LOGIN FOR USERS OTHER THAN ADMIN ---

secedit /export /cfg c:\secpol.cfg
(gc C:\secpol.cfg).replace("PasswordComplexity = 1", "PasswordComplexity = 0") | Out-File C:\secpol.cfg
(gc C:\secpol.cfg).replace("MinimumPasswordLength = 7", "MinimumPasswordLength = 1") | Out-File C:\secpol.cfg
(gc C:\secpol.cfg).replace("SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-548,*S-1-5-32-549,*S-1-5-32-550,*S-1-5-32-551,*S-1-5-9", "SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-548,*S-1-5-32-549,*S-1-5-32-550,*S-1-5-32-551,*S-1-5-9,*S-1-1-0,*S-1-5-11") | Out-File C:\secpol.cfg
secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg
rm -force c:\secpol.cfg -confirm:$false

New-ADFineGrainedPasswordPolicy `
-Name "DomainUsersPSO" `
-Precedence 10 `
-ComplexityEnabled $false `
-Description "The Domain Users Password Policy" `
-DisplayName "Domain Users PSO" `
-LockoutDuration "0.00:00:10" `
-LockoutObservationWindow "0.00:00:05" `
-LockoutThreshold 10 `
-MaxPasswordAge "60.00:00:00" `
-MinPasswordAge "1.00:00:00" `
-MinPasswordLength 1 `
-PasswordHistoryCount 24 `
-ReversibleEncryptionEnabled $false
Add-ADFineGrainedPasswordPolicySubject DomainUsersPSO -Subjects 'Domain Users'

#----- Disables Control Panel, Registry.exe GUIs, and Last User Name at login ---
New-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name NoControlPanel -Value 1 -PropertyType DWord | Out-Null
New-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name DisableRegistryTools -Value 1 -PropertyType DWord | Out-Null
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name DontDisplayLastUserName -Value 1

#----- CLreates 50 Domain User Accounts .. 3 hidden ---  all must have default password to be used in follow on psexec for loops

$users1 = @("Apprentice01","Apprentice02","Apprentice03","Apprentice04","Apprentice05","Apprentice06","Apprentice07","Apprentice08","Apprentice09","Apprentice10")
foreach ($user in $users1) {
dsadd user "CN=$user,OU=Apprentice,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Apprentices,CN=Users,DC=army,DC=warriors" -pwd "password" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
}
start-sleep -s 1

$users2 = @("Fighter01","Fighter02","Fighter03","Fighter04","Fighter05","Fighter06","Fighter07","Fighter08","Fighter09","Fighter10")
foreach ($user in $users2) {
dsadd user "CN=$user,OU=Fighter,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Fighters,CN=Users,DC=army,DC=warriors" -pwd "password" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no
}
start-sleep -s 1

$users3 = @("Paladin01","Paladin02","Paladin03","Paladin04","Paladin05","Paladin06","Paladin07","Paladin08","Paladin09","Paladin10")
foreach ($user in $users3) {
dsadd user "CN=$user,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Paladins,CN=Users,DC=army,DC=warriors" -pwd "password" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
}
start-sleep -s 1

$users4 = @("Wizard01","Wizard02","Wizard03","Wizard04","Wizard05","Wizard06","Wizard07","Wizard08","Wizard09","Wizard10")
foreach ($user in $users4) {
dsadd user "CN=$user,OU=Wizard,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Wizards,CN=Users,DC=army,DC=warriors" -pwd "password" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
}
start-sleep -s 1

$users5 = @("OSsassin01","OSsassin02","OSsassin03","OSsassin04","OSsassin05","OSsassin06","OSsassin07","OSsassin08","OSsassin09")
foreach ($user in $users5) {
dsadd user "CN=$user,OU=OSsassin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=OSsassins,CN=Users,DC=army,DC=warriors" -pwd "password" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no
}
start-sleep -s 1

dsadd user "CN=SYNmurai,OU=SYNmurai,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=SYNmurais,CN=Users,DC=army,DC=warriors" -pwd "password" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=Ranger,OU=SYNmurai,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=SYNmurais,CN=Users,DC=army,DC=warriors" -pwd "password" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=CodeSlinger,OU=SYNmurai,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=SYNmurais,CN=Users,DC=army,DC=warriors" -pwd "password" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=MASTER,OU=SYNmurai,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=SYNmurais,CN=Users,DC=army,DC=warriors" -pwd "password" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no

#----- Creates Profiles for Every User/Level in Domain .. to be populated with the follow-on challenges

$users1 = @("Apprentice01","Apprentice02","Apprentice03","Apprentice04","Apprentice05","Apprentice06","Apprentice07","Apprentice08","Apprentice09","Apprentice10")
foreach ($user in $users1) {
	psexec -accepteula -u army\$user -p password \\$(hostname) cmd /c "exit" -accepteula -nobanner
}
$users2 = @("Fighter01","Fighter02","Fighter03","Fighter04","Fighter05","Fighter06","Fighter07","Fighter08","Fighter09","Fighter10")
foreach ($user in $users2) {
	psexec -accepteula -u army\$user -p password \\$(hostname) cmd /c "exit" -accepteula -nobanner
}
$users3 = @("Paladin01","Paladin02","Paladin03","Paladin04","Paladin05","Paladin06","Paladin07","Paladin08","Paladin09","Paladin10")
foreach ($user in $users3) {
	psexec -accepteula -u army\$user -p password \\$(hostname) cmd /c "exit" -accepteula -nobanner
}
$users4 = @("Wizard01","Wizard02","Wizard03","Wizard04","Wizard05","Wizard06","Wizard07","Wizard08","Wizard09","Wizard10")
foreach ($user in $users4) {
	psexec -accepteula -u army\$user -p password \\$(hostname) cmd /c "exit" -accepteula -nobanner
}
$users5 = @("OSsassin01","OSsassin02","OSsassin03","OSsassin04","OSsassin05","OSsassin06","OSsassin07","OSsassin08","OSsassin09")
foreach ($user in $users5) {
	psexec -accepteula -u army\$user -p password \\$(hostname) cmd /c "exit" -accepteula -nobanner
}
$users6 = @("SYNmurai","Ranger","CodeSlinger","MASTER")
foreach ($user in $users6) {
	psexec -accepteula -u army\$user -p password \\$(hostname) cmd /c "exit" -accepteula -nobanner
}


#----- Specific Files for each account/level/challenge .. modifies domain user accounts with correct challenge "passwords"


dsmod user "CN=Apprentice01,OU=Apprentice,OU=WARRIORS,DC=army,DC=warriors" -pwd "password"
	Write-Output "The password for the next level is the Powershell build version. Note - Please be sure to include all periods" -n > C:\Users\Apprentice01\Desktop\challenge.txt

dsmod user "CN=Apprentice02,OU=Apprentice,OU=WARRIORS,DC=army,DC=warriors" -pwd "$(($PSVersionTable.BuildVersion).ToString())"
	Write-Output "The password for the next level is the short name of the domain in which this server is a part of." -n > C:\Users\Apprentice02\Desktop\challenge.txt
	
dsmod user "CN=Apprentice03,OU=Apprentice,OU=WARRIORS,DC=army,DC=warriors" -pwd "army"
	Write-Output "The password for the next level is in a readme file somewhere in this user’s profile." -n > C:\Users\Apprentice03\Desktop\challenge.txt
	
dsmod user "CN=Apprentice04,OU=Apprentice,OU=WARRIORS,DC=army,DC=warriors" -pwd "123456"
	Write-Output "The password for the next level is in a file in a hidden directory in the root of this user’s profile." -n > C:\Users\Apprentice04\Desktop\challenge.txt
	echo "123456" > C:\Users\Apprentice03\Favorites\README
	icacls C:\Users\Apprentice03 /grant Apprentice03:F /T /C

dsmod user "CN=Apprentice05,OU=Apprentice,OU=WARRIORS,DC=army,DC=warriors" -pwd "ketchup"
	Write-Output "The password for the next level is in a file in a directory on the desktop with spaces in it." -n > C:\Users\Apprentice05\Desktop\challenge.txt
	new-item -ItemType Directory -Path "C:\Users\Apprentice04\secretsauce" -Force
	echo "ketchup" > C:\Users\Apprentice04\secretsauce\saucey
	attrib +h C:\Users\Apprentice04\secretsauce
	icacls C:\Users\Apprentice04 /grant Apprentice04:F /T /C 
	
dsmod user "CN=Apprentice06,OU=Apprentice,OU=WARRIORS,DC=army,DC=warriors" -pwd "987654321"
	Write-Output "The password for the next level is the manufacturing name of the only USB drive that was plugged into this server at some point." -n > C:\Users\Apprentice06\Desktop\challenge.txt
	$dirs = @("1    -     99","100     -     199","a     -      z","z                                                                                                           -                                                                          a")
	foreach ($dir in $dirs) {
		new-item -ItemType Directory -Path C:\Users\Apprentice05\Desktop\$dir -Force
		}
	echo "987654321" > "C:\Users\Apprentice05\Desktop\z                                                                                                           -                                                                          a\space.txt"
	icacls C:\Users\Apprentice05 /grant Apprentice05:F /T /C
	
dsmod user "CN=Apprentice07,OU=Apprentice,OU=WARRIORS,DC=army,DC=warriors" -pwd "SanDisk"
	Write-Output "The password for the next level is the description of the Lego Land service." -n > C:\Users\Apprentice07\Desktop\challenge.txt
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name Start -Value 1 
	New-Item "C:\windows\system32" -ItemType File -Name reg.ps1 -Force
		echo 'New-Item "HKLM:\SYSTEM\CurrentControlSet\Enum" -Name USBSTOR -Force' > "C:\windows\system32\reg.ps1"
			echo 'New-Item "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0" -Name "Device Parameters" -Force' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0" -Name "Capabilities" -Value "0X00000010" -PropertyType DWord | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0" -Name "Class" -Value "DiskDrive" -PropertyType String | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0" -Name "ClassGUID" -Value "{4d36e967-e325-11ce-bfc1-08002be10318}" -PropertyType String | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0" -Name "CompatibleIDs" -Value "USBSTOR\Disk USBSTOR\RAW" -PropertyType MultiString | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0" -Name "ConfigFlags" -Value "0X00000000" -PropertyType DWord | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0" -Name "ContainerID" -Value "{c2dc3c42-a281-557a-a6ed-e607894e99b3}" -PropertyType String | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0" -Name "DeviceDesc" -Value "@disk.inf;%disk_devdesc%;Disk Drive" -PropertyType String | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0" -Name "Driver" -Value "{4d36e967-e325-11ce-bfc1-08002be10318}\0001" -PropertyType String | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0" -Name "FriendlyName" -Value "SanDisk Cruzer Blade USB Device" -PropertyType String | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0" -Name "HardwareID" -Value "USBSTOR\DiskSanDisk_Cruzer_Blade___PMAP USBST..." -PropertyType MultiString | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0" -Name "Mfg" -Value "@disk.inf;%genmanufacturer%;Standard disk drives" -PropertyType String | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0" -Name "Service" -Value "disk" -PropertyType String | Out-Null' >> "C:\windows\system32\reg.ps1"
				echo 'New-Item "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0\Device Parameters" -Name "MediaChangeNotification" -Force' >> "C:\windows\system32\reg.ps1"
				echo 'New-Item "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0\Device Parameters" -Name "Partmgr" -Force' >> "C:\windows\system32\reg.ps1"
					echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0\Device Parameters\Partmgr" -Name "Attributes" -Value "0X00000000" -PropertyType DWord | Out-Null' >> "C:\windows\system32\reg.ps1"
					echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0\Device Parameters\Partmgr" -Name "DiskId" -Value "{116c15b5-5f04-11e5-9d2b-000c293089ea}" -PropertyType String | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-Item "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0" -Name "LogConf" -Force' >> "C:\windows\system32\reg.ps1"
			echo 'New-Item "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk_Ven_SanDisk_Prod_Cruzer_Blade_Rev_PMAP\CF52A6CB0" -Name "Properties" -Force' >> "C:\windows\system32\reg.ps1"
		schtasks /create /tn "Reg" /tr "powershell.exe -file C:\windows\system32\reg.ps1" /ru SYSTEM /sc ONCE /st (get-date).AddMinutes(1).ToString("HH:mm") /V1 /z
		# Register-ScheduledJob -Name USB -FilePath  C:\windows\system32\reg.ps1 -RunNow
	    start-sleep -s 1
	
dsmod user "CN=Apprentice08,OU=Apprentice,OU=WARRIORS,DC=army,DC=warriors" -pwd "i_love_legos"
	Write-Output "The password for the next level is the number of files in the Videos folder." -n > C:\Users\Apprentice08\Desktop\challenge.txt
	new-service LegoLand -Desc "i_love_legos" "C:\windows\system32\notepad.exe"

dsmod user "CN=Apprentice09,OU=Apprentice,OU=WARRIORS,DC=army,DC=warriors" -pwd "925"
	Write-Output "The password for the next level is the number of folders in the Music folder." -n > C:\Users\Apprentice09\Desktop\challenge.txt
	0..698 | % { new-item -ItemType File -Path C:\Users\Apprentice08\Videos\file$_.txt -Force }
	710..776 | % { new-item -ItemType File -Path C:\Users\Apprentice08\Videos\file$_.txt -Force }
	834..991 | % { new-item -ItemType File -Path C:\Users\Apprentice08\Videos\file$_.txt -Force }
	new-item -ItemType Directory -Path "C:\Users\Apprentice08\Videos" -Force
	new-item -ItemType File -Path "C:\Users\Apprentice08\Videos\file1103.txt" -Force
	
dsmod user "CN=Apprentice10,OU=Apprentice,OU=WARRIORS,DC=army,DC=warriors" -pwd "411"
	Write-Output "The password for the next level is the number of words in a file on the desktop." -n > C:\Users\Apprentice10\Desktop\challenge.txt
	Write-Output "Note: Next Level Login - Fighter01" -n >> C:\Users\Apprentice10\Desktop\challenge.txt
	1..703 | % {if($_ % 2 -eq 1 ) { new-item -ItemType Directory -Path C:\Users\Apprentice09\Music\Stevie_Wonder$_ -Force } }
	18..73 | % { new-item -ItemType Directory -Path C:\Users\Apprentice09\Music\Teddy_Pendergrass$_ -Force }
	new-item -ItemType Directory -Path "C:\Users\Apprentice09\Music\Teddy_Pendergrass" -Force
	new-item -ItemType Directory -Path "C:\Users\Apprentice09\Music\Luther Vandros" -Force
	new-item -ItemType Directory -Path "C:\Users\Apprentice09\Music\Stevie_Wonder 139" -Force
	icacls C:\Users\Apprentice09 /grant Apprentice09:F /T /C

dsmod user "CN=Fighter01,OU=Fighter,OU=WARRIORS,DC=army,DC=warriors" -pwd "5254"
	Write-Output "The password for the next level is the last five digits of the MD5 hash of the hosts file." -n > C:\Users\Fighter01\Desktop\challenge.txt
	new-item -ItemType File -Path "C:\Users\Apprentice10\Desktop\words.txt" -Force
	function global:GET-8LetterWord() {
	[int32[]]$ArrayofAscii=26,97,26,65,10,48,15,33
	$Complexity=1
	# Complexity:
	# 1 - Pure lowercase ASCII
	# 2 - Mix Uppercase and Lowercase ASCII
	# 3 - ASCII Upper/Lower with Numbers
	# 4 - ASCII Upper/Lower with Numbers and Punctuation
	$WordLength=8
	$NewWord=$NULL
		Foreach ($counter in 1..$WordLength) {
			$pickSet=(GET-Random $complexity)*2
			$NewWord=$NewWord+[char]((get-random $ArrayOfAscii[$pickset])+$ArrayOfAscii[$pickset+1])
		}
	Return $NewWord
	}
	
	foreach ($Counter in 1..5254) { 
	GET-8LetterWord >> C:\Users\Apprentice10\Desktop\words.txt 
	}
	icacls C:\Users\Apprentice10 /grant Apprentice10:F /T /C
	
dsmod user "CN=Fighter02,OU=Fighter,OU=WARRIORS,DC=army,DC=warriors" -pwd "7566D"
	Write-Output "The password for the next level is the number of times 'gaab' is listed in the file on the desktop." -n > C:\Users\Fighter02\Desktop\challenge.txt
	# no prep necessary

dsmod user "CN=Fighter03,OU=Fighter,OU=WARRIORS,DC=army,DC=warriors" -pwd "1"
	Write-Output "The password for the next level is the number of times 'az' appears in the words.txt file on the desktop." -n > C:\Users\Fighter03\Desktop\challenge.txt
	Write-Output "Hint: 'az', may appear more than one time in a word." -n >> C:\Users\Fighter03\Desktop\challenge.txt
	$AA = [char[]]([char]'a'..[char]'z')
	$BB = [char[]]([char]'a'..[char]'z')
	$CC = [char[]]([char]'a'..[char]'z')
	$DD = [char[]]([char]'a'..[char]'z')
	$(foreach ($A in $AA) {
		"$A"
	}) > C:\Users\Fighter02\Desktop\words.txt
	
	$(foreach ($A in $AA) {
		foreach ($B in $BB) {
			"$A$B"
		}
	}) >> C:\Users\Fighter02\Desktop\words.txt
	
	$(foreach ($A in $AA) {
		foreach ($B in $BB) {
			foreach ($C in $CC) {
				"$A$B$C"
			}
		}
	}) >> C:\Users\Fighter02\Desktop\words.txt
	
	$(foreach ($A in $AA) {
		foreach ($B in $BB) {
			foreach ($C in $CC) {
				foreach ($D in $DD) {
					"$A$B$C$D"
				}
			}
		}
	}) >> C:\Users\Fighter02\Desktop\words.txt
	icacls C:\Users\Fighter02\Desktop /grant Fighter02:F /T /C
	
dsmod user "CN=Fighter04,OU=Fighter,OU=WARRIORS,DC=army,DC=warriors" -pwd "2081"
	Write-Output "The password for the next level is the number of words with either 'a' OR 'z', in the word, in the words.txt file on the desktop." -n > C:\Users\Fighter04\Desktop\challenge.txt
	new-item -ItemType Directory -Path "C:\Users\Fighter02\Desktop" -Force
	copy-item C:\Users\Fighter02\Desktop\words.txt C:\Users\Fighter03\Desktop\
	icacls C:\Users\Fighter03 /grant Fighter03:F /T /C

dsmod user "CN=Fighter05,OU=Fighter,OU=WARRIORS,DC=army,DC=warriors" -pwd "129054"
	Write-Output "The password for the next level is the number of words meeting the following criteria in the file on the desktop CRITERIA - 'a' appears at least twice, followed by either an a, b, c . .  OR g" -n > C:\Users\Fighter05\Desktop\challenge.txt
	new-item -ItemType Directory -Path "C:\Users\Fighter02\Desktop" -Force
	copy-item C:\Users\Fighter02\Desktop\words.txt C:\Users\Fighter04\Desktop\
	icacls C:\Users\Fighter04 /grant Fighter04:F /T /C
	
dsmod user "CN=Fighter06,OU=Fighter,OU=WARRIORS,DC=army,DC=warriors" -pwd "364"
	Write-Output "The password for the next level is the number of unique words in the file on the desktop." -n > C:\Users\Fighter06\Desktop\challenge.txt
	new-item -ItemType Directory -Path "C:\Users\Fighter02\Desktop" -Force
	copy-item C:\Users\Fighter02\Desktop\words.txt C:\Users\Fighter05\Desktop\
	icacls C:\Users\Fighter05 /grant Fighter05:F /T /C
	
dsmod user "CN=Fighter07,OU=Fighter,OU=WARRIORS,DC=army,DC=warriors" -pwd "456976"
	Write-Output "The password for the next level is the only line that makes the two files in the Downloads folder different." -n > C:\Users\Fighter07\Desktop\challenge.txt
	new-item -ItemType Directory -Path "C:\Users\Fighter06\Desktop" -Force
	$AA = [char[]]([char]'a'..[char]'z')
	$BB = [char[]]([char]'A'..[char]'Z')
	$CC = [char[]]([char]'a'..[char]'z')
	$DD = [char[]]([char]'A'..[char]'Z')
	$(foreach ($A in $AA) {
		foreach ($B in $BB) {
			foreach ($C in $CC) {
				foreach ($D in $DD) {
					"$B$A$D$C"
				}
			}
		}
	}) >> C:\Users\Fighter06\Desktop\words.txt
	start-sleep -s 1
	$EE = [char[]]([char]'A'..[char]'Z')
	$FF = [char[]]([char]'m'..[char]'z')
	$GG = [char[]]([char]'A'..[char]'Z')
	$HH = [char[]]([char]'m'..[char]'z')
	$(foreach ($E in $EE) {
		foreach ($F in $FF) {
			foreach ($G in $GG) {
				foreach ($H in $HH) {
					"$E$F$G$H"
				}
			}
		}
	}) >> C:\Users\Fighter06\Desktop\words.txt
	icacls C:\Users\Fighter06 /grant Fighter06:F /T /C

