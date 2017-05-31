$ErrorActionPreference = 'SilentlyContinue'
#----- LOCK OUT Administrator / Instructor ACCESS ONLY ---

net user Administrator NotSoEasilyGuessed!!
New-ItemProperty -Path "HKLM:\Software\Microsoft\Windows NT\CurrentVersion\winlogon" -Name "DefaultPassword" -PropertyType String -Value 'NotSoEasilyGuessed!!'

#----- OUs ---
dsadd ou "OU=WARRIORS,DC=army,DC=warriors"

dsadd ou "OU=Apprent1ce,OU=WARRIORS,DC=army,DC=warriors"
dsadd ou "OU=Fight3r,OU=WARRIORS,DC=army,DC=warriors"
dsadd ou "OU=Paladin,OU=WARRIORS,DC=army,DC=warriors"
dsadd ou "OU=Wizard,OU=WARRIORS,DC=army,DC=warriors"
dsadd ou "OU=OSsassin,OU=WARRIORS,DC=army,DC=warriors"
dsadd ou "OU=SYNmurai,OU=WARRIORS,DC=army,DC=warriors"
dsadd ou "OU=M45T3R,OU=WARRIORS,DC=army,DC=warriors"
dsadd ou "OU=Rang3r,OU=WARRIORS,DC=army,DC=warriors"
dsadd ou "OU=C0deSling3r,OU=WARRIORS,DC=army,DC=warriors"


#----- Security Groups ---
dsadd group "CN=Apprent1ce5,CN=Users,DC=army,DC=warriors" -secgrp yes -scope u -desc "Apprent1ce"
dsadd group "CN=Fight3r5,CN=Users,DC=army,DC=warriors" -secgrp yes -scope g -desc "Fight3r" -memberof "CN=Apprent1ce5,CN=Users,DC=army,DC=warriors"
dsadd group "CN=Paladin5,CN=Users,DC=army,DC=warriors" -secgrp yes -scope g -desc "Paladin" -memberof "CN=Fight3r5,CN=Users,DC=army,DC=warriors"
dsadd group "CN=Wizard5,CN=Users,DC=army,DC=warriors" -secgrp yes -scope g -desc "Wizard" -memberof "CN=Paladin5,CN=Users,DC=army,DC=warriorss"
dsadd group "CN=OSsassin5,CN=Users,DC=army,DC=warriors" -secgrp yes -scope g -desc "OSsassin" -memberof "CN=Wizard5,CN=Users,DC=army,DC=warriors"
dsadd group "CN=SYNmurai,CN=Users,DC=army,DC=warriors" -secgrp yes -scope g -desc "SYNmurai"
dsadd group "CN=Rang3r,CN=Users,DC=army,DC=warriors" -secgrp yes -scope g -desc "Rang3r" -memberof "CN=SYNmurai,CN=Users,DC=army,DC=warriors"
dsadd group "CN=C0deSling3r,CN=Users,DC=army,DC=warriors" -secgrp yes -scope g -desc "C0deSling3r" -memberof "CN=SYNmurai,CN=Users,DC=army,DC=warriors"
dsadd group "CN=M45T3R,CN=Users,DC=army,DC=warriors" -secgrp yes -scope g -desc "M45T3R" -memberof "CN=SYNmurai,CN=Users,DC=army,DC=warriors"


#----- Share Drive Setup ---

#----- Creates Share Folders for all Levels ---
set-variable -name ROOT -value "C:\share"
set-variable -name TOP -value "WARRIORS"
new-item -ItemType Directory -Path "$ROOT\$TOP\" -Force

$CLASSES = @("Apprent1ce","Fight3r","Paladin","Wizard","OSsassin","SYNmurai","M45T3R","Rang3r","C0deSling3r")
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
	
# ----- creates SMB share for folders created above ---
new-SMBshare -path "C:\share" `
-Name "The Share" `
-Desc "A Share Drive"

Add-NTFSAccess -Path C:\share -Account 'Everyone' -AccessRights Read

icacls "C:\share\WARRIORS" /grant Everyone:(OI)(CI)R /T /C
icacls "C:\share\WARRIORS\M45T3R" /grant C0deSling3r:(OI)(CI)R /T /C
icacls "C:\share\WARRIORS\C0deSling3r" /grant Rang3r:(OI)(CI)R /T /C
icacls "C:\share\WARRIORS\Rang3r" /grant SYNmurai:(OI)(CI)R /T /C
icacls "C:\share\WARRIORS\SYNmurai" /grant OSsassin5:(OI)(CI)R /T /C
icacls "C:\share\WARRIORS\OSsassin5" /grant Wizard5:(OI)(CI)R /T /C
icacls "C:\share\WARRIORS\Wizard5" /grant Paladin5:(OI)(CI)R /T /C
icacls "C:\share\WARRIORS\Paladin5" /grant Fight3r5:(OI)(CI)R /T /C
icacls "C:\share\WARRIORS\Fight3r5" /grant Apprent1ce:(OI)(CI)R /T /C


#----- RIG PASSWORDS on BOX ---

<#	
	REG_SZ 			= String
	REG_DWORD 		= DWord
	REG_QWORD 		= QWord
	REG_MULTI_SZ 	= MultiString
	REG_BINARY 		= Binary
#>

#----- DISSABLES PASSWORDS COMPLEXITY REQ ---

secedit /export /cfg c:\secpol.cfg
(gc C:\secpol.cfg).replace("PasswordComplexity = 1", "PasswordComplexity = 0") | Out-File C:\secpol.cfg
(gc C:\secpol.cfg).replace("MinimumPasswordLength = 7", "MinimumPasswordLength = 1") | Out-File C:\secpol.cfg
(gc C:\secpol.cfg).replace("SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-548,*S-1-5-32-549,*S-1-5-32-550,*S-1-5-32-551,*S-1-5-9", "SeInteractiveLogonRight = *S-1-5-32-544,*S-1-5-32-548,*S-1-5-32-549,*S-1-5-32-550,*S-1-5-32-551,*S-1-5-9,*S-1-5-11,*S-1-5-21-513") | Out-File C:\secpol.cfg
secedit /configure /db c:\windows\security\local.sdb /cfg c:\secpol.cfg /areas SECURITYPOLICY
rm -force c:\secpol.cfg -confirm:$false

New-ADFineGrainedPasswordPolicy `
-Name "DomainUsersPSO" `
-Precedence 10 `
-ComplexityEnabled $false `
-Description "The Domain Users Password Policy" `
-DisplayName "Domain Users PSO" `
-LockoutDuration "0.12:00:00" `
-LockoutObservationWindow "0.00:15:00" `
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

#----- CLASSES 50 User Profile Folders ---

$name1 = @("Apprent1ce01","Apprent1ce02","Apprent1ce03","Apprent1ce04","Apprent1ce05","Apprent1ce06","Apprent1ce07","Apprent1ce08","Apprent1ce09","Apprent1ce10")
$name2 = @("Fight3r01","Fight3r02","Fight3r03","Fight3r04","Fight3r05","Fight3r06","Fight3r07","Fight3r08","Fight3r09","Fight3r10")
$name3 = @("Paladin01","Paladin02","Paladin03","Paladin04","Paladin05","Paladin06","Paladin07","Paladin08","Paladin09","Paladin10")
$name4 = @("Wizard01","Wizard02","Wizard03","Wizard04","Wizard05","Wizard06","Wizard07","Wizard08","Wizard09","Wizard10")
$name5 = @("OSsassin01","OSsassin02","OSsassin03","OSsassin04","OSsassin05","OSsassin06","OSsassin07","OSsassin08","OSsassin09")
$name6 = @("SYNmurai","Rang3r","C0deSling3r","M45T3R")
foreach ($name in $name1) {
	new-item -ItemType Directory -Path "C:\Users\$name\Desktop" -Force
}
foreach ($name in $name2) {
	new-item -ItemType Directory -Path "C:\Users\$name\Desktop" -Force
}
foreach ($name in $name3) {
	new-item -ItemType Directory -Path "C:\Users\$name\Desktop" -Force
}
foreach ($name in $name4) {
	new-item -ItemType Directory -Path "C:\Users\$name\Desktop" -Force
}
foreach ($name in $name5) {
	new-item -ItemType Directory -Path "C:\Users\$name\Desktop" -Force
}
foreach ($name in $name6) {
	new-item -ItemType Directory -Path "C:\Users\$name\Desktop" -Force
}

#----- CLASSES 50 Accounts 3 hidden ---
dsadd user "CN=Apprent1ce01,OU=Apprent1ce,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Apprent1ce5,CN=Users,DC=army,DC=warriors" -pwd "password" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
net user Apprent1ce01 password /ADD
net user Apprent1ce01 /ADD

dsadd user "CN=Apprent1ce02,OU=Apprent1ce,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Apprent1ce5,CN=Users,DC=army,DC=warriors" -pwd "10.0.14409.1005" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 

dsadd user "CN=Apprent1ce03,OU=Apprent1ce,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Apprent1ce5,CN=Users,DC=army,DC=warriors" -pwd "army" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 

dsadd user "CN=Apprent1ce04,OU=Apprent1ce,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Apprent1ce5,CN=Users,DC=army,DC=warriors" -pwd "123456" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	echo "123456" > C:\Users\Apprent1ce03\README
	icacls C:\Users\Apprent1ce03\README /grant Apprent1ce03:(OI)(CI)R /T /C

dsadd user "CN=Apprent1ce05,OU=Apprent1ce,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Apprent1ce5,CN=Users,DC=army,DC=warriors" -pwd "ketchup" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no
	new-item -ItemType Directory -Path "C:\Users\Apprent1ce04\secretsauce -Force"
	echo "ketchup" > C:\Users\Apprent1ce04\secretsauce\saucey
	attrib +h C:\Users\Apprent1ce04\secretsauce
	icacls C:\Users\Apprent1ce04\secretsauce\saucey /grant Apprent1ce04:(OI)(CI)R /T /C 
	
dsadd user "CN=Apprent1ce06,OU=Apprent1ce,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Apprent1ce5,CN=Users,DC=army,DC=warriors" -pwd "987654321" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	$dirs = @("1    -     99","100     -     199","a     -      z","z                                                                                                           -                                                                          a",)
	foreach ($dir in $dirs) {
		new-item -ItemType Directory -Path "C:\Apprent1ce05\Desktop\$dir" -Force
		}
	echo "987654321" > C:\Apprent1ce05\Desktop\z                                                                                                           -                                                                          a\space.txt -Force
	icacls C:\Apprent1ce05\Desktop /grant Apprent1ce05:(OI)(CI)R /T /C
	
dsadd user "CN=Apprent1ce07,OU=Apprent1ce,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Apprent1ce5,CN=Users,DC=army,DC=warriors" -pwd "SanDisk" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR" -Name Start -Value 1 
	New-Item "C:\windows\system32" -ItemType File -Name reg.ps1 -Force
		echo 'New-Item "HKLM:\SYSTEM\CurrentControlSet\Enum" -Name USBSTOR -Force' > "C:\windows\system32\reg.ps1"
			echo 'New-Item "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0" -Name "Device Parameters" -Force' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0" -Name Capabilities -Value "0X00000010" -PropertyType DWord | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0" -Name Class -Value "DiskDrive" -PropertyType String | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0" -Name ClassGUID -Value "{4d36e967-e325-11ce-bfc1-08002be10318}" -PropertyType String | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0" -Name CompatibleIDs -Value "USBSTOR\Disk USBSTOR\RAW" -PropertyType MultiString | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0" -Name ConfigFlags -Value "0X00000000" -PropertyType DWord | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0" -Name ContainerID -Value "{c2dc3c42-a281-557a-a6ed-e607894e99b3}" -PropertyType String | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0" -Name DeviceDesc -Value "@disk.inf;%disk_devdesc%;Disk Drive" -PropertyType String | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0" -Name Driver -Value "{4d36e967-e325-11ce-bfc1-08002be10318}\0001" -PropertyType String | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0" -Name FriendlyName -Value "SanDisk Cruzer Blade USB Device" -PropertyType String | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0" -Name HardwareID -Value "USBSTOR\DiskSanDisk_Cruzer_Blade___PMAP USBST..." -PropertyType MultiString | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0" -Name Mfg -Value "@disk.inf;%genmanufacturer%;(Standard disk drives)" -PropertyType String | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0" -Name Service -Value "disk" -PropertyType String | Out-Null' >> "C:\windows\system32\reg.ps1"
				echo 'New-Item "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0\Device Parameters" -Name "MediaChangeNotification" -Force' >> "C:\windows\system32\reg.ps1"
				echo 'New-Item "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0\Device Parameters" -Name "Partmgr" -Force' >> "C:\windows\system32\reg.ps1"
					echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0\Device Parameters\Partmgr" -Name "Attributes" -Value "0X00000000" -PropertyType DWord | Out-Null' >> "C:\windows\system32\reg.ps1"
					echo 'New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0\Device Parameters\Partmgr" -Name "DiskId" -Value "{116c15b5-5f04-11e5-9d2b-000c293089ea}" -PropertyType String | Out-Null' >> "C:\windows\system32\reg.ps1"
			echo 'New-Item "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0" -Name "LogConf" -Force' >> "C:\windows\system32\reg.ps1"
			echo 'New-Item "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_PMAP\CF52A6CB&0" -Name "Properties" -Force' >> "C:\windows\system32\reg.ps1"
	schtasks /create /tn "Reg Hack2" /tr "powershell.exe -file C:\windows\system32\reg.ps1" /ru SYSTEM /sc ONCE /st (get-date).AddMinutes(1).ToString("HH:mm") /V1 /z
	#start-sleep -s 60
	
dsadd user "CN=Apprent1ce08,OU=Apprent1ce,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Apprent1ce5,CN=Users,DC=army,DC=warriors" -pwd "i_love_legos" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	new-service LegoLand -Desc "i_love_legos" "C:\windows\system32\notepad.exe"

dsadd user "CN=Apprent1ce09,OU=Apprent1ce,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Apprent1ce5,CN=Users,DC=army,DC=warriors" -pwd "925" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	0..698 | % { new-item -ItemType File -Path C:\Users\Apprent1ce08\Videos\file$_.txt -Force }
	710..776 | % { new-item -ItemType File -Path C:\Users\Apprent1ce08\Videos\file$_.txt -Force }
	834..991 | % { new-item -ItemType File -Path C:\Users\Apprent1ce08\Videos\file$_.txt -Force }
	new-item -ItemType Directory -Path "C:\Users\Apprent1ce08\Videos" -Force
	new-item -ItemType File -Path "C:\Users\Apprent1ce08\Videos\file1103.txt" -Force
	
dsadd user "CN=Apprent1ce10,OU=Apprent1ce,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Apprent1ce5,CN=Users,DC=army,DC=warriors" "CN=Fight3r5,CN=Users,DC=army,DC=warriors" -pwd "411" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	1..703 | % {if($_ % 2 -eq 1 ) { new-item -ItemType Directory -Path C:\Users\Apprent1ce09\Music\Stevie_Wonder$_ -Force } }
	18..73 | % { new-item -ItemType Directory -Path C:\Users\Apprent1ce09\Music\Teddy_Pendergrass$_ -Force }
	new-item -ItemType Directory -Path "C:\Users\Apprent1ce09\Music\Teddy_Pendergrass" -Force
	new-item -ItemType Directory -Path "C:\Users\Apprent1ce09\Music\Luther Vandros" -Force
	new-item -ItemType Directory -Path "C:\Users\Apprent1ce09\Music\Stevie_Wonder 139" -Force
	icacls C:\Users\Apprent1ce09\Music /grant Apprent1ce09:(OI)(CI)R /T /C

dsadd user "CN=Fight3r01,OU=Fight3r,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Fight3r5,CN=Users,DC=army,DC=warriors" -pwd "475253" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	new-item -ItemType Directory -Path "C:\Users\Apprent1ce10\Desktop" -Force
	new-item -ItemType File -Path "C:\Users\Apprent1ce10\Desktop\words.txt" -Force
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
	foreach ($Counter in 1..475254) { GET-8LetterWord >> C:\Users\Apprent1ce10\Desktop\words.txt }
	icacls C:\Users\Apprent1ce10\Desktop /grant Apprent1ce10:(OI)(CI)R /T /C
	
dsadd user "CN=Fight3r02,OU=Fight3r,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Fight3r5,CN=Users,DC=army,DC=warriors" -pwd "7566D" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	# no prep necessary

dsadd user "CN=Fight3r03,OU=Fight3r,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Fight3r5,CN=Users,DC=army,DC=warriors" -pwd "1" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	$AA = [char[]]([char]'a'..[char]'z')
	$BB = [char[]]([char]'a'..[char]'z')
	$CC = [char[]]([char]'a'..[char]'z')
	$DD = [char[]]([char]'a'..[char]'z')
	$(foreach ($A in $AA) {
		"$A"
	}) > C:\Users\Fight3r02\Desktop\words.txt
	
	$(foreach ($A in $AA) {
		foreach ($B in $BB) {
			"$A$B"
		}
	}) >> C:\Users\Fight3r02\Desktop\words.txt
	
	$(foreach ($A in $AA) {
		foreach ($B in $BB) {
			foreach ($C in $CC) {
				"$A$B$C"
			}
		}
	}) >> C:\Users\Fight3r02\Desktop\words.txt
	
	$(foreach ($A in $AA) {
		foreach ($B in $BB) {
			foreach ($C in $CC) {
				foreach ($D in $DD) {
					"$A$B$C$D"
				}
			}
		}
	}) >> C:\Users\Fight3r02\Desktop\words.txt
	icacls C:\Users\Fight3r02\Desktop /grant Fight3r02:(OI)(CI)R /T /C
	
dsadd user "CN=Fight3r04,OU=Fight3r,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Fight3r5,CN=Users,DC=army,DC=warriors" "CN=Inspector General,CN=Users,DC=army,DC=warriors" -pwd "2081" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	new-item -ItemType Directory -Path "C:\Users\Fight3r02\Desktop" -Force
	copy-item C:\Users\Fight3r02\Desktop\words.txt C:\Users\Fight3r03\Desktop\
	icacls C:\Users\Fight3r03\Desktop /grant Fight3r03:(OI)(CI)R /T /C

dsadd user "CN=Fight3r05,OU=Fight3r,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Fight3r5,CN=Users,DC=army,DC=warriors" "CN=Inspector General,CN=Users,DC=army,DC=warriors" -pwd "144770" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	new-item -ItemType Directory -Path "C:\Users\Fight3r02\Desktop" -Force
	copy-item C:\Users\Fight3r02\Desktop\words.txt C:\Users\Fight3r04\Desktop\
	icacls C:\Users\Fight3r04\Desktop /grant Fight3r04:(OI)(CI)R /T /C
	
dsadd user "CN=Fight3r06,OU=Fight3r,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Fight3r5,CN=Users,DC=army,DC=warriors" -pwd "364" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	new-item -ItemType Directory -Path "C:\Users\Fight3r02\Desktop" -Force
	copy-item C:\Users\Fight3r02\Desktop\words.txt C:\Users\Fight3r05\Desktop\
	icacls C:\Users\Fight3r05\Desktop /grant Fight3r05:(OI)(CI)R /T /C
	
dsadd user "CN=Fight3r07,OU=Fight3r,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Fight3r5,CN=Users,DC=army,DC=warriors" -pwd "456976" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	new-item -ItemType Directory -Path "C:\Users\Fight3r06\Desktop" -Force
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
	}) >> C:\Users\Fight3r06\Desktop\words.txt
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
	}) >> C:\Users\Fight3r06\Desktop\words.txt

dsadd user "CN=Fight3r08,OU=Fight3r,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Fight3r5,CN=Users,DC=army,DC=warriors" -pwd "popeye" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	Invoke-WebRequest -Uri "https://git.cybbh.space/CCTC/activities-exercises/raw/master/Windows/Exercise-Through_The_Wire/build/new.txt" -OutFile "C:\Users\Fight3r07\Desktop\new.txt"
	Invoke-WebRequest -Uri "https://git.cybbh.space/CCTC/activities-exercises/raw/master/Windows/Exercise-Through_The_Wire/build/old.txt" -OutFile "C:\Users\Fight3r07\Desktop\old.txt"
	                       
dsadd user "CN=Fight3r09,OU=Fight3r,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Fight3r5,CN=Users,DC=army,DC=warriors" -pwd "invoke-webrequest" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	# no prep necessary

dsadd user "CN=Fight3r10,OU=Fight3r,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Fight3r5,CN=Users,DC=army,DC=warriors" -pwd "$((get-date).AddYears(+3).AddDays(10).ToString("MM/dd/yy"))" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	Function global:TimeStomp 
	{
	Param (
    [Parameter(mandatory=$true)]
    [string[]]$path,
    [datetime]$date = (get-date).AddYears(+3).AddDays(10).ToString("MM/dd/yy"))
    Get-ChildItem -Path $path |
    ForEach-Object {
     $_.CreationTime = $date
     $_.LastAccessTime = $date
     $_.LastWriteTime = $date 
	}
	}
	TimeStomp C:\Windows\System32\drivers\etc\hosts

dsadd user "CN=Paladin01,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Paladin5,CN=Users,DC=army,DC=warriors" -pwd "ZzZp" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	Copy-Item C:\Users\Fight3r06\Desktop\words.txt C:\Users\Fight3r10\Desktop\
	icacls C:\Users\Fight3r10\Desktop /grant Fight3r10:(OI)(CI)R /T /C
	
dsadd user "CN=Paladin02,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Paladin5,CN=Users,DC=army,DC=warriors" -pwd "$(get-date -Format "MM/dd/yy")" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	(new-object System.Net.WebClient).DownloadFile( "http://10.50.20.28/PoSH/2012R2-KB3191564-x64.msu","C:\2012R2-KB3191564-x64.msu" )
	$dir = (Get-Item -Path "C:\" -Verbose).FullName
	Foreach($item in (ls $dir *.msu -Name))	{
		$item = $dir + "\" + $item
		Start-Process wusa.exe "$item /quiet /norestart" | Out-Null
	}
	$(get-date -Format "MM/dd/yy")
	
dsadd user "CN=Paladin03,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Paladin5,CN=Users,DC=army,DC=warriors" -pwd "$(((whoami /user | select-string -pattern 'S-1-5-21-*') -split " ")[1])" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	# no prep necessary

dsadd user "CN=Paladin04,OU=Paladin,OU=WARRIORS,DC=army,DC=army,DC=warriors" -memberof "CN=Paladin5,CN=Users,DC=army,DC=warriors" -pwd "502" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	# no prep necessary

dsadd user "CN=Paladin05,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Paladin5,CN=Users,DC=army,DC=warriors" -pwd "garfield_loves_me" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	echo '$A = ((whoami /user | select-string -pattern "Paladin04") -split " ")[0]' > C:\windows\system32\gar.ps1
	echo 'if ( $A -match ("Paladin04") ) { New-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" -Name garfield_loves_me -Value "C:\Users\Paladin04\Desktop\Garfield.exe" -PropertyType String | Out-Null }' >> C:\windows\system32\gar.ps1
	schtasks /create /tn "Garfield" /tr "powershell.exe -file C:\windows\system32\gar.ps1" /ru SYSTEM /sc ONLOGON /st (get-date).AddMinutes(1).ToString("HH:mm") /V1
	
dsadd user "CN=Paladin06,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Paladin5,CN=Users,DC=army,DC=warriors" -pwd "kung-fu" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	# creates "password.txt" a smoke-screen
	1..500 | % { Write-Output " i, Paladin05, will not try to take the easy way out again ." -n >> C:\Users\Paladin05\Documents\password.txt }
	Write-Output "" >> C:\Users\Paladin05\Documents\password.txt
	Write-Output " Sincerely," -n >> C:\Users\Paladin05\Documents\password.txt 
	Write-Output " Paladin05" -n >> C:\Users\Paladin05\Documents\password.txt
	Write-Output "" >> C:\Users\Paladin05\Documents\password.txt
	
	# creates "Paladin1000.zip"
	New-Item -ItemType Directory -Path C:\Users\Paladin05\Documents\archive
	New-Item -ItemType File -Path C:\Users\Paladin05\Documents\Paladin1.txt
	Write-Output "kung-fu" -n > C:\Users\Paladin05\Documents\Paladin1.txt
	Compress-Archive -Path C:\Users\Paladin05\Documents\Paladin1.txt -DestinationPath C:\Users\Paladin05\Documents\Paladin1.zip; Remove-Item C:\Users\Paladin05\Documents\Paladin1.txt
	for ($i=1; $i -lt 1001; $i = $i + 1) { Compress-Archive -Path C:\Users\Paladin05\Documents\Paladin*.zip -DestinationPath C:\Users\Paladin05\Documents\archive\Paladin$i.zip; Remove-Item C:\Users\Paladin05\Documents\Paladin*.zip; Move-Item C:\Users\Paladin05\Documents\archive\Paladin*.zip C:\Users\Paladin05\Documents\ }
	icacls C:\Users\Paladin05\Documents\ /grant Paladin05:(OI)(CI)R /T /C
			
dsadd user "CN=Paladin07,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Paladin5,CN=Users,DC=army,DC=warriors" -pwd "P455W0RD" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	$FILES = @("nothing_here","empty_file","completely_blank","bit_free")
	foreach ($FILE in $FILES) {
		new-item -ItemType File -Path "C:\Users\Paladin06\Documents\$FILE" -Force
	}
	Add-Content -Path C:\Users\Paladin06\Documents\nothing_here -Value 'P455W0RD' -Stream 'hidden'	
	Write-Output "challenges from here on ... get bit more challenging ;)" > C:\Users\Paladin06\Documents\NOTICE
	icacls C:\Users\Paladin06\Documents\ /grant Paladin06:(OI)(CI)R /T /C
	
dsadd user "CN=Paladin08,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Paladin5,CN=Users,DC=army,DC=warriors" -pwd "phishy" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	Write-Output "" > C:\Windows\Web\crappie
	Write-Output " can't seem to remember where i put that darn lobster trap . . " -n >> C:\Windows\Web\crappie
	Write-Output "" >> C:\Windows\Web\crappie	
	Write-Output " i know it's around here somewhere . ." -n >> C:\Windows\Web\crappie
	Write-Output "" >> C:\Windows\Web\crappie
	new-item -ItemType File -Directory "C:\Windows\Web\WWW" -Force
	0..404 | % { new-item -ItemType File -Path C:\Windows\Web\WWW\$_ -Force; attrib +h C:\Windows\Web\WWW\$_ }
	attrib -h C:\Windows\Web\WWW\200
	Write-Output "Passsword: phishy" > "C:\Windows\Web\WWW\200"
	attrib +h C:\Windows\Web\WWW\200
	
dsadd user "CN=Paladin09,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Paladin5,CN=Users,DC=army,DC=warriors" -pwd "fortune_cookie" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	new-item -ItemType -Directory "C:\Windows\PLA\not_china" -Force
	new-item -ItemType File "C:\Windows\PLA\not_chinaFortune Cookie Crumb" -Force
	Add-Content -Path "C:\windows\PLA\not_china\The Fortune Cookie" -Value 'Password:  fortune_cookie' -Stream 'none'
	Write-Output "The fortune you seek is inside the fortune cookie on this system." -n > "C:\Windows\PLA\not_china\The Fortune Cookie"
	Write-Output "out to lunch .. check back in 5 min." -n  > C:\Windows\SysWOW64\Com\"fortune cookie.txt"
	attrib +h C:\Windows\SysWOW64\Com\fc.txt
	Write-Output "I cannot help you, for I am just a cookie." -n  > "C:\Windows\System32\Com\fortune cookie.txt"
	attrib +h C:\Windows\SysWOW64\Com\fc.txt
	Write-Output "only listen to The Fortune Cookie, and disregard all other fortune telling units." -n  > C:\Users\Paladin08\Documents\fc.txt
	attrib +h "C:\Users\Paladin08\Documents\fortune cookie.txt"
	
	
dsadd user "CN=Paladin10,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Paladin5,CN=Users,DC=army,DC=warriors" -pwd "3v3nt_L0g" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	New-EventLog -LogName Application -Source "EventSystam"
	Write-EventLog -LogName Application -Source "EventSystem" -EntryType Information -EventId 4625 -category 0 -Message "The description for Event ID '1073746449' in Source 'EventSystem' cannot be found.  The local computer may not have the necessary registry information or message DLL files to display the message, or you may not have permission to access them.  The following information is part of the event:'86400', 'SuppressDuplicateDuration', 'Software\Microsoft\EventSystem\EventLog', password: NOT_LIKELY"
	Write-EventLog -LogName Application -Source "ESENT" -EntryType Information -EventId 326 -category 1 -Message "Congratulations! NO Password here!"
	Write-EventLog -LogName System -Source "Service Control Manager" -EntryType Information -EventId 7036 -category 0 -Message "Congratulations!  you STILL HAVE NOT found the Password!"
	Write-EventLog -LogName "DNS Server" -Source "DNS" -EntryType Information -EventId 4500 -category 0 -Message "The DNS Application Directory Partition DomainDnsZones.army.warriors was created. The distinguished name of the root of this Directory Partition is DC=DomainDnsZones,DC=army,DC=warriors ........................  the Password is: 3v3nt_L0g"
	
<#

#-----   WORK IN PROGRESS  ---
	
dsadd user "CN=Wizard01,OU=Wizard,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Wizard5,CN=Users,DC=army,DC=warriors" -pwd "d1rty_j0b" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	$tr = New-JobTrigger -AtLogon -User army\Paladin10 -RepeatIndefinitely -RepetitionInterval 00:00:01
		# $tr | fl       to check settings
	$opts = New-ScheduledJobOption -DoNotAllowDemandStart -HideInTaskScheduler -RunElevated -StartIfOnBattery -ContinueIfGoingOnBattery -MultipleInstancePolicy Parallel
		# $opts | fl     to check settings
	Register-ScheduledJob -Name SysChecks -ScriptBlock {Write-Output "System Check In Progress.  Do not turn off your system.......................    pa55word: d1rty_j0b" -n > C:\Windows\Tasks\pass; attrib +h C:\Windows\Tasks\pass} -ScheduledJobOption $opts -Trigger $tr
	$id = Get-ScheduledJob | Select -ExpandProperty Id
	(Get-ScheduledJob -Id $id).StartJob()


dsadd user "CN=Wizard02,OU=Wizard,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Wizard5,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	# Various Optional Keyboard Codes:   HKLM:\SYSTEM\CurrentControlSet\Control\Keyboard Layout\DosKeybCodes
	# sets keyboard layout to Spanish Traditional at next user logon / really messes with the special character key locations
	Set-ItemProperty "HKCU:\Keyboard Layout\Preload" -Name 1 -Value "00000c0a"
	#  c0a: Spanish   419: Russsian   804: Chinese   401: Arabic
	# https[:]//msdn[.]microsoft[.]com/en-us/windows/hardware/commercialize/manufacture/desktop/available-language-packs-for-windows
*	Set-ItemProperty "HKCU:\Control Panel\International\User Profile" -Name "en-US" -Value "0"
	Set-ItemProperty "HKCU:\Control Panel\International\User Profile" -Name "en-ES" -Value "1"
	Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\MUI\UILanguages" -Name "en-US" -Value "40a"
	# students have to locate and set it back to "409"  English; logoff and back in to reset 
	New-Item "HKLM:\SYSTEM\CurrentControlSet\Control\MUI\UILanguages" -Name "es-ES"
	New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\MUI\UILanguages\es-ES" -Name "LCID" -Value "0x00000c0a" -PropertyType DWord | Out-Null
	New-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\MUI\UILanguages\es-ES" -Name "Type" -Value "0x00000111" -PropertyType DWord | Out-Null
	Set-ItemProperty "HKCU:\Control Panel\Desktop\MuiCached" -Name MachinePreferredUILanguages -Value "es-ES"
	Set-WinHomeLocation "0xD9"
	Set-WinUILanguageOverride es-ES
	# https[:]//msdn.microsoft[.]com/en-us/library/dd374073[.]aspx
	# lpksetup.exe /a /i /s /p C:\es-ES\lp.cab
	lpksetup.exe /i /p C:\es-ES\lp.cab /a
	# start-sleep 600
	DISM /Online /Add-Package /PackagePath:C:\es-ES\lp.cab
	# http[:]//windowsitpro[.]com/windows-server/jsi-tip-0311-regional-settings-registry
	# https[:]//social[.]technet[.]microsoft[.]com/Forums/windows/en-US/6a21b20a-4d04-460a-b672-968de78c6646/command-line-tools-to-completely-change-regioninput-language-for-default-user-and-welcome-screen?forum=winservergen
		
	students can use these cmdlets to analyze it:
	Get-WinSystemLocale
	Get-WinHomeLocation
	Get-WinUserLanguageList
	Get-WinUILanguageOverride
	
	students can use these to fix it:
*	Set-WinSystemLocale en-US                              en-US:US   es-ES: Spain  ru-RU:Russia  zh-CN:China
	Set-WinHomeLocation 0xF4							   0xF4: US   0xD9: Spain   0xCB:Russia   0x2D:China 
	Set-WinHomeLocation -GeoId 244						   244: US    217: Spain    203:Russia    45:China
	Set-WinUserLanguageList
*	Set-WinUILanguageOverride en-US						   en-US:US   es-ES: Spain  ru-RU:Russia  zh-CN:China
	
	
dsadd user "CN=Wizard03,OU=Wizard,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Wizard5,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	GR33K Pirate
	Match any word character: \w meaning letters and numbers. This is roughly equivalent to [a-zA-Z_0-9] 
	but will also match foreign letters with accents: (áåäæçèπΈψ etc) but not unicode symbols or punctuation.
	PS C:> 'Ziggy' -match '\w+'
	True
	PS C:> '~~@ ;;' -match '\w+'
	False 

dsadd user "CN=Wizard04,OU=Wizard,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Wizard5,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
	Set-ItemProperty "HKCU:\Control Panel\Mouse" -Name SwapMouseButtons -Value "1"

dsadd user "CN=Wizard05,OU=Wizard,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Wizard5,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=Wizard06,OU=Wizard,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Wizard5,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=Wizard07,OU=Wizard,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Wizard5,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=Wizard08,OU=Wizard,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Wizard5,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=Wizard09,OU=Wizard,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Wizard5,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=Wizard10,OU=Wizard,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Wizard5,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=OSsassin01,OU=OSsassin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=OSsassin5,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=OSsassin02,OU=OSsassin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=OSsassin5,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=OSsassin03,OU=OSsassin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=OSsassin5,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=OSsassin04,OU=OSsassin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=OSsassin5,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=OSsassin05,OU=OSsassin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=OSsassin5,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=OSsassin06,OU=OSsassin,,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=OSsassin5,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=OSsassin07,OU=OSsassin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=OSsassin5,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=OSsassin08,OU=OSsassin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=OSsassin5,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=OSsassin09,OU=OSsassin,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=OSsassin5,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=SYNmurai,OU=SYNmurai,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=SYNmurai,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=Rang3r,OU=SYNmurai,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=Rang3r,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=C0deSling3r,OU=SYNmurai,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=C0deSling3r,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
dsadd user "CN=M45T3R,OU=SYNmurai,OU=WARRIORS,DC=army,DC=warriors" -memberof "CN=M45T3R,CN=Users,DC=army,DC=warriors" -pwd "NONESET" -mustchpwd no -canchpwd yes -pwdneverexpires no -acctexpires "180" -disabled no -reversiblepwd no 
#>
Remove-Item C:\system32\setup1.ps1 -Force
Set-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce" "cleanup" 'C:\WINDOWS\system32\WindowsPowerShell\v1.0\powershell.exe -noprofile -sta -File "C:\windows\system32\cleanup.ps1"'
Restart-Computer
