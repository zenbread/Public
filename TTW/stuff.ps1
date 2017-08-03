dsmod user "CN=Fighter08,OU=Fighter,OU=WARRIORS,DC=army,DC=warriors" -pwd "popeye"
	Write-Output "The password for the next level is the name of the built-in cmdlet that performs the wget like function on a Windows system." -n > C:\Users\Fighter08\Desktop\challenge.txt
	Invoke-WebRequest -Uri "https://raw.githubusercontent.com/D4NP0UL1N/Public/master/TTW/new.txt" -OutFile "C:\Users\Fighter07\Downloads\new.txt"
	Invoke-WebRequest -Uri "https://raw.githubusercontent.com/D4NP0UL1N/Public/master/TTW/old.txt" -OutFile "C:\Users\Fighter07\Downloads\old.txt"
	icacls C:\Users\Fighter07 /grant Fighter07:F /T /C
	
dsmod user "CN=Fighter09,OU=Fighter,OU=WARRIORS,DC=army,DC=warriors" -pwd "invoke-webrequest"
	Write-Output "The password for the next level is the last access time of the hosts file.  Note - format for the password is 2 digit month, 2 digit day, 2 digit year. Ex 5 jan 2015 would be 01/05/15." -n > C:\Users\Fighter09\Desktop\challenge.txt
	# no prep necessary

dsmod user "CN=Fighter10,OU=Fighter,OU=WARRIORS,DC=army,DC=warriors" -pwd "$((get-date).AddYears(+3).AddDays(10).ToString("MM/dd/yy"))"
	Write-Output "The password for the next level is the 21st line from the top in ASCII-sorted, descending order of the file on the desktop." -n > C:\Users\Fighter10\Desktop\challenge.txt
	Write-Output "Note: Next Level Login - Paladin01" -n >> C:\Users\Fighter10\Desktop\challenge.txt
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

dsmod user "CN=Paladin01,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -pwd "ZzZp"
	Write-Output "The password for the next level is the date KB3200970 was installed on the server.  Note - format for the password is 2 digit month, 2 digit day, 4 digit year. Ex 5 jan 2015 would be 01/05/2015" -n > C:\Users\Paladin01\Desktop\challenge.txt
	Copy-Item C:\Users\Fighter06\Desktop\words.txt C:\Users\Fighter10\Desktop\
	icacls C:\Users\Fighter10 /grant Fighter10:F /T /C
	
#dsmod user "CN=Paladin02,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -pwd "$((((Get-HotFix –ID KB3200970 | select Installedon) -split ' ')[0] -split '=')[1])"
dsmod user "CN=Paladin02,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -pwd "11/21/2016"
	Write-Output "The password for the next level is the SID of the current user. Example  S-1-5-21-1004336348-1177238915-[682003330]-1000" -n > C:\Users\Paladin02\Desktop\challenge.txt
	
dsmod user "CN=Paladin03,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -pwd "$(((wmic useraccount list brief | select-string 'Paladin02') -split '-')[6])"
	Write-Output "The password for the next level is the RID of the 'krbtgt' account. Example  S-1-5-21-1004336348-1177238915-682003330-[501]" -n > C:\Users\Paladin03\Desktop\challenge.txt
	# no prep necessary
  
dsmod user "CN=Paladin04,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -pwd "502"
	Write-Output "The password for the next level is the SID of the only Totally-Legit service. Example  S-1-5-80-159957745-2084983471-2137709666-960844832-[1182961511]" -n > C:\Users\Paladin04\Desktop\challenge.txt
	# no prep necessary
	
dsmod user "CN=Paladin05,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -pwd "$(((cmd.exe /c "sc showsid Legit") -split "-")[10])"
	Write-Output "The password for the next level is the name of the program that is set to start at logon." -n > C:\Users\Paladin05\Desktop\challenge.txt
	cmd.exe /c "sc create Legit binpath= C:\windows\system32\kbd101f.cmd start= auto DisplayName= Totally-Legit type= own"
	
dsmod user "CN=Paladin06,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -pwd "yes"
	Write-Output "The password for the next level is in the zip file." -n > C:\Users\Paladin06\Desktop\challenge.txt
	echo "$A = (((wmic useraccount list brief | select-string 'Paladin05') -split "\\")[1] -split " ")[0]" > C:\windows\system32\schd.ps1
	echo "if ( $A -match ('Paladin05') ) { New-ItemProperty "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -Name yes -Value "C:\Users\Paladin05\Desktop\no.exe" -PropertyType String | Out-Null}" >> C:\windows\system32\schd.ps1
	$tr = New-JobTrigger -AtLogon -User army\Paladin05
	$opts = New-ScheduledJobOption -HideInTaskScheduler -RunElevated -StartIfOnBattery -ContinueIfGoingOnBattery
	Register-ScheduledJob -Name Paladin05 -FilePath  C:\windows\system32\schd.ps1 -ScheduledJobOption $opts -Trigger $tr		
			
dsmod user "CN=Paladin07,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -pwd "kung-fu"
	Write-Output "The password for the next level is hidden in the users profile." -n > C:\Users\Paladin07\Desktop\challenge.txt
	# creates "password.txt" a smoke-screen
	1..500 | % { Write-Output " i, Paladin06, will not try to take the easy way out again ." -n >> C:\Users\Paladin06\Documents\password.txt }
	Write-Output "" >> C:\Users\Paladin06\Documents\password.txt
	Write-Output " Sincerely," -n >> C:\Users\Paladin06\Documents\password.txt 
	Write-Output " Paladin06" -n >> C:\Users\Paladin06\Documents\password.txt
	Write-Output "" >> C:\Users\Paladin06\Documents\password.txt
	# creates "Paladin1000.zip"
	New-Item -ItemType Directory -Path C:\Users\Paladin06\Documents\archive
	New-Item -ItemType File -Path C:\Users\Paladin06\Documents\Paladin1.txt
	Write-Output "kung-fu" -n > C:\Users\Paladin06\Documents\Paladin1.txt
	Compress-Archive -Path C:\Users\Paladin06\Documents\Paladin1.txt -DestinationPath C:\Users\Paladin06\Documents\Paladin1.zip; Remove-Item C:\Users\Paladin06\Documents\Paladin1.txt
	for ($i=1; $i -lt 1001; $i = $i + 1) { 
	Compress-Archive -Path C:\Users\Paladin06\Documents\Paladin*.zip -DestinationPath C:\Users\Paladin06\Documents\archive\Paladin$i.zip; Remove-Item C:\Users\Paladin06\Documents\Paladin*.zip; Move-Item C:\Users\Paladin06\Documents\archive\Paladin*.zip C:\Users\Paladin06\Documents\; 
	}
	Remove-Item C:\Users\Paladin06\Documents\archive -force
	icacls C:\Users\Paladin06 /grant Paladin06:F /T /C
	
dsmod user "CN=Paladin08,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -pwd "P455W0RD"
	Write-Output "Challenge Hint - its a crappie site, but someones gotta phish it.." -n > C:\Users\Paladin08\Desktop\challenge.txt
	$FILES = @("nothing_here","empty_file","completely_blank","bit_free")
	foreach ($FILE in $FILES) {
		new-item -ItemType File -Path "C:\Users\Paladin07\Documents\$FILE" -Force
	}
	Add-Content -Path C:\Users\Paladin07\Documents\nothing_here -Value "P455W0RD" -Stream "hidden"	
	Write-Output "challenges from here on ... get bit more challenging" > C:\Users\Paladin07\Documents\NOTICE
	icacls C:\Users\Paladin07 /grant Paladin07:F /T /C
		
dsmod user "CN=Paladin09,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -pwd "phi5hy" 
	Write-Output "Challenge Hint - Beijing to deny any knowledge of injecting cookies onto our systems . ." -n > C:\Users\Paladin09\Desktop\challenge.txt
	Write-Output "" > C:\Windows\Web\crappie
	Write-Output " can not seem to remember where i put that darn lobster trap . . " -n >> C:\Windows\Web\crappie
	Write-Output "" >> C:\Windows\Web\crappie	
	Write-Output " i know it is around here somewhere . ." -n >> C:\Windows\Web\crappie
	Write-Output "" >> C:\Windows\Web\crappie
	new-item -ItemType Directory "C:\Windows\Web\WWW" -Force
	new-item -ItemType File "C:\Windows\Web\WWW" -name "getting warmer" -Force
	0..404 | % { new-item -ItemType File -Path C:\Windows\Web\WWW\$_ -Force; attrib +h C:\Windows\Web\WWW\$_ }
	attrib -h C:\Windows\Web\WWW\200
	Write-Output "Passsword: phi5hy" > "C:\Windows\Web\WWW\200"
	attrib +h C:\Windows\Web\WWW\200
	
dsmod user "CN=Paladin10,OU=Paladin,OU=WARRIORS,DC=army,DC=warriors" -pwd "fortune_cookie" 
	Write-Output "Challenge Hint - let it be logged ..  the password is somewhere on this system . ." -n > C:\Users\Paladin10\Desktop\challenge.txt
	Write-Output "Note: Next Level Login - ??????" -n >> C:\Users\Paladin10\Desktop\challenge.txt
	new-item -ItemType Directory "C:\Windows\PLA\not_china" -Force
	new-item -ItemType File "C:\Windows\PLA\not_china\Fortune Cookie Crumb" -Force
	Write-Output "find the hidden fortune cookie.s . . " -n > "C:\Windows\PLA\not_china\Fortune Cookie Crumb"
	Add-Content -Path "C:\windows\PLA\not_china\The Fortune Cookie" -Value "Password:  fortune_cookie" -Stream "none"
	Write-Output "The fortune you seek is inside the fortune cookie on this system." -n > "C:\Windows\PLA\not_china\The Fortune Cookie"
	Write-Output "out to lunch .. check back in 5 min." -n  > C:\Windows\SysWOW64\Com\"fortune cookie.txt"
	attrib +h "C:\Windows\SysWOW64\Com\fortune cookie.txt"
	Write-Output "I cannot help you, for I am just a cookie." -n  > "C:\Windows\System32\Com\fortune cookie.txt"
	attrib +h "C:\Windows\System32\Com\fortune cookie.txt"
	Write-Output "only listen to The Fortune Cookie, and disregard all other fortune telling units." -n  > "C:\Users\Paladin09\Documents\fortune cookie.txt"
	attrib +h "C:\Users\Paladin09\Documents\fortune cookie.txt"


dsmod user "CN=Wizard01,OU=Wizard,OU=WARRIORS,DC=army,DC=warriors" -pwd "3v3nt_L0g"
	Write-Output "Challenge Hint - This Windows File System Filter finished dead last . ." -n > C:\Users\Wizard1\Desktop\challenge.txt
	Write-EventLog -LogName "Application" -Source "EventSystem" -EntryType Information -EventId "4625" -category 0 -Message "The description for Event ID '1073746449' in Source EventSystem cannot be found.  The local computer may not have the necessary registry information or message DLL files to display the message, or you may not have permission to access them.  The following information is part of the event:'86400', SuppressDuplicateDuration, Software\Microsoft\EventSystem\EventLog, password: NOT_LIKELY"
	Write-EventLog -LogName "Application" -Source "ESENT" -EntryType Information -EventId "326" -category 1 -Message "Congratulations! NO Password here!"
	Write-EventLog -LogName "System" -Source "Service Control Manager" -EntryType Information -EventId "7036" -category 0 -Message "Congratulations!  you STILL HAVE NOT found the Password"
	Write-EventLog -LogName "Application" -Source "ESENT" -EntryType Information -EventId "326" -category 1 -Message "The DNS Application Directory Partition DomainDnsZones.army.warriors was created. The distinguished name of the root of this Directory Partition is DC=DomainDnsZones,DC=army,DC=warriors ........................  the Password is: 3v3nt_L0g"

dsmod user "CN=Wizard02,OU=Wizard,OU=WARRIORS,DC=army,DC=warriors" -pwd "Top" 
	Write-Output "Challenge Hint - It is a dirty job, but someone has gotta do it"	-n > C:\Users\Wizard02\Desktop\challenge.txt
	# solution: (((Get-ItemProperty -Path "hklm:\system\currentcontrolset\control\servicegrouporder").List) | select-string FSFilter) -last
				   	
dsmod user "CN=Wizard03,OU=Wizard,OU=WARRIORS,DC=army,DC=warriors" -pwd "d1rty_j0b" 
	Write-Output "Challenge Hint - Arrr! thar be ΘΗΣΑΥΡΟΣ burried in the Share . ." -n > C:\Users\Wizard03\Desktop\challenge.txt
	echo "$B = (((wmic useraccount list brief | select-string 'Wizard02') -split '\\')[1] -split ' ')[0]" > C:\Windows\Resources\system.ps1
	echo "if ( $B -match ('Wizard02')) {write-output 'PASSWORD:  d1rty_j0b' > C:\Users\Wizard02\Desktop\PASSWORD.txt}" >> C:\Windows\Resources\system.ps1
		
	$username = army\Wizard02
	$password = ConvertTo-SecureString -String "Top" -AsPlainText -Force
	$Creds = New-Object System.Management.Automation.PSCredential -ArgumentList ($username,$password)
	
	$tr = New-JobTrigger -Once -RepeatIndefinitely -RepetitionInterval 00:01:05 -At $(date)
	$opts = New-ScheduledJobOption -StartIfOnBattery -ContinueIfGoingOnBattery
	Register-ScheduledJob -Name "RunMe" -FilePath C:\Windows\Resources\system.ps1 -RunNow -Credential $Creds
	Disable-ScheduledJob -Name "RunMe"
	cp C:\Users\Administrator\AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\RunMe  C:\Users\Wizard02\AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\
	icacls C:\Windows\System32\Tasks /grant Wizard02:RX /T /C
	icacls C:\Windows\System32\Tasks\Microsoft\Windows\PowerShell\ScheduledJobs /grant Wizard02:M /T /C

dsmod user "CN=Wizard04,OU=Wizard,OU=WARRIORS,DC=army,DC=warriors" -pwd "b00ty"
	Write-Output "Arrgh!  fools gold!  Blast!  " -n > "C:\share\WARRIORS\OSsassin\2\HOME\1\HOME\8\B00ty"
	attrib +s +h C:\share\WARRIORS\OSsassin\2\HOME\1\HOME\8\B00ty
	Write-Output "Arrgh!  just some old boot!  " -n > "C:\share\WARRIORS\SYNmurai\8\HOME\3\HOME\7\booty"
	attrib +s +h C:\share\WARRIORS\SYNmurai\8\HOME\3\HOME\7\booty
	Write-Output "Arrgh!  just some old boot!  " -n > "C:\share\WARRIORS\CodeSlinger\3\HOME\4\HOME\5\BOOTY"
	attrib +s +h C:\share\WARRIORS\CodeSlinger\3\HOME\4\HOME\5\BOOTY
	Write-Output "Arr!  Well Done Matey!  p@ss_w0rd - Gawld" -n > "C:\share\WARRIORS\Rang3r\8\HOME\3\HOME\9\ΒΘΘΤΨ"
	Write-Output "Congratulations! You have completed the exercise!" -n > "C:\share\WARRIORS\Rang3r\8\HOME\3\HOME\9\ΒΘΘΤΨ"
	attrib +s +h C:\share\WARRIORS\Rang3r\8\HOME\3\HOME\9\ΒΘΘΤΨ
	icacls "C:\share\WARRIORS" /grant Wizard03:R /T /C
	
attrib +h +s C:\Users\SYNmurai
attrib +h +s C:\Users\MASTER
attrib +h +s C:\Users\CodeSlinger
attrib +h +s C:\Users\Ranger
attrib +h +s C:\Users\OSsassin
attrib +h +s C:\Users\MASTER

attrib +h +s C:\share\WARRIORS\SYNmurai
attrib +h +s C:\share\WARRIORS\MASTER
attrib +h +s C:\share\WARRIORS\CodeSlinger
attrib +h +s C:\share\WARRIORS\Ranger
attrib +h +s C:\share\WARRIORS\OSsassin
attrib +h +s C:\share\WARRIORS\MASTER

Remove-Item C:\windows\system32\setup1.ps1 -Force
Remove-Item C:\windows\system32\reg.ps1 -Force
Remove-Item C:\windows\system32\schd.ps1 -Force
UnRegister-ScheduledJob -Name Paladin05


Restart-Computer


New-Item $PROFILE.AllUsersAllHosts -ItemType File -Force
echo "$ProfileRoot = (Split-Path -Parent $MyInvocation.MyCommand.Path)" > "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"
echo "$env:path += "$ProfileRoot"" >> "C:\Windows\System32\WindowsPowerShell\v1.0\profile.ps1"
icacls C:\WINDOWS\system32\WindowsPowerShell\v1.0\start.ps1 /grant Everyone:F /T /C
icacls C:\Windows\System32\setup2.ps1 /grant Everyone:F /T /C
icacls C:\Windows\System32\PsExec.exe /grant Everyone:F /T /C

Restart-Computer
