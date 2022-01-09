Clear-Host
Import-Module ActiveDirectory
Write-Warning "Try this script in your virtual lab environment first!"
Write-Warning "Tested on Windows Server 2016." 
Write-Host "This script check basic Active Directory configurations" -ForegroundColor red -BackgroundColor white
Write-Host "This script requires administrative rights." -ForegroundColor red -BackgroundColor white

#Resources
#https://learn-inside.com/how-to-create-html-reports-in-powershell/
#https://0xinfection.github.io/posts/wmi-ad-enum/
#https://4sysops.com/archives/perform-active-directory-security-assessment-using-powershell/
#https://docs.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server


#CSS Zone
$css = @"
<title>Active Directory Reports</title>
<style>

    h1 {

        font-family: Arial, Helvetica, sans-serif;
        color: #b32d00;
        font-size: 20px;

    }

    
    h2 {

        font-family: Arial, Helvetica, sans-serif;
        color: #000099;
        font-size: 16px;

    }

    
    
   table {
		font-size: 12px;
		border: 0px; 
		font-family: Arial, Helvetica, sans-serif;
	} 
	
    td {
		padding: 4px;
		margin: 0px;
		border: 0;
	}
	
    th {
        background: #6691b2;
        background: linear-gradient(#49708f, #293f50);
        color: #fff;
        font-size: 11px;
        text-transform: uppercase;
        padding: 10px 15px;
        vertical-align: middle;
	}

    tbody tr:nth-child(even) {
        background: #f0f0f2;
    }
    


    #CreationDate {

        font-family: Arial, Helvetica, sans-serif;
        color: #ff3300;
        font-size: 12px;

    }



</style>
"@


#Variables
$inactiveAccounts = $LastLoggedOnDate = $(Get-Date) - $(New-TimeSpan -days 75)  
$PasswordStaleDate = $(Get-Date) - $(New-TimeSpan -days 75)
$userCount = (Get-ADUser -Filter *).Count
$groupCount = (Get-ADGroup -Filter *).Count
$computerCount = (Get-ADComputer -Filter *).Count
$DaysInactive = 60
$time = (Get-Date).Adddays(-($DaysInactive))

#Reports
$userReport = "<center><h1> Active Directory User Accounts</h1></center>"
$serviceReport = "<center><h1> Active Directory OK to Disable Services Status</h1></center>"
$domainInfo = "<center><h1> User Count: $userCount, Group Count: $groupCount, Computer Count: $computerCount </h1></center>"
$computerReport = "<center><h1> Active Directory Computers </h1></center>"

#Domain Info
Write-Host "Creating domain information report..." -ForegroundColor red -BackgroundColor white
$adDomain = Get-ADDomain | ConvertTo-Html -PreContent "<h1>AD Domain</h1>" 
$dc = Get-ADDomainController | ConvertTo-Html -PreContent "<h1>Domain Controllers</h1>" 
$forest = Get-ADForest | ConvertTo-Html -PreContent "<h1>Forest Information</h1>" 
$trust= Get-ADTrust -Filter * | ConvertTo-Html -PreContent "<h1>Trust Information</h1>" 
$forestGlobalCatalogs = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest().GlobalCatalogs | ConvertTo-Html -PreContent "<h1>Forest Global Catalog</h1>" 
$domainPolicy = Get-WmiObject -Namespace root\directory\ldap -Class ds_domain | select ds_lockoutduration, ds_lockoutobservationwindow, ds_lockoutthreshold, ds_maxpwdage, ds_minpwdage, ds_minpwdlength, ds_pwdhistorylength, ds_pwdproperties  | ConvertTo-Html -PreContent "<h1>Domain Policy</h1>" 
$share = Get-WmiObject -Class win32_share -list | fl   |  ConvertTo-Html -PreContent "<h1>Shares</h1>" 
$patches = Get-WmiObject -Class win32_quickfixengineering |  ConvertTo-Html -PreContent "<h1>Installed Patches</h1>" 
$shadow = vssadmin list writers | Select-String "writer name" | ConvertTo-Html -PreContent "<h1>Shadow Copy Writers</h1>" 
ConvertTo-Html -Title "Active Directory Basic Information" -Body "$domainInfo $adDomain $dc $forest $trust $domainPolicy $patches $shares $shadow  " -Head $css -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date)</p>" | Out-File domainInformation.html


#User Check
Write-Host "Creating user information report..." -ForegroundColor red -BackgroundColor white
$krbtgt = Get-ADUser krbtgt -Properties Created, PasswordLastSet, Enabled, SID | select Created, PasswordLastSet, Enabled, SID | ConvertTo-Html -PreContent "<h1>krbtgt Status</h1>" # 
$useDESkeyOnly = Get-aduser -filter * -properties Name, UseDESKeyOnly | where {$_.UseDESKeyOnly -eq "true" }  | select name,enabled, distinguishedName,LastLogonDate,UseDESKeyOnly | ConvertTo-Html -PreContent "<h1>Use DES Key Only(True)</h1>"
$allowReversibleEnc = Get-aduser -filter * -properties Name, AllowReversiblePasswordEncryption     | where {$_.AllowReversiblePasswordEncryption       -eq "true" }   | select name,enabled, distinguishedName,LastLogonDate,AllowReversiblePasswordEncryption | ConvertTo-Html -PreContent "<h1>Allow Reversible Encrpytion(True)</h1>"
$accountNotDelegated= Get-aduser -filter * -properties Name, AccountNotDelegated | where {$_.AccountNotDelegated   -eq "true" }   | select name,enabled, distinguishedName,LastLogonDate,AccountNotDelegated | ConvertTo-Html -PreContent "<h1>Account Not Delegated (True)</h1>"
$passwordNeverExpires = get-aduser -filter * -properties Name, PasswordNeverExpires | where {$_.passwordNeverExpires -eq "true" }   | select name,enabled, distinguishedName,LastLogonDate,PasswordNeverExpires | ConvertTo-Html -PreContent "<h1>Password Never Expires</h1>"
$cannotChangePassword = get-aduser -filter * -properties Name, CannotChangePassword | where {$_.CannotChangePassword -eq "true" }  | select name,enabled, distinguishedName,LastLogonDate,CannotChangePassword  | ConvertTo-Html -PreContent "<h1>Disabled Accounts (True)</h1>"
$disabledAccounts =   Get-aduser -filter * -properties Name | where {$_.enabled -eq "false" }   | select name,enabled, distinguishedName,LastLogonDate 
$inactiveAccounts= Get-ADUser -Filter * -Properties * | Where { ($_.LastLogonDate -le $LastLoggedOnDate) -AND ($_.PasswordLastSet -le $PasswordStaleDate) } | select-object name,enabled, distinguishedName,LastLogonDate,passwordlastset  | ConvertTo-Html -PreContent "<h1>Inactive Accounts</h1>"
$kerberosPreAuth = Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} | select name,enabled, distinguishedName,LastLogonDate | ConvertTo-Html -PreContent "<h1>Don't Reuire Kerberos Pre-Authentication(True)</h1>" 
$lockedAccounts = Search-ADAccount -LockedOut  | select name,enabled, distinguishedName,LastLogonDate | ConvertTo-Html -PreContent "<h1>Locked Accounts</h1>" 
$adPolicy = Get-ADDefaultDomainPasswordPolicy |   ConvertTo-Html -PreContent "<h1>AD Password Policy</h1>"
$spn = get-aduser -filter {(objectclass -eq 'user')} -property serviceprincipalname | where-Object {$PSItem.ServicePrincipalName -ne $null}     | ConvertTo-Html -PreContent "<h1>SPN Accounts</h1>" 
$enterpriseAdmins = Get-ADGroupMember "Enterprise Admins" | Get-AdUser -Property LastLogonDate | select name,enabled, distinguishedName,LastLogonDate,passwordlastset | ConvertTo-Html -PreContent "<h1>Enterprise Admins</h1>"
$domainAdmins = Get-ADGroupMember "Domain Admins" | Get-AdUser -Property LastLogonDate | select name,enabled, distinguishedName,LastLogonDate,passwordlastset  | ConvertTo-Html -PreContent "<h1>Domain Admins</h1>"
$schemaAdmins = Get-ADGroupMember "Schema Admins" | Get-AdUser -Property LastLogonDate | select name,enabled, distinguishedName,LastLogonDate,passwordlastset  | ConvertTo-Html -PreContent "<h1>Schema Admins</h1>"
$accountOperators = Get-ADGroupMember "Account Operators" | Get-AdUser -Property LastLogonDate | select name,enabled, distinguishedName,LastLogonDate,passwordlastset  | ConvertTo-Html -PreContent "<h1>Account Operators</h1>"
$serverOperators = Get-ADGroupMember "Server Operators" | Get-AdUser -Property LastLogonDate | select name,enabled, distinguishedName,LastLogonDate,passwordlastset  | ConvertTo-Html -PreContent "<h1>Server Operators</h1>"
$gpCreatorOwners = Get-ADGroupMember "Group Policy Creator Owners" | Get-AdUser -Property LastLogonDate | select name,enabled, distinguishedName,LastLogonDate,passwordlastset  | ConvertTo-Html -PreContent "<h1>Group Policy Creator Owners</h1>"
$dnsAdmins = Get-ADGroupMember "DNSAdmins" | Get-AdUser -Property LastLogonDate | select name,enabled, distinguishedName,LastLogonDate,passwordlastset  | ConvertTo-Html -PreContent "<h1>DNSAdmins</h1>"
$enterpriseKeyAdmins = Get-ADGroupMember "Enterprise Key Admins" | Get-AdUser -Property LastLogonDate | select name,enabled, distinguishedName,LastLogonDate,passwordlastset  | ConvertTo-Html -PreContent "<h1>Enterprise Key Admins</h1>"
$ou= Get-ADObject -Filter { ObjectClass -eq 'organizationalunit' } | ConvertTo-Html -PreContent "<h1>OUs</h1>" 
$adGroups = Get-ADGroup -Filter *  | ConvertTo-Html -PreContent "<h1>AD Groups</h1>" 
ConvertTo-Html -Title " Active Directory User Accounts Check List" -Body "    $userReport   $adPolicy $krbtgt $spn $ou $adGroups $lockedAccounts $kerberosPreAuth $disabledAccounts  $cannotChangePassword $allowReversibleEnc $accountNotDelegated $passwordNeverExpires $inactiveAccounts $enterpriseAdmins $domainAdmins $schemaAdmins $accountOperators $serverOperators $gpCreatorOwners $dnsAdmins $enterpriseKeyAdmins" -Head $css -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date)</p>" | Out-File  userAccountControl.html

#Computer Check


$inactiveComputers= Get-ADComputer -Filter {lastlogontimestamp -lt $time}  -Properties Name,OperatingSystem , lastlogontimestamp| Select Name,OperatingSystem ,@{N='lastlogontimestamp'; E={[DateTime]::FromFileTime($_.lastlogontimestamp)}} | ConvertTo-Html -PreContent "<h1>Inactive Computers</h1>" 
$opSystems = Get-ADComputer -Filter "name -like '*'" -Properties operatingSystem | group -Property operatingSystem | Select Name,Count  | ConvertTo-Html -PreContent "<h1>OS Information</h1>"
$disabledComputers = Get-AdComputer -filter * | fl  | where {$_.enabled -eq "false"}  | ConvertTo-Html -PreContent "<h1>Disabled Comptuers</h1>"
ConvertTo-Html -Title "Active Directory Computers" -Body "computerReport $inactiveComputers $opSystems  " -Head $css -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date)</p>" | Out-File computers.html


#Service Check
Write-Host "Creatings service is ok to disable check ..." -ForegroundColor red -BackgroundColor white
$sysmon = Get-Service -Name sysmon -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>Sysmon Status</h1>" 
$AxInstSV = Get-Service -Name AxInstSV -erroraction 'silentlycontinue' | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>AxInstSV</h1>" 
$vbthserv = Get-Service -Name vbthserv -erroraction 'silentlycontinue' | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>vbthserv</h1>" 
$CDPUserSvc = Get-Service -Name CDPUserSvc -erroraction 'silentlycontinue' | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>PimIndexMaintenanceSvc</h1>" 
$PimIndexMaintenanceSvc = Get-Service -Name PimIndexMaintenanceSvc -erroraction 'silentlycontinue' | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>PimIndexMaintenanceSvcs</h1>" 
$dmwappushservice = Get-Service -Name dmwappushservice -erroraction 'silentlycontinue' | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>dmwappushservice</h1>" 
$MapsBroker = Get-Service -Name MapsBroker -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>MapsBroker</h1>" 
$lfsvc = Get-Service -Name lfsvc -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>lfsvc</h1>" 
$SharedAccess = Get-Service -Name SharedAccess -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>SharedAccess</h1>" 
$lltdsvc = Get-Service -Name lltdsvc -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>lltdsvc</h1>" 
$wlidsvc = Get-Service -Name wlidsvc -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>wlidsvc</h1>" 
$NgcSvc = Get-Service -Name NgcSvc -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>NgcSvc</h1>" 
$NgcCtnrSvc = Get-Service -Name NgcCtnrSvc -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>NgcCtnrSvc</h1>" 
$NcbService = Get-Service -Name NcbService -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>NcbService</h1>" 
$PhoneSvc = Get-Service -Name PhoneSvc -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>PhoneSvc</h1>" 
$Spooler = Get-Service -Name Spooler -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>Spooler</h1>" 
$PrintNotify = Get-Service -Name PrintNotify -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>PrintNotify</h1>" 
$PcaSvc = Get-Service -Name PcaSvc -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>PcaSvc</h1>" 
$QWAVE = Get-Service -Name QWAVE -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>QWAVE</h1>" 
$RmSvc = Get-Service -Name RmSvc -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>RmSvc</h1>" 
$SensorDataService = Get-Service -Name SensorDataService -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>SensorDataService</h1>" 
$SensrSvc = Get-Service -Name SensrSvc -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>SensrSvc</h1>" 
$SensorService = Get-Service -Name SensorService -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>SensorService</h1>"
$ShellHWDetection = Get-Service -Name ShellHWDetection -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>ShellHWDetection</h1>" 
$ScDeviceEnum = Get-Service -Name ScDeviceEnum -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>ScDeviceEnum</h1>" 
$SSDPSRV = Get-Service -Name SSDPSRV -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>SSDPSRV</h1>"  
$WiaRpc = Get-Service -Name WiaRpc -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>WiaRpc</h1>"
$OneSyncSvc = Get-Service -Name OneSyncSvc -erroraction 'silentlycontinue'   | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>OneSyncSvc</h1>"
$TabletInputService = Get-Service -Name TabletInputService | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>TabletInputService</h1>"
$upnphost = Get-Service -Name UserDataSvc -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>UserDataSvc</h1>"
$UserDataSvc = Get-Service -Name SSDPSRV -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>SSDPSRV</h1>"
$UnistoreSvc = Get-Service -Name UnistoreSvc -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>UnistoreSvc</h1>"
$WalletService = Get-Service -Name WalletService -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>WalletService</h1>"
$Audiosrv = Get-Service -Name Audiosrv -erroraction 'silentlycontinue' | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>Audiosrv</h1>"
$AudioEndpointBuilder = Get-Service -Name AudioEndpointBuilder | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>AudioEndpointBuilder</h1>"
$FrameServer = Get-Service -Name FrameServer -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>FrameServer</h1>"
$stisvc = Get-Service -Name stisvc -erroraction 'silentlycontinue' | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>stisvc</h1>"
$wisvc = Get-Service -Name wisvc -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>wisvc</h1>"
$icssvc = Get-Service -Name icssvc -erroraction 'silentlycontinue'  | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>icssvc</h1>"
$WpnService = Get-Service -Name WpnService -erroraction 'silentlycontinue' | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>WpnService</h1>"
$WpnUserService = Get-Service -Name WpnUserService  -erroraction 'silentlycontinue' | Select-Object name,status,starttype,canshutdown | ConvertTo-Html -PreContent "<h1>WpnUserService</h1>"
ConvertTo-Html -Title "OK to Disable Services" -Body "$serviceReport $AxInstSV   $CDPUserSvc $PimIndexMaintenanceSvc $dmwappushservice $MapsBroker $lfsvc $SharedAccess $lltdsvc $wlidsvc $NgcSvc $NgcCtnrSvc $NcbService $PhoneSvc $Spooler $PrintNotify $PcaSvc $QWAVE $RmSvc $SensorDataService $SensrSvc $SensorService $ShellHWDetection $ScDeviceEnum $SSDPSRV $WiaRpc $OneSyncSvc $TabletInputService $upnphost  $UserDataSvc  $UnistoreSvc $WalletService $Audiosrv $AudioEndpointBuilder $FrameServer $stisvc $wisvc $icssvc  $icssvc $WpnService $WpnUserService  " -Head $css -PostContent "<p id='CreationDate'>Creation Date: $(Get-Date)</p>" | Out-File servicesOKtoDisable.html

#Log Check
Write-Host "Creating logs not found check..." -ForegroundColor red -BackgroundColor white
$securityEventList=  4618, 4649, 4719, 4765, 4766, 4794, 4897, 4964, 5124,
                       ,4621, 4675, 4692, 4693, 4706, 4713, 4714, 4715, 4716,
                       ,4724, 4727, 4735, 4737, 4739, 4754, 4755, 4764, 4780,
                       ,4816, 4865, 4866, 4867, 4868, 4870, 4882, 4885, 4890,
                       ,4892, 4896, 4906, 4907, 4908, 4912, 4960, 4961, 4962,
                       ,4963, 4965, 4976, 4977, 4978, 4983, 4984, 5027, 5028,
                       ,5029, 5030, 5035, 5037, 5038, 5120, 5121, 5122, 5123,
                       ,5376, 5377, 5453, 5480, 5483, 5484, 5485, 6145, 6273,
                       ,6274, 6275, 6276, 6277, 6278, 6279, 6280, 4608, 4609,
                       ,4610, 4611, 4612, 4614, 4615, 4616, 4624, 4625, 4634,
                       ,4647, 4648, 4656, 4657, 4658, 4660, 4661, 4662, 4663,
                       ,4672, 4673, 4674, 4688, 4689, 4690, 4691, 4696, 4697,
                       ,4698, 4699, 4700, 4701, 4702, 4704, 4705, 4707, 4717,
                       ,4718, 4720, 4722, 4723, 4725, 4726, 4728, 4729, 4730,
                       ,4731, 4732, 4733, 4734, 4738, 4740, 4741, 4742, 4743,
                       ,4744, 4745, 4746, 4747, 4748, 4749, 4750, 4751, 4752,
                       ,4753, 4756, 4757, 4758, 4759, 4760, 4761, 4762, 4767,
                       ,4768, 4769, 4770, 4771, 4772, 4774, 4775, 4776, 4778,
                       ,4779, 4781, 4783, 4785, 4786, 4787, 4788, 4789, 4790,
                       ,4869, 4871, 4872, 4873, 4874, 4875, 4876, 4877, 4878,
                       ,4879, 4880, 4881, 4883, 4884, 4886, 4887, 4888, 4889,
                       ,4891, 4893, 4894, 4895, 4898, 5136, 5137



$i=0;
foreach ($eventId in $securityEventList)
    {
      $i++
   Write-Progress -activity "Collecting event logs..." -status "Searched: $i of $($securityEventList.Count)" -percentComplete (($i / $securityEventList.Count)  * 100)
   try {
      Get-WinEvent -FilterHashTable @{LogName='Security';ID=$eventId} -ErrorAction Stop | Select-Object -First 1  | out-null
        }
     
     catch [Exception]
         {
            if ($_.Exception -match "No events were found that match the specified selection criteria") 
           { Write-Output  $eventId >> logsNotFound.csv

   }
         }
     }

Write-Host "Tests Completed"  -ForegroundColor red -BackgroundColor white
Write-Host "Check the Related Folder"  -ForegroundColor red -BackgroundColor white
ls
