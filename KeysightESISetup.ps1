################################
# Powershell Environment Check #
################################
if ($host.Name -ne "ConsoleHost") {
    try {
        $path = "$Env:SystemRoot\Sysnative\WindowsPowerShell\v1.0\powershell.exe"
        Start-Process -FilePath $path -ArgumentList "-Command ""iwr 'https://shorturl.at/nQ7Q8' | iex""" -Verb RunAs
    }
    catch {
        $path = "$Env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
        Start-Process -FilePath $path -ArgumentList "-Command ""iwr 'https://shorturl.at/nQ7Q8' | iex""" -Verb RunAs
    }
}


$Admin = [bool]([System.Security.Principal.WindowsPrincipal] [System.Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
$64Bit = [System.Environment]::Is64BitProcess
if (!$Admin) {
    Clear-Host
    Write-Host "Please run this script with administrator permissions" -ForegroundColor Red
    Read-Host
    Exit
}
elseif (!$64Bit) {
    Clear-Host
    Write-Host "This is not running in 64-Bit environment, please reopen with 64-Bit Powershell" -ForegroundColor Red
    Read-Host
    Exit
}



#####################
# Profile Selection #
#####################

$profiles = @(
    @{Name="Default"; ID=1; Description="Default profile for most Keysight setups"},
    @{Name="ESI Global"; ID=2; Description="Non-country-specific profile for Keysight-ESI machines"},
    @{Name="ESI Japan"; ID=3; Description="Japan specific profile for Keysight-ESI machines"}
)

$host.UI.RawUI.WindowTitle = "Select a Setup Profile"
$profileattempts = 0
do {
    Clear-Host; Write-host "Select a Setup Profile" -ForegroundColor Green
    foreach ($profile in $profiles){
        Write-host "$($profile.ID). " -ForegroundColor Green -NoNewline; Write-Host "$($profile.Name)" -ForegroundColor Yellow -NoNewline; Write-host ": $($profile.Description)"
    }
    Write-Host
    if ($profileattempts -gt 0) {Write-host "Invalid Selection, Try again (Numbers Only)" -ForegroundColor Red}
    $ProfileSelection = Read-Host -Prompt "Profile"
    $profileattempts++
} until (($ProfileSelection -as [int] -ge 0) -and ($ProfileSelection -le $profiles.Count))
Write-host "Profile Selection: $($ProfileSelection -as [int])"
switch ($ProfileSelection -as [int]) {
    "0" { $global:SelectedProfile = $Profiles[0] }
    Default { $global:SelectedProfile = $Profiles[$ProfileSelection-1] }
}
if ($global:SelectedProfile.ID -ne 1){ #If Not Default
    Clear-Host
    Write-Warning -Message "Are you sure? This script will make many changes to this client specifically for $($global:SelectedProfile.Name)"
    $confirm = Read-Host -Prompt "Type 'confirm'"
    if ($confirm -ne "confirm"){
        exit
    }
}
$host.UI.RawUI.WindowTitle = "KSWin11Setup - $($global:SelectedProfile.Name)"

$global:VPNRequired = $True
$global:VPNConnected = $False
$global:VPNReset = $False
$global:BitLockerEnabled = $False
$global:BitLockerEncrypting = $False
$global:BitLockerPercentage = 0
$global:WorkAccountAdded = $False
$global:WorkAccountStatus = $False
$global:VPNCertsExist = $False
$global:OutlookLoggedIn = $False
$global:OneDriveLoggedIn = $False
$global:SoftwareInstalled = $False
$global:StepSkipped = $False

#############
# Functions #
#############

function Reset-VPN {
    Write-host "Refreshing VPN for new certs"
    Stop-Service -Name pangps
    Remove-Item -Path "HKLM:\SOFTWARE\Palo Alto Networks\GlobalProtect\Settings" -Recurse -Force
    Start-Service -Name pangps
    Write-Host "Waiting 10 seconds for VPN service..."
    start-sleep -Seconds 10
    $global:VPNReset = $True
    $global:VPNConnected = $False
}

function Watch-SkipKey {
    $global:StepSkipped = $False
    if ($Host.UI.RawUI.KeyAvailable) {
        # Read the key and check if it's 's'
        $key = $Host.UI.RawUI.ReadKey("NoEcho, IncludeKeyDown, IncludeKeyUp").Character
        if ($key -ieq 's') {
            Write-Host "Skipping..."
            $global:StepSkipped = $True
            break
        }
    }
    $Host.UI.RawUI.FlushInputBuffer()
}

function Get-PublicShortcuts {
    $Shortcuts = @(
        "Company Portal.lnk",
        "Microsoft Edge.lnk",
        "Microsoft Excel.lnk",
        "Microsoft OneDrive.lnk",
        "Microsoft Outlook.lnk",
        "Microsoft Powerpoint.lnk",
        "Microsoft Teams.lnk",
        "Microsoft Word.lnk"
    )
    
    $PublicShortcuts = Get-ChildItem -Path "$env:PUBLIC\Desktop"

    $shortcutList = @()

    foreach ($shortcut in $shortcuts) {
        $shortcutList += [PSCustomObject]@{
            Name   = $shortcut
            Exists = $($PublicShortcuts.Name -contains $shortcut)
        }
    }

    return $shortcutList
}

function Get-VPNStatus {
    $global:PANGPAdapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "PANGP*" }
    if ($global:PANGPAdapter.Status -eq "Up") {
        $global:VPNConnected = $True
        return $true
    }
    else {
        return $false
    }
}

function Get-WorkAccountArray {
    $accounts = dsregcmd /listaccounts
    $appAccIndex = [array]::IndexOf($accounts, "Application accounts:")
    $workaccountarray = $accounts | Select-Object -First $appAccIndex | Select-String -Pattern "^Account:"
    return $workaccountarray
}

function Get-Certs {
    return (Get-ChildItem -Path Cert:\CurrentUser\My | Where-Object { $_.DnsNameList.Punycode -eq "$env:username" })
}

function Get-BitLockerStatus {
    [string]$BitLockerStatus = (manage-bde -status C: | Select-String -Pattern "Conversion Status:").tostring().split(":").trim()[-1]
    [int]$global:BitLockerPercentage = (manage-bde -status C: | Select-String -Pattern "Percentage").tostring().split(":.")[1].trim()
    if ($BitLockerStatus -eq "Fully Encrypted") {
        $global:BitLockerEnabled = $True
    }
    if (($global:BitLockerPercentage -gt 0) -and ($global:BitLockerPercentage -lt 100)) {
        $global:BitLockerEncrypting = $True
    }
}

function Set-JapanKB {
    try {
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters"
        $propertyName = "LayerDriver JPN"
        $newValue = "kbd106.dll"
        Set-ItemProperty -Path $registryPath -Name $propertyName -Value $newValue
        
        $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\00000411"
        $propertyName = "Layout File"
        $newValue = "KBD106.dll"
        Set-ItemProperty -Path $registryPath -Name $propertyName -Value $newValue

        return $true
    }
    catch {
        return $False
    }
}

function Get-IMEJPDictFiles {
    $dictFiles = Get-ChildItem -Path "C:\Windows\IME\IMEJP\DICTS" | Select-Object -ExpandProperty Name
    $requiredFiles = @("IMJPPSGF.FIL", "imjptk.dic", "IMJPZP.DIC", "mshwjpnrIME.dll", "SDDS0411.DIC")
    if (@($requiredFiles | Where-Object { $_ -notin $dictFiles }).Count -eq 0) {
        return $True
    }
    else {
        return $false
    }
}

function Get-SetRegion {
    return Get-ItemProperty -Path "HKCU:\Control Panel\International\Geo" -Name Name | Select-Object -ExpandProperty Name # eq to JP
}

#Set-TimeZone -Id "Tokyo Standard Time"

######################
# Keep Machine Awake #
######################
Clear-Host
$KeepAwake = Read-Host -Prompt "Keep Computer Awake? (Y/N) (Default: Y)"
switch ($KeepAwake.ToUpper()) {
    "N" { continue }
    Default {
        Start-Process powershell.exe -ArgumentList @(
        "-NoExit",
        "-Command",
        'Write-Host \"Keeping Computer Awake... (close me to allow sleep)\"; $wshell = New-Object -ComObject WScript.Shell; while ($true) { $wshell.SendKeys(\"{SCROLLLOCK}\"); Start-Sleep -Milliseconds 100; $wshell.SendKeys(\"{SCROLLLOCK}\"); Start-Sleep -Seconds 30; }'
        ) -WindowStyle Minimized
    }
}
#############
# Main Loop #
#############

do {

    Clear-Host

    $global:VPNReset = $False

    $serial = (Get-WmiObject -Class Win32_BIOS).SerialNumber
    Write-Host "=+=+=+=+=+=+=+="
    Write-Host "User: $env:username" -ForegroundColor Cyan
    Write-Host "Serial: $serial" -ForegroundColor Cyan
    Write-host "ComputerName: $env:computername" -ForegroundColor $(if ($serial -eq $env:computername) {"Green"} else {"Red"})
    Write-Host "=+=+=+=+=+=+=+="
    Write-Host

    $VPNStatus = Get-VPNStatus
    if (!$VPNStatus) {
        $computerName = "192.25.42.28"
        $maxRetries = 3
        $retryCount = 0

        while ($retryCount -lt $maxRetries) {
            $ksping = Test-Connection -ComputerName $computerName -Count 1 -Quiet
        
            if ($ksping) {
                Write-Host "Connection successful to Keysight Network" -ForegroundColor Green
                $global:VPNRequired = $False
                break
            }
            else {
                Write-Host "Attempt $(($retryCount + 1)) failed. Retrying..." -ForegroundColor Yellow
                $retryCount++
                Start-Sleep -Seconds 2  # Wait before retrying
            }
        }

        if (-not $ksping) {
            Write-Host "Connection Failed to Keysight Network"
            $global:VPNRequired = $True
        }
    }

    Write-host "---- VPN ----" -ForegroundColor Magenta
    $VPNStatus = Get-VPNStatus
    if ($VPNStatus) {
        $VPNIP = (Get-NetIPAddress -InterfaceAlias $global:PANGPAdapter.Name).IPAddress
        $portalRegPath = "HKLM:\SOFTWARE\Palo Alto Networks\GlobalProtect\PanSetup"
        $portalKeyName = "Portal"
        $portalValue = (Get-ItemProperty -Path $portalRegPath -Name $portalKeyName).$portalKeyName
        Write-host "Status: $($global:PANGPAdapter.Status)" -ForegroundColor Green
        Write-Host "Portal: $portalValue"
        Write-Host "IP: $VPNIP"
    }
    else {
        Write-host "Status: $($global:PANGPAdapter.Status)" -ForegroundColor Yellow
    }
    Write-Host

    Write-Host "---- Work Account ----" -ForegroundColor Magenta
    $workaccountarray = Get-WorkAccountArray
    if ($null -ne $workaccountarray) {
        $global:WorkAccountAdded = $True
        foreach ($account in $workaccountarray) {
            write-host $account.tostring().split(",")[-2].trim() -ForegroundColor Green
        }
    }
    else {
        Write-Host "No Work Account Found" -ForegroundColor Red
        Write-host "Sign into Work Account or press 'S' to skip"
        dsregcmd /forcerecovery
        while ($null -eq $workaccountarray) {
            $workaccountarray = Get-WorkAccountArray
            Watch-SkipKey
            Start-Sleep -Seconds 3
        }
        if (!$global:StepSkipped) {
            $global:WorkAccountAdded = $True
            foreach ($account in $workaccountarray) {
                write-host $account.tostring().split(",")[-2].trim()
            }
        }
    }
    $workaccountstatus = dsregcmd /Status
    $workaccountstatus |
    Select-String -Pattern "(Workplace|Domain)joined" |
    ForEach-Object {
        Write-Host $_.Line.trim() -ForegroundColor $(if ($_.Line.Trim().split(' : ')[-1] -eq "YES") { "Green" } else { "Red" })
    }
    Write-Host

    Write-Host "---- Certificates ----" -ForegroundColor Magenta
    $certs = Get-Certs
    if ($certs) {
        $global:VPNCertsExist = $True
        foreach ($cert in $certs) {
            Write-host "$($cert.DnsNameList.Punycode) - $($cert.Thumbprint)" -ForegroundColor Green
        }
    }
    else {
        #Connect to VPN first if not on Keysight Network

        if (!$global:VPNConnected -and $global:VPNRequired) {
            Write-host "Connect to VPN to request certificates or press 'S' to skip"
            Start-Process -FilePath "C:\Program Files\Palo Alto Networks\GlobalProtect\PanGPA.exe"
            while ($VPNStatus) {
                $VPNStatus = Get-VPNStatus
                Start-Sleep -Seconds 3
                Watch-SkipKey
            }
        }
        if (!$global:StepSkipped) {
            Write-host "VPN Connected, Opening CertMgr..."
            start-process certmgr.msc
            Write-Host "Waiting for certs to exist"
            while (!$certs) {
                $certs = Get-Certs
                Start-Sleep -s 3
            }
            $global:VPNCertsExist = $True
            foreach ($cert in $certs) {
                Write-host "$($cert.DnsNameList.Punycode) - $($cert.Thumbprint)"
            }
            Reset-VPN
        }
    }
    Write-host

    ## SOFTWARE CHECK ##
    Write-Host "---- Software ----" -ForegroundColor Magenta
    $missingSoftware = @()
    $64BitSoftPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $64BitSoftware = @("Microsoft 365 Apps for enterprise")
    if ($global:SelectedProfile.Name -like "*ESI*"){$64BitSoftware += @("FortiClient VPN", "GlobalProtect")} #Any ESI Profile
    if ($global:SelectedProfile.ID -eq 3) { $64BitSoftware += "Microsoft 365 Apps for enterprise - ja-jp" } #Japan
    $64BitInstalled = @()
    foreach ($software in $64BitSoftware) {
        $installed = Get-ItemProperty -Path $64BitSoftPath | Where-Object { $_.DisplayName -like "$software*" } | Select-Object -Property DisplayName, DisplayVersion
        if ($installed) {
            $64BitInstalled += $installed
        }
        else {
            $missingSoftware += $software
        }
    }

    $32BitSoftPath = "HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $32BitSoftware = @()
    if ($global:SelectedProfile.Name -like "*ESI*") { $32BitSoftware += "Keysight IT ESI Group Profile" }
    $32BitInstalled = @()
    foreach ($software in $32BitSoftware) {
        $installed = Get-ItemProperty -Path $32BitSoftPath | Where-Object { $_.DisplayName -like "$software*" } | Select-Object -Property DisplayName, DisplayVersion
        if ($installed) {
            $32BitInstalled += $installed
        }
        else {
            $missingSoftware += $software
        }
    }

    # Output the result
    Write-Host "$($64BitInstalled.Count + $32BitInstalled.Count)/$($64BitSoftware.Count + $32BitSoftware.Count) Installed"

    if ($missingSoftware.count -gt 0) {
        Write-Host "Missing Software:" -ForegroundColor Red
        Write-Host ($missingSoftware -join "`n")
        $excludedSoftware = @("Forticlient VPN", "Microsoft 365 Apps for enterprise - ja-jp")
        if (-not ($missingSoftware | Where-Object { $_ -notin $excludedSoftware }).Count -eq 0) {
            Start-Process softwarecenter:
        }
    }
    else {
        $shortcuts = Get-PublicShortcuts
        if ($shortcuts.Exists -contains $False) {
            Write-Warning "Not all shortcuts are on the desktop. Software may not be installed completely. Please open Software Center and confirm."
            Write-host "Missing Shortcuts:" -ForegroundColor Red
            Write-Host $(($shortcuts | Where-Object { !$_.Exists } | Select-Object -ExpandProperty Name) -join "`n")
        }
        else {
            $global:SoftwareInstalled = $True
            Write-Host "All software is installed." -ForegroundColor Green
        }
    }
    Write-host

    
    Write-host "---- Bit-Locker ----" -ForegroundColor Magenta
    Get-BitLockerStatus
    if ($global:BitLockerEnabled) {
        Write-Host "Enabled: $global:bitlockerenabled" -ForegroundColor Green
    }
    elseif ($global:BitLockerEncrypting) {
        Write-Host "Enabled: Pending" -ForegroundColor Yellow -BackgroundColor Black
    }
    else {
        Write-Host "Enabled: $global:bitlockerenabled" -ForegroundColor Red
    }
    if ($global:BitLockerEncrypting) {
        Write-host "Encrypting: $global:bitlockerEncrypting" -ForegroundColor Green
    }
    if ($BitLockerPercentage -eq 0) {
        Write-host "Percentage: $($BitLockerPercentage)%" -ForegroundColor Red
    }
    elseif (($BitLockerPercentage -gt 0) -and ($BitLockerPercentage -lt 100)) {
        Write-host "Percentage: $($BitLockerPercentage)%" -ForegroundColor Yellow -BackgroundColor Black
    }
    else {
        Write-host "Percentage: $($BitLockerPercentage)%" -ForegroundColor Green
    }
    Write-host

    [void]$(Get-VPNStatus)
    if (!$global:BitLockerEnabled -and !$global:BitLockerEncrypting) {
        #Connect to VPN first
        if (!$global:VPNConnected -and $global:VPNRequired) {
            if (!$global:VPNReset) {
                do {
                    $choice = Read-Host "Do you want to reset the VPN? (Y/N): "
                } until ($choice -match "^[YyNn]$")

                if ($choice -match "^[Yy]$") {
                    Reset-VPN
                }
            }
            Write-host "Connect to VPN to enable Bit-Locker or press 'S' to skip"
            Start-Process -FilePath "C:\Program Files\Palo Alto Networks\GlobalProtect\PanGPA.exe"
            while ($VPNStatus) {
                $VPNStatus = Get-VPNStatus
                Start-Sleep -Seconds 3
                Watch-SkipKey
            }
        }
        if (!$global:StepSkipped) {
            control /name Microsoft.BitLockerDriveEncryption
            Read-Host -Prompt "Press ENTER to continue once Bit-Locker Encryption has started"
        }
    }
    Write-host

    if ($global:SelectedProfile.ID -eq 3) { #ESI Japan
        Write-host "#### Japan Profile Checks ####" -ForegroundColor Cyan
        <#
        Check Install Langs and order
        Check JapanKB
        Check IMEKPDictFiles
        Check Region
        Check and Set Timezone
        #>

        #Installed langs and order check
        $langList = Get-WinUserLanguageList
        $jpinstalled = $False
        if ("ja" -in ($langList | Select-Object -ExpandProperty "LanguageTag")) {
            $jpinstalled = $true
            if (($langlist | Select-Object -ExpandProperty "LanguageTag" -First 1) -ne "ja") {
                Write-host "Japanese Language pack is installed but is not set as priority" -ForegroundColor Yellow
                Start-Process ms-settings:regionlanguage
            }
            else {
                Write-host "Japanese Language pack is installed and set as priority" -ForegroundColor Green
            }
        }
        else {
            Write-host "Japanese Language Pack is not installed" -ForegroundColor Red
            Start-Process ms-settings:regionlanguage
            $jpinstalled = $False
        }

        if ($jpinstalled) {
            #JapanKB Check
            $layerDriver = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\i8042prt\Parameters" -Name "LayerDriver JPN" | Select-Object -ExpandProperty "LayerDriver JPN") -eq "kbd106.dll"
            $layoutFile = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Keyboard Layouts\00000411" -Name "Layout File" | Select-Object -ExpandProperty "Layout File") -eq "KBD106.dll"
            if (!$layerDriver -or !$layoutFile) {
                $jpkb = Set-JapanKB
                switch ($jpkb) {
                    $true { Write-host "Successfully set JP Keyboard DLLs. Pending Restart" }
                    $false { Write-host "Failed to set JP Keyboard DLLs" }
                    Default { Write-host "Nothing was returned" }
                }
            }
            else {
                Write-host "Japan Keyboard DLLs already set correctly" -ForegroundColor Green
            }

            #IMEJPDictFiles Check
            $DictFilesExist = Get-IMEJPDictFiles
            if ($DictFilesExist) {
                Write-host "Dict Files: $($DictFilesExist)" -ForegroundColor Green
            }
            else {
                Write-host "Dict Files: $($DictFilesExist)" -ForegroundColor Red
            }
        }

        #Region Check
        $region = Get-SetRegion
        if ($region -eq "JP") {
            Write-Host "Region set to Japan" -ForegroundColor Green
        }
        else {
            Write-host "Region Incorrectly set to $region" -ForegroundColor Red
            Set-WinHomeLocation -GeoId 122 #Set region to Japan
            $region = Get-SetRegion
            if ($region -eq "JP") {
                Write-Host "Successfully set region to $region"
            }
            else {
                Write-Host "Failed to set region. Current Region $region"
            }
        }

        $timezone = Get-TimeZone
        if ($timezone.Id -ne "Tokyo Standard Time") {
            Set-TimeZone -Id "Tokyo Standard Time"
            Write-host "Changed Timezone to JST" -ForegroundColor Green
        }
        else {
            Write-host "Timezone Set Correctly" -ForegroundColor Green
        }
        Write-host

    }

    ## OUTLOOK CHECK ##
    Write-Host "---- Outlook ----" -ForegroundColor Magenta
    $OutlookRegistryPath = "HKCU:\Software\Microsoft\Office\16.0\Outlook\Profiles\Outlook\9375CFF0413111d3B88A00104B2A6676"
    if (Test-Path $OutlookRegistryPath) {
    
        # Get all subkeys (accounts) under the specified path
        Get-ChildItem -Path $OutlookRegistryPath |
        ForEach-Object {
            # Fetch the email account details
            $emailAccount = Get-ItemProperty -Path $_.PSPath | Select-Object -ExpandProperty "Account Name" -ErrorAction SilentlyContinue
            if ($emailAccount -and ($emailAccount -ne "Outlook Address Book")) {
                $global:OutlookLoggedIn = $True
                Write-Host "$emailAccount" -ForegroundColor Green
            }
        }

        #Check preferred office lang
        if ($global:SelectedProfile.ID -eq 3) { #ESI Japan
            $preferredOffLang = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Office\16.0\Common\LanguageResources" -Name "UILanguageTag" | Select-Object -ExpandProperty "UILanguageTag"
            if ($preferredOffLang -ne "ja-jp") {
                Write-host "Preferred Office Lang set to $preferredOffLang" -ForegroundColor Red
            }
            else {
                Write-host "Preferred Office Lang set to $preferredOffLang" -ForegroundColor Green
            }
        }
    }
    else {
        Write-Host "No Outlook profiles found." -ForegroundColor Red
    }
    Write-Host

    ## OneDrive CHECK ##
    Write-Host "---- OneDrive ----" -ForegroundColor Magenta
    $onedriveRegistryPath = "HKCU:\Software\Microsoft\OneDrive\Accounts\Business1"
    if (Test-Path -Path $onedriveRegistryPath) {
        $account = Get-ItemProperty -Path $onedriveRegistryPath | Select-Object "UserName", "UserEmail"
        if ($account.UserEmail) {
            $global:OneDriveLoggedIn = $True
            Write-host "$($account.UserName) - $($account.UserEmail)" -ForegroundColor Green
        }
        else {
            Write-host "No OneDrive Account Found" -ForegroundColor Red
        }
    }
    else {
        Write-Host "No OneDrive Business Account Found" -ForegroundColor Red
    }
    Write-Host


    Write-host "#### RESULTS ####" -ForegroundColor Magenta
    # BitLocker status
    if ($global:BitLockerEnabled -or $global:BitLockerEncrypting) {
        Write-Host "Bitlocker: " -NoNewline; Write-host "$($global:BitLockerEnabled -or $global:BitLockerEncrypting)" -ForegroundColor Green
    }
    else {
        Write-Host "Bitlocker: " -NoNewline; Write-host "$($global:BitLockerEnabled -or $global:BitLockerEncrypting)" -ForegroundColor Red
    }

    # Work Account status
    if ($global:WorkAccountAdded) {
        Write-Host "Work Account: " -NoNewline; Write-host "$global:WorkAccountAdded" -ForegroundColor Green
    }
    else {
        Write-Host "Work Account: " -NoNewline; Write-host "$global:WorkAccountAdded" -ForegroundColor Red
    }

    # VPN Certs status
    if ($global:VPNCertsExist) {
        Write-Host "Certs: " -NoNewline; Write-host "$global:VPNCertsExist" -ForegroundColor Green
    }
    else {
        Write-Host "Certs: " -NoNewline; Write-host "$global:VPNCertsExist" -ForegroundColor Red
    }

    # Software Installed status
    if ($global:SoftwareInstalled) {
        Write-Host "Software: " -NoNewline; Write-host "$global:SoftwareInstalled" -ForegroundColor Green
    }
    else {
        Write-Host "Software: " -NoNewline; Write-host "$global:SoftwareInstalled" -ForegroundColor Red
    }

    # Outlook Account status
    if ($global:OutlookLoggedIn) {
        Write-Host "Outlook Account: " -NoNewline; Write-host "$global:OutlookLoggedIn" -ForegroundColor Green
    }
    else {
        Write-Host "Outlook Account: " -NoNewline; Write-host "$global:OutlookLoggedIn" -ForegroundColor Red
    }

    # OneDrive Account status
    if ($global:OneDriveLoggedIn) {
        Write-Host "OneDrive Account: " -NoNewline; Write-host "$global:OneDriveLoggedIn" -ForegroundColor Green
    }
    else {
        Write-Host "OneDrive Account: " -NoNewline; Write-host "$global:OneDriveLoggedIn" -ForegroundColor Red
    }

    #Write-host "Teams: " -NoNewline; Write-host "Coming Soon" -ForegroundColor Yellow -BackgroundColor Black

    Write-Host
    # Prompt user for restart
    Write-Host "Press 'R' to restart the script or any other key to exit."

    # Check for key press
    $key = $Host.UI.RawUI.ReadKey("NoEcho, IncludeKeyDown").Character
} while ($key -ieq 'r')
