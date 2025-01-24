############################
# Powershell Console Check #
############################
if ($host.Name -ne "ConsoleHost") {
    Start-Process PowerShell -ArgumentList "-Command ""iwr 'https://shorturl.at/nQ7Q8' | iex""" -Verb RunAs
    Exit
}


####################
# Global Variables #
####################

$global:VPNConnected = $false
$global:BitLockerEnabled = $false
$global:BitLockerEncrypting = $false
$global:BitLockerPercentage = 0
$global:WorkAccountAdded = $false
$global:VPNCertsExist = $false
$global:OutlookLoggedIn = $false
$global:OneDriveLoggedIn = $false
$global:SoftwareInstalled = $false
$global:StepSkipped = $false


#############
# Functions #
#############

function Watch-SkipKey {
    $global:StepSkipped = $false
    if ($Host.UI.RawUI.KeyAvailable) {
        # Read the key and check if it's 's'
        $key = $Host.UI.RawUI.ReadKey("NoEcho, IncludeKeyDown, IncludeKeyUp").Character
        if ($key -ieq 's') {
            Write-Host "Skipping..."
            $global:StepSkipped = $true
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
        $global:VPNConnected = $true
    }
    return $global:PANGPAdapter.Status
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
        $global:BitLockerEnabled = $true
    }
    if (($global:BitLockerPercentage -gt 0) -and ($global:BitLockerPercentage -lt 100)) {
        $global:BitLockerEncrypting = $true
    }
}


#############
# Main Loop #
#############

do {

    Clear-Host

    Write-Host "=+=+=+=+=+=+=+="
    Write-Host "User: $env:username" -ForegroundColor Cyan
    Write-Host "Serial: $((Get-WmiObject -Class Win32_BIOS).SerialNumber)" -ForegroundColor Cyan
    Write-Host "=+=+=+=+=+=+=+="
    Write-Host

    Write-host "---- VPN ----" -ForegroundColor Magenta
    $VPNStatus = Get-VPNStatus
    if ($VPNStatus -eq "Up") {
        $VPNIP = (Get-NetIPAddress -InterfaceAlias $global:PANGPAdapter.Name).IPAddress
        $portalRegPath = "HKLM:\SOFTWARE\Palo Alto Networks\GlobalProtect\PanSetup"
        $portalKeyName = "Portal"
        $portalValue = (Get-ItemProperty -Path $portalRegPath -Name $portalKeyName).$portalKeyName
        Write-host "Status: $($VPNStatus)" -ForegroundColor Green
        Write-Host "Portal: $portalValue"
        Write-Host "IP: $VPNIP"
    }
    else {
        Write-host "Status: $($VPNStatus)" -ForegroundColor Yellow
    }
    Write-Host

    Write-Host "---- Work Account ----" -ForegroundColor Magenta
    $workaccountarray = Get-WorkAccountArray
    if ($null -ne $workaccountarray) {
        $global:WorkAccountAdded = $true
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
            $global:WorkAccountAdded = $true
            foreach ($account in $workaccountarray) {
                write-host $account.tostring().split(",")[-2].trim()
            }
        }
    }
    Write-Host

    Write-Host "---- Certificates ----" -ForegroundColor Magenta
    $certs = Get-Certs
    if ($certs) {
        $global:VPNCertsExist = $true
        foreach ($cert in $certs) {
            Write-host "$($cert.DnsNameList.Punycode) - $($cert.Thumbprint)" -ForegroundColor Green
        }
    }
    else {
        #Connect to VPN first
        if (!$global:VPNConnected) {
            Write-host "Connect to VPN to request certificates or press 'S' to skip"
            Start-Process -FilePath "C:\Program Files\Palo Alto Networks\GlobalProtect\PanGPA.exe"
            while ($VPNStatus -ne "Up") {
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
            $global:VPNCertsExist = $true
            foreach ($cert in $certs) {
                Write-host "$($cert.DnsNameList.Punycode) - $($cert.Thumbprint)"
            }
            Write-host "Refreshing VPN for new certs"
            Stop-Service -Name pangps
            $global:VPNConnected = $false
            Remove-Item -Path "HKLM:\SOFTWARE\Palo Alto Networks\GlobalProtect\Settings" -Recurse -Force
            Start-Service -Name pangps
            Write-Host "Waiting 10 seconds for VPN service..."
            start-sleep -Seconds 10
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
        if (!$global:VPNConnected) {
            Write-host "Connect to VPN to enable Bit-Locker or press 'S' to skip"
            Start-Process -FilePath "C:\Program Files\Palo Alto Networks\GlobalProtect\PanGPA.exe"
            while ($VPNStatus -ne "Up") {
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

    ## SOFTWARE CHECK ##
    Write-Host "---- Software ----" -ForegroundColor Magenta
    $missingSoftware = @()
    $64BitSoftPath = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*"
    $64BitSoftware = @("FortiClient VPN", "GlobalProtect", "Microsoft 365 Apps for enterprise")
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
    $32BitSoftware = @("Keysight IT ESI Group Profile")
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

    if (($64BitInstalled.Count -lt $64BitSoftware.Count) -or ($32BitInstalled.Count -lt $32BitSoftware.Count)) {
        Write-Host "Missing Software:" -ForegroundColor Red
        Write-Host ($missingSoftware -join "`n")
        if ($missingSoftware -ne @("FortiClient VPN")) {
            Start-Process softwarecenter:
        }
    }
    else {
        $shortcuts = Get-PublicShortcuts
        if ($shortcuts.Exists -contains $false) {
            Write-Warning "Not all shortcuts are on the desktop. Software may not be installed completely. Please open Software Center and confirm."
            Write-host "Missing Shortcuts:" -ForegroundColor Red
            Write-Host $(($shortcuts | Where-Object { !$_.Exists } | Select-Object -ExpandProperty Name) -join "`n")
        }
        else {
            $global:SoftwareInstalled = $true
            Write-Host "All software is installed." -ForegroundColor Green
        }
    }
    Write-host


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
                $global:OutlookLoggedIn = $true
                Write-Host "$emailAccount" -ForegroundColor Green
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
            $global:OneDriveLoggedIn = $true
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
