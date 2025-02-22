# ==================================================
#  Windows-MAC-Address-Spoofer v2.1 (Improved)
#  Improvements - Added error handling, input validation, logging, and modularity
# ==================================================
#  Based on Work from the following people:
#  Devs - Scut1ny & Ammar S.A.A
#  Original Link - https://github.com/Scrut1ny/Windows-MAC-Address-Spoofer
# ==================================================

# ANSI escape sequences for colors and formatting
$ANSI_RESET = "[0m"
$ANSI_GREEN = "[92m"
$ANSI_RED = "[91m"
$ANSI_INFO = "[104;97m"  # Light blue background, white text
$ANSI_WARNING = "[101;97m"  # Red background, white text

# Warn user about risks
Write-Host "`n  $ANSI_WARNING[!]$ANSI_RESET WARNING: This script requires administrator privileges and modifies system settings. Use it at your own risk.`n"
Start-Sleep -Seconds 2

# Check for admin rights
function Test-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "`n  $ANSI_GREEN# Administrator privileges are required.$ANSI_RESET"
        Start-Process powershell -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        exit
    }
}
Test-Admin

# Variable(s)
$regPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Class\{4d36e972-e325-11ce-bfc1-08002be10318}"
$logFile = "$env:TEMP\MAC_Spoof_Log.txt"

# Log changes
function Log-Change {
    param (
        [string]$message
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$timestamp - $message" | Out-File -FilePath $logFile -Append
}

# Main selection menu
function Selection-Menu {
    Clear-Host
    Write-Host "`n  $ANSI_INFO[i]$ANSI_RESET Input NIC # to modify.`n"
    
    $counter = 0
    $nic = Get-CimInstance Win32_NetworkAdapter | Where-Object {$_.NetConnectionID -ne $null} | ForEach-Object {
        $counter++
        Write-Host "  $counter - $($_.NetConnectionID)"
        $_.NetConnectionID
    }

    Write-Host "`n  $ANSI_GREEN99$ANSI_RESET - Revise Networking`n"
    $nicSelection = Read-Host "  "
    $nicSelection = [int]$nicSelection

    if ($nicSelection -gt 0 -and $nicSelection -le $nic.Count) {
        $global:NetworkAdapter = $nic[$nicSelection - 1]
        Spoof-MAC
    } elseif ($nicSelection -eq 99) {
        Clear-Host
        Write-Host "`n  $ANSI_GREEN# Revising networking configurations...$ANSI_RESET"
        {
            ipconfig /release
            arp -d *
            ipconfig /renew
        } *> $null
        Start-Sleep -Seconds 1
        Selection-Menu
    } else {
        Invalid-Selection
    }
}

# Function to display methods to modify MAC address
function Spoof-MAC {
    $originalMAC = Get-MAC
    Clear-Host
    Write-Host "`n  $ANSI_RED# Selected NIC:$ANSI_RESET $NetworkAdapter"
    Write-Host "`n  $ANSI_RED1$ANSI_RESET - Randomize MAC Address"
    Write-Host "`n  $ANSI_RED2$ANSI_RESET - Customize MAC Address"
    $choice = Read-Host "`n  "

    switch ($choice) {
        1 { 
            Clear-Host
            $useVendorPreset = Read-Host "`n  # Apply custom vendor preset? (Y/N)"
            if ($useVendorPreset -eq 'Y' -or $useVendorPreset -eq 'y') {
                Spoof-Vendor-Preset
            } else {
                Spoof-Random-MAC
            }
        }
        2 { Set-Custom-MAC }
        default { Invalid-Selection }
    }
}

# Function to spoof a random MAC address
function Spoof-Random-MAC {
    $randomMac = Generate-MAC
    $nicIndex = Get-NICIndex

    if (-not $nicIndex) {
        Write-Host "`n  $ANSI_WARNING[!]$ANSI_RESET NIC index not found. Aborting MAC spoofing."
        Exit-Menu
    }
    
    Clear-Host
    Write-Host "`n  $ANSI_RED> Registry Path:$ANSI_RESET $regPath\$nicIndex"
    Write-Host "`n  $ANSI_RED> Selected NIC:$ANSI_RESET $NetworkAdapter"
    Write-Host "`n  $ANSI_RED> Previous MAC:$ANSI_RESET $originalMAC"
    Write-Host "`n  $ANSI_RED> Modified MAC:$ANSI_RESET $randomMac"

    # Log the change
    Log-Change "Changed MAC address of $NetworkAdapter from $originalMAC to $randomMac"

    # Disable NIC, modify MAC, enable NIC
    try {
        Disable-NetAdapter -InterfaceAlias "$NetworkAdapter" -Confirm:$false
        Remove-ItemProperty -Path "$regPath\$nicIndex" -Name "OriginalNetworkAddress" -ErrorAction SilentlyContinue
        Set-ItemProperty -Path "$regPath\$nicIndex" -Name "NetworkAddress" -Value "$randomMac" -Force
        Restart-Service -Force -Name "winmgmt"
    } catch {
        Write-Host "`n  $ANSI_WARNING[!]$ANSI_RESET Error setting MAC address: $_"
    } finally {
        Enable-NetAdapter -InterfaceAlias "$NetworkAdapter" -Confirm:$false
    }

    Write-Host "`n  # Press any key to continue..."
    $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    Exit-Menu
}

# Function to manually set a custom MAC address
function Set-Custom-MAC {
    $originalMAC = Get-MAC
    Clear-Host
    Write-Host "`n  $ANSI_INFO[i]$ANSI_RESET Enter a custom MAC address for `"$NetworkAdapter`" NIC. (Format: FF:FF:FF:FF:FF:FF)"
    $customMAC = Read-Host "`n  "

    if ($customMAC -match '^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$') {
        $nicIndex = Get-NICIndex
        
        Clear-Host
        Write-Host "`n  $ANSI_RED> Registry Path:$ANSI_RESET $regPath\$nicIndex"
        Write-Host "`n  $ANSI_RED> Selected NIC:$ANSI_RESET $NetworkAdapter"
        Write-Host "`n  $ANSI_RED> Previous MAC:$ANSI_RESET $originalMAC"
        Write-Host "`n  $ANSI_RED> Custom MAC:$ANSI_RESET $customMAC"

        # Log the change
        Log-Change "Changed MAC address of $NetworkAdapter from $originalMAC to $customMAC"

        # Disable NIC, modify MAC, enable NIC
        try {
            Disable-NetAdapter -InterfaceAlias "$NetworkAdapter" -Confirm:$false
            Remove-ItemProperty -Path "$regPath\$nicIndex" -Name "OriginalNetworkAddress" -ErrorAction SilentlyContinue
            Set-ItemProperty -Path "$regPath\$nicIndex" -Name "NetworkAddress" -Value "$customMAC" -Force
            Restart-Service -Force -Name "winmgmt"
        } catch {
            Write-Host "`n  $ANSI_WARNING[!]$ANSI_RESET Error setting MAC address: $_"
        } finally {
            Enable-NetAdapter -InterfaceAlias "$NetworkAdapter" -Confirm:$false
        }

        Write-Host "`n  # Press any key to continue..."
        $null = $host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        Exit-Menu
    } else {
        Clear-Host
        Write-Host "`n  $ANSI_WARNING[!]$ANSI_RESET Invalid MAC address format. Please enter a valid MAC address."
        Start-Sleep -Seconds 3
        Set-Custom-MAC
    }
}

# Function to retrieve current MAC address
function Get-MAC {
    $nicIndex = Get-NICIndex
    $macAddress = (Get-ItemProperty -Path "$regPath\$nicIndex" -Name "NetworkAddress" -ErrorAction SilentlyContinue).NetworkAddress

    if (-not $macAddress) {
        $macAddress = (Get-CimInstance -Class Win32_NetworkAdapter | Where-Object { $_.NetConnectionId -eq "$NetworkAdapter" }).MacAddress
    }

    return $macAddress
}

# Function to retrieve NIC index
function Get-NICIndex {
    $nicCaption = (Get-CimInstance -Class Win32_NetworkAdapter | Where-Object { $_.NetConnectionId -eq "$NetworkAdapter" }).Caption
    $nicIndex = $nicCaption -replace ".*\[", "" -replace "\].*"
    $nicIndex = $nicIndex.Substring($nicIndex.Length - 4)
    return $nicIndex
}

# Function to generate random MAC address
function Generate-MAC {
    $randomMac = ('{0:X}' -f (Get-Random 0xFFFFFFFFFFFF)).PadLeft(12, "0")
    $replacementChar = Get-Random -InputObject @('A', 'E', '2', '6')
    $randomMac = $randomMac.Substring(0, 1) + $replacementChar + $randomMac.Substring(2)
    return $randomMac
}

# Function to handle invalid selection
function Invalid-Selection {
    Clear-Host
    Write-Host "`n  $ANSI_WARNING[!]$ANSI_RESET Invalid selection, please choose a valid option."
    Start-Sleep -Seconds 2
    Selection-Menu
}

# Function to display exit menu
function Exit-Menu {
    Clear-Host
    Write-Host "`n  $ANSI_RED1$ANSI_RESET - Selection Menu"
    Write-Host "  $ANSI_RED2$ANSI_RESET - Restart Device"
    Write-Host "  $ANSI_RED3$ANSI_RESET - Exit`n"
    $choice = Read-Host "  "

    switch ($choice) {
        1 { Selection-Menu }
        2 { Restart-Computer -Force }
        3 { exit 1 }
        default { Invalid-Selection }
    }
}

# Main execution
Selection-Menu
