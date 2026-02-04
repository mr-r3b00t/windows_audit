<#
.SYNOPSIS
    Windows Security Audit Tool - Compliance Edition v1.3.0
    
.DESCRIPTION
    A PowerShell 5.0 compatible security configuration auditing tool designed for 
    compliance assessments. Generates comprehensive HTML reports with risk ratings.
    
    This tool performs READ-ONLY checks and does not modify any system settings.
    Designed to minimize EDR false positives by using native PowerShell cmdlets.
    
.PARAMETER OutputPath
    Path for the HTML report output. Defaults to current directory.
    
.PARAMETER SkipNetworkChecks
    Skip network-related checks if running in restricted environment.
    
.PARAMETER Quiet
    Suppress console output during scan.

.PARAMETER PrivacyMode
    Redact hostnames, usernames, IP addresses, MAC addresses, and serial numbers
    from the report. Can also be enabled interactively when the script starts.
    
.EXAMPLE
    .\WinSecurityAudit.ps1 -OutputPath "C:\AuditReports"

.EXAMPLE
    .\WinSecurityAudit.ps1 -PrivacyMode -ExportJson
    
.NOTES
    Author: Security Audit Team
    Version: 1.1.0
    Requires: PowerShell 5.0+
    Purpose: Legal compliance auditing
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$OutputPath = $PWD.Path,
    
    [Parameter()]
    [switch]$SkipNetworkChecks,
    
    [Parameter()]
    [switch]$Quiet,
    
    [Parameter()]
    [switch]$ExportJson,
    
    [Parameter()]
    [switch]$PrivacyMode
)

#Requires -Version 5.0

# ============================================================================
# CONFIGURATION & GLOBALS
# ============================================================================

$Script:AuditVersion = "1.3.0"
$Script:AuditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$Script:Hostname = $env:COMPUTERNAME
$Script:Findings = [System.Collections.ArrayList]::new()
$Script:PrivacyEnabled = $false
$Script:PrivacyRedactions = @{}

# Load System.Web for HTML encoding (required for report generation)
Add-Type -AssemblyName System.Web -ErrorAction SilentlyContinue

# Risk levels and their numeric values for sorting
$Script:RiskLevels = @{
    'Critical' = 4
    'High'     = 3
    'Medium'   = 2
    'Low'      = 1
    'Info'     = 0
}

# Well-known service/system accounts to exclude from certain checks
$Script:SystemAccounts = @(
    'DefaultAccount',
    'WDAGUtilityAccount', 
    'Guest',
    'defaultuser0',
    'ASPNET',
    'krbtgt'
)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

function Write-AuditLog {
    param(
        [string]$Message,
        [string]$Level = "INFO"
    )
    
    if (-not $Quiet) {
        $timestamp = Get-Date -Format "HH:mm:ss"
        $color = switch ($Level) {
            "INFO"    { "Cyan" }
            "WARN"    { "Yellow" }
            "ERROR"   { "Red" }
            "SUCCESS" { "Green" }
            default   { "White" }
        }
        Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
    }
}

function Initialize-PrivacyMode {
    <#
    .SYNOPSIS
        Builds the redaction lookup table from live system data.
        Called once after Get-SystemInformation so all values are available.
    #>
    if (-not $Script:PrivacyEnabled) { return }
    
    Write-AuditLog "Privacy Mode: Building redaction table..." -Level "INFO"
    
    # Hostname / computer name
    $names = @($env:COMPUTERNAME)
    if ($Script:SystemInfo.Hostname) { $names += $Script:SystemInfo.Hostname }
    if ($env:USERDNSDOMAIN) { $names += $env:USERDNSDOMAIN }
    if ($Script:SystemInfo.Domain -and $Script:SystemInfo.Domain -ne 'WORKGROUP') {
        $names += $Script:SystemInfo.Domain
    }
    foreach ($n in ($names | Select-Object -Unique)) {
        if ($n -and $n.Length -ge 2) {
            $Script:PrivacyRedactions[$n] = "[REDACTED-HOST]"
        }
    }
    
    # Current user
    $usernames = @($env:USERNAME)
    if ($env:USERDOMAIN -and $env:USERDOMAIN -ne $env:COMPUTERNAME) {
        $Script:PrivacyRedactions[$env:USERDOMAIN] = "[REDACTED-DOMAIN]"
    }
    
    # All local user accounts
    try {
        $localUsers = Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" -ErrorAction SilentlyContinue
        if ($localUsers) {
            $luList = if ($localUsers -is [array]) { $localUsers } else { @($localUsers) }
            foreach ($lu in $luList) {
                if ($lu.Name -and $lu.Name.Length -ge 2) {
                    $usernames += $lu.Name
                }
            }
        }
    } catch { }
    
    # All user profile paths -> extract usernames from C:\Users\<name>
    try {
        $profiles = Get-CimInstance -ClassName Win32_UserProfile -ErrorAction SilentlyContinue
        if ($profiles) {
            $pList = if ($profiles -is [array]) { $profiles } else { @($profiles) }
            foreach ($p in $pList) {
                if ($p.LocalPath -match '\\Users\\(.+)$') {
                    $profName = $Matches[1]
                    if ($profName -and $profName.Length -ge 2 -and $profName -notin $Script:SystemAccounts) {
                        $usernames += $profName
                    }
                }
            }
        }
    } catch { }
    
    foreach ($u in ($usernames | Select-Object -Unique)) {
        if ($u -and $u.Length -ge 2) {
            $Script:PrivacyRedactions[$u] = "[REDACTED-USER]"
        }
    }
    
    # Serial number
    if ($Script:SystemInfo.SerialNumber -and $Script:SystemInfo.SerialNumber.Length -ge 3) {
        $Script:PrivacyRedactions[$Script:SystemInfo.SerialNumber] = "[REDACTED-SERIAL]"
    }
    
    # Disk serial numbers
    if ($Script:DiskInventory) {
        foreach ($d in $Script:DiskInventory) {
            if ($d.SerialNumber -and $d.SerialNumber.Length -ge 3) {
                $Script:PrivacyRedactions[$d.SerialNumber] = "[REDACTED-DISK-SERIAL]"
            }
        }
    }
    
    # IP addresses (local)
    try {
        $ipAddrs = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction SilentlyContinue
        if ($ipAddrs) {
            $ipList = if ($ipAddrs -is [array]) { $ipAddrs } else { @($ipAddrs) }
            foreach ($adapter in $ipList) {
                if ($adapter.IPAddress) {
                    foreach ($ip in $adapter.IPAddress) {
                        if ($ip -and $ip -ne '127.0.0.1' -and $ip -ne '::1' -and $ip.Length -ge 3) {
                            $Script:PrivacyRedactions[$ip] = "[REDACTED-IP]"
                        }
                    }
                }
                if ($adapter.DefaultIPGateway) {
                    foreach ($gw in $adapter.DefaultIPGateway) {
                        if ($gw -and $gw.Length -ge 3) {
                            $Script:PrivacyRedactions[$gw] = "[REDACTED-GATEWAY]"
                        }
                    }
                }
                if ($adapter.DNSServerSearchOrder) {
                    foreach ($dns in $adapter.DNSServerSearchOrder) {
                        if ($dns -and $dns.Length -ge 3) {
                            $Script:PrivacyRedactions[$dns] = "[REDACTED-DNS]"
                        }
                    }
                }
                if ($adapter.DHCPServer -and $adapter.DHCPServer.Length -ge 3) {
                    $Script:PrivacyRedactions[$adapter.DHCPServer] = "[REDACTED-DHCP]"
                }
            }
        }
    } catch { }
    
    # MAC addresses
    try {
        $macNics = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter "MACAddress IS NOT NULL" -ErrorAction SilentlyContinue
        if ($macNics) {
            $macList = if ($macNics -is [array]) { $macNics } else { @($macNics) }
            foreach ($nic in $macList) {
                if ($nic.MACAddress -and $nic.MACAddress.Length -ge 8) {
                    $Script:PrivacyRedactions[$nic.MACAddress] = "[REDACTED-MAC]"
                    # Also redact hyphen format
                    $hyphenMac = $nic.MACAddress -replace ':', '-'
                    if ($hyphenMac -ne $nic.MACAddress) {
                        $Script:PrivacyRedactions[$hyphenMac] = "[REDACTED-MAC]"
                    }
                }
            }
        }
    } catch { }
    
    # Hyper-V host/VM names from registry
    $hvHostName = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters" -Name "HostName" -Default $null
    if ($hvHostName -and $hvHostName.Length -ge 2) { $Script:PrivacyRedactions[$hvHostName] = "[REDACTED-HV-HOST]" }
    $hvVmName = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters" -Name "VirtualMachineName" -Default $null
    if ($hvVmName -and $hvVmName.Length -ge 2) { $Script:PrivacyRedactions[$hvVmName] = "[REDACTED-VM-NAME]" }
    
    # Sort redactions by length descending so longer matches are replaced first
    # (prevents partial replacements, e.g. replacing "ADMIN" inside "ADMIN-PC")
    $Script:PrivacyRedactionKeys = $Script:PrivacyRedactions.Keys | Sort-Object { $_.Length } -Descending
    
    Write-AuditLog "Privacy Mode: $($Script:PrivacyRedactions.Count) redaction patterns loaded" -Level "INFO"
}

function Protect-PrivacyString {
    <#
    .SYNOPSIS
        Applies all privacy redactions to a string. Returns the redacted string.
        If privacy mode is disabled, returns the input unchanged.
    #>
    param([string]$InputString)
    
    if (-not $Script:PrivacyEnabled -or -not $InputString -or $InputString.Length -eq 0) {
        return $InputString
    }
    
    $result = $InputString
    foreach ($key in $Script:PrivacyRedactionKeys) {
        if ($result -match [regex]::Escape($key)) {
            $result = $result -replace [regex]::Escape($key), $Script:PrivacyRedactions[$key]
        }
    }
    
    return $result
}

function Add-Finding {
    param(
        [Parameter(Mandatory)]
        [string]$Category,
        
        [Parameter(Mandatory)]
        [string]$Name,
        
        [Parameter(Mandatory)]
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')]
        [string]$Risk,
        
        [Parameter(Mandatory)]
        [string]$Description,
        
        [Parameter()]
        [string]$Details = "",
        
        [Parameter()]
        [string]$Recommendation = "",
        
        [Parameter()]
        [string]$Reference = ""
    )
    
    $finding = [PSCustomObject]@{
        Category       = $Category
        Name           = $Name
        Risk           = $Risk
        RiskValue      = $Script:RiskLevels[$Risk]
        Description    = $Description
        Details        = $Details
        Recommendation = $Recommendation
        Reference      = $Reference
        Timestamp      = Get-Date -Format "HH:mm:ss"
    }
    
    [void]$Script:Findings.Add($finding)
    
    $riskColor = switch ($Risk) {
        'Critical' { "Red" }
        'High'     { "DarkYellow" }
        'Medium'   { "Yellow" }
        'Low'      { "Cyan" }
        'Info'     { "Gray" }
    }
    
    if (-not $Quiet) {
        Write-Host "  [" -NoNewline
        Write-Host $Risk.ToUpper() -ForegroundColor $riskColor -NoNewline
        Write-Host "] $Name"
    }
}

function Test-IsAdmin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SafeWmiObject {
    param(
        [string]$Class,
        [string]$Namespace = "root\cimv2",
        [string]$Filter = ""
    )
    
    try {
        if ($Filter) {
            Get-CimInstance -ClassName $Class -Namespace $Namespace -Filter $Filter -ErrorAction Stop
        } else {
            Get-CimInstance -ClassName $Class -Namespace $Namespace -ErrorAction Stop
        }
    } catch {
        Write-AuditLog "Failed to query $Class : $_" -Level "WARN"
        return $null
    }
}

function Get-RegistryValue {
    param(
        [string]$Path,
        [string]$Name,
        [object]$Default = $null
    )
    
    try {
        $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction Stop
        return $item.$Name
    } catch {
        return $Default
    }
}

function Test-RegistryPathExists {
    param([string]$Path)
    return Test-Path -Path $Path -ErrorAction SilentlyContinue
}

# HTML encoding fallback if System.Web not available
function ConvertTo-HtmlSafe {
    param([string]$Text)
    
    if ([string]::IsNullOrEmpty($Text)) { return "" }
    
    try {
        return [System.Web.HttpUtility]::HtmlEncode($Text)
    } catch {
        # Fallback manual encoding
        return $Text.Replace('&', '&amp;').Replace('<', '&lt;').Replace('>', '&gt;').Replace('"', '&quot;').Replace("'", '&#39;')
    }
}

# ============================================================================
# AUDIT MODULES
# ============================================================================

function Get-SystemInformation {
    Write-AuditLog "Gathering System Information..." -Level "INFO"
    
    $os = Get-SafeWmiObject -Class Win32_OperatingSystem
    $cs = Get-SafeWmiObject -Class Win32_ComputerSystem
    $bios = Get-SafeWmiObject -Class Win32_BIOS
    $cpu = Get-SafeWmiObject -Class Win32_Processor
    $gpu = Get-SafeWmiObject -Class Win32_VideoController
    $baseboard = Get-SafeWmiObject -Class Win32_BaseBoard
    
    # Calculate uptime
    $uptimeStr = "Unknown"
    $lastBootStr = ""
    try {
        if ($os.LastBootUpTime) {
            # Get-CimInstance returns DateTime directly; Get-WmiObject returns a string
            $lastBoot = $null
            if ($os.LastBootUpTime -is [DateTime]) {
                $lastBoot = $os.LastBootUpTime
            } else {
                try { $lastBoot = [System.Management.ManagementDateTimeConverter]::ToDateTime($os.LastBootUpTime) } catch { }
            }
            
            if (-not $lastBoot) {
                try { $lastBoot = [DateTime]::Parse($os.LastBootUpTime.ToString()) } catch { }
            }
            
            if ($lastBoot) {
                $uptime = (Get-Date) - $lastBoot
                $lastBootStr = $lastBoot.ToString('yyyy-MM-dd HH:mm:ss')
                
                if ($uptime.TotalDays -ge 60) {
                    $months = [math]::Floor($uptime.TotalDays / 30)
                    $remDays = [math]::Floor($uptime.TotalDays % 30)
                    $uptimeStr = "$months months, $remDays days"
                } elseif ($uptime.TotalDays -ge 1) {
                    $days = [math]::Floor($uptime.TotalDays)
                    $hours = $uptime.Hours
                    $uptimeStr = "$days days, $hours hours"
                } else {
                    $hours = [math]::Floor($uptime.TotalHours)
                    $mins = $uptime.Minutes
                    $uptimeStr = "$hours hours, $mins minutes"
                }
            }
        }
    } catch { }
    
    # BIOS release date
    $biosDate = ""
    try {
        if ($bios.ReleaseDate) {
            if ($bios.ReleaseDate -is [DateTime]) {
                $biosDate = $bios.ReleaseDate.ToString('yyyy-MM-dd')
            } else {
                try {
                    $biosDate = ([System.Management.ManagementDateTimeConverter]::ToDateTime($bios.ReleaseDate)).ToString('yyyy-MM-dd')
                } catch {
                    try { $biosDate = ([DateTime]::Parse($bios.ReleaseDate.ToString())).ToString('yyyy-MM-dd') } catch { }
                }
            }
        }
    } catch { }
    
    # CPU details - handle array or single
    $cpuName = ""; $cpuCores = ""; $cpuThreads = ""; $cpuSpeed = ""
    if ($cpu) {
        $cpuObj = if ($cpu -is [array]) { $cpu[0] } else { $cpu }
        $cpuName = $cpuObj.Name -replace '\s+', ' '
        $cpuCores = $cpuObj.NumberOfCores
        $cpuThreads = $cpuObj.NumberOfLogicalProcessors
        $cpuSpeed = "$([math]::Round($cpuObj.MaxClockSpeed / 1000, 2)) GHz"
        if ($cpu -is [array] -and $cpu.Count -gt 1) {
            $cpuName = "$cpuName (x$($cpu.Count) sockets)"
        }
    }
    
    # GPU details - may have multiple
    $gpuDetails = @()
    if ($gpu) {
        $gpuList = if ($gpu -is [array]) { $gpu } else { @($gpu) }
        foreach ($g in $gpuList) {
            $vram = ""
            if ($g.AdapterRAM -and $g.AdapterRAM -gt 0) {
                $vramGB = [math]::Round($g.AdapterRAM / 1GB, 1)
                # AdapterRAM is a UInt32, so max ~4GB. For larger GPUs the value wraps
                if ($vramGB -le 0) { $vram = "N/A" }
                else { $vram = "${vramGB} GB" }
            }
            $driverVer = if ($g.DriverVersion) { $g.DriverVersion } else { "N/A" }
            $gpuDetails += [PSCustomObject]@{
                Name       = $g.Name
                VRAM       = $vram
                Driver     = $driverVer
                Resolution = if ($g.CurrentHorizontalResolution) { "$($g.CurrentHorizontalResolution)x$($g.CurrentVerticalResolution)" } else { "N/A" }
            }
        }
    }
    
    # RAM details
    $totalRAM = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
    $ramModules = @()
    try {
        $physMem = Get-SafeWmiObject -Class Win32_PhysicalMemory
        if ($physMem) {
            $memList = if ($physMem -is [array]) { $physMem } else { @($physMem) }
            foreach ($m in $memList) {
                $sizeGB = [math]::Round($m.Capacity / 1GB, 1)
                $speed = if ($m.ConfiguredClockSpeed) { "$($m.ConfiguredClockSpeed) MHz" } elseif ($m.Speed) { "$($m.Speed) MHz" } else { "N/A" }
                $type = switch ($m.SMBIOSMemoryType) {
                    20 { "DDR" } 21 { "DDR2" } 24 { "DDR3" } 26 { "DDR4" } 34 { "DDR5" }
                    default { 
                        switch ($m.MemoryType) { 20 { "DDR" } 21 { "DDR2" } 22 { "DDR2" } 24 { "DDR3" } 26 { "DDR4" } default { "" } }
                    }
                }
                $ramModules += "${sizeGB}GB $type $speed"
            }
        }
    } catch { }
    
    $Script:SystemInfo = [PSCustomObject]@{
        Hostname        = $env:COMPUTERNAME
        Domain          = $env:USERDOMAIN
        OSName          = $os.Caption
        OSVersion       = $os.Version
        OSBuild         = $os.BuildNumber
        Architecture    = $os.OSArchitecture
        InstallDate     = $os.InstallDate
        LastBoot        = $lastBootStr
        Uptime          = $uptimeStr
        Manufacturer    = $cs.Manufacturer
        Model           = $cs.Model
        Baseboard       = if ($baseboard) { "$($baseboard.Manufacturer) $($baseboard.Product)" } else { "N/A" }
        BIOSVersion     = $bios.SMBIOSBIOSVersion
        BIOSDate        = $biosDate
        SerialNumber    = $bios.SerialNumber
        CPU             = $cpuName
        CPUCores        = $cpuCores
        CPUThreads      = $cpuThreads
        CPUMaxSpeed     = $cpuSpeed
        TotalMemoryGB   = $totalRAM
        RAMModules      = $ramModules
        GPUs            = $gpuDetails
        CurrentUser     = "$env:USERDOMAIN\$env:USERNAME"
        IsAdmin         = Test-IsAdmin
        PowerShellVer   = $PSVersionTable.PSVersion.ToString()
        DotNetVersions  = (Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP' -Recurse -ErrorAction SilentlyContinue | 
                          Get-ItemProperty -Name Version -ErrorAction SilentlyContinue | 
                          Select-Object -ExpandProperty Version -Unique) -join ", "
    }
    
    Add-Finding -Category "System Info" -Name "System Overview" -Risk "Info" `
        -Description "Basic system information collected" `
        -Details "OS: $($Script:SystemInfo.OSName) | Build: $($Script:SystemInfo.OSBuild) | Arch: $($Script:SystemInfo.Architecture)"
    
    Add-Finding -Category "System Info" -Name "Hardware Summary" -Risk "Info" `
        -Description "Hardware identification and specification" `
        -Details "Make/Model: $($Script:SystemInfo.Manufacturer) $($Script:SystemInfo.Model)`nSerial: $($Script:SystemInfo.SerialNumber)`nBIOS: $($Script:SystemInfo.BIOSVersion) ($($Script:SystemInfo.BIOSDate))`nCPU: $($Script:SystemInfo.CPU) ($($Script:SystemInfo.CPUCores)C/$($Script:SystemInfo.CPUThreads)T @ $($Script:SystemInfo.CPUMaxSpeed))`nRAM: $($Script:SystemInfo.TotalMemoryGB) GB$(if ($ramModules.Count -gt 0) { " [$($ramModules -join ' + ')]" })`nGPU: $(($gpuDetails | ForEach-Object { "$($_.Name) ($($_.VRAM))" }) -join '; ')`nUptime: $($Script:SystemInfo.Uptime) (since $lastBootStr)"
    
    # Virtual Machine Detection
    # Strategy: use tiered indicators. Strong indicators (manufacturer/model, guest-only
    # tools/registry) are definitive. Weak indicators (services, MACs) need corroboration.
    # Physical OEM manufacturers are counter-indicators that prevent false positives
    # on hosts running Hyper-V, VBS, or Credential Guard.
    $vmDetected = $false
    $vmPlatform = "Physical"
    $vmIndicators = @()
    $isKnownPhysicalOEM = $false
    $isHyperVHost = $false
    
    $mfr = ($Script:SystemInfo.Manufacturer).ToLower()
    $model = ($Script:SystemInfo.Model).ToLower()
    $biosVer = if ($Script:SystemInfo.BIOSVersion) { ($Script:SystemInfo.BIOSVersion).ToLower() } else { "" }
    
    # Known physical OEM manufacturers - these make VM detection far less likely
    $physicalOEMs = @('dell', 'hewlett', 'lenovo', 'asus', 'acer', 'toshiba', 'samsung',
                      'fujitsu', 'panasonic', 'sony', 'msi', 'gigabyte', 'razer', 'apple',
                      'dynabook', 'getac', 'motion computing', 'nec', 'sharp', 'vaio',
                      'alienware', 'system76', 'framework', 'surface')
    foreach ($oem in $physicalOEMs) {
        if ($mfr -match [regex]::Escape($oem) -or $model -match [regex]::Escape($oem)) {
            $isKnownPhysicalOEM = $true
            break
        }
    }
    
    # Check if this machine is a Hyper-V HOST (runs vmms management service)
    $vmmsService = Get-Service -Name "vmms" -ErrorAction SilentlyContinue
    if ($vmmsService) {
        $isHyperVHost = $true
        $vmIndicators += "Hyper-V Host: vmms service present ($($vmmsService.Status)) - this is a hypervisor HOST"
    }
    
    # ---- STRONG indicators: manufacturer/model strings ----
    # These are set by the hypervisor BIOS and are definitive for guests
    if ($mfr -match 'vmware' -or $model -match 'vmware') {
        $vmDetected = $true; $vmPlatform = "VMware"
        $vmIndicators += "Manufacturer/Model contains 'VMware'"
    }
    elseif ($mfr -match 'microsoft' -and $model -match 'virtual') {
        $vmDetected = $true; $vmPlatform = "Hyper-V"
        $vmIndicators += "Model: Microsoft Virtual Machine"
    }
    elseif ($mfr -match 'innotek' -or $model -match 'virtualbox') {
        $vmDetected = $true; $vmPlatform = "VirtualBox"
        $vmIndicators += "Manufacturer/Model contains 'VirtualBox'"
    }
    elseif ($mfr -match 'qemu' -or $model -match 'qemu' -or $model -match 'standard pc' -or $model -match 'bochs') {
        $vmDetected = $true; $vmPlatform = "QEMU/KVM"
        $vmIndicators += "Manufacturer/Model indicates QEMU/KVM"
    }
    elseif ($mfr -match 'xen' -or $model -match 'xen' -or $model -match 'hvm domu') {
        $vmDetected = $true; $vmPlatform = "Xen"
        $vmIndicators += "Manufacturer/Model contains 'Xen'"
    }
    elseif ($mfr -match 'parallels' -or $model -match 'parallels') {
        $vmDetected = $true; $vmPlatform = "Parallels"
        $vmIndicators += "Manufacturer/Model contains 'Parallels'"
    }
    elseif ($mfr -match 'amazon' -or $model -match 'amazon' -or $biosVer -match 'amazon') {
        $vmDetected = $true; $vmPlatform = "Amazon EC2"
        $vmIndicators += "Manufacturer/BIOS indicates Amazon EC2"
    }
    elseif ($mfr -match 'google' -and ($model -match 'google' -or $model -match 'compute engine')) {
        $vmDetected = $true; $vmPlatform = "Google Cloud"
        $vmIndicators += "Manufacturer indicates Google Cloud"
    }
    elseif ($biosVer -match 'vbox' -or $biosVer -match 'vmware') {
        $vmDetected = $true; $vmPlatform = "Virtual Machine (BIOS)"
        $vmIndicators += "BIOS version contains virtualisation indicator"
    }
    
    # HypervisorPresent - supporting indicator only, NOT standalone
    # Physical hosts with Hyper-V role, VBS, or Credential Guard all set this
    if ($cs.HypervisorPresent -eq $true) {
        if ($vmDetected) {
            $vmIndicators += "HypervisorPresent: True (confirms VM)"
        } elseif ($isHyperVHost) {
            $vmIndicators += "HypervisorPresent: True (Hyper-V host role)"
        } else {
            $vmIndicators += "HypervisorPresent: True (VBS/Credential Guard or hypervisor role)"
        }
    }
    
    # ---- STRONG indicators: baseboard (only if not a known OEM) ----
    if (-not $vmDetected -and -not $isKnownPhysicalOEM -and $baseboard) {
        $bbProduct = if ($baseboard.Product) { $baseboard.Product.ToLower() } else { "" }
        $bbMfr = if ($baseboard.Manufacturer) { $baseboard.Manufacturer.ToLower() } else { "" }
        if ($bbProduct -match 'virtual|vmware|vbox|qemu|xen' -or $bbMfr -match 'virtual|vmware|vbox|qemu|xen') {
            $vmDetected = $true; $vmPlatform = "Virtual Machine (Baseboard)"
            $vmIndicators += "Baseboard: $($baseboard.Manufacturer) $($baseboard.Product)"
        }
    }
    
    # ---- STRONG indicators: guest-only tools and registry ----
    # These only exist inside a VM guest, never on a host
    $guestOnlyServices = @(
        @{ Name = "vmtools";        Platform = "VMware" },
        @{ Name = "vmtoolsd";       Platform = "VMware" },
        @{ Name = "VMUSBArbService"; Platform = "VMware" },
        @{ Name = "VBoxService";    Platform = "VirtualBox" },
        @{ Name = "VBoxClient";     Platform = "VirtualBox" }
    )
    
    foreach ($svc in $guestOnlyServices) {
        $service = Get-Service -Name $svc.Name -ErrorAction SilentlyContinue
        if ($service) {
            if (-not $vmDetected) { $vmDetected = $true; $vmPlatform = $svc.Platform }
            $vmIndicators += "Guest agent: $($svc.Name) ($($service.Status))"
        }
    }
    
    # Hyper-V integration services: these run on BOTH host and guest
    # Only count as VM evidence if this is NOT a known physical OEM and NOT a Hyper-V host
    $hvIntegrationServices = @("vmicheartbeat", "vmicshutdown", "vmickvpexchange", "vmicguestinterface",
                                "vmicrdv", "vmictimesync", "vmicvmsession", "vmicvss")
    $hvIntSvcFound = @()
    foreach ($svcName in $hvIntegrationServices) {
        $service = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($service) { $hvIntSvcFound += "$svcName ($($service.Status))" }
    }
    
    if ($hvIntSvcFound.Count -gt 0) {
        if ($vmDetected) {
            $vmIndicators += "Hyper-V integration services: $($hvIntSvcFound -join ', ')"
        } elseif ($isKnownPhysicalOEM -or $isHyperVHost) {
            # Known OEM or Hyper-V host - these services are expected, not a VM indicator
            $vmIndicators += "Hyper-V integration services present (expected on host/physical): $($hvIntSvcFound -join ', ')"
        } else {
            # Unknown manufacturer + integration services + no host indicator = likely guest
            if (-not $vmDetected) { $vmDetected = $true; $vmPlatform = "Hyper-V" }
            $vmIndicators += "Hyper-V integration services (no physical OEM detected): $($hvIntSvcFound -join ', ')"
        }
    }
    
    # Guest-only registry keys
    $guestOnlyRegKeys = @(
        @{ Path = "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools"; Platform = "VMware" },
        @{ Path = "HKLM:\SOFTWARE\Oracle\VirtualBox Guest Additions"; Platform = "VirtualBox" }
    )
    
    foreach ($reg in $guestOnlyRegKeys) {
        if (Test-Path $reg.Path) {
            if (-not $vmDetected) { $vmDetected = $true; $vmPlatform = $reg.Platform }
            $vmIndicators += "Guest tools registry: $($reg.Path)"
        }
    }
    
    # Hyper-V guest parameters key - this is guest-only (not present on hosts)
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters") {
        if (-not $vmDetected) { $vmDetected = $true; $vmPlatform = "Hyper-V" }
        $vmIndicators += "Hyper-V guest registry: HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters"
    }
    
    # ---- MAC address analysis ----
    # On a physical host with Hyper-V, there will be a MIX of physical and virtual MACs.
    # On a VM guest, ALL MACs will typically be virtual OUIs.
    # So: only use MAC as a VM indicator if there are NO physical MACs present.
    try {
        $nics = Get-CimInstance -ClassName Win32_NetworkAdapter -Filter "MACAddress IS NOT NULL AND PhysicalAdapter = True" -ErrorAction SilentlyContinue
        if ($nics) {
            $nicList = if ($nics -is [array]) { $nics } else { @($nics) }
            $physicalMacCount = 0
            $virtualMacCount = 0
            $virtualMacDetails = @()
            
            foreach ($nic in $nicList) {
                if ($nic.MACAddress) {
                    $mac = $nic.MACAddress.ToUpper()
                    $oui = $mac.Substring(0, 8)
                    $vmMac = switch -Wildcard ($oui) {
                        "00:50:56*" { "VMware" }
                        "00:0C:29*" { "VMware" }
                        "00:05:69*" { "VMware" }
                        "00:15:5D*" { "Hyper-V" }
                        "08:00:27*" { "VirtualBox" }
                        "52:54:00*" { "QEMU/KVM" }
                        "00:16:3E*" { "Xen" }
                        "00:1C:42*" { "Parallels" }
                        default { $null }
                    }
                    if ($vmMac) {
                        $virtualMacCount++
                        $virtualMacDetails += "$mac ($($nic.Name)) -> $vmMac"
                    } else {
                        $physicalMacCount++
                    }
                }
            }
            
            if ($virtualMacCount -gt 0 -and $physicalMacCount -eq 0) {
                # ALL MACs are virtual - strong VM indicator
                if (-not $vmDetected) { $vmDetected = $true; $vmPlatform = $virtualMacDetails[0].Split('>')[-1].Trim() }
                $vmIndicators += "All NICs have VM MACs (no physical MACs): $($virtualMacDetails -join '; ')"
            } elseif ($virtualMacCount -gt 0 -and $physicalMacCount -gt 0) {
                # Mix of virtual and physical - this is a host with virtual switches
                $vmIndicators += "Mixed MACs detected (physical host with virtual switch): $virtualMacCount virtual, $physicalMacCount physical"
            }
        }
    } catch { }
    
    # ---- Disk models ----
    try {
        $diskModels = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Model
        if ($diskModels) {
            foreach ($disk in $diskModels) {
                $diskLower = $disk.ToLower()
                if ($diskLower -match 'vmware virtual|vbox harddisk|qemu harddisk|virtual hd|msft virtual disk|xen') {
                    if (-not $vmDetected) { $vmDetected = $true; $vmPlatform = "Virtual Machine (Disk)" }
                    $vmIndicators += "Virtual disk: $disk"
                }
            }
        }
    } catch { }
    
    # ---- Final physical OEM sanity check ----
    # If a known physical OEM (Dell, HP, Lenovo etc.) is the manufacturer and no strong
    # guest-specific indicator was found, override any weak false-positive detections
    if ($vmDetected -and $isKnownPhysicalOEM) {
        # Check if we have a truly strong indicator or only weak ones
        $hasStrongIndicator = $false
        foreach ($ind in $vmIndicators) {
            if ($ind -match 'Guest agent:|Guest tools registry:|Hyper-V guest registry:|Virtual disk:|All NICs have VM MACs|Model: Microsoft Virtual') {
                $hasStrongIndicator = $true
                break
            }
        }
        if (-not $hasStrongIndicator) {
            # Known OEM with only weak indicators - this is a physical machine
            $vmDetected = $false
            $vmPlatform = "Physical"
            $vmIndicators += "Physical OEM override: $($Script:SystemInfo.Manufacturer) detected - weak VM indicators dismissed"
        }
    }
    
    # Store in SystemInfo
    $Script:SystemInfo | Add-Member -NotePropertyName "IsVirtualMachine" -NotePropertyValue $vmDetected -Force
    $Script:SystemInfo | Add-Member -NotePropertyName "VMPlatform" -NotePropertyValue $vmPlatform -Force
    $Script:SystemInfo | Add-Member -NotePropertyName "VMIndicators" -NotePropertyValue $vmIndicators -Force
    $Script:SystemInfo | Add-Member -NotePropertyName "IsHyperVHost" -NotePropertyValue $isHyperVHost -Force
    $Script:SystemInfo | Add-Member -NotePropertyName "IsKnownOEM" -NotePropertyValue $isKnownPhysicalOEM -Force
    
    if ($vmDetected) {
        $detailStr = "Platform: $vmPlatform`nDetection indicators:`n$(($vmIndicators | ForEach-Object { "  - $_" }) -join "`n")"
        
        Add-Finding -Category "System Info" -Name "Virtual Machine Detected" -Risk "Info" `
            -Description "This system is running as a $vmPlatform virtual machine" `
            -Details $detailStr
        
        # Security implications for VMs
        $vmSecDetails = @()
        
        # Check if VM tools are installed and up to date
        if ($vmPlatform -eq "VMware") {
            $vmToolsVer = Get-RegistryValue -Path "HKLM:\SOFTWARE\VMware, Inc.\VMware Tools" -Name "ProductVersion" -Default $null
            if ($vmToolsVer) {
                $vmSecDetails += "VMware Tools version: $vmToolsVer"
            } else {
                $vmSecDetails += "VMware Tools: Not detected or not installed"
            }
        }
        
        # Check for Hyper-V enhanced session
        if ($vmPlatform -eq "Hyper-V") {
            $hvGuest = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters" -Name "HostName" -Default $null
            if ($hvGuest) { $vmSecDetails += "Hyper-V Host: $hvGuest" }
            $hvVmName = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters" -Name "VirtualMachineName" -Default $null
            if ($hvVmName) { $vmSecDetails += "VM Name: $hvVmName" }
        }
        
        # Nested virtualisation check
        if ($cs.HypervisorPresent -eq $true -and $vmDetected) {
            $vmSecDetails += "Nested virtualisation may be available (hypervisor present inside VM)"
        }
        
        if ($vmSecDetails.Count -gt 0) {
            Add-Finding -Category "System Info" -Name "VM Platform Details" -Risk "Info" `
                -Description "Additional virtual machine platform information" `
                -Details ($vmSecDetails -join "`n")
        }
    } else {
        $physicalDesc = "No guest VM indicators detected - system is running on physical hardware"
        $physicalDetail = "Manufacturer: $($Script:SystemInfo.Manufacturer)`nModel: $($Script:SystemInfo.Model)"
        if ($isHyperVHost) {
            $physicalDesc = "Physical hardware with Hyper-V host role installed"
            $physicalDetail += "`nHyper-V Management Service (vmms): $($vmmsService.Status)"
        }
        if ($cs.HypervisorPresent -eq $true -and -not $isHyperVHost) {
            $physicalDetail += "`nNote: HypervisorPresent is True (VBS/Credential Guard active)"
        }
        Add-Finding -Category "System Info" -Name "Physical Hardware" -Risk "Info" `
            -Description $physicalDesc `
            -Details $physicalDetail
    }
    
    # -- Battery / Form Factor Detection --
    $formFactor = "Desktop"
    $hasBattery = $false
    $batteryDetails = @()
    
    # Check for battery via WMI
    try {
        $batteries = Get-CimInstance -ClassName Win32_Battery -ErrorAction SilentlyContinue
        if ($batteries) {
            $hasBattery = $true
            $batList = if ($batteries -is [array]) { $batteries } else { @($batteries) }
            foreach ($bat in $batList) {
                $batStatus = switch ($bat.BatteryStatus) {
                    1 { "Discharging" } 2 { "AC Power" } 3 { "Fully Charged" }
                    4 { "Low" } 5 { "Critical" } 6 { "Charging" }
                    7 { "Charging/High" } 8 { "Charging/Low" } 9 { "Charging/Critical" }
                    10 { "Undefined" } 11 { "Partially Charged" }
                    default { "Unknown ($($bat.BatteryStatus))" }
                }
                $chargeStr = if ($bat.EstimatedChargeRemaining) { "$($bat.EstimatedChargeRemaining)%" } else { "N/A" }
                $runtimeStr = ""
                if ($bat.EstimatedRunTime -and $bat.EstimatedRunTime -ne 71582788) {
                    $rtHrs = [math]::Floor($bat.EstimatedRunTime / 60)
                    $rtMin = $bat.EstimatedRunTime % 60
                    $runtimeStr = "${rtHrs}h ${rtMin}m"
                }
                $batName = if ($bat.Name) { $bat.Name } elseif ($bat.DeviceID) { $bat.DeviceID } else { "Battery" }
                $batLine = "$batName | Charge: $chargeStr | Status: $batStatus"
                if ($runtimeStr) { $batLine += " | Runtime: $runtimeStr" }
                $batteryDetails += $batLine
            }
        }
    } catch { }
    
    # Check chassis type for form factor
    try {
        $chassis = Get-CimInstance -ClassName Win32_SystemEnclosure -ErrorAction SilentlyContinue
        if ($chassis) {
            $chList = if ($chassis -is [array]) { $chassis[0] } else { $chassis }
            $chassisTypes = @($chList.ChassisTypes)
            # Map chassis type numbers to form factors
            # Laptop/Portable: 8,9,10,11,12,14,18,21,31,32
            # Desktop: 3,4,5,6,7,13,15,16,24,34,35,36
            # Server: 17,23,28
            # Tablet: 30
            # Mini PC: 33,35
            $chassisDesc = @()
            foreach ($ct in $chassisTypes) {
                $desc = switch ([int]$ct) {
                    1  { "Other" }
                    2  { "Unknown" }
                    3  { "Desktop" }
                    4  { "Low Profile Desktop" }
                    5  { "Pizza Box" }
                    6  { "Mini Tower" }
                    7  { "Tower" }
                    8  { "Portable" }
                    9  { "Laptop" }
                    10 { "Notebook" }
                    11 { "Handheld" }
                    12 { "Docking Station" }
                    13 { "All-in-One" }
                    14 { "Sub-Notebook" }
                    15 { "Space Saving" }
                    16 { "Lunch Box" }
                    17 { "Main Server Chassis" }
                    18 { "Expansion Chassis" }
                    19 { "Sub-Chassis" }
                    20 { "Bus Expansion Chassis" }
                    21 { "Peripheral Chassis" }
                    22 { "RAID Chassis" }
                    23 { "Rack Mount Chassis" }
                    24 { "Sealed-Case PC" }
                    25 { "Multi-System Chassis" }
                    26 { "Compact PCI" }
                    27 { "Advanced TCA" }
                    28 { "Blade" }
                    29 { "Blade Enclosure" }
                    30 { "Tablet" }
                    31 { "Convertible" }
                    32 { "Detachable" }
                    33 { "IoT Gateway" }
                    34 { "Embedded PC" }
                    35 { "Mini PC" }
                    36 { "Stick PC" }
                    default { "Type $ct" }
                }
                $chassisDesc += $desc
                
                if ([int]$ct -in @(8,9,10,11,14,18,21,30,31,32)) {
                    $formFactor = "Laptop"
                } elseif ([int]$ct -in @(17,23,28)) {
                    $formFactor = "Server"
                } elseif ([int]$ct -eq 30) {
                    $formFactor = "Tablet"
                } elseif ([int]$ct -in @(33,35,36)) {
                    $formFactor = "Mini PC"
                } elseif ([int]$ct -eq 13) {
                    $formFactor = "All-in-One"
                }
            }
            
            # Battery presence overrides chassis type for laptop detection
            # BUT only on physical hardware - VMs on laptops pass through the host battery
            if ($hasBattery -and $formFactor -eq "Desktop" -and -not $vmDetected) {
                $formFactor = "Laptop"
            }
            
            $Script:SystemInfo | Add-Member -NotePropertyName "ChassisType" -NotePropertyValue ($chassisDesc -join ", ") -Force
        }
    } catch { }
    
    $Script:SystemInfo | Add-Member -NotePropertyName "FormFactor" -NotePropertyValue $formFactor -Force
    $Script:SystemInfo | Add-Member -NotePropertyName "HasBattery" -NotePropertyValue $hasBattery -Force
    $Script:SystemInfo | Add-Member -NotePropertyName "BatteryDetails" -NotePropertyValue $batteryDetails -Force
    
    $formFactorDetail = "Form Factor: $formFactor"
    if ($Script:SystemInfo.ChassisType) { $formFactorDetail += "`nChassis Type: $($Script:SystemInfo.ChassisType)" }
    $formFactorDetail += "`nBattery: $(if ($hasBattery) { 'Detected' } else { 'Not detected' })"
    if ($batteryDetails.Count -gt 0) {
        $formFactorDetail += "`n$($batteryDetails -join "`n")"
    }
    
    Add-Finding -Category "System Info" -Name "Device Form Factor" -Risk "Info" `
        -Description "Device identified as: $formFactor$(if ($hasBattery -and -not $vmDetected) { ' (battery present)' } elseif ($hasBattery -and $vmDetected) { ' (battery passed through from host)' })" `
        -Details $formFactorDetail
    
    # -- Disk and Volume Enumeration --
    Write-AuditLog "Enumerating Disks and Storage Volumes..." -Level "INFO"
    
    $Script:DiskInventory = @()
    $Script:VolumeInventory = @()
    
    # Physical / Virtual Disks
    try {
        $diskDrives = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop
        if ($diskDrives) {
            $ddList = if ($diskDrives -is [array]) { $diskDrives } else { @($diskDrives) }
            foreach ($dd in $ddList) {
                $sizeGB = if ($dd.Size) { [math]::Round($dd.Size / 1GB, 2) } else { 0 }
                $mediaType = if ($dd.MediaType) { $dd.MediaType } else { "Unknown" }
                $busType = if ($dd.InterfaceType) { $dd.InterfaceType } else { "Unknown" }
                
                # Try to get more detail from MSFT_PhysicalDisk (Storage Spaces / NVMe aware)
                $healthStatus = "N/A"
                $msftMediaType = ""
                $serialNum = if ($dd.SerialNumber) { $dd.SerialNumber.Trim() } else { "" }
                $fwRev = if ($dd.FirmwareRevision) { $dd.FirmwareRevision.Trim() } else { "" }
                
                try {
                    $pDisks = Get-CimInstance -Namespace "root\Microsoft\Windows\Storage" -ClassName MSFT_PhysicalDisk -ErrorAction SilentlyContinue
                    if ($pDisks) {
                        $pdList = if ($pDisks -is [array]) { $pDisks } else { @($pDisks) }
                        # Match by disk number from DeviceID
                        $diskNum = $null
                        if ($dd.DeviceID -match '(\d+)$') { $diskNum = $Matches[1] }
                        foreach ($pd in $pdList) {
                            if ($pd.DeviceId -eq $diskNum) {
                                $healthStatus = switch ($pd.HealthStatus) {
                                    0 { "Healthy" } 1 { "Warning" } 2 { "Unhealthy" } 5 { "Unknown" } default { "Status $($pd.HealthStatus)" }
                                }
                                $msftMediaType = switch ($pd.MediaType) {
                                    0 { "Unspecified" } 3 { "HDD" } 4 { "SSD" } 5 { "SCM" } default { "" }
                                }
                                if (-not $serialNum -and $pd.SerialNumber) { $serialNum = $pd.SerialNumber.Trim() }
                                if (-not $fwRev -and $pd.FirmwareVersion) { $fwRev = $pd.FirmwareVersion.Trim() }
                                break
                            }
                        }
                    }
                } catch { }
                
                $diskType = if ($msftMediaType -and $msftMediaType -ne "Unspecified") { $msftMediaType } else {
                    # Heuristic: if no rotational media string and model suggests SSD/NVMe
                    $modelLower = ($dd.Model).ToLower()
                    if ($modelLower -match 'ssd|nvme|solid state|flash') { "SSD" }
                    elseif ($modelLower -match 'hdd|hard disk|barracuda|ironwolf|caviar') { "HDD" }
                    else { "Unknown" }
                }
                
                $Script:DiskInventory += [PSCustomObject]@{
                    DiskNumber    = if ($dd.DeviceID -match '(\d+)$') { [int]$Matches[1] } else { -1 }
                    Model         = if ($dd.Model) { $dd.Model.Trim() } else { "Unknown" }
                    SerialNumber  = $serialNum
                    FirmwareRev   = $fwRev
                    MediaType     = $diskType
                    BusType       = $busType
                    SizeGB        = $sizeGB
                    Partitions    = $dd.Partitions
                    Health        = $healthStatus
                    Status        = if ($dd.Status) { $dd.Status } else { "Unknown" }
                }
            }
        }
    } catch {
        Write-AuditLog "Failed to enumerate disk drives: $_" -Level "WARN"
    }
    
    # Volumes / Logical Disks
    try {
        $volumes = Get-CimInstance -ClassName Win32_LogicalDisk -ErrorAction Stop
        if ($volumes) {
            $volList = if ($volumes -is [array]) { $volumes } else { @($volumes) }
            foreach ($vol in $volList) {
                $driveType = switch ($vol.DriveType) {
                    0 { "Unknown" } 1 { "No Root" } 2 { "Removable" } 3 { "Fixed" }
                    4 { "Network" } 5 { "Optical" } 6 { "RAM Disk" } default { "Type $($vol.DriveType)" }
                }
                
                $totalGB = if ($vol.Size) { [math]::Round($vol.Size / 1GB, 2) } else { 0 }
                $freeGB = if ($vol.FreeSpace) { [math]::Round($vol.FreeSpace / 1GB, 2) } else { 0 }
                $usedGB = [math]::Round($totalGB - $freeGB, 2)
                $pctFree = if ($totalGB -gt 0) { [math]::Round(($freeGB / $totalGB) * 100, 1) } else { 0 }
                $pctUsed = if ($totalGB -gt 0) { [math]::Round(100 - $pctFree, 1) } else { 0 }
                
                $Script:VolumeInventory += [PSCustomObject]@{
                    DriveLetter   = $vol.DeviceID
                    VolumeName    = if ($vol.VolumeName) { $vol.VolumeName } else { "(No Label)" }
                    DriveType     = $driveType
                    FileSystem    = if ($vol.FileSystem) { $vol.FileSystem } else { "N/A" }
                    TotalGB       = $totalGB
                    UsedGB        = $usedGB
                    FreeGB        = $freeGB
                    PercentFree   = $pctFree
                    PercentUsed   = $pctUsed
                    Compressed    = [bool]$vol.Compressed
                }
            }
        }
    } catch {
        Write-AuditLog "Failed to enumerate volumes: $_" -Level "WARN"
    }
    
    # Also grab BitLocker volume encryption status if available
    $Script:VolumeEncryption = @{}
    try {
        $blVolumes = Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftVolumeEncryption" -ClassName Win32_EncryptableVolume -ErrorAction SilentlyContinue
        if ($blVolumes) {
            $blList = if ($blVolumes -is [array]) { $blVolumes } else { @($blVolumes) }
            foreach ($blv in $blList) {
                $protStatus = switch ($blv.ProtectionStatus) {
                    0 { "Unprotected" } 1 { "Protected" } 2 { "Unknown" } default { "Status $($blv.ProtectionStatus)" }
                }
                $convStatus = switch ($blv.ConversionStatus) {
                    0 { "Fully Decrypted" } 1 { "Fully Encrypted" } 2 { "Encrypting" }
                    3 { "Decrypting" } 4 { "Encryption Paused" } 5 { "Decryption Paused" }
                    default { "Status $($blv.ConversionStatus)" }
                }
                $encMethod = switch ($blv.EncryptionMethod) {
                    0 { "None" } 1 { "AES-128 Diffuser" } 2 { "AES-256 Diffuser" }
                    3 { "AES-128" } 4 { "AES-256" } 6 { "XTS-AES-128" } 7 { "XTS-AES-256" }
                    default { "Method $($blv.EncryptionMethod)" }
                }
                $letter = $blv.DriveLetter
                if ($letter) {
                    $Script:VolumeEncryption[$letter] = [PSCustomObject]@{
                        Protection = $protStatus
                        Conversion = $convStatus
                        Method     = $encMethod
                    }
                }
            }
        }
    } catch { }
    
    # Store in SystemInfo
    $Script:SystemInfo | Add-Member -NotePropertyName "Disks" -NotePropertyValue $Script:DiskInventory -Force
    $Script:SystemInfo | Add-Member -NotePropertyName "Volumes" -NotePropertyValue $Script:VolumeInventory -Force
    
    # Generate findings
    $diskSummaryLines = @()
    foreach ($d in $Script:DiskInventory) {
        $diskSummaryLines += "Disk $($d.DiskNumber): $($d.Model) | $($d.MediaType) | $($d.SizeGB) GB | $($d.BusType) | Health: $($d.Health)"
    }
    
    $volSummaryLines = @()
    foreach ($v in $Script:VolumeInventory) {
        if ($v.DriveType -eq "Fixed" -or $v.DriveType -eq "Removable") {
            $encStr = ""
            if ($Script:VolumeEncryption.ContainsKey($v.DriveLetter)) {
                $enc = $Script:VolumeEncryption[$v.DriveLetter]
                $encStr = " | BitLocker: $($enc.Protection) ($($enc.Method))"
            }
            $volSummaryLines += "$($v.DriveLetter) $($v.VolumeName) | $($v.FileSystem) | $($v.TotalGB) GB total, $($v.FreeGB) GB free ($($v.PercentFree)%)$encStr"
        }
    }
    
    if ($diskSummaryLines.Count -gt 0) {
        Add-Finding -Category "System Info" -Name "Storage Disks" -Risk "Info" `
            -Description "$($Script:DiskInventory.Count) disk(s) detected" `
            -Details ($diskSummaryLines -join "`n")
    }
    
    if ($volSummaryLines.Count -gt 0) {
        Add-Finding -Category "System Info" -Name "Storage Volumes" -Risk "Info" `
            -Description "$($Script:VolumeInventory.Count) volume(s) detected" `
            -Details ($volSummaryLines -join "`n")
    }
    
    # Flag volumes with low free space
    foreach ($v in $Script:VolumeInventory) {
        if ($v.DriveType -eq "Fixed" -and $v.TotalGB -gt 0) {
            if ($v.PercentFree -lt 5) {
                Add-Finding -Category "System Info" -Name "Critical Low Disk Space: $($v.DriveLetter)" -Risk "High" `
                    -Description "Volume $($v.DriveLetter) ($($v.VolumeName)) has only $($v.FreeGB) GB free ($($v.PercentFree)%)" `
                    -Details "Total: $($v.TotalGB) GB | Used: $($v.UsedGB) GB | Free: $($v.FreeGB) GB`nLow disk space can prevent Windows Update, crash applications, and impact security logging." `
                    -Recommendation "Free up disk space or expand the volume immediately"
            } elseif ($v.PercentFree -lt 10) {
                Add-Finding -Category "System Info" -Name "Low Disk Space: $($v.DriveLetter)" -Risk "Medium" `
                    -Description "Volume $($v.DriveLetter) ($($v.VolumeName)) has $($v.FreeGB) GB free ($($v.PercentFree)%)" `
                    -Details "Total: $($v.TotalGB) GB | Used: $($v.UsedGB) GB | Free: $($v.FreeGB) GB" `
                    -Recommendation "Consider freeing disk space to ensure Windows Update and security tools can function"
            }
        }
    }
    
    # Flag unhealthy disks
    foreach ($d in $Script:DiskInventory) {
        if ($d.Health -eq "Warning") {
            Add-Finding -Category "System Info" -Name "Disk Health Warning: Disk $($d.DiskNumber)" -Risk "High" `
                -Description "Disk $($d.DiskNumber) ($($d.Model)) is reporting a health warning" `
                -Details "Health: $($d.Health) | Status: $($d.Status) | Size: $($d.SizeGB) GB" `
                -Recommendation "Back up data immediately and consider replacing this disk"
        } elseif ($d.Health -eq "Unhealthy") {
            Add-Finding -Category "System Info" -Name "Disk Unhealthy: Disk $($d.DiskNumber)" -Risk "Critical" `
                -Description "Disk $($d.DiskNumber) ($($d.Model)) is reporting as unhealthy - imminent failure risk" `
                -Details "Health: $($d.Health) | Status: $($d.Status) | Size: $($d.SizeGB) GB" `
                -Recommendation "Back up all data IMMEDIATELY and replace this disk"
        }
    }
    
    # Flag non-NTFS system volumes
    foreach ($v in $Script:VolumeInventory) {
        if ($v.DriveLetter -eq "C:" -and $v.FileSystem -and $v.FileSystem -ne "NTFS" -and $v.FileSystem -ne "ReFS") {
            Add-Finding -Category "System Info" -Name "System Drive Non-NTFS" -Risk "Medium" `
                -Description "System drive C: is using $($v.FileSystem) instead of NTFS" `
                -Details "File system: $($v.FileSystem). NTFS is required for proper Windows security features including file permissions, EFS, and audit logging." `
                -Recommendation "The system drive should use NTFS for proper security controls"
        }
    }
    
    # CRITICAL: Warn if not running as admin
    if (-not $Script:SystemInfo.IsAdmin) {
        Add-Finding -Category "System Info" -Name "[!!] SCAN RUN WITHOUT ADMIN RIGHTS" -Risk "Critical" `
            -Description "This audit was NOT run with administrative privileges - RESULTS ARE INCOMPLETE" `
            -Details "Many security checks require admin rights to access protected settings, registry keys, and system configuration. The findings in this report do not represent the complete security posture of this system.`n`nAffected areas include: Security policies, BitLocker, Credential Guard, LSA protection, Windows Defender configuration, audit policies, user rights, driver signing, and many others." `
            -Recommendation "RE-RUN THIS AUDIT FROM AN ELEVATED POWERSHELL PROMPT (Run as Administrator) to get complete and accurate results." `
            -Reference "Administrative privileges required for full security audit"
    }
    
    # Check Windows version/build for support status
    # Windows 10: 19041 (2004), 19042 (20H2), 19043 (21H1), 19044 (21H2), 19045 (22H2)
    # Windows 11: 22000 (21H2), 22621 (22H2), 22631 (23H2)
    $build = [int]$Script:SystemInfo.OSBuild
    
    $isWindows11 = $build -ge 22000
    $isSupported = $false
    
    if ($isWindows11) {
        # Windows 11 - check for supported builds
        $isSupported = $build -ge 22621  # 22H2 and later
    } else {
        # Windows 10 - check for supported builds  
        $isSupported = $build -ge 19044  # 21H2 and later
    }
    
    if (-not $isSupported) {
        $osType = if ($isWindows11) { "Windows 11" } else { "Windows 10" }
        Add-Finding -Category "System Info" -Name "Outdated Windows Build" -Risk "High" `
            -Description "System is running an older $osType build that may be out of support" `
            -Details "Current Build: $build. Recommend updating to a supported version." `
            -Recommendation "Update Windows to a currently supported version" `
            -Reference "https://docs.microsoft.com/en-us/windows/release-health/"
    } else {
        Add-Finding -Category "System Info" -Name "Windows Build Status" -Risk "Info" `
            -Description "Windows build appears to be supported" `
            -Details "Current Build: $build"
    }
}

function Test-MDMEnrollment {
    Write-AuditLog "Checking Mobile Device Management (MDM) Enrollment..." -Level "INFO"
    
    $Script:MDMStatus = [PSCustomObject]@{
        IsEnrolled = $false
        MDMProvider = $null
        EnrollmentType = $null
        Details = @()
    }
    
    # Check for MDM enrollment via registry
    $mdmEnrollmentPath = "HKLM:\SOFTWARE\Microsoft\Enrollments"
    $mdmFound = $false
    
    if (Test-Path $mdmEnrollmentPath) {
        $enrollments = Get-ChildItem -Path $mdmEnrollmentPath -ErrorAction SilentlyContinue
        foreach ($enrollment in $enrollments) {
            $providerId = Get-RegistryValue -Path $enrollment.PSPath -Name "ProviderId" -Default $null
            $upn = Get-RegistryValue -Path $enrollment.PSPath -Name "UPN" -Default $null
            $enrollmentType = Get-RegistryValue -Path $enrollment.PSPath -Name "EnrollmentType" -Default $null
            
            if ($providerId) {
                $mdmFound = $true
                $Script:MDMStatus.IsEnrolled = $true
                $Script:MDMStatus.MDMProvider = $providerId
                $Script:MDMStatus.EnrollmentType = $enrollmentType
                $Script:MDMStatus.Details += "Provider: $providerId, UPN: $upn"
            }
        }
    }
    
    # Check for Intune enrollment specifically
    $intunePath = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension"
    $intuneEnrolled = Test-Path $intunePath
    
    # Check for Azure AD Join status
    $aadJoined = $false
    $aadPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
    if (Test-Path $aadPath) {
        $joinInfo = Get-ChildItem -Path $aadPath -ErrorAction SilentlyContinue
        if ($joinInfo) {
            $aadJoined = $true
            foreach ($info in $joinInfo) {
                $tenantId = Get-RegistryValue -Path $info.PSPath -Name "TenantId" -Default $null
                if ($tenantId) {
                    $Script:MDMStatus.Details += "Azure AD Tenant: $tenantId"
                }
            }
        }
    }
    
    # Check dsregcmd for detailed status (if available)
    try {
        $dsregOutput = dsregcmd /status 2>&1
        if ($dsregOutput -match "AzureAdJoined\s*:\s*YES") {
            $aadJoined = $true
        }
        if ($dsregOutput -match "DomainJoined\s*:\s*YES") {
            $Script:MDMStatus.Details += "Domain Joined: Yes"
        }
        if ($dsregOutput -match "MdmUrl\s*:\s*(\S+)") {
            $mdmFound = $true
            $Script:MDMStatus.IsEnrolled = $true
            $Script:MDMStatus.Details += "MDM URL: $($Matches[1])"
        }
    } catch { }
    
    # Report findings
    if ($Script:MDMStatus.IsEnrolled -or $intuneEnrolled) {
        $details = "MDM Enrollment: Yes"
        if ($Script:MDMStatus.MDMProvider) { $details += "`nProvider: $($Script:MDMStatus.MDMProvider)" }
        if ($intuneEnrolled) { $details += "`nMicrosoft Intune: Detected" }
        if ($aadJoined) { $details += "`nAzure AD Joined: Yes" }
        $details += "`n$($Script:MDMStatus.Details -join "`n")"
        
        Add-Finding -Category "MDM" -Name "Device is MDM Enrolled" -Risk "Info" `
            -Description "This device is enrolled in Mobile Device Management" `
            -Details $details `
            -Reference "Cyber Essentials: Secure Configuration"
    } else {
        $details = "MDM Enrollment: Not detected"
        if ($aadJoined) { $details += "`nAzure AD Joined: Yes (but no MDM)" }
        
        Add-Finding -Category "MDM" -Name "Device Not MDM Enrolled" -Risk "Medium" `
            -Description "This device does not appear to be enrolled in Mobile Device Management" `
            -Details $details `
            -Recommendation "Consider enrolling device in MDM (e.g., Microsoft Intune) for centralized management and policy enforcement" `
            -Reference "Cyber Essentials: Secure Configuration"
    }
    
    $Script:MDMStatus.IsAzureADJoined = $aadJoined
}

function Get-CyberEssentialsSummary {
    Write-AuditLog "Generating Cyber Essentials Summary..." -Level "INFO"
    
    # Initialize Cyber Essentials assessment
    $Script:CyberEssentials = @{
        Firewalls = @{ Status = "Unknown"; Pass = $false; Details = @() }
        SecureConfiguration = @{ Status = "Unknown"; Pass = $false; Details = @() }
        UserAccessControl = @{ Status = "Unknown"; Pass = $false; Details = @() }
        MalwareProtection = @{ Status = "Unknown"; Pass = $false; Details = @() }
        PatchManagement = @{ Status = "Unknown"; Pass = $false; Details = @() }
    }
    
    # 1. FIREWALLS - Check Windows Firewall status
    try {
        $firewallProfiles = Get-NetFirewallProfile -ErrorAction Stop
        $allEnabled = $true
        $enabledProfiles = @()
        $disabledProfiles = @()
        
        foreach ($profile in $firewallProfiles) {
            if ($profile.Enabled) {
                $enabledProfiles += $profile.Name
            } else {
                $allEnabled = $false
                $disabledProfiles += $profile.Name
            }
        }
        
        if ($allEnabled) {
            $Script:CyberEssentials.Firewalls.Status = "PASS"
            $Script:CyberEssentials.Firewalls.Pass = $true
            $Script:CyberEssentials.Firewalls.Details += "All firewall profiles enabled: $($enabledProfiles -join ', ')"
        } else {
            $Script:CyberEssentials.Firewalls.Status = "FAIL"
            $Script:CyberEssentials.Firewalls.Details += "Disabled profiles: $($disabledProfiles -join ', ')"
        }
    } catch {
        $Script:CyberEssentials.Firewalls.Status = "UNKNOWN"
        $Script:CyberEssentials.Firewalls.Details += "Could not check firewall status"
    }
    
    # 2. SECURE CONFIGURATION - MDM, Admin accounts, UAC
    $secConfigIssues = 0
    
    # Check MDM
    if ($Script:MDMStatus -and $Script:MDMStatus.IsEnrolled) {
        $Script:CyberEssentials.SecureConfiguration.Details += "[OK] MDM Enrolled"
    } else {
        $secConfigIssues++
        $Script:CyberEssentials.SecureConfiguration.Details += "[FAIL] Not MDM Enrolled"
    }
    
    # Check UAC
    $uacEnabled = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLUA" -Default 0
    if ($uacEnabled -eq 1) {
        $Script:CyberEssentials.SecureConfiguration.Details += "[OK] UAC Enabled"
    } else {
        $secConfigIssues++
        $Script:CyberEssentials.SecureConfiguration.Details += "[FAIL] UAC Disabled"
    }
    
    # Check for old third-party software
    if ($Script:SoftwareInventory) {
        $twoYearsAgo = (Get-Date).AddDays(-730)
        $oldThirdParty = @($Script:SoftwareInventory | Where-Object { 
            $_.InstallDate -and $_.InstallDate -lt $twoYearsAgo -and -not $_.IsSystemVendor
        })
        if ($oldThirdParty.Count -gt 10) {
            $secConfigIssues++
            $Script:CyberEssentials.SecureConfiguration.Details += "[FAIL] $($oldThirdParty.Count) old third-party apps (>2 years)"
        } elseif ($oldThirdParty.Count -gt 0) {
            $Script:CyberEssentials.SecureConfiguration.Details += "[WARN] $($oldThirdParty.Count) old third-party apps"
        } else {
            $Script:CyberEssentials.SecureConfiguration.Details += "[OK] No old third-party software"
        }
    }
    
    $Script:CyberEssentials.SecureConfiguration.Status = if ($secConfigIssues -eq 0) { "PASS" } elseif ($secConfigIssues -le 1) { "REVIEW" } else { "FAIL" }
    $Script:CyberEssentials.SecureConfiguration.Pass = $secConfigIssues -eq 0
    
    # 3. USER ACCESS CONTROL - Admin account usage
    $uacIssues = 0
    
    try {
        $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
        $adminCount = @($adminGroup).Count
        
        if ($adminCount -gt 3) {
            $uacIssues++
            $Script:CyberEssentials.UserAccessControl.Details += "[FAIL] $adminCount local admin accounts (recommend <=3)"
        } else {
            $Script:CyberEssentials.UserAccessControl.Details += "[OK] $adminCount local admin accounts"
        }
    } catch {
        $Script:CyberEssentials.UserAccessControl.Details += "[WARN] Could not enumerate admins"
    }
    
    # Check if current user is admin for daily use
    if ($Script:SystemInfo.IsAdmin) {
        $Script:CyberEssentials.UserAccessControl.Details += "[WARN] Current session running as admin"
    }
    
    # Check Guest account
    try {
        $guest = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
        if ($guest -and $guest.Enabled) {
            $uacIssues++
            $Script:CyberEssentials.UserAccessControl.Details += "[FAIL] Guest account enabled"
        } else {
            $Script:CyberEssentials.UserAccessControl.Details += "[OK] Guest account disabled"
        }
    } catch { }
    
    $Script:CyberEssentials.UserAccessControl.Status = if ($uacIssues -eq 0) { "PASS" } elseif ($uacIssues -eq 1) { "REVIEW" } else { "FAIL" }
    $Script:CyberEssentials.UserAccessControl.Pass = $uacIssues -eq 0
    
    # 4. MALWARE PROTECTION
    $malwareIssues = 0
    
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        
        if ($defenderStatus.AntivirusEnabled) {
            $Script:CyberEssentials.MalwareProtection.Details += "[OK] Windows Defender enabled"
        } else {
            $malwareIssues++
            $Script:CyberEssentials.MalwareProtection.Details += "[FAIL] Windows Defender disabled"
        }
        
        if ($defenderStatus.RealTimeProtectionEnabled) {
            $Script:CyberEssentials.MalwareProtection.Details += "[OK] Real-time protection on"
        } else {
            $malwareIssues++
            $Script:CyberEssentials.MalwareProtection.Details += "[FAIL] Real-time protection off"
        }
        
        if ($defenderStatus.AntivirusSignatureAge -le 1) {
            $Script:CyberEssentials.MalwareProtection.Details += "[OK] Signatures up to date"
        } elseif ($defenderStatus.AntivirusSignatureAge -le 7) {
            $Script:CyberEssentials.MalwareProtection.Details += "[WARN] Signatures $($defenderStatus.AntivirusSignatureAge) days old"
        } else {
            $malwareIssues++
            $Script:CyberEssentials.MalwareProtection.Details += "[FAIL] Signatures $($defenderStatus.AntivirusSignatureAge) days old"
        }
    } catch {
        $Script:CyberEssentials.MalwareProtection.Details += "[WARN] Could not check Defender status"
    }
    
    $Script:CyberEssentials.MalwareProtection.Status = if ($malwareIssues -eq 0) { "PASS" } elseif ($malwareIssues -eq 1) { "REVIEW" } else { "FAIL" }
    $Script:CyberEssentials.MalwareProtection.Pass = $malwareIssues -eq 0
    
    # 5. PATCH MANAGEMENT - Windows Update configuration and status
    $patchIssues = 0
    
    # Check Windows Update service - Disabled is bad, Manual is normal/expected
    $wuService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
    if ($wuService -and $wuService.StartType -eq 'Disabled') {
        $patchIssues++
        $Script:CyberEssentials.PatchManagement.Details += "[FAIL] Windows Update service disabled"
    } else {
        $Script:CyberEssentials.PatchManagement.Details += "[OK] Windows Update service enabled"
    }
    
    # Check if automatic updates are configured
    $auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
    $noAutoUpdate = Get-RegistryValue -Path $auPath -Name "NoAutoUpdate" -Default 0
    $auOptions = Get-RegistryValue -Path $auPath -Name "AUOptions" -Default $null
    
    if ($noAutoUpdate -eq 1 -or $auOptions -eq 1) {
        $patchIssues++
        $Script:CyberEssentials.PatchManagement.Details += "[FAIL] Automatic updates disabled"
    } elseif ($auOptions -eq 4) {
        $Script:CyberEssentials.PatchManagement.Details += "[OK] Auto-install updates enabled"
    } elseif ($auOptions -in @(2, 3)) {
        $Script:CyberEssentials.PatchManagement.Details += "[WARN] Updates require manual install"
    } else {
        $Script:CyberEssentials.PatchManagement.Details += "[OK] Using Windows default updates"
    }
    
    # Check WSUS configuration for security issues
    $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
    $wsusServer = Get-RegistryValue -Path $wuPath -Name "WUServer" -Default $null
    $useWUServer = Get-RegistryValue -Path $auPath -Name "UseWUServer" -Default 0
    
    if ($wsusServer -and $useWUServer -eq 1) {
        if ($wsusServer -match '^http://') {
            $patchIssues++
            $Script:CyberEssentials.PatchManagement.Details += "[FAIL] WSUS uses HTTP (insecure)"
        } else {
            $Script:CyberEssentials.PatchManagement.Details += "[OK] WSUS uses HTTPS"
        }
        
        $serverName = $wsusServer -replace '^https?://' -replace '/.*$' -replace ':\d+$'
        if ($serverName -notmatch '\.') {
            $Script:CyberEssentials.PatchManagement.Details += "[WARN] WSUS uses NetBIOS name"
        }
    }
    
    # Check for recent updates
    try {
        $hotfixes = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending
        if ($hotfixes.Count -gt 0) {
            $latestHotfix = $hotfixes[0]
            $daysSinceUpdate = if ($latestHotfix.InstalledOn) { ((Get-Date) - $latestHotfix.InstalledOn).Days } else { $null }
            
            if ($daysSinceUpdate -and $daysSinceUpdate -le 30) {
                $Script:CyberEssentials.PatchManagement.Details += "[OK] Updated within 30 days"
            } elseif ($daysSinceUpdate -and $daysSinceUpdate -le 60) {
                $Script:CyberEssentials.PatchManagement.Details += "[WARN] Last update $daysSinceUpdate days ago"
            } elseif ($daysSinceUpdate) {
                $patchIssues++
                $Script:CyberEssentials.PatchManagement.Details += "[FAIL] Last update $daysSinceUpdate days ago"
            }
        }
    } catch {
        $Script:CyberEssentials.PatchManagement.Details += "[WARN] Could not check hotfix history"
    }
    
    # Check Windows build
    $build = [int]$Script:SystemInfo.OSBuild
    $isWindows11 = $build -ge 22000
    $isSupported = if ($isWindows11) { $build -ge 22621 } else { $build -ge 19044 }
    
    if ($isSupported) {
        $Script:CyberEssentials.PatchManagement.Details += "[OK] Windows build supported ($build)"
    } else {
        $patchIssues++
        $Script:CyberEssentials.PatchManagement.Details += "[FAIL] Windows build may be unsupported ($build)"
    }
    
    $Script:CyberEssentials.PatchManagement.Status = if ($patchIssues -eq 0) { "PASS" } elseif ($patchIssues -eq 1) { "REVIEW" } else { "FAIL" }
    $Script:CyberEssentials.PatchManagement.Pass = $patchIssues -eq 0
    
    # Calculate overall Cyber Essentials readiness
    $passCount = @($Script:CyberEssentials.Values | Where-Object { $_.Pass }).Count
    $Script:CyberEssentialsScore = [math]::Round(($passCount / 5) * 100)
}

function Test-PasswordPolicy {
    Write-AuditLog "Checking Password Policy..." -Level "INFO"
    
    try {
        $netAccounts = net accounts 2>&1
        
        $minPwdLen = 0
        $maxPwdAge = 0
        $minPwdAge = 0
        $lockoutThreshold = 0
        $lockoutDuration = 0
        
        foreach ($line in $netAccounts) {
            $lineStr = $line.ToString()
            if ($lineStr -match "Minimum password length[:\s]+(\d+)") { $minPwdLen = [int]$Matches[1] }
            if ($lineStr -match "Maximum password age[^:]*[:\s]+(\d+|Unlimited)") { 
                if ($Matches[1] -eq "Unlimited") { $maxPwdAge = 0 }
                else { $maxPwdAge = [int]$Matches[1] }
            }
            if ($lineStr -match "Minimum password age[^:]*[:\s]+(\d+)") { $minPwdAge = [int]$Matches[1] }
            if ($lineStr -match "Lockout threshold[:\s]+(\w+)") { 
                if ($Matches[1] -eq "Never") { $lockoutThreshold = 0 } 
                else { try { $lockoutThreshold = [int]$Matches[1] } catch { $lockoutThreshold = 0 } }
            }
            if ($lineStr -match "Lockout duration[^:]*[:\s]+(\d+)") { $lockoutDuration = [int]$Matches[1] }
        }
        
        # Check minimum password length
        if ($minPwdLen -lt 8) {
            Add-Finding -Category "Password Policy" -Name "Weak Minimum Password Length" -Risk "High" `
                -Description "Minimum password length is less than 8 characters" `
                -Details "Current: $minPwdLen characters" `
                -Recommendation "Set minimum password length to at least 14 characters (NIST SP 800-63B)" `
                -Reference "CIS Benchmark 1.1.4"
        } elseif ($minPwdLen -lt 14) {
            Add-Finding -Category "Password Policy" -Name "Suboptimal Password Length" -Risk "Medium" `
                -Description "Minimum password length is less than 14 characters" `
                -Details "Current: $minPwdLen characters" `
                -Recommendation "Consider increasing to 14+ characters per NIST guidelines" `
                -Reference "NIST SP 800-63B"
        } else {
            Add-Finding -Category "Password Policy" -Name "Password Length Compliant" -Risk "Info" `
                -Description "Minimum password length meets recommendations" `
                -Details "Current: $minPwdLen characters"
        }
        
        # Check account lockout
        if ($lockoutThreshold -eq 0) {
            Add-Finding -Category "Password Policy" -Name "No Account Lockout" -Risk "High" `
                -Description "Account lockout is not configured" `
                -Details "Lockout threshold: Never" `
                -Recommendation "Configure account lockout after 5-10 failed attempts" `
                -Reference "CIS Benchmark 1.2.1"
        } elseif ($lockoutThreshold -gt 10) {
            Add-Finding -Category "Password Policy" -Name "High Lockout Threshold" -Risk "Medium" `
                -Description "Account lockout threshold is set too high" `
                -Details "Current threshold: $lockoutThreshold attempts" `
                -Recommendation "Set lockout threshold to 5-10 failed attempts" `
                -Reference "CIS Benchmark 1.2.1"
        } else {
            Add-Finding -Category "Password Policy" -Name "Account Lockout Configured" -Risk "Info" `
                -Description "Account lockout policy is properly configured" `
                -Details "Threshold: $lockoutThreshold attempts, Duration: $lockoutDuration minutes"
        }
        
        # Check max password age - NIST now recommends no forced expiration
        if ($maxPwdAge -eq 0) {
            Add-Finding -Category "Password Policy" -Name "Password Expiration Disabled" -Risk "Info" `
                -Description "Password expiration is disabled" `
                -Details "Maximum password age: Never expires" `
                -Recommendation "Per NIST SP 800-63B, this is acceptable if breach detection is in place" `
                -Reference "NIST SP 800-63B Section 5.1.1.2"
        } elseif ($maxPwdAge -gt 365) {
            Add-Finding -Category "Password Policy" -Name "Very Long Password Expiration" -Risk "Low" `
                -Description "Password expiration is set to over 1 year" `
                -Details "Maximum password age: $maxPwdAge days" `
                -Recommendation "Consider organizational policy requirements" `
                -Reference "NIST SP 800-63B"
        }
        
    } catch {
        Add-Finding -Category "Password Policy" -Name "Policy Check Failed" -Risk "Info" `
            -Description "Unable to retrieve password policy" `
            -Details "Error: $_"
    }
}

function Test-UserAccounts {
    Write-AuditLog "Analyzing User Accounts..." -Level "INFO"
    
    try {
        # Get local users
        $localUsers = Get-LocalUser -ErrorAction Stop
        
        # Check for enabled Guest account
        $guest = $localUsers | Where-Object { $_.Name -eq "Guest" }
        if ($guest -and $guest.Enabled) {
            Add-Finding -Category "User Accounts" -Name "Guest Account Enabled" -Risk "High" `
                -Description "The built-in Guest account is enabled" `
                -Details "Account: Guest, Enabled: True" `
                -Recommendation "Disable the Guest account" `
                -Reference "CIS Benchmark 2.3.1.2"
        } else {
            Add-Finding -Category "User Accounts" -Name "Guest Account Disabled" -Risk "Info" `
                -Description "The built-in Guest account is properly disabled" `
                -Details "Account: Guest, Enabled: False"
        }
        
        # Check for enabled built-in Administrator account
        $admin = $localUsers | Where-Object { $_.Name -eq "Administrator" }
        if ($admin -and $admin.Enabled) {
            Add-Finding -Category "User Accounts" -Name "Built-in Administrator Enabled" -Risk "Medium" `
                -Description "The built-in Administrator account is enabled" `
                -Details "Account: Administrator, Enabled: True. Consider using a renamed/different admin account." `
                -Recommendation "Disable or rename the built-in Administrator account" `
                -Reference "CIS Benchmark 2.3.1.1"
        }
        
        # Check for users with no password required
        # IMPORTANT: Only flag ENABLED accounts that don't require passwords
        $noPwdUsers = $localUsers | Where-Object { 
            $_.PasswordRequired -eq $false -and 
            $_.Enabled -eq $true -and
            $_.Name -notin $Script:SystemAccounts
        }
        
        if ($noPwdUsers) {
            # Double-check these are real user accounts that matter
            $realNoPwdUsers = $noPwdUsers | Where-Object {
                # Exclude accounts that are clearly system/service accounts
                $_.Name -notmatch '^(svc_|sql|iis|app|service)'
            }
            
            if ($realNoPwdUsers) {
                Add-Finding -Category "User Accounts" -Name "Accounts Without Password Requirement" -Risk "Critical" `
                    -Description "Found ENABLED accounts that don't require a password" `
                    -Details "Accounts: $($realNoPwdUsers.Name -join ', ')`nThese accounts are enabled and can log in without a password!" `
                    -Recommendation "Either require passwords for these accounts or disable them" `
                    -Reference "CIS Benchmark 1.1.1"
            }
        } else {
            Add-Finding -Category "User Accounts" -Name "Password Requirements" -Risk "Info" `
                -Description "All enabled user accounts require passwords" `
                -Details "No enabled accounts found without password requirement"
        }
        
        # Check for DISABLED accounts that don't require passwords (informational only)
        $disabledNoPwd = $localUsers | Where-Object {
            $_.PasswordRequired -eq $false -and 
            $_.Enabled -eq $false -and
            $_.Name -notin $Script:SystemAccounts
        }
        
        if ($disabledNoPwd) {
            Add-Finding -Category "User Accounts" -Name "Disabled Accounts Without Password" -Risk "Info" `
                -Description "Found disabled accounts that don't require passwords" `
                -Details "Accounts: $($disabledNoPwd.Name -join ', ')`nThese are disabled so not an immediate risk, but consider cleaning up." `
                -Recommendation "Consider removing these accounts if no longer needed"
        }
        
        # Check for accounts with non-expiring passwords (exclude system/service accounts)
        $nonExpiring = $localUsers | Where-Object { 
            $_.PasswordNeverExpires -eq $true -and 
            $_.Enabled -eq $true -and 
            $_.Name -notin $Script:SystemAccounts -and
            $_.Name -notmatch '^(svc_|sql|iis|app|service|admin)'
        }
        
        if ($nonExpiring) {
            Add-Finding -Category "User Accounts" -Name "Non-Expiring Passwords" -Risk "Low" `
                -Description "Found user accounts with passwords set to never expire" `
                -Details "Accounts: $($nonExpiring.Name -join ', ')" `
                -Recommendation "Review if these accounts truly need non-expiring passwords. Note: NIST now recommends against forced expiration." `
                -Reference "NIST SP 800-63B"
        }
        
        # List all local admins
        try {
            $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop
            $adminCount = ($adminGroup | Measure-Object).Count
            
            if ($adminCount -gt 3) {
                Add-Finding -Category "User Accounts" -Name "Excessive Local Administrators" -Risk "Medium" `
                    -Description "More than 3 accounts have local administrator privileges" `
                    -Details "Admin count: $adminCount`nMembers: $($adminGroup.Name -join ', ')" `
                    -Recommendation "Review and minimize local administrator accounts" `
                    -Reference "Principle of Least Privilege"
            } else {
                Add-Finding -Category "User Accounts" -Name "Local Administrators" -Risk "Info" `
                    -Description "Local administrator accounts enumerated" `
                    -Details "Admin count: $adminCount`nMembers: $($adminGroup.Name -join ', ')"
            }
        } catch {
            Write-AuditLog "Could not enumerate admin group: $_" -Level "WARN"
        }
        
        # Check for stale accounts (no login in 90+ days)
        $staleAccounts = $localUsers | Where-Object {
            $_.Enabled -and 
            $_.LastLogon -and 
            $_.LastLogon -lt (Get-Date).AddDays(-90) -and
            $_.Name -notin $Script:SystemAccounts
        }
        
        if ($staleAccounts) {
            Add-Finding -Category "User Accounts" -Name "Stale User Accounts" -Risk "Low" `
                -Description "Found enabled accounts with no login in 90+ days" `
                -Details "Accounts: $($staleAccounts.Name -join ', ')" `
                -Recommendation "Review and disable/remove unused accounts" `
                -Reference "Account Lifecycle Management"
        }
        
    } catch {
        Add-Finding -Category "User Accounts" -Name "User Enumeration Failed" -Risk "Info" `
            -Description "Unable to enumerate local users" `
            -Details "Error: $_"
    }
}

function Test-AuditPolicy {
    Write-AuditLog "Checking Audit Policy Configuration..." -Level "INFO"
    
    try {
        $auditpol = auditpol /get /category:* 2>&1
        
        $criticalAudits = @{
            "Credential Validation"        = "Success and Failure"
            "Security Group Management"    = "Success"
            "User Account Management"      = "Success and Failure"
            "Process Creation"             = "Success"
            "Logoff"                       = "Success"
            "Logon"                        = "Success and Failure"
            "Special Logon"                = "Success"
            "Removable Storage"            = "Success and Failure"
            "Audit Policy Change"          = "Success"
            "Authentication Policy Change" = "Success"
            "Sensitive Privilege Use"      = "Success and Failure"
            "System Integrity"             = "Success and Failure"
            "Security State Change"        = "Success"
        }
        
        $missingAudits = @()
        $auditText = $auditpol -join "`n"
        
        foreach ($audit in $criticalAudits.Keys) {
            if ($auditText -match "$audit\s+No Auditing") {
                $missingAudits += $audit
            }
        }
        
        if ($missingAudits.Count -gt 5) {
            Add-Finding -Category "Audit Policy" -Name "Insufficient Audit Configuration" -Risk "High" `
                -Description "Multiple critical audit categories are not configured" `
                -Details "Missing audits ($($missingAudits.Count)): $($missingAudits -join ', ')" `
                -Recommendation "Enable auditing for security-critical events" `
                -Reference "CIS Benchmark Chapter 17"
        } elseif ($missingAudits.Count -gt 0) {
            Add-Finding -Category "Audit Policy" -Name "Partial Audit Configuration" -Risk "Medium" `
                -Description "Some audit categories are not configured" `
                -Details "Missing audits ($($missingAudits.Count)): $($missingAudits -join ', ')" `
                -Recommendation "Review and enable all recommended audit categories" `
                -Reference "CIS Benchmark Chapter 17"
        } else {
            Add-Finding -Category "Audit Policy" -Name "Audit Policy Configured" -Risk "Info" `
                -Description "Critical audit categories appear to be configured" `
                -Details "All $($criticalAudits.Count) critical audit categories are enabled"
        }
        
        # Check if command line auditing is enabled
        $cmdLineAudit = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name "ProcessCreationIncludeCmdLine_Enabled" -Default 0
        if ($cmdLineAudit -ne 1) {
            Add-Finding -Category "Audit Policy" -Name "Command Line Auditing Disabled" -Risk "Medium" `
                -Description "Process command line is not included in audit events" `
                -Details "ProcessCreationIncludeCmdLine_Enabled is not set to 1" `
                -Recommendation "Enable command line process auditing for better forensics" `
                -Reference "Microsoft Security Baseline"
        } else {
            Add-Finding -Category "Audit Policy" -Name "Command Line Auditing Enabled" -Risk "Info" `
                -Description "Process command line auditing is enabled" `
                -Details "Command lines will be captured in process creation events"
        }
        
    } catch {
        Add-Finding -Category "Audit Policy" -Name "Audit Policy Check Failed" -Risk "Info" `
            -Description "Unable to retrieve audit policy" `
            -Details "Error: $_"
    }
}

function Test-SecurityOptions {
    Write-AuditLog "Checking Security Options..." -Level "INFO"
    
    $securityChecks = @(
        @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Name = "LmCompatibilityLevel"
            Expected = 5
            Comparison = "GreaterOrEqual"
            Risk = "High"
            Finding = "LAN Manager Authentication Level"
            Desc = "NTLMv2 should be enforced, LM and NTLMv1 should be refused"
            Rec = "Set to 'Send NTLMv2 response only. Refuse LM & NTLM'"
            Ref = "CIS Benchmark 2.3.11.7"
            DefaultInsecure = $true
        },
        @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Name = "NoLMHash"
            Expected = 1
            Comparison = "Equal"
            Risk = "High"
            Finding = "LM Hash Storage"
            Desc = "LM hashes should not be stored as they are easily cracked"
            Rec = "Enable 'Do not store LAN Manager hash value'"
            Ref = "CIS Benchmark 2.3.11.5"
            DefaultInsecure = $false  # Default is secure on modern Windows
        },
        @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Name = "RestrictAnonymous"
            Expected = 1
            Comparison = "GreaterOrEqual"
            Risk = "Medium"
            Finding = "Anonymous Access Restriction"
            Desc = "Anonymous enumeration of shares should be restricted"
            Rec = "Restrict anonymous access to named pipes and shares"
            Ref = "CIS Benchmark 2.3.10.5"
            DefaultInsecure = $true
        },
        @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Name = "RestrictAnonymousSAM"
            Expected = 1
            Comparison = "Equal"
            Risk = "Medium"
            Finding = "Anonymous SAM Enumeration"
            Desc = "Anonymous SAM enumeration should be disabled"
            Rec = "Do not allow anonymous enumeration of SAM accounts"
            Ref = "CIS Benchmark 2.3.10.2"
            DefaultInsecure = $false  # Default is 1 on modern Windows
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Name = "EnableLUA"
            Expected = 1
            Comparison = "Equal"
            Risk = "Critical"
            Finding = "User Account Control (UAC)"
            Desc = "UAC must be enabled to prevent unauthorized elevation"
            Rec = "Enable User Account Control"
            Ref = "CIS Benchmark 2.3.17.1"
            DefaultInsecure = $false  # UAC is on by default
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Name = "ConsentPromptBehaviorAdmin"
            Expected = 1  # 1 = Prompt for credentials on secure desktop (most secure for admins)
            Comparison = "LessOrEqual"  # Lower values are MORE secure (0=no prompt, but elevates; 1,2=prompt)
            Risk = "Medium"
            Finding = "UAC Admin Consent Prompt"
            Desc = "UAC should prompt admins for consent"
            Rec = "Set to 'Prompt for consent on the secure desktop' (value 1 or 2)"
            Ref = "CIS Benchmark 2.3.17.2"
            DefaultInsecure = $false
            CustomCheck = $true
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Name = "FilterAdministratorToken"
            Expected = 1
            Comparison = "Equal"
            Risk = "Medium"
            Finding = "UAC Admin Approval Mode for Built-in Admin"
            Desc = "Admin Approval Mode should be enabled for built-in Administrator"
            Rec = "Enable Admin Approval Mode for the built-in Administrator account"
            Ref = "CIS Benchmark 2.3.17.1"
            DefaultInsecure = $true
        },
        @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
            Name = "UseLogonCredential"
            Expected = 0
            Comparison = "Equal"
            Risk = "High"
            Finding = "WDigest Authentication"
            Desc = "WDigest caches credentials in clear text in memory"
            Rec = "Disable WDigest Authentication (set to 0)"
            Ref = "Microsoft KB2871997"
            DefaultInsecure = $false  # Disabled by default on Win 8.1+/2012 R2+
        },
        @{
            Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging"
            Name = "EnableScriptBlockLogging"
            Expected = 1
            Comparison = "Equal"
            Risk = "Medium"
            Finding = "PowerShell Script Block Logging"
            Desc = "Script block logging aids in forensic analysis of attacks"
            Rec = "Enable PowerShell script block logging via Group Policy"
            Ref = "Microsoft Security Baseline"
            DefaultInsecure = $true
        },
        @{
            Path = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging"
            Name = "EnableModuleLogging"
            Expected = 1
            Comparison = "Equal"
            Risk = "Low"
            Finding = "PowerShell Module Logging"
            Desc = "Module logging provides visibility into PowerShell module usage"
            Rec = "Enable PowerShell module logging via Group Policy"
            Ref = "Security Best Practice"
            DefaultInsecure = $true
        },
        @{
            Path = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
            Name = "RunAsPPL"
            Expected = 1
            Comparison = "Equal"
            Risk = "Medium"
            Finding = "LSA Protection (PPL)"
            Desc = "LSA should run as Protected Process Light to prevent credential theft"
            Rec = "Enable LSA Protection"
            Ref = "Microsoft Security Baseline"
            DefaultInsecure = $true
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
            Name = "CachedLogonsCount"
            Expected = 4
            Comparison = "LessOrEqual"
            Risk = "Low"
            Finding = "Cached Logon Credentials"
            Desc = "Limits cached domain credentials that can be attacked offline"
            Rec = "Set cached logons to 4 or fewer (0-2 for high security)"
            Ref = "CIS Benchmark 2.3.7.6"
            DefaultInsecure = $true  # Default is 10
        },
        @{
            Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
            Name = "LocalAccountTokenFilterPolicy"
            Expected = 0
            Comparison = "Equal"
            Risk = "High"
            Finding = "Remote UAC for Local Accounts"
            Desc = "Should be 0 to prevent pass-the-hash with local accounts over network"
            Rec = "Set to 0 to enable UAC token filtering for remote connections"
            Ref = "Microsoft KB951016"
            DefaultInsecure = $false
        }
    )
    
    foreach ($check in $securityChecks) {
        $value = Get-RegistryValue -Path $check.Path -Name $check.Name -Default $null
        $failed = $false
        
        # Handle custom checks
        if ($check.CustomCheck -and $check.Name -eq "ConsentPromptBehaviorAdmin") {
            # For UAC consent prompt: 0=Elevate without prompting (bad), 1=Prompt for creds on secure desktop
            # 2=Prompt for consent on secure desktop, 3=Prompt for creds, 4=Prompt for consent, 5=Prompt for consent for non-Windows
            # Values 1-2 are most secure, 0 is insecure, 3-5 are less secure than 1-2
            if ($null -eq $value) {
                $failed = $false  # Default (5) is reasonably secure
                $details = "Using default value (prompts for consent)"
            } elseif ($value -eq 0) {
                $failed = $true
                $details = "Current value: $value (Elevate without prompting - INSECURE)"
            } else {
                $failed = $false
                $details = "Current value: $value (Prompting is enabled)"
            }
        } elseif ($null -eq $value) {
            # Value not set - check if default is insecure
            if ($check.DefaultInsecure) {
                $failed = $true
                $details = "Registry value not configured (using potentially insecure default)"
            } else {
                $failed = $false
                $details = "Registry value not configured (default is secure)"
            }
        } else {
            switch ($check.Comparison) {
                "Equal" { $failed = $value -ne $check.Expected }
                "GreaterOrEqual" { $failed = $value -lt $check.Expected }
                "LessOrEqual" { $failed = $value -gt $check.Expected }
            }
            $details = "Current value: $value (Expected: $($check.Comparison) $($check.Expected))"
        }
        
        if ($failed) {
            Add-Finding -Category "Security Options" -Name $check.Finding -Risk $check.Risk `
                -Description $check.Desc `
                -Details $details `
                -Recommendation $check.Rec `
                -Reference $check.Ref
        } else {
            Add-Finding -Category "Security Options" -Name $check.Finding -Risk "Info" `
                -Description "Configuration is compliant" `
                -Details $details
        }
    }
}

function Test-WindowsFeatures {
    Write-AuditLog "Checking Windows Features & Components..." -Level "INFO"
    
    try {
        # Check SMB1 using Get-WindowsOptionalFeature (most reliable method)
        $smb1Server = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Server" -ErrorAction SilentlyContinue
        $smb1Client = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol-Client" -ErrorAction SilentlyContinue
        
        $smb1Enabled = ($smb1Server.State -eq "Enabled") -or ($smb1Client.State -eq "Enabled")
        
        if ($smb1Enabled) {
            Add-Finding -Category "Windows Features" -Name "SMBv1 Protocol Enabled" -Risk "High" `
                -Description "SMBv1 is enabled - this protocol has critical vulnerabilities (EternalBlue/WannaCry)" `
                -Details "SMB1 Server: $($smb1Server.State), SMB1 Client: $($smb1Client.State)" `
                -Recommendation "Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol" `
                -Reference "MS17-010, CVE-2017-0144"
        } else {
            Add-Finding -Category "Windows Features" -Name "SMBv1 Protocol Status" -Risk "Info" `
                -Description "SMBv1 is disabled" `
                -Details "SMB1 Server: $($smb1Server.State), SMB1 Client: $($smb1Client.State)"
        }
        
        # Also check via SmbServerConfiguration if available
        try {
            $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop
            if ($smbConfig.EnableSMB1Protocol -eq $true) {
                Add-Finding -Category "Windows Features" -Name "SMBv1 Server Protocol Active" -Risk "High" `
                    -Description "SMB1 protocol is enabled on the SMB server" `
                    -Details "EnableSMB1Protocol: True" `
                    -Recommendation "Run: Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force" `
                    -Reference "Microsoft Security Guidance"
            }
        } catch {
            # SmbServerConfiguration not available - OK, we checked via feature
        }
        
        # Check PowerShell v2
        $psv2 = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -ErrorAction SilentlyContinue
        if ($psv2.State -eq "Enabled") {
            Add-Finding -Category "Windows Features" -Name "PowerShell v2 Enabled" -Risk "Medium" `
                -Description "PowerShell v2 can be used to bypass security logging and AMSI" `
                -Details "MicrosoftWindowsPowerShellV2 State: Enabled" `
                -Recommendation "Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2" `
                -Reference "Security Best Practice"
        } else {
            Add-Finding -Category "Windows Features" -Name "PowerShell v2 Status" -Risk "Info" `
                -Description "PowerShell v2 is disabled" `
                -Details "MicrosoftWindowsPowerShellV2 State: $($psv2.State)"
        }
        
        # Check Telnet Client
        $telnet = Get-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -ErrorAction SilentlyContinue
        if ($telnet.State -eq "Enabled") {
            Add-Finding -Category "Windows Features" -Name "Telnet Client Installed" -Risk "Low" `
                -Description "Telnet client is installed - transmits data in cleartext" `
                -Details "TelnetClient State: Enabled" `
                -Recommendation "Remove if not needed; use SSH instead" `
                -Reference "Security Best Practice"
        }
        
    } catch {
        Write-AuditLog "Could not check Windows features: $_" -Level "WARN"
    }
    
    # Check Windows Defender status
    try {
        $defenderStatus = Get-MpComputerStatus -ErrorAction Stop
        
        if (-not $defenderStatus.AntivirusEnabled) {
            Add-Finding -Category "Windows Features" -Name "Windows Defender Disabled" -Risk "Critical" `
                -Description "Windows Defender antivirus is not enabled" `
                -Details "AntivirusEnabled: False" `
                -Recommendation "Enable Windows Defender or ensure alternative AV is active" `
                -Reference "Endpoint Protection Requirement"
        } else {
            Add-Finding -Category "Windows Features" -Name "Windows Defender Status" -Risk "Info" `
                -Description "Windows Defender is enabled" `
                -Details "AV Enabled: $($defenderStatus.AntivirusEnabled), Real-time: $($defenderStatus.RealTimeProtectionEnabled), IOAV: $($defenderStatus.IoavProtectionEnabled)"
        }
        
        if ($defenderStatus.AntivirusEnabled -and -not $defenderStatus.RealTimeProtectionEnabled) {
            Add-Finding -Category "Windows Features" -Name "Real-time Protection Disabled" -Risk "High" `
                -Description "Windows Defender real-time protection is disabled" `
                -Details "RealTimeProtectionEnabled: False" `
                -Recommendation "Enable real-time protection: Set-MpPreference -DisableRealtimeMonitoring `$false" `
                -Reference "Security Best Practice"
        }
        
        if ($defenderStatus.AntivirusEnabled -and -not $defenderStatus.BehaviorMonitorEnabled) {
            Add-Finding -Category "Windows Features" -Name "Behavior Monitoring Disabled" -Risk "Medium" `
                -Description "Windows Defender behavior monitoring is disabled" `
                -Details "BehaviorMonitorEnabled: False" `
                -Recommendation "Enable behavior monitoring" `
                -Reference "Security Best Practice"
        }
        
        # Check signature age
        if ($defenderStatus.AntivirusSignatureLastUpdated) {
            $sigAge = (Get-Date) - $defenderStatus.AntivirusSignatureLastUpdated
            if ($sigAge.Days -gt 7) {
                Add-Finding -Category "Windows Features" -Name "Outdated AV Signatures" -Risk "Medium" `
                    -Description "Antivirus signatures are more than 7 days old" `
                    -Details "Last updated: $($defenderStatus.AntivirusSignatureLastUpdated) ($($sigAge.Days) days ago)" `
                    -Recommendation "Update antivirus signatures: Update-MpSignature" `
                    -Reference "Security Best Practice"
            }
        }
        
        # Check for exclusions that might be suspicious
        try {
            $prefs = Get-MpPreference -ErrorAction Stop
            $exclusionPaths = $prefs.ExclusionPath
            $exclusionProcesses = $prefs.ExclusionProcess
            
            if ($exclusionPaths -or $exclusionProcesses) {
                $details = ""
                if ($exclusionPaths) { $details += "Path exclusions: $($exclusionPaths -join ', ')`n" }
                if ($exclusionProcesses) { $details += "Process exclusions: $($exclusionProcesses -join ', ')" }
                
                Add-Finding -Category "Windows Features" -Name "Defender Exclusions Configured" -Risk "Info" `
                    -Description "Windows Defender has exclusions configured - verify these are legitimate" `
                    -Details $details.Trim() `
                    -Recommendation "Review exclusions to ensure they are necessary and not masking malware"
            }
        } catch { }
        
    } catch {
        Add-Finding -Category "Windows Features" -Name "Defender Status Unknown" -Risk "Info" `
            -Description "Could not determine Windows Defender status" `
            -Details "May be using third-party antivirus or running on Windows Server without Defender"
    }
    
    # -- Full Windows Optional Features Inventory --
    Write-AuditLog "Enumerating Windows Optional Features..." -Level "INFO"
    $Script:WindowsFeatures = @()
    
    try {
        $allFeatures = Get-WindowsOptionalFeature -Online -ErrorAction Stop
        if ($allFeatures) {
            $fList = if ($allFeatures -is [array]) { $allFeatures } else { @($allFeatures) }
            
            # Security-relevant features to flag
            $securityRelevant = @{
                'SMB1Protocol'                   = @{ Risk = "High";   Note = "Legacy SMB - EternalBlue/WannaCry attack vector" }
                'SMB1Protocol-Server'             = @{ Risk = "High";   Note = "SMBv1 server component" }
                'SMB1Protocol-Client'             = @{ Risk = "High";   Note = "SMBv1 client component" }
                'MicrosoftWindowsPowerShellV2'    = @{ Risk = "High";   Note = "PowerShell v2 bypasses script logging and AMSI" }
                'MicrosoftWindowsPowerShellV2Root'= @{ Risk = "High";   Note = "PowerShell v2 engine root feature" }
                'TelnetClient'                    = @{ Risk = "Medium"; Note = "Unencrypted remote access protocol" }
                'TelnetServer'                    = @{ Risk = "High";   Note = "Unencrypted remote access server" }
                'TFTP'                            = @{ Risk = "Medium"; Note = "Unauthenticated file transfer protocol" }
                'TIFFIFilter'                     = @{ Risk = "Low";    Note = "TIFF image filter - rarely needed" }
                'Internet-Explorer-Optional-amd64'= @{ Risk = "Medium"; Note = "Legacy browser with known vulnerabilities" }
                'IIS-WebServer'                   = @{ Risk = "Medium"; Note = "Web server - increases attack surface" }
                'IIS-WebServerRole'               = @{ Risk = "Medium"; Note = "IIS web server role" }
                'IIS-FTPServer'                   = @{ Risk = "High";   Note = "FTP server - credentials sent in cleartext" }
                'Microsoft-Windows-Subsystem-Linux' = @{ Risk = "Low"; Note = "WSL - can bypass Windows security controls" }
                'VirtualMachinePlatform'          = @{ Risk = "Low";    Note = "Hypervisor platform for WSL2/Hyper-V" }
                'Microsoft-Hyper-V-All'           = @{ Risk = "Low";    Note = "Hyper-V virtualisation" }
                'Microsoft-Hyper-V'               = @{ Risk = "Low";    Note = "Hyper-V hypervisor" }
                'Containers'                      = @{ Risk = "Low";    Note = "Windows Containers support" }
                'Windows-Defender-ApplicationGuard' = @{ Risk = "Info"; Note = "Application Guard browser isolation" }
                'Windows-Sandbox'                 = @{ Risk = "Info";   Note = "Disposable sandbox environment" }
                'WorkFolders-Client'              = @{ Risk = "Low";    Note = "Work Folders sync client" }
                'NetFx3'                          = @{ Risk = "Low";    Note = ".NET Framework 3.5 - may be needed for legacy apps" }
                'WCF-Services45'                  = @{ Risk = "Low";    Note = "WCF services - may expand attack surface" }
                'SimpleTCP'                       = @{ Risk = "Medium"; Note = "Simple TCP/IP services (echo, daytime, etc.)" }
                'SmbDirect'                       = @{ Risk = "Low";    Note = "SMB Direct (RDMA) support" }
                'MSRDC-Infrastructure'            = @{ Risk = "Low";    Note = "Remote Desktop client infrastructure" }
                'DirectPlay'                      = @{ Risk = "Low";    Note = "Legacy DirectPlay networking" }
                'LegacyComponents'                = @{ Risk = "Low";    Note = "Legacy Windows components" }
                'Printing-Foundation-Features'     = @{ Risk = "Low";    Note = "Print foundation" }
                'Printing-Foundation-LPDPrintService' = @{ Risk = "Medium"; Note = "LPD print service - legacy, rarely needed" }
                'Printing-Foundation-LPRPortMonitor'  = @{ Risk = "Low";    Note = "LPR port monitor" }
                'SearchEngine-Client-Package'     = @{ Risk = "Low";    Note = "Windows Search" }
                'SNMP'                            = @{ Risk = "Medium"; Note = "SNMP - community strings often weak" }
                'WMISnmpProvider'                 = @{ Risk = "Medium"; Note = "WMI SNMP provider" }
                'RasRip'                          = @{ Risk = "Medium"; Note = "RIP listener - routing protocol" }
                'MediaPlayback'                   = @{ Risk = "Low";    Note = "Media playback features" }
                'WindowsMediaPlayer'              = @{ Risk = "Low";    Note = "Windows Media Player" }
            }
            
            foreach ($f in $fList) {
                $state = $f.State.ToString()
                $secInfo = $null
                $secRisk = "None"
                $secNote = ""
                
                if ($securityRelevant.ContainsKey($f.FeatureName)) {
                    $secInfo = $securityRelevant[$f.FeatureName]
                    $secRisk = $secInfo.Risk
                    $secNote = $secInfo.Note
                }
                
                $Script:WindowsFeatures += [PSCustomObject]@{
                    FeatureName  = $f.FeatureName
                    State        = $state
                    SecurityRisk = $secRisk
                    SecurityNote = $secNote
                    RestartNeeded = if ($f.RestartNeeded) { $f.RestartNeeded.ToString() } else { "No" }
                }
            }
            
            # Count enabled features
            $enabledFeatures = @($Script:WindowsFeatures | Where-Object { $_.State -eq 'Enabled' })
            $disabledFeatures = @($Script:WindowsFeatures | Where-Object { $_.State -eq 'Disabled' })
            $enabledSecRisk = @($enabledFeatures | Where-Object { $_.SecurityRisk -ne 'None' -and $_.SecurityRisk -ne 'Info' })
            
            Add-Finding -Category "Windows Features" -Name "Windows Features Inventory" -Risk "Info" `
                -Description "$($enabledFeatures.Count) features enabled, $($disabledFeatures.Count) disabled out of $($Script:WindowsFeatures.Count) total" `
                -Details "Enabled: $($enabledFeatures.Count)`nDisabled: $($disabledFeatures.Count)`nSecurity-relevant enabled: $($enabledSecRisk.Count)"
            
            # Flag enabled security-relevant features
            $highRiskEnabled = @($enabledFeatures | Where-Object { $_.SecurityRisk -eq 'High' })
            $medRiskEnabled = @($enabledFeatures | Where-Object { $_.SecurityRisk -eq 'Medium' })
            
            if ($highRiskEnabled.Count -gt 0) {
                $flaggedList = ($highRiskEnabled | ForEach-Object { "  $($_.FeatureName) - $($_.SecurityNote)" }) -join "`n"
                Add-Finding -Category "Windows Features" -Name "High-Risk Features Enabled" -Risk "High" `
                    -Description "$($highRiskEnabled.Count) high-risk Windows optional feature(s) are enabled" `
                    -Details "Enabled high-risk features:`n$flaggedList" `
                    -Recommendation "Disable unnecessary high-risk features using: Disable-WindowsOptionalFeature -Online -FeatureName <name>" `
                    -Reference "CIS Benchmark - Windows Features"
            }
            
            if ($medRiskEnabled.Count -gt 0) {
                $flaggedList = ($medRiskEnabled | ForEach-Object { "  $($_.FeatureName) - $($_.SecurityNote)" }) -join "`n"
                Add-Finding -Category "Windows Features" -Name "Medium-Risk Features Enabled" -Risk "Medium" `
                    -Description "$($medRiskEnabled.Count) medium-risk Windows optional feature(s) are enabled" `
                    -Details "Enabled medium-risk features:`n$flaggedList" `
                    -Recommendation "Review whether these features are required and disable if not needed"
            }
        }
    } catch {
        Write-AuditLog "Failed to enumerate Windows Optional Features: $_" -Level "WARN"
    }
}

function Test-Services {
    Write-AuditLog "Analyzing Services..." -Level "INFO"
    
    # Services that should typically be disabled or reviewed
    $riskyServices = @{
        "RemoteRegistry"  = @{ Risk = "Medium"; Desc = "Allows remote registry access - disable if not needed" }
        "TermService"     = @{ Risk = "Info"; Desc = "Remote Desktop Services - verify if needed and properly secured" }
        "TlntSvr"         = @{ Risk = "High"; Desc = "Telnet Server - insecure protocol, transmits in cleartext" }
        "SNMP"            = @{ Risk = "Medium"; Desc = "Simple Network Management Protocol - often misconfigured" }
        "SSDPSRV"         = @{ Risk = "Low"; Desc = "SSDP Discovery Service - can expose device info" }
        "upnphost"        = @{ Risk = "Low"; Desc = "UPnP Device Host - can be exploited for port forwarding" }
        "Browser"         = @{ Risk = "Low"; Desc = "Computer Browser service - legacy, rarely needed" }
        "FTPSVC"          = @{ Risk = "Medium"; Desc = "FTP Server - consider using SFTP instead" }
        "W3SVC"           = @{ Risk = "Info"; Desc = "IIS Web Server - verify configuration if intentional" }
        "SharedAccess"    = @{ Risk = "Medium"; Desc = "Internet Connection Sharing - can bypass network controls" }
        "lmhosts"         = @{ Risk = "Low"; Desc = "TCP/IP NetBIOS Helper - legacy name resolution" }
        "WinRM"           = @{ Risk = "Info"; Desc = "Windows Remote Management - ensure properly secured with HTTPS" }
        "ssh-agent"       = @{ Risk = "Info"; Desc = "OpenSSH Agent - verify if intentional" }
        "sshd"            = @{ Risk = "Info"; Desc = "OpenSSH Server - ensure properly configured" }
    }
    
    $services = Get-Service -ErrorAction SilentlyContinue
    
    foreach ($svcName in $riskyServices.Keys) {
        $svc = $services | Where-Object { $_.Name -eq $svcName }
        if ($svc -and $svc.Status -eq 'Running') {
            $info = $riskyServices[$svcName]
            Add-Finding -Category "Services" -Name "$($svc.DisplayName) Running" -Risk $info.Risk `
                -Description $info.Desc `
                -Details "Service: $svcName, Status: Running, StartType: $($svc.StartType)" `
                -Recommendation "Evaluate if this service is required; disable if not needed" `
                -Reference "Principle of Least Functionality"
        }
    }
    
    # Check for unquoted service paths (privilege escalation vulnerability)
    Write-AuditLog "Checking for unquoted service paths..." -Level "INFO"
    
    $svcConfigs = Get-CimInstance -ClassName Win32_Service -ErrorAction SilentlyContinue
    
    foreach ($svc in $svcConfigs) {
        if ($svc.PathName) {
            $path = $svc.PathName
            
            # Skip if already quoted or no spaces
            if ($path.StartsWith('"') -or $path -notmatch '\s') {
                continue
            }
            
            # Check if there's a space BEFORE the .exe (the actual vulnerability condition)
            # Pattern: Starts without quote, has space, then eventually .exe
            # But we need to ensure the space is in the path portion, not just in arguments
            
            # Extract the executable path (before any arguments)
            $exePath = $path
            if ($path -match '^([^"]+\.exe)') {
                $exePath = $Matches[1]
            }
            
            # Check if the exe path itself contains spaces
            if ($exePath -match '\s' -and -not $path.StartsWith('"')) {
                # Verify this is actually exploitable (path like "C:\Program Files\...")
                if ($exePath -match '^[A-Za-z]:\\[^\\]+\\[^\\]+') {
                    Add-Finding -Category "Services" -Name "Unquoted Service Path" -Risk "Medium" `
                        -Description "Service has unquoted path with spaces - potential privilege escalation" `
                        -Details "Service: $($svc.Name)`nPath: $path" `
                        -Recommendation "Quote the service executable path in the registry" `
                        -Reference "CWE-428"
                }
            }
        }
    }
    
    # Check for services running as LocalSystem from user-writable locations
    foreach ($svc in $svcConfigs) {
        if ($svc.StartName -match 'LocalSystem|Local System' -and $svc.PathName) {
            $path = $svc.PathName -replace '"', ''
            
            # Check if path is in a user-writable location
            if ($path -match '^(C:\\Users|C:\\Temp|C:\\Windows\\Temp|%TEMP%|%USERPROFILE%|%APPDATA%)') {
                Add-Finding -Category "Services" -Name "SYSTEM Service in User-Writable Path" -Risk "High" `
                    -Description "Service runs as SYSTEM with executable in potentially user-writable location" `
                    -Details "Service: $($svc.Name)`nPath: $path`nRuns As: $($svc.StartName)" `
                    -Recommendation "Move service executable to a protected location like Program Files" `
                    -Reference "Privilege Escalation Prevention"
            }
        }
    }
}

function Test-NetworkConfiguration {
    Write-AuditLog "Checking Network Configuration..." -Level "INFO"
    
    if ($SkipNetworkChecks) {
        Add-Finding -Category "Network" -Name "Network Checks Skipped" -Risk "Info" `
            -Description "Network checks were skipped per user request"
        return
    }
    
    # Check firewall status
    try {
        $fwProfiles = Get-NetFirewallProfile -ErrorAction Stop
        
        foreach ($profile in $fwProfiles) {
            if (-not $profile.Enabled) {
                Add-Finding -Category "Network" -Name "Firewall Disabled ($($profile.Name))" -Risk "Critical" `
                    -Description "Windows Firewall is disabled for $($profile.Name) profile" `
                    -Details "Profile: $($profile.Name), Enabled: $($profile.Enabled)" `
                    -Recommendation "Enable Windows Firewall: Set-NetFirewallProfile -Profile $($profile.Name) -Enabled True" `
                    -Reference "CIS Benchmark 9.1.1"
            } else {
                $inboundAction = if ($profile.DefaultInboundAction -eq 'Block') { "Block (Good)" } else { "Allow (Review)" }
                Add-Finding -Category "Network" -Name "Firewall Enabled ($($profile.Name))" -Risk "Info" `
                    -Description "Windows Firewall is enabled for $($profile.Name) profile" `
                    -Details "Default Inbound: $inboundAction, Default Outbound: $($profile.DefaultOutboundAction)"
            }
        }
    } catch {
        Add-Finding -Category "Network" -Name "Firewall Check Failed" -Risk "Info" `
            -Description "Could not check firewall status" `
            -Details "Error: $_"
    }
    
    # Check for open shares
    try {
        $shares = Get-SmbShare -ErrorAction Stop | Where-Object { $_.Name -notmatch '^(ADMIN|IPC|[A-Z])\$$' }
        
        if ($shares) {
            $shareList = ($shares | ForEach-Object { "$($_.Name) -> $($_.Path)" }) -join "`n"
            Add-Finding -Category "Network" -Name "Network Shares Found" -Risk "Info" `
                -Description "Non-administrative network shares are configured" `
                -Details "Shares:`n$shareList" `
                -Recommendation "Review share permissions and necessity"
        }
        
        # Check for Everyone access on shares
        foreach ($share in $shares) {
            try {
                $access = Get-SmbShareAccess -Name $share.Name -ErrorAction Stop
                $everyone = $access | Where-Object { $_.AccountName -match 'Everyone|ANONYMOUS|Authenticated Users' -and $_.AccessRight -ne 'Deny' }
                if ($everyone) {
                    $risk = if ($everyone.AccessRight -eq 'Full') { "Critical" } elseif ($everyone.AccessRight -eq 'Change') { "High" } else { "Medium" }
                    Add-Finding -Category "Network" -Name "Share Open to $($everyone.AccountName)" -Risk $risk `
                        -Description "Share '$($share.Name)' is accessible by $($everyone.AccountName)" `
                        -Details "Share: $($share.Name), Path: $($share.Path), Access: $($everyone.AccessRight)" `
                        -Recommendation "Remove broad access from shares; use specific groups" `
                        -Reference "Principle of Least Privilege"
                }
            } catch { }
        }
    } catch {
        Write-AuditLog "Could not enumerate shares: $_" -Level "WARN"
    }
    
    # Check listening ports
    try {
        $listeners = Get-NetTCPConnection -State Listen -ErrorAction Stop | 
            Select-Object LocalAddress, LocalPort, OwningProcess, @{N='ProcessName';E={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} |
            Sort-Object LocalPort -Unique
        
        # Check for risky ports exposed to network (not just localhost)
        $riskyPorts = @{
            21   = @{ Name = "FTP"; Risk = "High"; Desc = "FTP transmits credentials in cleartext" }
            23   = @{ Name = "Telnet"; Risk = "High"; Desc = "Telnet transmits all data in cleartext" }
            25   = @{ Name = "SMTP"; Risk = "Medium"; Desc = "SMTP server - verify if needed" }
            110  = @{ Name = "POP3"; Risk = "Medium"; Desc = "POP3 often transmits in cleartext" }
            143  = @{ Name = "IMAP"; Risk = "Medium"; Desc = "IMAP often transmits in cleartext" }
            445  = @{ Name = "SMB"; Risk = "Info"; Desc = "SMB file sharing - ensure SMBv1 is disabled" }
            1433 = @{ Name = "SQL Server"; Risk = "Medium"; Desc = "SQL Server - should not be exposed externally" }
            1521 = @{ Name = "Oracle"; Risk = "Medium"; Desc = "Oracle database - should not be exposed externally" }
            3306 = @{ Name = "MySQL"; Risk = "Medium"; Desc = "MySQL database - should not be exposed externally" }
            3389 = @{ Name = "RDP"; Risk = "Medium"; Desc = "RDP - ensure NLA is enabled if exposed" }
            5432 = @{ Name = "PostgreSQL"; Risk = "Medium"; Desc = "PostgreSQL - should not be exposed externally" }
            5900 = @{ Name = "VNC"; Risk = "High"; Desc = "VNC - often has weak authentication" }
            5985 = @{ Name = "WinRM HTTP"; Risk = "Medium"; Desc = "WinRM over HTTP - use HTTPS instead" }
            5986 = @{ Name = "WinRM HTTPS"; Risk = "Info"; Desc = "WinRM over HTTPS - verify authentication" }
        }
        
        foreach ($port in $riskyPorts.Keys) {
            # Check if listening on non-localhost address
            $listener = $listeners | Where-Object { 
                $_.LocalPort -eq $port -and 
                $_.LocalAddress -notmatch '^(127\.|::1|0\.0\.0\.0|::)' 
            }
            
            # Also check 0.0.0.0 which means all interfaces
            $allInterfacesListener = $listeners | Where-Object {
                $_.LocalPort -eq $port -and
                $_.LocalAddress -match '^(0\.0\.0\.0|::)$'
            }
            
            if ($listener -or $allInterfacesListener) {
                $l = if ($listener) { $listener } else { $allInterfacesListener }
                $portInfo = $riskyPorts[$port]
                Add-Finding -Category "Network" -Name "$($portInfo.Name) Port Open ($port)" -Risk $portInfo.Risk `
                    -Description $portInfo.Desc `
                    -Details "Process: $($l.ProcessName) (PID: $($l.OwningProcess)), Address: $($l.LocalAddress)" `
                    -Recommendation "Verify this service is required and properly secured"
            }
        }
    } catch {
        Write-AuditLog "Could not check listening ports: $_" -Level "WARN"
    }
    
    # Check for IPv6 (informational)
    $ipv6Adapters = Get-NetAdapterBinding -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue | Where-Object { $_.Enabled }
    if ($ipv6Adapters) {
        Add-Finding -Category "Network" -Name "IPv6 Enabled" -Risk "Info" `
            -Description "IPv6 is enabled on network adapters" `
            -Details "IPv6 increases attack surface if not managed. Disable if not required." `
            -Recommendation "Disable IPv6 if not required by your network infrastructure"
    }
    
    # Check Network Level Authentication for RDP
    $nla = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Default 0
    $rdpEnabled = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Default 1
    
    if ($rdpEnabled -eq 0) {  # 0 means RDP is enabled
        if ($nla -ne 1) {
            Add-Finding -Category "Network" -Name "RDP NLA Disabled" -Risk "High" `
                -Description "Network Level Authentication is not enabled for RDP" `
                -Details "UserAuthentication: $nla (should be 1)" `
                -Recommendation "Enable NLA: Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication -Value 1" `
                -Reference "CIS Benchmark 18.9.65.3.9.1"
        } else {
            Add-Finding -Category "Network" -Name "RDP Configuration" -Risk "Info" `
                -Description "RDP is enabled with Network Level Authentication" `
                -Details "RDP: Enabled, NLA: Enabled"
        }
    }
}

function Get-SoftwareInventory {
    Write-AuditLog "Building Software Inventory..." -Level "INFO"
    
    $Script:SoftwareInventory = @()
    
    # Registry paths for installed software (both 32-bit and 64-bit)
    $regPaths = @(
        @{ Path = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"; Architecture = "64-bit" }
        @{ Path = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"; Architecture = "32-bit" }
        @{ Path = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"; Architecture = "User" }
    )
    
    foreach ($reg in $regPaths) {
        try {
            $software = Get-ItemProperty -Path $reg.Path -ErrorAction SilentlyContinue | 
                Where-Object { $_.DisplayName -and $_.DisplayName.Trim() -ne "" }
            
            foreach ($app in $software) {
                # Parse install date
                $installDate = $null
                if ($app.InstallDate) {
                    try {
                        if ($app.InstallDate -match '^\d{8}$') {
                            $installDate = [datetime]::ParseExact($app.InstallDate, "yyyyMMdd", $null)
                        }
                    } catch { }
                }
                
                # Calculate age in days
                $ageDays = if ($installDate) { ((Get-Date) - $installDate).Days } else { $null }
                
                # Determine if system/OEM software (not third-party)
                # These are vendors whose software typically comes pre-installed or is system-level
                $isSystemVendor = $false
                
                $systemVendors = @(
                    # Microsoft
                    'Microsoft', 'Windows', 'Visual C++', 'Visual Studio', 'SQL Server', 
                    'Azure', 'OneDrive', 'Xbox', 'Skype', '.NET', 'MSVC',
                    # PC OEMs
                    'Dell', 'Hewlett-Packard', 'Hewlett Packard', 'HP Inc', 'HP Development',
                    'Lenovo', 'Lenovo Group',
                    'ASUS', 'ASUSTeK', 'Acer', 'Samsung', 'Toshiba', 'Sony', 'Fujitsu', 
                    'Panasonic', 'MSI', 'Micro-Star', 'Gigabyte', 'Razer Inc',
                    # Hardware/Chip vendors
                    'Intel', 'AMD', 'Advanced Micro Devices', 'NVIDIA', 
                    'Realtek', 'Qualcomm', 'Broadcom', 'Marvell', 'MediaTek',
                    'Synaptics', 'ELAN', 'Conexant', 'IDT', 'Cirrus Logic',
                    'Texas Instruments', 'Analog Devices',
                    # Audio
                    'Dolby', 'Waves Audio', 'Creative Technology', 'Bang & Olufsen',
                    # Peripherals
                    'DisplayLink', 'Logitech', 'Corsair', 'SteelSeries',
                    # Virtualization
                    'VMware', 'Citrix', 'Parallels', 'Oracle VM',
                    # Apple
                    'Apple Inc', 'Apple Computer'
                )
                
                if ($app.Publisher) {
                    foreach ($vendor in $systemVendors) {
                        if ($app.Publisher -like "*$vendor*") {
                            $isSystemVendor = $true
                            break
                        }
                    }
                }
                
                # Also check display name for Microsoft products that may have different publishers
                if (-not $isSystemVendor -and $app.DisplayName) {
                    if ($app.DisplayName -match '^(Microsoft |Windows |Intel |NVIDIA |AMD |Realtek |Dell |HP |Lenovo )') {
                        $isSystemVendor = $true
                    }
                }
                
                $Script:SoftwareInventory += [PSCustomObject]@{
                    DisplayName     = $app.DisplayName
                    Publisher       = $app.Publisher
                    DisplayVersion  = $app.DisplayVersion
                    InstallDate     = $installDate
                    InstallDateRaw  = $app.InstallDate
                    AgeDays         = $ageDays
                    Architecture    = $reg.Architecture
                    ProductCode     = $app.PSChildName
                    UninstallString = $app.UninstallString
                    InstallLocation = $app.InstallLocation
                    EstimatedSizeMB = if ($app.EstimatedSize) { [math]::Round($app.EstimatedSize / 1024, 2) } else { $null }
                    IsSystemVendor  = $isSystemVendor
                }
            }
        } catch { }
    }
    
    # Sort by DisplayName
    $Script:SoftwareInventory = $Script:SoftwareInventory | Sort-Object DisplayName
    
    Add-Finding -Category "Software Inventory" -Name "Installed Applications" -Risk "Info" `
        -Description "Software inventory collected from Add/Remove Programs" `
        -Details "Total applications: $($Script:SoftwareInventory.Count)`n64-bit: $(@($Script:SoftwareInventory | Where-Object { $_.Architecture -eq '64-bit' }).Count)`n32-bit: $(@($Script:SoftwareInventory | Where-Object { $_.Architecture -eq '32-bit' }).Count)`nUser-installed: $(@($Script:SoftwareInventory | Where-Object { $_.Architecture -eq 'User' }).Count)"
}

function Test-InstalledSoftware {
    Write-AuditLog "Analyzing Installed Software for Risks..." -Level "INFO"
    
    # Ensure inventory exists
    if (-not $Script:SoftwareInventory -or $Script:SoftwareInventory.Count -eq 0) {
        Get-SoftwareInventory
    }
    
    # Known risky/outdated software patterns
    $riskySoftware = @(
        @{ Pattern = "^Java\s+[1-8]\s+Update\s+([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-3][0-9]|24[0-9]|250)$"; Risk = "High"; Desc = "Outdated Java version with known vulnerabilities" }
        @{ Pattern = "Adobe Flash Player"; Risk = "Critical"; Desc = "Adobe Flash is end-of-life since Dec 2020 with many critical vulnerabilities" }
        @{ Pattern = "Adobe Reader\s+(9|10|11|15|17|18|19)[\.\s]"; Risk = "High"; Desc = "Outdated Adobe Reader version" }
        @{ Pattern = "^VNC|RealVNC|TightVNC|UltraVNC"; Risk = "Medium"; Desc = "VNC remote access software - verify if authorized" }
        @{ Pattern = "TeamViewer"; Risk = "Info"; Desc = "Remote access software - verify if authorized by policy" }
        @{ Pattern = "LogMeIn"; Risk = "Info"; Desc = "Remote access software - verify if authorized by policy" }
        @{ Pattern = "AnyDesk"; Risk = "Info"; Desc = "Remote access software - verify if authorized by policy" }
        @{ Pattern = "WinRAR\s+[1-5]\."; Risk = "Medium"; Desc = "Outdated WinRAR - update for security fixes (CVE-2023-38831)" }
        @{ Pattern = "Python\s+2\.[0-7]"; Risk = "Medium"; Desc = "Python 2 is end-of-life since Jan 2020" }
        @{ Pattern = "QuickTime"; Risk = "High"; Desc = "Apple QuickTime for Windows is end-of-life with known vulnerabilities" }
        @{ Pattern = "Silverlight"; Risk = "Medium"; Desc = "Microsoft Silverlight is end-of-life" }
        @{ Pattern = "Adobe Shockwave"; Risk = "Critical"; Desc = "Adobe Shockwave is end-of-life" }
        @{ Pattern = "7-Zip\s+(1[0-8]|[0-9])\."; Risk = "Medium"; Desc = "Outdated 7-Zip version - update for security fixes" }
        @{ Pattern = "PuTTY\s+release\s+0\.[0-7]"; Risk = "High"; Desc = "Outdated PuTTY has known vulnerabilities" }
        @{ Pattern = "FileZilla Client\s+[0-2]\."; Risk = "Medium"; Desc = "Outdated FileZilla - update for security fixes" }
        @{ Pattern = "Notepad\+\+\s+\([1-7]\."; Risk = "Low"; Desc = "Outdated Notepad++ - consider updating" }
    )
    
    foreach ($check in $riskySoftware) {
        $found = $Script:SoftwareInventory | Where-Object { $_.DisplayName -match $check.Pattern }
        foreach ($app in $found) {
            Add-Finding -Category "Software" -Name "Risky Software: $($app.DisplayName)" -Risk $check.Risk `
                -Description $check.Desc `
                -Details "Version: $($app.DisplayVersion)`nPublisher: $($app.Publisher)`nInstalled: $($app.InstallDate)" `
                -Recommendation "Update or remove this software if not required"
        }
    }
    
    # Check for common remote access tools (informational)
    $remoteAccessTools = @("RemotePC", "Splashtop", "ConnectWise", "ScreenConnect", "GoToMyPC", "Bomgar", "DameWare", "Ammyy", "NetSupport", "Radmin")
    foreach ($tool in $remoteAccessTools) {
        $found = $Script:SoftwareInventory | Where-Object { $_.DisplayName -match $tool }
        foreach ($app in $found) {
            Add-Finding -Category "Software" -Name "Remote Access Tool: $($app.DisplayName)" -Risk "Info" `
                -Description "Remote access software detected - verify if authorized" `
                -Details "Version: $($app.DisplayVersion)`nPublisher: $($app.Publisher)" `
                -Recommendation "Verify this remote access tool is authorized by security policy"
        }
    }
    
    # Check for very old third-party software (installed more than 2 years ago)
    $twoYearsAgo = (Get-Date).AddDays(-730)
    $oldThirdParty = @($Script:SoftwareInventory | Where-Object { 
        $_.InstallDate -and 
        $_.InstallDate -lt $twoYearsAgo -and 
        -not $_.IsSystemVendor
    })
    
    if ($oldThirdParty.Count -gt 0) {
        $oldList = ($oldThirdParty | Sort-Object InstallDate | Select-Object -First 15 | ForEach-Object { 
            "$($_.DisplayName) v$($_.DisplayVersion) ($(if ($_.InstallDate) { $_.InstallDate.ToString('yyyy-MM-dd') } else { 'Unknown' }))" 
        }) -join "`n"
        
        Add-Finding -Category "Software" -Name "Old Third-Party Software" -Risk "Medium" `
            -Description "Found $($oldThirdParty.Count) third-party applications installed over 2 years ago" `
            -Details "Old software may have unpatched vulnerabilities:`n$oldList$(if ($oldThirdParty.Count -gt 15) { "`n... and $($oldThirdParty.Count - 15) more" })" `
            -Recommendation "Review old software for updates or removal - this is a Cyber Essentials requirement" `
            -Reference "Cyber Essentials: Secure Configuration"
    }
}

function Test-ScheduledTasks {
    Write-AuditLog "Checking Scheduled Tasks..." -Level "INFO"
    
    try {
        $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object { $_.State -ne 'Disabled' }
        
        foreach ($task in $tasks) {
            # Skip Microsoft/Windows tasks
            if ($task.TaskPath -match '^\\Microsoft\\' -or $task.Author -match '^Microsoft') {
                continue
            }
            
            # Check for tasks running as SYSTEM with executable in user-writable locations
            if ($task.Principal.UserId -match 'SYSTEM|LocalSystem|S-1-5-18') {
                $actions = $task.Actions | Where-Object { $_.Execute }
                foreach ($action in $actions) {
                    $execPath = $action.Execute
                    
                    # Expand environment variables
                    $execPath = [Environment]::ExpandEnvironmentVariables($execPath)
                    
                    # Check if path is in user-writable location
                    if ($execPath -match '^(C:\\Users|C:\\Temp|C:\\Windows\\Temp|.*\\AppData)') {
                        Add-Finding -Category "Scheduled Tasks" -Name "Risky SYSTEM Task" -Risk "High" `
                            -Description "Scheduled task runs as SYSTEM with executable in user-writable location" `
                            -Details "Task: $($task.TaskName)`nPath: $($task.TaskPath)`nExecutable: $execPath" `
                            -Recommendation "Move executable to protected location or change run-as account" `
                            -Reference "Privilege Escalation Vector"
                    }
                }
            }
            
            # Check for tasks with suspicious executables
            foreach ($action in $task.Actions) {
                if ($action.Execute -match '(powershell|cmd|wscript|cscript|mshta|regsvr32)\.exe') {
                    # Get the arguments for context
                    $args = $action.Arguments
                    
                    # Check for encoded commands or suspicious patterns
                    if ($args -match '(-enc|-encoded|FromBase64|IEX|Invoke-Expression|downloadstring|webclient)') {
                        Add-Finding -Category "Scheduled Tasks" -Name "Suspicious Task Arguments" -Risk "Medium" `
                            -Description "Scheduled task uses potentially suspicious command-line patterns" `
                            -Details "Task: $($task.TaskName)`nExecutable: $($action.Execute)`nArguments: $($args.Substring(0, [Math]::Min(200, $args.Length)))" `
                            -Recommendation "Review this task to ensure it is legitimate"
                    }
                }
            }
        }
        
        # Count custom tasks
        $customTasks = @($tasks | Where-Object { $_.TaskPath -notmatch '^\\Microsoft\\' })
        Add-Finding -Category "Scheduled Tasks" -Name "Scheduled Tasks Overview" -Risk "Info" `
            -Description "Active scheduled tasks enumerated" `
            -Details "Total enabled tasks: $(@($tasks).Count), Custom (non-Microsoft) tasks: $($customTasks.Count)"
            
    } catch {
        Add-Finding -Category "Scheduled Tasks" -Name "Task Enumeration Failed" -Risk "Info" `
            -Description "Could not enumerate scheduled tasks" `
            -Details "Error: $_. May require elevated privileges."
    }
}

function Test-UpdateStatus {
    Write-AuditLog "Checking Windows Update Configuration..." -Level "INFO"
    
    try {
        # Check last update time via registry
        $updatePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\Results\Install"
        $lastUpdate = Get-RegistryValue -Path $updatePath -Name "LastSuccessTime"
        
        if ($lastUpdate) {
            try {
                $lastUpdateDate = [DateTime]::Parse($lastUpdate)
                $daysSinceUpdate = ((Get-Date) - $lastUpdateDate).Days
                
                if ($daysSinceUpdate -gt 90) {
                    Add-Finding -Category "Updates" -Name "Severely Outdated System" -Risk "Critical" `
                        -Description "Windows has not been updated in over 90 days" `
                        -Details "Last update: $lastUpdateDate ($daysSinceUpdate days ago)" `
                        -Recommendation "Apply Windows updates immediately" `
                        -Reference "Cyber Essentials: Patch Management"
                } elseif ($daysSinceUpdate -gt 30) {
                    Add-Finding -Category "Updates" -Name "Outdated Updates" -Risk "High" `
                        -Description "Windows has not been updated in over 30 days" `
                        -Details "Last update: $lastUpdateDate ($daysSinceUpdate days ago)" `
                        -Recommendation "Apply Windows updates" `
                        -Reference "Cyber Essentials: Patch Management"
                } else {
                    Add-Finding -Category "Updates" -Name "Update Status" -Risk "Info" `
                        -Description "Windows updates are relatively current" `
                        -Details "Last update: $lastUpdateDate ($daysSinceUpdate days ago)"
                }
            } catch {
                Write-AuditLog "Could not parse update date: $_" -Level "WARN"
            }
        }
        
        # Check Windows Update service - note: Manual start type is normal/expected
        $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        if ($wuService.StartType -eq 'Disabled') {
            Add-Finding -Category "Updates" -Name "Windows Update Service Disabled" -Risk "High" `
                -Description "The Windows Update service is disabled" `
                -Details "Service Status: $($wuService.Status), StartType: $($wuService.StartType)" `
                -Recommendation "Set Windows Update service to Manual (default) or Automatic"
        }
        
        # Check Automatic Update Configuration
        $auPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
        $noAutoUpdate = Get-RegistryValue -Path $auPath -Name "NoAutoUpdate" -Default 0
        $auOptions = Get-RegistryValue -Path $auPath -Name "AUOptions" -Default $null
        $scheduledDay = Get-RegistryValue -Path $auPath -Name "ScheduledInstallDay" -Default $null
        $scheduledTime = Get-RegistryValue -Path $auPath -Name "ScheduledInstallTime" -Default $null
        $useWUServer = Get-RegistryValue -Path $auPath -Name "UseWUServer" -Default 0
        
        # Also check non-GPO settings
        $auPathLocal = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
        $auOptionsLocal = Get-RegistryValue -Path $auPathLocal -Name "AUOptions" -Default $null
        
        # Determine effective AU setting
        $effectiveAUOption = if ($auOptions) { $auOptions } else { $auOptionsLocal }
        
        $auOptionDesc = switch ($effectiveAUOption) {
            1 { "Disabled (Keep me updated is off)" }
            2 { "Notify for download and notify for install" }
            3 { "Auto download and notify for install" }
            4 { "Auto download and schedule install" }
            5 { "Allow local admin to choose setting" }
            default { "Not configured (Windows default)" }
        }
        
        if ($noAutoUpdate -eq 1) {
            Add-Finding -Category "Updates" -Name "Automatic Updates Disabled" -Risk "High" `
                -Description "Automatic Windows Updates are disabled via policy" `
                -Details "NoAutoUpdate: 1`nThis prevents automatic security patches" `
                -Recommendation "Enable automatic updates for timely security patching" `
                -Reference "Cyber Essentials: Patch Management"
        } elseif ($effectiveAUOption -eq 1) {
            Add-Finding -Category "Updates" -Name "Automatic Updates Disabled" -Risk "High" `
                -Description "Automatic Windows Updates are disabled" `
                -Details "AUOptions: 1 (Keep me updated is off)" `
                -Recommendation "Enable automatic updates for security patches" `
                -Reference "Cyber Essentials: Patch Management"
        } elseif ($effectiveAUOption -in @(2, 3)) {
            Add-Finding -Category "Updates" -Name "Updates Require Manual Install" -Risk "Medium" `
                -Description "Updates download but require manual installation" `
                -Details "AUOptions: $effectiveAUOption ($auOptionDesc)" `
                -Recommendation "Consider enabling automatic installation of updates"
        } elseif ($effectiveAUOption -eq 4) {
            $dayName = switch ($scheduledDay) {
                0 { "Every day" }
                1 { "Sunday" }
                2 { "Monday" }
                3 { "Tuesday" }
                4 { "Wednesday" }
                5 { "Thursday" }
                6 { "Friday" }
                7 { "Saturday" }
                default { "Not specified" }
            }
            $timeStr = if ($scheduledTime -ne $null) { "${scheduledTime}:00" } else { "Not specified" }
            
            Add-Finding -Category "Updates" -Name "Automatic Updates Configured" -Risk "Info" `
                -Description "Updates are configured to install automatically on a schedule" `
                -Details "AUOptions: $effectiveAUOption ($auOptionDesc)`nSchedule: $dayName at $timeStr"
        } else {
            Add-Finding -Category "Updates" -Name "Automatic Update Setting" -Risk "Info" `
                -Description "Automatic update configuration" `
                -Details "AUOptions: $effectiveAUOption ($auOptionDesc)"
        }
        
        # Check for WSUS configuration
        $wuPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        $wsusServer = Get-RegistryValue -Path $wuPath -Name "WUServer" -Default $null
        $wsusStatusServer = Get-RegistryValue -Path $wuPath -Name "WUStatusServer" -Default $null
        $doNotConnectToWU = Get-RegistryValue -Path $wuPath -Name "DoNotConnectToWindowsUpdateInternetLocations" -Default 0
        
        if ($wsusServer -and $useWUServer -eq 1) {
            $wsusIssues = @()
            
            # Check if WSUS uses HTTP (insecure) vs HTTPS
            if ($wsusServer -match '^http://') {
                $wsusIssues += "Uses HTTP (unencrypted) - vulnerable to MITM attacks"
                Add-Finding -Category "Updates" -Name "WSUS Using HTTP" -Risk "High" `
                    -Description "WSUS server is configured to use unencrypted HTTP" `
                    -Details "WSUS Server: $wsusServer`nHTTP connections are vulnerable to man-in-the-middle attacks (WSUSpect)" `
                    -Recommendation "Configure WSUS to use HTTPS for secure update delivery" `
                    -Reference "CVE-2020-1013 - WSUS MITM"
            } elseif ($wsusServer -match '^https://') {
                Add-Finding -Category "Updates" -Name "WSUS Using HTTPS" -Risk "Info" `
                    -Description "WSUS server is configured to use encrypted HTTPS" `
                    -Details "WSUS Server: $wsusServer"
            }
            
            # Check if WSUS server name is NetBIOS (no dots) vs FQDN
            $serverName = $wsusServer -replace '^https?://' -replace '/.*$' -replace ':\d+$'
            
            if ($serverName -notmatch '\.') {
                Add-Finding -Category "Updates" -Name "WSUS Using NetBIOS Name" -Risk "Medium" `
                    -Description "WSUS server is configured with a NetBIOS name instead of FQDN" `
                    -Details "Server: $serverName`nNetBIOS names are vulnerable to name resolution poisoning (LLMNR/NBT-NS)" `
                    -Recommendation "Use a fully qualified domain name (FQDN) for the WSUS server" `
                    -Reference "Security Best Practice"
            } else {
                Add-Finding -Category "Updates" -Name "WSUS Server Configuration" -Risk "Info" `
                    -Description "WSUS is configured with FQDN" `
                    -Details "Server: $serverName"
            }
            
            # Check if system is blocked from Windows Update
            if ($doNotConnectToWU -eq 1) {
                Add-Finding -Category "Updates" -Name "Windows Update Internet Blocked" -Risk "Info" `
                    -Description "System is configured to only receive updates from WSUS" `
                    -Details "DoNotConnectToWindowsUpdateInternetLocations: 1`nDevice cannot fall back to Microsoft Update if WSUS unavailable"
            }
            
            # WSUS status server
            if ($wsusStatusServer -and $wsusStatusServer -ne $wsusServer) {
                Add-Finding -Category "Updates" -Name "WSUS Status Server" -Risk "Info" `
                    -Description "Separate WSUS status server is configured" `
                    -Details "Status Server: $wsusStatusServer"
            }
        } elseif ($wsusServer) {
            Add-Finding -Category "Updates" -Name "WSUS Configured But Not Used" -Risk "Info" `
                -Description "WSUS server is defined but UseWUServer is not enabled" `
                -Details "WSUS Server: $wsusServer`nUseWUServer: $useWUServer"
        }
        
        # Check for Windows Update for Business / Delivery Optimization
        $wufbPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"
        $deferFeature = Get-RegistryValue -Path $wufbPath -Name "DeferFeatureUpdates" -Default $null
        $deferQuality = Get-RegistryValue -Path $wufbPath -Name "DeferQualityUpdates" -Default $null
        $deferFeatureDays = Get-RegistryValue -Path $wufbPath -Name "DeferFeatureUpdatesPeriodInDays" -Default $null
        $deferQualityDays = Get-RegistryValue -Path $wufbPath -Name "DeferQualityUpdatesPeriodInDays" -Default $null
        
        if ($deferFeatureDays -or $deferQualityDays) {
            $deferDetails = ""
            if ($deferFeatureDays) { $deferDetails += "Feature updates deferred: $deferFeatureDays days`n" }
            if ($deferQualityDays) { $deferDetails += "Quality updates deferred: $deferQualityDays days" }
            
            $risk = if ($deferQualityDays -gt 14) { "Medium" } else { "Info" }
            
            Add-Finding -Category "Updates" -Name "Update Deferral Configured" -Risk $risk `
                -Description "Windows Update for Business deferral is configured" `
                -Details $deferDetails.Trim() `
                -Recommendation "Ensure security updates are not deferred excessively (max 14 days recommended)"
        }
        
    } catch {
        Add-Finding -Category "Updates" -Name "Update Check Failed" -Risk "Info" `
            -Description "Could not determine update status" `
            -Details "Error: $_"
    }
}

function Test-BitLockerStatus {
    Write-AuditLog "Checking BitLocker Status..." -Level "INFO"
    
    try {
        $volumes = Get-BitLockerVolume -ErrorAction Stop
        
        foreach ($vol in $volumes) {
            if ($vol.VolumeType -eq 'OperatingSystem') {
                if ($vol.ProtectionStatus -ne 'On') {
                    Add-Finding -Category "Encryption" -Name "BitLocker Not Enabled (OS Drive)" -Risk "High" `
                        -Description "The operating system drive is not encrypted with BitLocker" `
                        -Details "Volume: $($vol.MountPoint), Protection: $($vol.ProtectionStatus), Encryption: $($vol.VolumeStatus)" `
                        -Recommendation "Enable BitLocker on the OS drive to protect data at rest" `
                        -Reference "CIS Benchmark - Full Disk Encryption"
                } else {
                    Add-Finding -Category "Encryption" -Name "BitLocker Enabled (OS Drive)" -Risk "Info" `
                        -Description "BitLocker is enabled on the OS drive" `
                        -Details "Volume: $($vol.MountPoint), Status: $($vol.ProtectionStatus), Method: $($vol.EncryptionMethod)"
                }
            }
        }
    } catch {
        # BitLocker cmdlet not available
        Add-Finding -Category "Encryption" -Name "BitLocker Check Unavailable" -Risk "Info" `
            -Description "Could not check BitLocker status" `
            -Details "BitLocker cmdlets not available or requires admin privileges. May not be supported on this Windows edition."
    }
}

function Test-CredentialStorage {
    Write-AuditLog "Checking for Credential Storage Issues..." -Level "INFO"
    
    # Check for stored credentials in Credential Manager
    try {
        $cmdkeyOutput = cmdkey /list 2>&1
        $storedCreds = @($cmdkeyOutput | Select-String "Target:").Count
        
        if ($storedCreds -gt 0) {
            Add-Finding -Category "Credentials" -Name "Stored Credentials Found" -Risk "Info" `
                -Description "Windows Credential Manager contains stored credentials" `
                -Details "Number of stored credentials: $storedCreds" `
                -Recommendation "Review stored credentials periodically; remove unused ones"
        }
    } catch { }
    
    # Check for credentials in common file locations
    $credentialFiles = @(
        @{ Path = "$env:USERPROFILE\.aws\credentials"; Name = "AWS Credentials"; Risk = "Medium" }
        @{ Path = "$env:USERPROFILE\.azure\accessTokens.json"; Name = "Azure Access Tokens"; Risk = "Medium" }
        @{ Path = "$env:USERPROFILE\.ssh\id_rsa"; Name = "SSH Private Key (unencrypted check needed)"; Risk = "Info" }
        @{ Path = "$env:USERPROFILE\.git-credentials"; Name = "Git Credentials (plaintext)"; Risk = "Medium" }
        @{ Path = "$env:USERPROFILE\.docker\config.json"; Name = "Docker Config"; Risk = "Low" }
        @{ Path = "$env:USERPROFILE\.kube\config"; Name = "Kubernetes Config"; Risk = "Medium" }
        @{ Path = "$env:USERPROFILE\AppData\Roaming\npm\_authToken"; Name = "NPM Auth Token"; Risk = "Medium" }
        @{ Path = "$env:APPDATA\NuGet\NuGet.Config"; Name = "NuGet Config"; Risk = "Low" }
    )
    
    foreach ($cred in $credentialFiles) {
        if (Test-Path $cred.Path) {
            Add-Finding -Category "Credentials" -Name "$($cred.Name) Found" -Risk $cred.Risk `
                -Description "Credential file detected" `
                -Details "Path: $($cred.Path)" `
                -Recommendation "Ensure this file has appropriate permissions and credentials are rotated regularly"
        }
    }
    
    # Check Credential Guard status
    $credGuard = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" -Name "EnableVirtualizationBasedSecurity" -Default 0
    $credGuardConfig = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Default 0
    
    if ($credGuard -eq 1 -and $credGuardConfig -ge 1) {
        Add-Finding -Category "Credentials" -Name "Credential Guard Enabled" -Risk "Info" `
            -Description "Virtualization-based security with Credential Guard is enabled" `
            -Details "VBS: Enabled, LsaCfgFlags: $credGuardConfig"
    } elseif ($credGuard -ne 1) {
        Add-Finding -Category "Credentials" -Name "Credential Guard Not Enabled" -Risk "Low" `
            -Description "Virtualization-based security (Credential Guard) is not enabled" `
            -Details "EnableVirtualizationBasedSecurity: $credGuard" `
            -Recommendation "Consider enabling Credential Guard on supported hardware" `
            -Reference "Windows 10/11 Security Baseline"
    }
}

function Test-AutoRunLocations {
    Write-AuditLog "Checking AutoRun Locations..." -Level "INFO"
    
    $autorunPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run"
    )
    
    $autorunEntries = @()
    
    foreach ($path in $autorunPaths) {
        try {
            $entries = Get-ItemProperty -Path $path -ErrorAction SilentlyContinue
            if ($entries) {
                $entries.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object {
                    $autorunEntries += [PSCustomObject]@{
                        Location = $path
                        Name     = $_.Name
                        Value    = $_.Value
                    }
                }
            }
        } catch { }
    }
    
    if ($autorunEntries.Count -gt 0) {
        $details = ($autorunEntries | ForEach-Object { "$($_.Name): $($_.Value)" }) -join "`n"
        if ($details.Length -gt 2000) { $details = $details.Substring(0, 2000) + "..." }
        
        Add-Finding -Category "AutoRuns" -Name "AutoRun Entries Found" -Risk "Info" `
            -Description "Found $($autorunEntries.Count) auto-start registry entries" `
            -Details $details `
            -Recommendation "Review auto-start entries for unauthorized software"
        
        # Check for suspicious patterns
        foreach ($entry in $autorunEntries) {
            $value = $entry.Value
            if ($value -match '(powershell|cmd|wscript|cscript|mshta|regsvr32).*(-enc|-encoded|FromBase64|IEX|downloadstring)') {
                Add-Finding -Category "AutoRuns" -Name "Suspicious AutoRun Entry" -Risk "High" `
                    -Description "AutoRun entry contains suspicious command patterns" `
                    -Details "Name: $($entry.Name)`nValue: $value" `
                    -Recommendation "Investigate this autorun entry for potential malware"
            }
            
            # Check if executable is in user-writable location
            if ($value -match '^"?([^"]+)"?' -and $Matches[1] -match '^(C:\\Users|C:\\Temp|%TEMP%|%APPDATA%)') {
                Add-Finding -Category "AutoRuns" -Name "AutoRun from User Location" -Risk "Medium" `
                    -Description "AutoRun executable is in a user-writable location" `
                    -Details "Name: $($entry.Name)`nPath: $($Matches[1])" `
                    -Recommendation "Verify this is legitimate; consider moving to Program Files"
            }
        }
    }
    
    # Check startup folders
    $startupFolders = @(
        "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup",
        "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\Startup"
    )
    
    foreach ($folder in $startupFolders) {
        if (Test-Path $folder) {
            $files = Get-ChildItem -Path $folder -ErrorAction SilentlyContinue | Where-Object { $_.Name -notmatch '^desktop\.ini$' }
            if ($files) {
                Add-Finding -Category "AutoRuns" -Name "Startup Folder Items" -Risk "Info" `
                    -Description "Items found in startup folder" `
                    -Details "Folder: $folder`nItems: $($files.Name -join ', ')" `
                    -Recommendation "Review startup folder contents for unauthorized items"
            }
        }
    }
}

function Test-NetworkProtocols {
    Write-AuditLog "Checking Network Protocol Security..." -Level "INFO"
    
    # Check LLMNR (Link-Local Multicast Name Resolution) - used in responder attacks
    $llmnr = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Default 1
    if ($llmnr -ne 0) {
        Add-Finding -Category "Network Protocols" -Name "LLMNR Enabled" -Risk "Medium" `
            -Description "Link-Local Multicast Name Resolution is enabled - vulnerable to poisoning attacks" `
            -Details "EnableMulticast: $llmnr (should be 0)" `
            -Recommendation "Disable LLMNR via Group Policy: Computer Config > Admin Templates > Network > DNS Client > Turn off multicast name resolution" `
            -Reference "MITRE ATT&CK T1557.001"
    } else {
        Add-Finding -Category "Network Protocols" -Name "LLMNR Disabled" -Risk "Info" `
            -Description "LLMNR is properly disabled" `
            -Details "EnableMulticast: 0"
    }
    
    # Check NetBIOS over TCP/IP
    try {
        $adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" -ErrorAction Stop
        $netbiosEnabled = @($adapters | Where-Object { $_.TcpipNetbiosOptions -ne 2 })
        
        if ($netbiosEnabled.Count -gt 0) {
            Add-Finding -Category "Network Protocols" -Name "NetBIOS over TCP/IP Enabled" -Risk "Medium" `
                -Description "NetBIOS is enabled on network adapters - vulnerable to poisoning and relay attacks" `
                -Details "Adapters with NetBIOS enabled: $($netbiosEnabled.Count)" `
                -Recommendation "Disable NetBIOS over TCP/IP on all adapters where not required" `
                -Reference "MITRE ATT&CK T1557.001"
        } else {
            Add-Finding -Category "Network Protocols" -Name "NetBIOS over TCP/IP" -Risk "Info" `
                -Description "NetBIOS appears to be disabled on all adapters" `
                -Details "All adapters have TcpipNetbiosOptions set to disable"
        }
    } catch {
        Write-AuditLog "Could not check NetBIOS settings: $_" -Level "WARN"
    }
    
    # Check WPAD (Web Proxy Auto-Discovery)
    $wpad = Get-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Default $null
    $wpadDisabled = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad" -Name "WpadOverride" -Default $null
    
    if ($wpad -ne 1 -and $wpadDisabled -ne 1) {
        Add-Finding -Category "Network Protocols" -Name "WPAD May Be Enabled" -Risk "Low" `
            -Description "Web Proxy Auto-Discovery may be enabled - can be abused for credential theft" `
            -Details "WpadOverride not explicitly disabled" `
            -Recommendation "Consider disabling WPAD if proxy auto-detection is not required" `
            -Reference "MITRE ATT&CK T1557.001"
    }
    
    # Check mDNS
    $mdns = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters" -Name "EnableMDNS" -Default 1
    if ($mdns -ne 0) {
        Add-Finding -Category "Network Protocols" -Name "mDNS Enabled" -Risk "Low" `
            -Description "Multicast DNS is enabled - can be used for network reconnaissance" `
            -Details "EnableMDNS: $mdns" `
            -Recommendation "Disable mDNS if not required for local service discovery"
    }
    
    # Check SMB Signing
    $smbSigningRequired = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "RequireSecuritySignature" -Default 0
    $smbSigningEnabled = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" -Name "EnableSecuritySignature" -Default 1
    
    if ($smbSigningRequired -ne 1) {
        Add-Finding -Category "Network Protocols" -Name "SMB Signing Not Required" -Risk "Medium" `
            -Description "SMB signing is not required - vulnerable to relay attacks" `
            -Details "Server RequireSecuritySignature: $smbSigningRequired" `
            -Recommendation "Enable SMB signing: Set-SmbServerConfiguration -RequireSecuritySignature `$true" `
            -Reference "CIS Benchmark 2.3.9.2"
    } else {
        Add-Finding -Category "Network Protocols" -Name "SMB Signing Required" -Risk "Info" `
            -Description "SMB signing is properly required" `
            -Details "RequireSecuritySignature: 1"
    }
    
    # Check SMB Encryption
    try {
        $smbConfig = Get-SmbServerConfiguration -ErrorAction Stop
        if (-not $smbConfig.EncryptData) {
            Add-Finding -Category "Network Protocols" -Name "SMB Encryption Disabled" -Risk "Low" `
                -Description "SMB encryption is not enabled by default" `
                -Details "EncryptData: $($smbConfig.EncryptData)" `
                -Recommendation "Consider enabling SMB encryption for sensitive file shares" `
                -Reference "Security Best Practice"
        }
    } catch { }
    
    # Check LDAP Signing (for domain-joined machines)
    $ldapSigning = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters" -Name "LDAPServerIntegrity" -Default $null
    $ldapClientSigning = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\ldap" -Name "LDAPClientIntegrity" -Default 1
    
    if ($ldapClientSigning -lt 1) {
        Add-Finding -Category "Network Protocols" -Name "LDAP Client Signing Not Required" -Risk "Medium" `
            -Description "LDAP client signing is not required - vulnerable to relay attacks" `
            -Details "LDAPClientIntegrity: $ldapClientSigning" `
            -Recommendation "Set LDAP client signing to 'Require signing'" `
            -Reference "CIS Benchmark 2.3.11.8"
    }
}

function Test-PrivilegeEscalation {
    Write-AuditLog "Checking Privilege Escalation Vectors..." -Level "INFO"
    
    # Check AlwaysInstallElevated (MSI privilege escalation)
    $aieHKLM = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Default 0
    $aieHKCU = Get-RegistryValue -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer" -Name "AlwaysInstallElevated" -Default 0
    
    if ($aieHKLM -eq 1 -and $aieHKCU -eq 1) {
        Add-Finding -Category "Privilege Escalation" -Name "AlwaysInstallElevated Enabled" -Risk "Critical" `
            -Description "AlwaysInstallElevated is enabled - allows any user to install MSI packages with SYSTEM privileges" `
            -Details "HKLM: $aieHKLM, HKCU: $aieHKCU" `
            -Recommendation "Disable AlwaysInstallElevated in both HKLM and HKCU" `
            -Reference "MITRE ATT&CK T1548.002"
    } elseif ($aieHKLM -eq 1 -or $aieHKCU -eq 1) {
        Add-Finding -Category "Privilege Escalation" -Name "AlwaysInstallElevated Partially Set" -Risk "Medium" `
            -Description "AlwaysInstallElevated is set in one hive - potential for exploitation if both become set" `
            -Details "HKLM: $aieHKLM, HKCU: $aieHKCU" `
            -Recommendation "Ensure AlwaysInstallElevated is disabled in both hives"
    } else {
        Add-Finding -Category "Privilege Escalation" -Name "AlwaysInstallElevated Disabled" -Risk "Info" `
            -Description "AlwaysInstallElevated is properly disabled" `
            -Details "HKLM: $aieHKLM, HKCU: $aieHKCU"
    }
    
    # Check for PATH DLL hijacking opportunities
    $pathDirs = $env:PATH -split ';'
    $writablePaths = @()
    
    foreach ($dir in $pathDirs) {
        if ([string]::IsNullOrWhiteSpace($dir)) { continue }
        if ($dir -match '^(C:\\Windows|C:\\Program Files)') { continue }
        
        if (Test-Path $dir) {
            try {
                # Check if current user can write to this directory
                $acl = Get-Acl -Path $dir -ErrorAction Stop
                $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
                $principal = New-Object Security.Principal.WindowsPrincipal($identity)
                
                foreach ($access in $acl.Access) {
                    if ($access.FileSystemRights -match 'Write|FullControl|Modify') {
                        if ($access.IdentityReference -match 'Users|Everyone|Authenticated Users|BUILTIN\\Users') {
                            $writablePaths += $dir
                            break
                        }
                    }
                }
            } catch { }
        }
    }
    
    if ($writablePaths.Count -gt 0) {
        Add-Finding -Category "Privilege Escalation" -Name "Writable PATH Directories" -Risk "Medium" `
            -Description "System PATH contains directories that may be writable by standard users" `
            -Details "Potentially writable: $($writablePaths -join ', ')" `
            -Recommendation "Review PATH directories and ensure proper permissions" `
            -Reference "DLL Hijacking Prevention"
    }
    
    # Check DLL Safe Search Mode
    $safeSearch = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name "SafeDllSearchMode" -Default 1
    if ($safeSearch -ne 1) {
        Add-Finding -Category "Privilege Escalation" -Name "DLL Safe Search Mode Disabled" -Risk "Medium" `
            -Description "Safe DLL search mode is disabled - increases DLL hijacking risk" `
            -Details "SafeDllSearchMode: $safeSearch" `
            -Recommendation "Enable Safe DLL Search Mode" `
            -Reference "Microsoft Security Advisory"
    }
    
    # Check for Print Spooler service (PrintNightmare)
    $spooler = Get-Service -Name "Spooler" -ErrorAction SilentlyContinue
    if ($spooler -and $spooler.Status -eq 'Running') {
        # Check if Point and Print restrictions are in place
        $noWarning = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "NoWarningNoElevationOnInstall" -Default 0
        $updatePrompt = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint" -Name "UpdatePromptSettings" -Default 0
        
        if ($noWarning -eq 1 -or $updatePrompt -eq 1) {
            Add-Finding -Category "Privilege Escalation" -Name "Print Spooler Vulnerable Configuration" -Risk "High" `
                -Description "Print Spooler is running with Point and Print restrictions disabled" `
                -Details "NoWarningNoElevationOnInstall: $noWarning, UpdatePromptSettings: $updatePrompt" `
                -Recommendation "Apply PrintNightmare mitigations or disable Print Spooler if not needed" `
                -Reference "CVE-2021-34527"
        } else {
            Add-Finding -Category "Privilege Escalation" -Name "Print Spooler Running" -Risk "Info" `
                -Description "Print Spooler service is running with restrictions in place" `
                -Details "Status: Running, Point and Print restrictions appear configured"
        }
    }
    
    # Note: WSUS HTTP vulnerability is checked in Test-UpdateStatus
    
    # Check Co-installer Settings (Device Installation)
    $coInstallerDisabled = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer" -Name "DisableCoInstallers" -Default 0
    $deviceInstallPolicy = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Settings" -Name "DisableCoInstallers" -Default $null
    
    if ($coInstallerDisabled -eq 1 -or $deviceInstallPolicy -eq 1) {
        Add-Finding -Category "Privilege Escalation" -Name "Device Co-installers Disabled" -Risk "Info" `
            -Description "Device co-installers are disabled - reduces attack surface from third-party driver installers" `
            -Details "Registry: $coInstallerDisabled, Policy: $deviceInstallPolicy"
    } else {
        Add-Finding -Category "Privilege Escalation" -Name "Device Co-installers Enabled" -Risk "Medium" `
            -Description "Device co-installers are enabled - third-party co-installers run as SYSTEM during device installation" `
            -Details "DisableCoInstallers not set or set to 0" `
            -Recommendation "Consider disabling co-installers via Group Policy (Computer Configuration > Admin Templates > Windows Components > Device Installation) or set HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Device Installer\DisableCoInstallers = 1" `
            -Reference "Microsoft Security Guidance - Device Installation Settings"
    }
    
    # Check Device Installation Restrictions
    $denyDeviceIDs = Test-RegistryPathExists -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceIDs"
    $denyDeviceClasses = Test-RegistryPathExists -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions\DenyDeviceClasses"
    $denyAll = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeviceInstall\Restrictions" -Name "DenyAll" -Default 0
    
    if ($denyAll -eq 1 -or $denyDeviceIDs -or $denyDeviceClasses) {
        $details = @()
        if ($denyAll -eq 1) { $details += "DenyAll: Enabled" }
        if ($denyDeviceIDs) { $details += "Device ID restrictions: Configured" }
        if ($denyDeviceClasses) { $details += "Device class restrictions: Configured" }
        Add-Finding -Category "Privilege Escalation" -Name "Device Installation Restrictions" -Risk "Info" `
            -Description "Device installation restrictions are configured" `
            -Details ($details -join "`n")
    } else {
        Add-Finding -Category "Privilege Escalation" -Name "No Device Installation Restrictions" -Risk "Low" `
            -Description "No device installation restrictions are configured - any device class can be installed" `
            -Details "DenyAll: Not set, No DenyDeviceIDs or DenyDeviceClasses policies" `
            -Recommendation "Consider restricting device installation to approved device classes via Group Policy"
    }
    
    # Check Autologon credentials
    $autoLogonEnabled = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoAdminLogon" -Default "0"
    $autoLogonUser = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultUserName" -Default ""
    $autoLogonDomain = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultDomainName" -Default ""
    $autoLogonPassword = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "DefaultPassword" -Default $null
    # Also check for LSA Secrets stored autologon (no cleartext password in registry)
    $autoLogonCount = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "AutoLogonCount" -Default $null
    
    if ($autoLogonEnabled -eq "1") {
        if ($autoLogonPassword) {
            Add-Finding -Category "Privilege Escalation" -Name "Autologon with Cleartext Password" -Risk "Critical" `
                -Description "Autologon is enabled with a cleartext password stored in the registry - any local user can read it" `
                -Details "AutoAdminLogon: Enabled`nUser: $autoLogonDomain\$autoLogonUser`nDefaultPassword: Present in HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon (cleartext!)" `
                -Recommendation "Disable autologon or use the Sysinternals Autologon tool which encrypts the password in LSA Secrets instead of storing it in cleartext" `
                -Reference "MITRE ATT&CK T1552.002 - Unsecured Credentials: Credentials in Registry"
        } else {
            Add-Finding -Category "Privilege Escalation" -Name "Autologon Enabled" -Risk "Medium" `
                -Description "Autologon is enabled - system automatically logs in without requiring a password at the console" `
                -Details "AutoAdminLogon: Enabled`nUser: $autoLogonDomain\$autoLogonUser`nPassword: Stored in LSA Secrets (not cleartext)$(if ($autoLogonCount) { "`nAutoLogonCount: $autoLogonCount (remaining auto-logons)" })" `
                -Recommendation "Disable autologon unless required for kiosk/dedicated systems. Ensure physical access is controlled." `
                -Reference "MITRE ATT&CK T1552.002"
        }
    } else {
        Add-Finding -Category "Privilege Escalation" -Name "Autologon Disabled" -Risk "Info" `
            -Description "Autologon is not enabled" `
            -Details "AutoAdminLogon: $autoLogonEnabled"
    }
}

function Test-SecureBoot {
    Write-AuditLog "Checking Secure Boot and Hardware Security..." -Level "INFO"
    
    # Check Secure Boot status
    try {
        $secureBoot = Confirm-SecureBootUEFI -ErrorAction Stop
        if ($secureBoot) {
            Add-Finding -Category "Hardware Security" -Name "Secure Boot Enabled" -Risk "Info" `
                -Description "UEFI Secure Boot is enabled" `
                -Details "SecureBoot: Enabled"
        } else {
            Add-Finding -Category "Hardware Security" -Name "Secure Boot Disabled" -Risk "Medium" `
                -Description "UEFI Secure Boot is not enabled" `
                -Details "SecureBoot: Disabled" `
                -Recommendation "Enable Secure Boot in UEFI/BIOS settings" `
                -Reference "Hardware Security Best Practice"
        }
    } catch {
        Add-Finding -Category "Hardware Security" -Name "Secure Boot Status Unknown" -Risk "Info" `
            -Description "Could not determine Secure Boot status" `
            -Details "System may be using legacy BIOS or cmdlet not available"
    }
    
    # Check Virtualization Based Security (VBS)
    try {
        $vbs = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
        
        if ($vbs.VirtualizationBasedSecurityStatus -eq 2) {
            Add-Finding -Category "Hardware Security" -Name "VBS Running" -Risk "Info" `
                -Description "Virtualization Based Security is running" `
                -Details "VBS Status: Running, Security Services: $($vbs.SecurityServicesRunning -join ', ')"
        } elseif ($vbs.VirtualizationBasedSecurityStatus -eq 1) {
            Add-Finding -Category "Hardware Security" -Name "VBS Enabled Not Running" -Risk "Low" `
                -Description "VBS is enabled but not currently running" `
                -Details "VBS Status: Enabled but not running (may require reboot)" `
                -Recommendation "Reboot to activate Virtualization Based Security"
        } else {
            Add-Finding -Category "Hardware Security" -Name "VBS Not Enabled" -Risk "Low" `
                -Description "Virtualization Based Security is not enabled" `
                -Details "VBS Status: Not enabled" `
                -Recommendation "Enable VBS for enhanced security (requires compatible hardware)" `
                -Reference "Windows Security Baseline"
        }
        
        # Check specific security services
        $hvci = $vbs.SecurityServicesRunning -contains 1
        $credGuard = $vbs.SecurityServicesRunning -contains 2
        
        if (-not $hvci) {
            Add-Finding -Category "Hardware Security" -Name "HVCI Not Running" -Risk "Low" `
                -Description "Hypervisor-protected Code Integrity (HVCI) is not running" `
                -Details "Memory Integrity is not enabled" `
                -Recommendation "Enable Memory Integrity in Windows Security settings"
        }
    } catch {
        Write-AuditLog "Could not query Device Guard status: $_" -Level "WARN"
    }
    
    # Check TPM status - comprehensive
    $Script:TPMInfo = $null
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        
        # Get detailed TPM info from WMI
        $tpmWmi = $null
        try {
            $tpmWmi = Get-CimInstance -Namespace "root\cimv2\Security\MicrosoftTpm" -ClassName Win32_Tpm -ErrorAction Stop
        } catch { }
        
        # Build TPM info object
        $tpmVersion = "Unknown"
        $tpmManufacturer = "Unknown"
        $tpmManufacturerId = ""
        $tpmSpecVersion = ""
        $tpmFirmware = ""
        $tpmPhysicalPresenceVersionInfo = ""
        
        if ($tpmWmi) {
            # Spec version string (e.g. "2.0, 0, 1.59")
            if ($tpmWmi.SpecVersion) {
                $tpmSpecVersion = $tpmWmi.SpecVersion
                if ($tpmWmi.SpecVersion -match '^(\d+\.\d+)') {
                    $tpmVersion = $Matches[1]
                }
            }
            
            # Manufacturer
            if ($tpmWmi.ManufacturerIdTxt) {
                $tpmManufacturer = $tpmWmi.ManufacturerIdTxt
            } elseif ($tpmWmi.ManufacturerId) {
                $tpmManufacturerId = $tpmWmi.ManufacturerId
                # Common manufacturer IDs
                $tpmManufacturer = switch ($tpmManufacturerId) {
                    1229346816 { "Infineon" }
                    1398033696 { "STMicroelectronics" }
                    1112687437 { "Broadcom" }
                    1095582720 { "Atmel" }
                    1314145024 { "Nuvoton" }
                    1196379975 { "Google (Cr50/Ti50)" }
                    1296651087 { "Microsoft (fTPM/Pluton)" }
                    1095844163 { "AMD (fTPM)" }
                    1229870147 { "Intel (PTT)" }
                    1314079556 { "NationZ" }
                    default { "ID: $tpmManufacturerId" }
                }
            }
            
            # Firmware version
            if ($tpmWmi.ManufacturerVersion) {
                $tpmFirmware = $tpmWmi.ManufacturerVersion
            }
            
            # Physical Presence Interface version
            if ($tpmWmi.PhysicalPresenceVersionInfo) {
                $tpmPhysicalPresenceVersionInfo = $tpmWmi.PhysicalPresenceVersionInfo
            }
        }
        
        # Fallback version detection from registry
        if ($tpmVersion -eq "Unknown") {
            $tpmRegVer = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\TPM\WMI" -Name "SpecVersion" -Default $null
            if ($tpmRegVer) { $tpmSpecVersion = $tpmRegVer; if ($tpmRegVer -match '^(\d+\.\d+)') { $tpmVersion = $Matches[1] } }
        }
        
        # Check TPM-related registry settings
        $tpmOwnerAuth = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\TPM" -Name "OSManagedAuthLevel" -Default $null
        $tpmAuthLevel = switch ($tpmOwnerAuth) {
            0 { "None" }
            2 { "Delegated" }
            4 { "Full" }
            default { if ($null -eq $tpmOwnerAuth) { "Not configured (default)" } else { "Unknown ($tpmOwnerAuth)" } }
        }
        
        # Check if TPM lockout is configured
        $tpmLockoutThreshold = $null
        $tpmLockoutDuration = $null
        $tpmLockoutRecovery = $null
        if ($tpmWmi) {
            try {
                # GetLockoutRecoveryInfo if available
                $tpmLockoutThreshold = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\TPM" -Name "StandardUserAuthorizationFailureIndividualThreshold" -Default $null
                $tpmLockoutDuration = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\TPM" -Name "StandardUserAuthorizationFailureTotalThreshold" -Default $null
                $tpmLockoutRecovery = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\TPM" -Name "StandardUserAuthorizationFailureDuration" -Default $null
            } catch { }
        }
        
        # Check for TPM vulnerability indicators
        $tpmVulnerable = $false
        $tpmVulnDetails = @()
        
        # ROCA vulnerability (CVE-2017-15361) affects Infineon TPMs with certain firmware
        if ($tpmManufacturer -match "Infineon") {
            $tpmVulnDetails += "Infineon TPM detected - verify firmware is patched for ROCA vulnerability (CVE-2017-15361)"
            $tpmVulnerable = $true
        }
        
        # TPM 1.2 is considered weaker
        if ($tpmVersion -match "^1\.") {
            $tpmVulnDetails += "TPM 1.2 uses SHA-1 which is deprecated - TPM 2.0 is recommended"
            $tpmVulnerable = $true
        }
        
        # Check if TPM clear has been blocked
        $blockTpmClear = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\TPM" -Name "BlockTpmClear" -Default $null
        
        # Check TPM auto-provisioning
        $tpmAutoProvision = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\TPM" -Name "AllowClearAfterWindowsInstall" -Default $null
        
        # Store for HTML/JSON
        $Script:TPMInfo = [PSCustomObject]@{
            Present        = $tpm.TpmPresent
            Ready          = $tpm.TpmReady
            Enabled        = $tpm.TpmEnabled
            Activated      = $tpm.TpmActivated
            Owned          = $tpm.TpmOwned
            Version        = $tpmVersion
            SpecVersion    = $tpmSpecVersion
            Manufacturer   = $tpmManufacturer
            FirmwareVersion = $tpmFirmware
            PPIVersion     = $tpmPhysicalPresenceVersionInfo
            OwnerAuth      = $tpmAuthLevel
            BlockClear     = $blockTpmClear
            IsVulnerable   = $tpmVulnerable
        }
        
        # Build detail string
        $detailLines = @(
            "Present: $($tpm.TpmPresent)",
            "Ready: $($tpm.TpmReady)",
            "Enabled: $($tpm.TpmEnabled)",
            "Activated: $($tpm.TpmActivated)",
            "Owned: $($tpm.TpmOwned)",
            "TPM Version: $tpmVersion",
            "Spec Version: $tpmSpecVersion",
            "Manufacturer: $tpmManufacturer"
        )
        if ($tpmFirmware) { $detailLines += "Firmware: $tpmFirmware" }
        if ($tpmPhysicalPresenceVersionInfo) { $detailLines += "PPI Version: $tpmPhysicalPresenceVersionInfo" }
        $detailLines += "Owner Authorization: $tpmAuthLevel"
        if ($null -ne $blockTpmClear) { $detailLines += "Block TPM Clear: $(if ($blockTpmClear -eq 1) { 'Yes' } else { 'No' })" }
        if ($tpmLockoutThreshold) { $detailLines += "Lockout Threshold (per-user): $tpmLockoutThreshold" }
        if ($tpmLockoutDuration) { $detailLines += "Lockout Threshold (total): $tpmLockoutDuration" }
        if ($tpmLockoutRecovery) { $detailLines += "Lockout Duration (minutes): $tpmLockoutRecovery" }
        
        if ($tpm.TpmPresent -and $tpm.TpmReady) {
            Add-Finding -Category "Hardware Security" -Name "TPM Status" -Risk "Info" `
                -Description "TPM $tpmVersion is present and ready ($tpmManufacturer)" `
                -Details ($detailLines -join "`n")
            
            # Version check
            if ($tpmVersion -match "^1\.") {
                Add-Finding -Category "Hardware Security" -Name "TPM Version 1.2 Detected" -Risk "Medium" `
                    -Description "TPM 1.2 uses SHA-1 hashing which is cryptographically weak - TPM 2.0 is required for Windows 11 and recommended for all systems" `
                    -Details "TPM Version: $tpmVersion`nSHA-1 is vulnerable to collision attacks`nTPM 2.0 supports SHA-256 and is required for Credential Guard, Windows Hello, and measured boot" `
                    -Recommendation "Upgrade to a TPM 2.0 module or enable fTPM 2.0 in BIOS if supported by the CPU" `
                    -Reference "Microsoft: TPM 2.0 requirement for Windows 11"
            }
            
            # Vulnerability check
            if ($tpmVulnerable -and $tpmVulnDetails.Count -gt 0) {
                Add-Finding -Category "Hardware Security" -Name "TPM Vulnerability Advisory" -Risk "Medium" `
                    -Description "Potential TPM vulnerabilities detected" `
                    -Details ($tpmVulnDetails -join "`n") `
                    -Recommendation "Check manufacturer website for firmware updates" `
                    -Reference "CVE-2017-15361 (ROCA)"
            }
            
        } elseif ($tpm.TpmPresent) {
            Add-Finding -Category "Hardware Security" -Name "TPM Not Ready" -Risk "Medium" `
                -Description "TPM is present but not ready - security features depending on TPM will not function" `
                -Details ($detailLines -join "`n") `
                -Recommendation "Initialize and take ownership of the TPM in BIOS/UEFI settings or via tpm.msc"
        } else {
            Add-Finding -Category "Hardware Security" -Name "No TPM Detected" -Risk "Medium" `
                -Description "No TPM detected - full disk encryption, measured boot, and credential protection are limited" `
                -Details "TPM not present" `
                -Recommendation "Enable fTPM in BIOS (Intel PTT / AMD fTPM) or install a discrete TPM 2.0 module"
        }
        
        # Owner auth policy check
        if ($null -ne $tpmOwnerAuth -and $tpmOwnerAuth -eq 0) {
            Add-Finding -Category "Hardware Security" -Name "TPM Owner Auth Not Stored" -Risk "Low" `
                -Description "OS-managed TPM authorization level is set to None - OS will not store TPM owner authorization" `
                -Details "OSManagedAuthLevel: $tpmOwnerAuth ($tpmAuthLevel)" `
                -Recommendation "Consider setting to Delegated (2) or Full (4) for easier TPM management"
        }
        
    } catch {
        Add-Finding -Category "Hardware Security" -Name "TPM Status Unknown" -Risk "Info" `
            -Description "Could not determine TPM status - Get-Tpm cmdlet may require admin privileges" `
            -Details "Error: $($_.Exception.Message)"
    }
    
    # Check CPU vulnerability mitigations (Spectre/Meltdown)
    $spectre = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverride" -Default $null
    $spectreMask = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management" -Name "FeatureSettingsOverrideMask" -Default $null
    
    if ($null -eq $spectre -or $null -eq $spectreMask) {
        Add-Finding -Category "Hardware Security" -Name "CPU Mitigations Default" -Risk "Info" `
            -Description "CPU vulnerability mitigations using default settings" `
            -Details "No explicit override configured"
    } elseif ($spectre -eq 3 -and $spectreMask -eq 3) {
        Add-Finding -Category "Hardware Security" -Name "CPU Mitigations Disabled" -Risk "High" `
            -Description "Spectre/Meltdown mitigations appear to be disabled" `
            -Details "FeatureSettingsOverride: $spectre, FeatureSettingsOverrideMask: $spectreMask" `
            -Recommendation "Enable CPU vulnerability mitigations" `
            -Reference "CVE-2017-5754, CVE-2017-5753"
    }
}

function Test-DefenderASR {
    Write-AuditLog "Checking Windows Defender Attack Surface Reduction..." -Level "INFO"
    
    try {
        $prefs = Get-MpPreference -ErrorAction Stop
        
        # Check if ASR rules are configured
        $asrRules = $prefs.AttackSurfaceReductionRules_Ids
        $asrActions = $prefs.AttackSurfaceReductionRules_Actions
        
        if (-not $asrRules -or $asrRules.Count -eq 0) {
            Add-Finding -Category "Defender ASR" -Name "No ASR Rules Configured" -Risk "Medium" `
                -Description "No Attack Surface Reduction rules are configured" `
                -Details "ASR rules provide protection against common attack techniques" `
                -Recommendation "Enable ASR rules via Group Policy or Intune" `
                -Reference "Microsoft Defender ASR Documentation"
        } else {
            # Count enabled rules (action = 1 is Block, 2 is Audit, 6 is Warn)
            $enabledCount = 0
            for ($i = 0; $i -lt $asrRules.Count; $i++) {
                if ($asrActions[$i] -in @(1, 2, 6)) { $enabledCount++ }
            }
            
            Add-Finding -Category "Defender ASR" -Name "ASR Rules Configured" -Risk "Info" `
                -Description "Attack Surface Reduction rules are configured" `
                -Details "Total rules: $($asrRules.Count), Active rules: $enabledCount"
            
            # Check for critical ASR rules
            $criticalRules = @{
                "BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550" = "Block executable content from email client and webmail"
                "D4F940AB-401B-4EFC-AADC-AD5F3C50688A" = "Block all Office applications from creating child processes"
                "3B576869-A4EC-4529-8536-B80A7769E899" = "Block Office applications from creating executable content"
                "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84" = "Block Office applications from injecting code into other processes"
                "D3E037E1-3EB8-44C8-A917-57927947596D" = "Block JavaScript or VBScript from launching downloaded executable content"
                "5BEB7EFE-FD9A-4556-801D-275E5FFC04CC" = "Block execution of potentially obfuscated scripts"
                "92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B" = "Block Win32 API calls from Office macros"
                "01443614-CD74-433A-B99E-2ECDC07BFC25" = "Block executable files from running unless they meet a prevalence, age, or trusted list criterion"
                "C1DB55AB-C21A-4637-BB3F-A12568109D35" = "Use advanced protection against ransomware"
                "9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2" = "Block credential stealing from LSASS"
                "D1E49AAC-8F56-4280-B9BA-993A6D77406C" = "Block process creations originating from PSExec and WMI commands"
                "B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4" = "Block untrusted and unsigned processes that run from USB"
                "26190899-1602-49E8-8B27-EB1D0A1CE869" = "Block Office communication application from creating child processes"
                "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C" = "Block Adobe Reader from creating child processes"
                "E6DB77E5-3DF2-4CF1-B95A-636979351E5B" = "Block persistence through WMI event subscription"
            }
            
            $missingCritical = @()
            foreach ($ruleId in $criticalRules.Keys) {
                $index = [Array]::IndexOf($asrRules, $ruleId)
                if ($index -eq -1 -or $asrActions[$index] -eq 0) {
                    $missingCritical += $criticalRules[$ruleId]
                }
            }
            
            if ($missingCritical.Count -gt 5) {
                Add-Finding -Category "Defender ASR" -Name "Critical ASR Rules Not Enabled" -Risk "Medium" `
                    -Description "Several critical ASR rules are not enabled" `
                    -Details "Missing/disabled rules: $($missingCritical.Count)`n$($missingCritical[0..4] -join "`n")..." `
                    -Recommendation "Enable additional ASR rules for better protection"
            } elseif ($missingCritical.Count -gt 0) {
                Add-Finding -Category "Defender ASR" -Name "Some ASR Rules Not Enabled" -Risk "Low" `
                    -Description "Some recommended ASR rules are not enabled" `
                    -Details "Missing/disabled rules:`n$($missingCritical -join "`n")" `
                    -Recommendation "Consider enabling these additional ASR rules"
            }
        }
        
        # Check Controlled Folder Access (ransomware protection)
        if ($prefs.EnableControlledFolderAccess -eq 1) {
            Add-Finding -Category "Defender ASR" -Name "Controlled Folder Access Enabled" -Risk "Info" `
                -Description "Ransomware protection (Controlled Folder Access) is enabled" `
                -Details "Protected folders are guarded against unauthorized changes"
        } else {
            Add-Finding -Category "Defender ASR" -Name "Controlled Folder Access Disabled" -Risk "Low" `
                -Description "Ransomware protection (Controlled Folder Access) is not enabled" `
                -Details "EnableControlledFolderAccess: $($prefs.EnableControlledFolderAccess)" `
                -Recommendation "Enable Controlled Folder Access for ransomware protection"
        }
        
        # Check Network Protection
        if ($prefs.EnableNetworkProtection -eq 1) {
            Add-Finding -Category "Defender ASR" -Name "Network Protection Enabled" -Risk "Info" `
                -Description "Network Protection is enabled (blocks malicious network connections)" `
                -Details "EnableNetworkProtection: Enabled"
        } else {
            Add-Finding -Category "Defender ASR" -Name "Network Protection Disabled" -Risk "Low" `
                -Description "Network Protection is not enabled" `
                -Details "EnableNetworkProtection: $($prefs.EnableNetworkProtection)" `
                -Recommendation "Enable Network Protection to block malicious sites and downloads"
        }
        
    } catch {
        Add-Finding -Category "Defender ASR" -Name "ASR Check Failed" -Risk "Info" `
            -Description "Could not check ASR configuration" `
            -Details "Error: $_. Windows Defender may not be the active AV."
    }
}

function Test-EventLogConfiguration {
    Write-AuditLog "Checking Event Log Configuration..." -Level "INFO"
    
    $criticalLogs = @{
        "Security"    = @{ MinSize = 128MB; Importance = "Critical" }
        "System"      = @{ MinSize = 64MB; Importance = "High" }
        "Application" = @{ MinSize = 64MB; Importance = "Medium" }
        "Microsoft-Windows-PowerShell/Operational" = @{ MinSize = 64MB; Importance = "High" }
        "Microsoft-Windows-Sysmon/Operational" = @{ MinSize = 128MB; Importance = "High" }
        "Microsoft-Windows-Windows Defender/Operational" = @{ MinSize = 32MB; Importance = "Medium" }
    }
    
    foreach ($logName in $criticalLogs.Keys) {
        try {
            $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
            $config = $criticalLogs[$logName]
            $sizeInMB = [math]::Round($log.MaximumSizeInBytes / 1MB, 1)
            $minSizeInMB = $config.MinSize / 1MB
            
            if ($log.MaximumSizeInBytes -lt $config.MinSize) {
                $risk = switch ($config.Importance) {
                    "Critical" { "High" }
                    "High" { "Medium" }
                    default { "Low" }
                }
                
                Add-Finding -Category "Event Logs" -Name "$logName Log Size Too Small" -Risk $risk `
                    -Description "Event log maximum size is below recommended value" `
                    -Details "Current: ${sizeInMB}MB, Recommended: ${minSizeInMB}MB" `
                    -Recommendation "Increase log size: wevtutil sl `"$logName`" /ms:$($config.MinSize)" `
                    -Reference "Security Logging Best Practice"
            } else {
                Add-Finding -Category "Event Logs" -Name "$logName Log Configuration" -Risk "Info" `
                    -Description "Event log size is adequately configured" `
                    -Details "Size: ${sizeInMB}MB, Enabled: $($log.IsEnabled)"
            }
            
            # Check if log is enabled
            if (-not $log.IsEnabled) {
                Add-Finding -Category "Event Logs" -Name "$logName Log Disabled" -Risk "Medium" `
                    -Description "Event log is disabled" `
                    -Details "Log: $logName, Enabled: False" `
                    -Recommendation "Enable this event log for security monitoring"
            }
            
        } catch {
            # Log doesn't exist - only report for important ones
            if ($logName -eq "Microsoft-Windows-Sysmon/Operational") {
                Add-Finding -Category "Event Logs" -Name "Sysmon Not Installed" -Risk "Low" `
                    -Description "Sysmon does not appear to be installed" `
                    -Details "Microsoft-Windows-Sysmon/Operational log not found" `
                    -Recommendation "Consider installing Sysmon for enhanced endpoint visibility" `
                    -Reference "https://docs.microsoft.com/en-us/sysinternals/downloads/sysmon"
            }
        }
    }
    
    # Check log retention/archiving
    try {
        $secLog = Get-WinEvent -ListLog "Security" -ErrorAction Stop
        if ($secLog.LogMode -eq "Circular") {
            Add-Finding -Category "Event Logs" -Name "Security Log Retention" -Risk "Info" `
                -Description "Security log is in circular mode (overwrites oldest events)" `
                -Details "LogMode: Circular. Consider archiving logs for compliance." `
                -Recommendation "Implement log forwarding to SIEM for retention"
        }
    } catch { }
}

function Test-InactivityTimeout {
    Write-AuditLog "Checking Session Security Settings..." -Level "INFO"
    
    # Check screen saver timeout and password protection
    $ssTimeout = Get-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Default 0
    $ssActive = Get-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaveActive" -Default "0"
    $ssSecure = Get-RegistryValue -Path "HKCU:\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Default "0"
    
    # Check policy-enforced settings
    $policyTimeout = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaveTimeOut" -Default $null
    $policySecure = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Control Panel\Desktop" -Name "ScreenSaverIsSecure" -Default $null
    
    $effectiveTimeout = if ($policyTimeout) { $policyTimeout } else { $ssTimeout }
    $effectiveSecure = if ($policySecure) { $policySecure } else { $ssSecure }
    
    if ([int]$effectiveTimeout -eq 0 -or $ssActive -ne "1") {
        Add-Finding -Category "Session Security" -Name "No Screen Saver Timeout" -Risk "Medium" `
            -Description "Screen saver/lock timeout is not configured" `
            -Details "Timeout: $effectiveTimeout seconds, Active: $ssActive" `
            -Recommendation "Configure screen saver with 15-minute (900 second) timeout" `
            -Reference "CIS Benchmark 2.3.7.3"
    } elseif ([int]$effectiveTimeout -gt 900) {
        Add-Finding -Category "Session Security" -Name "Long Screen Saver Timeout" -Risk "Low" `
            -Description "Screen saver timeout exceeds 15 minutes" `
            -Details "Current timeout: $([math]::Round([int]$effectiveTimeout/60, 1)) minutes" `
            -Recommendation "Consider reducing to 15 minutes or less" `
            -Reference "CIS Benchmark 2.3.7.3"
    }
    
    if ($effectiveSecure -ne "1") {
        Add-Finding -Category "Session Security" -Name "Screen Saver Not Password Protected" -Risk "Medium" `
            -Description "Screen saver is not configured to require password on resume" `
            -Details "ScreenSaverIsSecure: $effectiveSecure" `
            -Recommendation "Enable 'On resume, display logon screen' for screen saver" `
            -Reference "CIS Benchmark 2.3.7.4"
    }
    
    # Check machine inactivity limit (automatic lock)
    $machineTimeout = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "InactivityTimeoutSecs" -Default 0
    
    if ($machineTimeout -eq 0) {
        Add-Finding -Category "Session Security" -Name "No Machine Inactivity Limit" -Risk "Low" `
            -Description "No policy-enforced machine inactivity timeout is configured" `
            -Details "InactivityTimeoutSecs: Not set" `
            -Recommendation "Configure via Group Policy: Interactive logon: Machine inactivity limit"
    } elseif ($machineTimeout -gt 900) {
        Add-Finding -Category "Session Security" -Name "Long Machine Inactivity Limit" -Risk "Info" `
            -Description "Machine inactivity limit is set but may be too long" `
            -Details "Timeout: $([math]::Round($machineTimeout/60, 1)) minutes" `
            -Recommendation "Consider 15 minutes or less for better security"
    } else {
        Add-Finding -Category "Session Security" -Name "Machine Inactivity Limit Set" -Risk "Info" `
            -Description "Machine inactivity limit is properly configured" `
            -Details "Timeout: $([math]::Round($machineTimeout/60, 1)) minutes"
    }
    
    # Check legal notice/banner
    $legalCaption = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticecaption" -Default ""
    $legalText = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "legalnoticetext" -Default ""
    
    if ([string]::IsNullOrWhiteSpace($legalCaption) -and [string]::IsNullOrWhiteSpace($legalText)) {
        Add-Finding -Category "Session Security" -Name "No Login Banner" -Risk "Low" `
            -Description "No legal notice/login banner is configured" `
            -Details "Login banners are recommended for compliance" `
            -Recommendation "Configure a login banner via Group Policy" `
            -Reference "CIS Benchmark 2.3.7.1"
    } else {
        Add-Finding -Category "Session Security" -Name "Login Banner Configured" -Risk "Info" `
            -Description "A login banner is configured" `
            -Details "Caption: $legalCaption"
    }
}

function Test-AppLockerWDAC {
    Write-AuditLog "Checking Application Control Policies..." -Level "INFO"
    
    # Check AppLocker status
    try {
        $applockerSvc = Get-Service -Name "AppIDSvc" -ErrorAction Stop
        
        if ($applockerSvc.Status -eq 'Running') {
            # Check for AppLocker policies
            try {
                $applockerPolicy = Get-AppLockerPolicy -Effective -ErrorAction Stop
                
                if ($applockerPolicy.RuleCollections.Count -gt 0) {
                    $ruleCount = ($applockerPolicy.RuleCollections | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum
                    Add-Finding -Category "Application Control" -Name "AppLocker Enabled" -Risk "Info" `
                        -Description "AppLocker is configured with active policies" `
                        -Details "Rule collections: $($applockerPolicy.RuleCollections.Count), Total rules: $ruleCount"
                } else {
                    Add-Finding -Category "Application Control" -Name "AppLocker No Rules" -Risk "Info" `
                        -Description "AppLocker service is running but no rules are configured" `
                        -Details "Consider implementing application whitelisting"
                }
            } catch {
                Add-Finding -Category "Application Control" -Name "AppLocker Policy Check Failed" -Risk "Info" `
                    -Description "Could not retrieve AppLocker policy" `
                    -Details "Error: $_"
            }
        } else {
            Add-Finding -Category "Application Control" -Name "AppLocker Not Running" -Risk "Info" `
                -Description "AppLocker (Application Identity) service is not running" `
                -Details "Service Status: $($applockerSvc.Status)" `
                -Recommendation "Consider implementing AppLocker for application whitelisting"
        }
    } catch {
        Add-Finding -Category "Application Control" -Name "AppLocker Not Available" -Risk "Info" `
            -Description "AppLocker service not found" `
            -Details "AppLocker may not be available on this Windows edition"
    }
    
    # Check WDAC (Windows Defender Application Control)
    $wdacEnforced = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI" -Name "UMCIAuditMode" -Default $null
    $wdacPolicy = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI" -Name "PolicyOptions" -Default $null
    
    if ($null -ne $wdacPolicy) {
        if ($wdacEnforced -eq 0) {
            Add-Finding -Category "Application Control" -Name "WDAC Enforced" -Risk "Info" `
                -Description "Windows Defender Application Control policy is enforced" `
                -Details "WDAC is actively enforcing code integrity policies"
        } else {
            Add-Finding -Category "Application Control" -Name "WDAC Audit Mode" -Risk "Info" `
                -Description "Windows Defender Application Control is in audit mode" `
                -Details "UMCIAuditMode: $wdacEnforced"
        }
    }
}

function Test-CertificateSecurity {
    Write-AuditLog "Checking Certificate Store Security..." -Level "INFO"
    
    try {
        # Check for suspicious root certificates
        $rootCerts = Get-ChildItem -Path Cert:\LocalMachine\Root -ErrorAction Stop
        
        # Known suspicious certificate indicators
        $suspiciousIssuers = @(
            "Superfish",
            "eDellRoot",
            "DSDTestProvider",
            "Privdog",
            "Visual Discovery",
            "Komodia"
        )
        
        $untrustedCerts = @()
        $expiredCerts = @()
        $selfSignedSuspicious = @()
        
        foreach ($cert in $rootCerts) {
            # Check for known bad certs
            foreach ($suspicious in $suspiciousIssuers) {
                if ($cert.Subject -match $suspicious -or $cert.Issuer -match $suspicious) {
                    $untrustedCerts += $cert
                }
            }
            
            # Check for expired root certs
            if ($cert.NotAfter -lt (Get-Date)) {
                $expiredCerts += $cert
            }
            
            # Check for recently added self-signed certs (last 90 days)
            $certAge = (Get-Date) - $cert.NotBefore
            if ($certAge.Days -lt 90 -and $cert.Subject -eq $cert.Issuer) {
                # Skip Microsoft certs
                if ($cert.Subject -notmatch 'Microsoft|Windows') {
                    $selfSignedSuspicious += $cert
                }
            }
        }
        
        if ($untrustedCerts.Count -gt 0) {
            Add-Finding -Category "Certificates" -Name "Suspicious Root Certificates Found" -Risk "Critical" `
                -Description "Found root certificates matching known malicious patterns" `
                -Details "Certificates: $($untrustedCerts.Subject -join ', ')" `
                -Recommendation "Remove these suspicious root certificates immediately" `
                -Reference "Superfish/Komodia Certificate Injection"
        }
        
        if ($expiredCerts.Count -gt 0) {
            Add-Finding -Category "Certificates" -Name "Expired Root Certificates" -Risk "Low" `
                -Description "Found expired certificates in the root store" `
                -Details "Count: $($expiredCerts.Count) expired certificates" `
                -Recommendation "Review and remove unnecessary expired certificates"
        }
        
        if ($selfSignedSuspicious.Count -gt 0) {
            Add-Finding -Category "Certificates" -Name "Recently Added Self-Signed Root Certs" -Risk "Medium" `
                -Description "Found self-signed root certificates added in the last 90 days" `
                -Details "Certificates: $($selfSignedSuspicious.Subject -join ', ')" `
                -Recommendation "Verify these certificates are legitimate and authorized"
        }
        
        Add-Finding -Category "Certificates" -Name "Root Certificate Store" -Risk "Info" `
            -Description "Root certificate store enumerated" `
            -Details "Total root certificates: $($rootCerts.Count)"
            
    } catch {
        Add-Finding -Category "Certificates" -Name "Certificate Check Failed" -Risk "Info" `
            -Description "Could not check certificate stores" `
            -Details "Error: $_"
    }
}

function Test-MediaAutoPlay {
    Write-AuditLog "Checking AutoPlay/AutoRun Settings..." -Level "INFO"
    
    # Check AutoPlay settings
    $autoplayDisabled = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Default 0
    $autorunDisabled = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoAutorun" -Default 0
    
    # 0xFF (255) disables autorun on all drives
    if ($autoplayDisabled -eq 255) {
        Add-Finding -Category "Media Security" -Name "AutoRun Disabled (All Drives)" -Risk "Info" `
            -Description "AutoRun is properly disabled for all drive types" `
            -Details "NoDriveTypeAutoRun: 0xFF (All drives)"
    } elseif ($autoplayDisabled -eq 0) {
        Add-Finding -Category "Media Security" -Name "AutoRun Not Restricted" -Risk "Medium" `
            -Description "AutoRun is not disabled - removable media can auto-execute" `
            -Details "NoDriveTypeAutoRun: Not configured" `
            -Recommendation "Disable AutoRun via Group Policy: Turn off AutoPlay" `
            -Reference "CIS Benchmark 18.9.8.2"
    } else {
        Add-Finding -Category "Media Security" -Name "AutoRun Partially Restricted" -Risk "Low" `
            -Description "AutoRun is restricted but not fully disabled" `
            -Details "NoDriveTypeAutoRun: $autoplayDisabled" `
            -Recommendation "Set to 0xFF to disable on all drives"
    }
    
    # Check for Autorun.inf handling
    $honorAutorun = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "HonorAutorunSetting" -Default 1
    
    if ($honorAutorun -ne 0) {
        # Check if autorun.inf is blocked
        $autorunInf = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\IniFileMapping\Autorun.inf" -Name "(Default)" -Default $null
        
        if ($autorunInf -match '@SYS:DoesNotExist') {
            Add-Finding -Category "Media Security" -Name "Autorun.inf Blocked" -Risk "Info" `
                -Description "Autorun.inf execution is blocked via registry" `
                -Details "IniFileMapping redirects autorun.inf"
        }
    }
}

function Test-RemoteAccess {
    Write-AuditLog "Checking Remote Access Configuration..." -Level "INFO"
    
    # Check Remote Desktop settings in depth
    $rdpEnabled = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -Default 1
    
    if ($rdpEnabled -eq 0) {
        # RDP is enabled - check security settings
        
        # Check encryption level
        $encryptionLevel = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "MinEncryptionLevel" -Default 1
        if ($encryptionLevel -lt 3) {
            Add-Finding -Category "Remote Access" -Name "RDP Encryption Level Low" -Risk "Medium" `
                -Description "RDP minimum encryption level is not set to High" `
                -Details "MinEncryptionLevel: $encryptionLevel (3 = High)" `
                -Recommendation "Set minimum encryption to High" `
                -Reference "CIS Benchmark 18.9.65.3.9.2"
        }
        
        # Check security layer
        $securityLayer = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -Default 1
        if ($securityLayer -lt 2) {
            Add-Finding -Category "Remote Access" -Name "RDP Not Using TLS" -Risk "Medium" `
                -Description "RDP is not configured to require TLS security" `
                -Details "SecurityLayer: $securityLayer (2 = TLS)" `
                -Recommendation "Set SecurityLayer to 2 (TLS)" `
                -Reference "CIS Benchmark 18.9.65.3.9.3"
        }
        
        # Check for RDP port change
        $rdpPort = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "PortNumber" -Default 3389
        if ($rdpPort -eq 3389) {
            Add-Finding -Category "Remote Access" -Name "RDP Using Default Port" -Risk "Info" `
                -Description "RDP is using the default port 3389" `
                -Details "Consider changing from default for obscurity (not security)" `
                -Recommendation "Changing port provides minimal security benefit; focus on NLA and firewall"
        }
        
        # Check RDP timeout settings
        $idleLimit = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -Name "MaxIdleTime" -Default 0
        if ($idleLimit -eq 0) {
            Add-Finding -Category "Remote Access" -Name "No RDP Idle Timeout" -Risk "Low" `
                -Description "No idle timeout configured for RDP sessions" `
                -Details "MaxIdleTime: Not configured" `
                -Recommendation "Configure idle timeout to disconnect inactive sessions"
        }
        
    } else {
        Add-Finding -Category "Remote Access" -Name "Remote Desktop Disabled" -Risk "Info" `
            -Description "Remote Desktop is disabled on this system" `
            -Details "fDenyTSConnections: 1"
    }
    
    # Check Remote Assistance
    $raEnabled = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Default 0
    if ($raEnabled -eq 1) {
        Add-Finding -Category "Remote Access" -Name "Remote Assistance Enabled" -Risk "Low" `
            -Description "Windows Remote Assistance is enabled" `
            -Details "fAllowToGetHelp: 1" `
            -Recommendation "Disable if not required" `
            -Reference "CIS Benchmark 18.9.64.1"
    }
    
    # Check WinRM configuration via registry (avoids starting the service)
    # Only report on WinRM settings if the service exists
    $winrmService = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
    if ($winrmService) {
        $winrmRunning = $winrmService.Status -eq 'Running'
        
        # Check AllowUnencrypted via registry
        $allowUnencrypted = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service" -Name "allow_unencrypted" -Default 0
        if ($allowUnencrypted -eq 1) {
            Add-Finding -Category "Remote Access" -Name "WinRM Allows Unencrypted" -Risk "High" `
                -Description "WinRM is configured to allow unencrypted traffic" `
                -Details "allow_unencrypted = 1 (Service running: $winrmRunning)" `
                -Recommendation "Set AllowUnencrypted to false: winrm set winrm/config/service @{AllowUnencrypted=`"false`"}" `
                -Reference "CIS Benchmark"
        }
        
        # Check Basic Auth via registry
        $basicAuth = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Service" -Name "auth_basic" -Default 0
        if ($basicAuth -eq 1) {
            Add-Finding -Category "Remote Access" -Name "WinRM Basic Auth Enabled" -Risk "Medium" `
                -Description "WinRM allows Basic authentication" `
                -Details "auth_basic = 1 (Service running: $winrmRunning)" `
                -Recommendation "Disable Basic authentication if not required"
        }
        
        # Check for HTTP listeners via registry
        $listenerPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WSMAN\Listener"
        if (Test-Path $listenerPath) {
            $listeners = Get-ChildItem -Path $listenerPath -ErrorAction SilentlyContinue
            foreach ($listener in $listeners) {
                $transport = Get-RegistryValue -Path $listener.PSPath -Name "transport" -Default ""
                $port = Get-RegistryValue -Path $listener.PSPath -Name "port" -Default ""
                
                if ($transport -eq "HTTP") {
                    Add-Finding -Category "Remote Access" -Name "WinRM HTTP Listener Configured" -Risk "Medium" `
                        -Description "WinRM has an HTTP (non-encrypted) listener configured" `
                        -Details "Transport: HTTP, Port: $port (Service running: $winrmRunning)" `
                        -Recommendation "Use HTTPS for WinRM or remove HTTP listener" `
                        -Reference "Security Best Practice"
                }
            }
        }
        
        # Report WinRM status
        if ($winrmRunning) {
            Add-Finding -Category "Remote Access" -Name "WinRM Service Running" -Risk "Info" `
                -Description "Windows Remote Management service is running" `
                -Details "Verify WinRM is properly secured if intentionally enabled"
        }
    }
    
    # Check SSH Server
    $sshService = Get-Service -Name "sshd" -ErrorAction SilentlyContinue
    if ($sshService -and $sshService.Status -eq 'Running') {
        Add-Finding -Category "Remote Access" -Name "OpenSSH Server Running" -Risk "Info" `
            -Description "OpenSSH Server is running" `
            -Details "Verify SSH configuration in %ProgramData%\ssh\sshd_config" `
            -Recommendation "Review sshd_config for security settings"
    }
}

function Test-LAPS {
    Write-AuditLog "Checking Local Administrator Password Solution (LAPS)..." -Level "INFO"
    
    # Check for legacy LAPS
    $lapsInstalled = $false
    $lapsPath = "C:\Program Files\LAPS\CSE\Admpwd.dll"
    
    if (Test-Path $lapsPath) {
        $lapsInstalled = $true
        Add-Finding -Category "LAPS" -Name "Legacy LAPS Installed" -Risk "Info" `
            -Description "Microsoft LAPS (Legacy) is installed" `
            -Details "LAPS CSE found at: $lapsPath"
    }
    
    # Check for Windows LAPS (built into Windows 11 22H2+, Server 2019+)
    $windowsLaps = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS\Config" -Name "BackupDirectory" -Default $null
    
    if ($null -ne $windowsLaps) {
        $lapsInstalled = $true
        Add-Finding -Category "LAPS" -Name "Windows LAPS Configured" -Risk "Info" `
            -Description "Windows LAPS is configured" `
            -Details "Backup Directory: $windowsLaps"
    }
    
    # Check LAPS GPO settings
    $lapsGpo = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "AdmPwdEnabled" -Default $null
    
    if ($lapsGpo -eq 1) {
        $lapsInstalled = $true
        $pwdAge = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "PasswordAgeDays" -Default 30
        $pwdLength = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft Services\AdmPwd" -Name "PasswordLength" -Default 14
        
        Add-Finding -Category "LAPS" -Name "LAPS Policy Enabled" -Risk "Info" `
            -Description "LAPS is enabled via Group Policy" `
            -Details "Password Age: $pwdAge days, Password Length: $pwdLength characters"
    }
    
    if (-not $lapsInstalled) {
        # Check if this is a domain-joined machine
        $domain = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction SilentlyContinue).PartOfDomain
        
        if ($domain) {
            Add-Finding -Category "LAPS" -Name "LAPS Not Detected" -Risk "Medium" `
                -Description "Local Administrator Password Solution (LAPS) is not installed/configured" `
                -Details "LAPS provides automatic local admin password rotation" `
                -Recommendation "Deploy LAPS to manage local administrator passwords" `
                -Reference "Microsoft LAPS Documentation"
        } else {
            Add-Finding -Category "LAPS" -Name "LAPS N/A (Workgroup)" -Risk "Info" `
                -Description "System is not domain-joined; LAPS not applicable" `
                -Details "LAPS requires Active Directory"
        }
    }
}

function Test-OfficeSecurity {
    Write-AuditLog "Checking Microsoft Office Security Settings..." -Level "INFO"
    
    # Detect installed Office versions
    $officeVersions = @(
        @{ Version = "16.0"; Name = "Office 2016/2019/365" }
        @{ Version = "15.0"; Name = "Office 2013" }
        @{ Version = "14.0"; Name = "Office 2010" }
    )
    
    $officeApps = @("Word", "Excel", "PowerPoint", "Outlook")
    
    foreach ($ver in $officeVersions) {
        foreach ($app in $officeApps) {
            $basePath = "HKCU:\SOFTWARE\Microsoft\Office\$($ver.Version)\$app\Security"
            $policyPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$($ver.Version)\$app\Security"
            
            if (Test-RegistryPathExists $basePath) {
                # Check VBA Macro settings
                $vbaMacros = Get-RegistryValue -Path $basePath -Name "VBAWarnings" -Default 0
                $policyMacros = Get-RegistryValue -Path $policyPath -Name "VBAWarnings" -Default $null
                
                $effectiveMacros = if ($null -ne $policyMacros) { $policyMacros } else { $vbaMacros }
                
                # 1 = Enable all, 2 = Disable with notification, 3 = Disable except digitally signed, 4 = Disable all
                $macroStatus = switch ($effectiveMacros) {
                    1 { "All macros enabled (DANGEROUS)" }
                    2 { "Disabled with notification" }
                    3 { "Digitally signed only" }
                    4 { "All macros disabled" }
                    default { "Default (Disabled with notification)" }
                }
                
                if ($effectiveMacros -eq 1) {
                    Add-Finding -Category "Office Security" -Name "$app Macros Enabled" -Risk "High" `
                        -Description "All macros are enabled in $app - major security risk" `
                        -Details "VBAWarnings: $effectiveMacros ($macroStatus)" `
                        -Recommendation "Set macro security to 'Disable all except digitally signed'" `
                        -Reference "Microsoft Office Security Baseline"
                } elseif ($effectiveMacros -eq 2 -or $effectiveMacros -eq 0) {
                    Add-Finding -Category "Office Security" -Name "$app Macro Setting" -Risk "Low" `
                        -Description "$app macros disabled with notification (user can enable)" `
                        -Details "VBAWarnings: $effectiveMacros" `
                        -Recommendation "Consider requiring digital signatures for macros"
                }
                
                # Check for macro execution from internet (Block Macros from Internet)
                $blockInternet = Get-RegistryValue -Path $basePath -Name "blockcontentexecutionfrominternet" -Default 0
                $policyBlockInternet = Get-RegistryValue -Path $policyPath -Name "blockcontentexecutionfrominternet" -Default $null
                
                if (($policyBlockInternet -ne 1) -and ($blockInternet -ne 1)) {
                    Add-Finding -Category "Office Security" -Name "$app Internet Macros Not Blocked" -Risk "Medium" `
                        -Description "Macros from internet sources are not automatically blocked" `
                        -Details "blockcontentexecutionfrominternet not enabled" `
                        -Recommendation "Enable 'Block macros from running in Office files from the Internet'" `
                        -Reference "CVE-2022-30190 mitigation"
                }
                
                break  # Found this Office version, no need to check older ones for this app
            }
        }
    }
    
    # Check Protected View settings
    foreach ($ver in $officeVersions) {
        $pvPath = "HKCU:\SOFTWARE\Microsoft\Office\$($ver.Version)\Word\Security\ProtectedView"
        
        if (Test-RegistryPathExists $pvPath) {
            $disableInternet = Get-RegistryValue -Path $pvPath -Name "DisableInternetFilesInPV" -Default 0
            $disableAttachments = Get-RegistryValue -Path $pvPath -Name "DisableAttachmentsInPV" -Default 0
            $disableUnsafe = Get-RegistryValue -Path $pvPath -Name "DisableUnsafeLocationsInPV" -Default 0
            
            if ($disableInternet -eq 1 -or $disableAttachments -eq 1 -or $disableUnsafe -eq 1) {
                Add-Finding -Category "Office Security" -Name "Protected View Disabled" -Risk "Medium" `
                    -Description "One or more Protected View settings are disabled" `
                    -Details "Internet: $disableInternet, Attachments: $disableAttachments, Unsafe: $disableUnsafe (0=Protected, 1=Disabled)" `
                    -Recommendation "Enable all Protected View settings" `
                    -Reference "Office Security Baseline"
            }
            
            break
        }
    }
}

function Test-ExploitProtection {
    Write-AuditLog "Checking Windows Exploit Protection Settings..." -Level "INFO"
    
    try {
        $processSettings = Get-ProcessMitigation -System -ErrorAction Stop
        
        # Check DEP (Data Execution Prevention)
        if ($processSettings.DEP.Enable -eq "OFF") {
            Add-Finding -Category "Exploit Protection" -Name "DEP Disabled" -Risk "High" `
                -Description "Data Execution Prevention is disabled system-wide" `
                -Details "DEP: OFF" `
                -Recommendation "Enable DEP: Set-ProcessMitigation -System -Enable DEP" `
                -Reference "CIS Benchmark"
        } else {
            Add-Finding -Category "Exploit Protection" -Name "DEP Enabled" -Risk "Info" `
                -Description "Data Execution Prevention is enabled" `
                -Details "DEP: $($processSettings.DEP.Enable)"
        }
        
        # Check ASLR (Address Space Layout Randomization)
        if ($processSettings.ASLR.BottomUp -eq "OFF" -and $processSettings.ASLR.HighEntropy -eq "OFF") {
            Add-Finding -Category "Exploit Protection" -Name "ASLR Disabled" -Risk "High" `
                -Description "Address Space Layout Randomization is disabled" `
                -Details "BottomUp: $($processSettings.ASLR.BottomUp), HighEntropy: $($processSettings.ASLR.HighEntropy)" `
                -Recommendation "Enable ASLR for exploit mitigation" `
                -Reference "Windows Security Baseline"
        } elseif ($processSettings.ASLR.HighEntropy -eq "OFF") {
            Add-Finding -Category "Exploit Protection" -Name "High Entropy ASLR Disabled" -Risk "Medium" `
                -Description "High Entropy ASLR is not enabled" `
                -Details "HighEntropy: OFF" `
                -Recommendation "Enable High Entropy ASLR for better protection"
        } else {
            Add-Finding -Category "Exploit Protection" -Name "ASLR Enabled" -Risk "Info" `
                -Description "ASLR is enabled" `
                -Details "BottomUp: $($processSettings.ASLR.BottomUp), HighEntropy: $($processSettings.ASLR.HighEntropy)"
        }
        
        # Check CFG (Control Flow Guard)
        if ($processSettings.CFG.Enable -eq "OFF") {
            Add-Finding -Category "Exploit Protection" -Name "CFG Disabled" -Risk "Medium" `
                -Description "Control Flow Guard is disabled system-wide" `
                -Details "CFG: OFF" `
                -Recommendation "Enable CFG for control flow integrity protection"
        }
        
        # Check SEHOP
        if ($processSettings.SEHOP.Enable -eq "OFF") {
            Add-Finding -Category "Exploit Protection" -Name "SEHOP Disabled" -Risk "Medium" `
                -Description "SEHOP is disabled" `
                -Details "SEHOP: OFF" `
                -Recommendation "Enable SEHOP for SEH overwrite protection"
        }
        
    } catch {
        Add-Finding -Category "Exploit Protection" -Name "Exploit Protection Check Failed" -Risk "Info" `
            -Description "Could not check exploit protection settings" `
            -Details "Error: $_. May require Windows 10 1709+ or admin privileges."
    }
}

function Test-PowerShellSecurity {
    Write-AuditLog "Checking PowerShell Security Configuration..." -Level "INFO"
    
    # Check PowerShell execution policy
    try {
        $execPolicy = Get-ExecutionPolicy -List -ErrorAction Stop
        $machinePolicy = ($execPolicy | Where-Object { $_.Scope -eq 'MachinePolicy' }).ExecutionPolicy
        $userPolicy = ($execPolicy | Where-Object { $_.Scope -eq 'UserPolicy' }).ExecutionPolicy
        $effectivePolicy = Get-ExecutionPolicy
        
        if ($effectivePolicy -eq 'Unrestricted' -or $effectivePolicy -eq 'Bypass') {
            Add-Finding -Category "PowerShell Security" -Name "Weak Execution Policy" -Risk "Medium" `
                -Description "PowerShell execution policy is set to $effectivePolicy" `
                -Details "Effective: $effectivePolicy, Machine: $machinePolicy, User: $userPolicy" `
                -Recommendation "Set execution policy to RemoteSigned or AllSigned" `
                -Reference "Security Best Practice"
        } else {
            Add-Finding -Category "PowerShell Security" -Name "Execution Policy" -Risk "Info" `
                -Description "PowerShell execution policy is configured" `
                -Details "Effective: $effectivePolicy"
        }
    } catch { }
    
    # Check Constrained Language Mode
    $clm = $ExecutionContext.SessionState.LanguageMode
    if ($clm -eq 'ConstrainedLanguage') {
        Add-Finding -Category "PowerShell Security" -Name "Constrained Language Mode Active" -Risk "Info" `
            -Description "PowerShell is running in Constrained Language Mode" `
            -Details "LanguageMode: $clm"
    }
    
    # Check PowerShell transcription
    $transcription = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -Default 0
    $transcriptDir = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "OutputDirectory" -Default ""
    
    if ($transcription -eq 1) {
        Add-Finding -Category "PowerShell Security" -Name "PowerShell Transcription Enabled" -Risk "Info" `
            -Description "PowerShell transcription is enabled" `
            -Details "Output Directory: $transcriptDir"
    } else {
        Add-Finding -Category "PowerShell Security" -Name "PowerShell Transcription Disabled" -Risk "Low" `
            -Description "PowerShell transcription is not enabled" `
            -Details "EnableTranscripting: $transcription" `
            -Recommendation "Enable transcription for forensic logging"
    }
    
    # Check for PS Remoting restrictions (only if WinRM is already running to avoid starting it)
    $winrmSvc = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
    if ($winrmSvc -and $winrmSvc.Status -eq 'Running') {
        try {
            $psSessionConfig = Get-PSSessionConfiguration -Name Microsoft.PowerShell -ErrorAction Stop
            
            if ($psSessionConfig.Permission -match 'Everyone|Authenticated Users') {
                Add-Finding -Category "PowerShell Security" -Name "PS Remoting Broadly Accessible" -Risk "Medium" `
                    -Description "PowerShell remoting may be accessible to broad groups" `
                    -Details "Permission: $($psSessionConfig.Permission)" `
                    -Recommendation "Restrict PS Remoting access to specific admin groups"
            }
        } catch { }
    }
}

function Test-BrowserSecurity {
    Write-AuditLog "Checking Browser Security Settings..." -Level "INFO"
    
    # Check IE Enhanced Security Configuration
    $ieEsc = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{A509B1A7-37EF-4b3f-8CFC-4F3A74704073}" -Name "IsInstalled" -Default 0
    
    if ($ieEsc -eq 1) {
        Add-Finding -Category "Browser Security" -Name "IE Enhanced Security (Admin)" -Risk "Info" `
            -Description "IE Enhanced Security Configuration is enabled for Administrators" `
            -Details "IE ESC (Admin): Enabled"
    }
    
    # Check Edge SmartScreen
    $edgeSmartScreen = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name "SmartScreenEnabled" -Default $null
    
    if ($edgeSmartScreen -eq 0) {
        Add-Finding -Category "Browser Security" -Name "Edge SmartScreen Disabled" -Risk "Medium" `
            -Description "Microsoft Edge SmartScreen is disabled via policy" `
            -Details "SmartScreenEnabled: 0" `
            -Recommendation "Enable SmartScreen for phishing and malware protection"
    }
    
    # Check Chrome if installed
    $chromeInstalled = (Test-Path "C:\Program Files\Google\Chrome\Application\chrome.exe") -or (Test-Path "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe")
    
    if ($chromeInstalled) {
        $chromeSafeBrowsing = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -Name "SafeBrowsingProtectionLevel" -Default $null
        
        if ($chromeSafeBrowsing -eq 0) {
            Add-Finding -Category "Browser Security" -Name "Chrome Safe Browsing Disabled" -Risk "Medium" `
                -Description "Chrome Safe Browsing is disabled via policy" `
                -Details "SafeBrowsingProtectionLevel: 0" `
                -Recommendation "Enable Safe Browsing protection"
        }
        
        $chromeUpdates = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Google\Update" -Name "UpdateDefault" -Default $null
        
        if ($chromeUpdates -eq 0) {
            Add-Finding -Category "Browser Security" -Name "Chrome Auto-Update Disabled" -Risk "High" `
                -Description "Chrome automatic updates are disabled" `
                -Details "UpdateDefault: 0" `
                -Recommendation "Enable automatic updates for security patches"
        }
    }
    
    # Enumerate browser extensions across all user profiles
    Get-BrowserExtensions
}

function Get-BrowserExtensions {
    Write-AuditLog "Enumerating Browser Extensions..." -Level "INFO"
    
    $Script:BrowserExtensions = @()
    
    # Get all user profile directories
    $usersDir = "$env:SystemDrive\Users"
    $userProfiles = @()
    
    try {
        $userProfiles = Get-ChildItem -Path $usersDir -Directory -ErrorAction Stop | 
            Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }
    } catch {
        Write-AuditLog "Could not enumerate user profiles: $_" -Level "WARN"
        return
    }
    
    foreach ($profile in $userProfiles) {
        $userName = $profile.Name
        $profilePath = $profile.FullName
        
        # --- GOOGLE CHROME ---
        $chromeExtPath = Join-Path $profilePath "AppData\Local\Google\Chrome\User Data"
        if (Test-Path $chromeExtPath) {
            # Chrome can have multiple profiles (Default, Profile 1, Profile 2, etc.)
            $chromeProfiles = @()
            $defaultProfile = Join-Path $chromeExtPath "Default"
            if (Test-Path $defaultProfile) { $chromeProfiles += $defaultProfile }
            
            Get-ChildItem -Path $chromeExtPath -Directory -Filter "Profile *" -ErrorAction SilentlyContinue | 
                ForEach-Object { $chromeProfiles += $_.FullName }
            
            foreach ($cp in $chromeProfiles) {
                $cpName = Split-Path $cp -Leaf
                $extDir = Join-Path $cp "Extensions"
                if (Test-Path $extDir) {
                    Get-ChildItem -Path $extDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                        $extId = $_.Name
                        $extInfo = Get-ChromiumExtensionInfo -ExtensionPath $_.FullName -ExtensionId $extId
                        if ($extInfo) {
                            $Script:BrowserExtensions += [PSCustomObject]@{
                                Browser        = "Chrome"
                                UserProfile    = $userName
                                BrowserProfile = $cpName
                                ExtensionId    = $extId
                                Name           = $extInfo.Name
                                Version        = $extInfo.Version
                                Description    = $extInfo.Description
                                Enabled        = $extInfo.Enabled
                                InstallType    = $extInfo.InstallType
                            }
                        }
                    }
                }
            }
        }
        
        # --- MICROSOFT EDGE ---
        $edgeExtPath = Join-Path $profilePath "AppData\Local\Microsoft\Edge\User Data"
        if (Test-Path $edgeExtPath) {
            $edgeProfiles = @()
            $defaultProfile = Join-Path $edgeExtPath "Default"
            if (Test-Path $defaultProfile) { $edgeProfiles += $defaultProfile }
            
            Get-ChildItem -Path $edgeExtPath -Directory -Filter "Profile *" -ErrorAction SilentlyContinue | 
                ForEach-Object { $edgeProfiles += $_.FullName }
            
            foreach ($ep in $edgeProfiles) {
                $epName = Split-Path $ep -Leaf
                $extDir = Join-Path $ep "Extensions"
                if (Test-Path $extDir) {
                    Get-ChildItem -Path $extDir -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                        $extId = $_.Name
                        $extInfo = Get-ChromiumExtensionInfo -ExtensionPath $_.FullName -ExtensionId $extId
                        if ($extInfo) {
                            $Script:BrowserExtensions += [PSCustomObject]@{
                                Browser        = "Edge"
                                UserProfile    = $userName
                                BrowserProfile = $epName
                                ExtensionId    = $extId
                                Name           = $extInfo.Name
                                Version        = $extInfo.Version
                                Description    = $extInfo.Description
                                Enabled        = $extInfo.Enabled
                                InstallType    = $extInfo.InstallType
                            }
                        }
                    }
                }
            }
        }
        
        # --- MOZILLA FIREFOX ---
        $firefoxProfilesPath = Join-Path $profilePath "AppData\Roaming\Mozilla\Firefox\Profiles"
        if (Test-Path $firefoxProfilesPath) {
            Get-ChildItem -Path $firefoxProfilesPath -Directory -ErrorAction SilentlyContinue | ForEach-Object {
                $ffProfileName = $_.Name
                $ffProfilePath = $_.FullName
                
                # Firefox stores extensions in extensions.json
                $extensionsJson = Join-Path $ffProfilePath "extensions.json"
                if (Test-Path $extensionsJson) {
                    try {
                        $ffData = Get-Content -Path $extensionsJson -Raw -ErrorAction Stop | ConvertFrom-Json
                        
                        if ($ffData.addons) {
                            foreach ($addon in $ffData.addons) {
                                # Skip system/built-in addons and language packs
                                if ($addon.location -eq 'app-system-defaults' -or 
                                    $addon.location -eq 'app-builtin' -or
                                    $addon.type -eq 'locale' -or
                                    $addon.type -eq 'dictionary' -or
                                    ($addon.id -and $addon.id -match '^(langpack-|default-theme@|firefox-compact-)')) {
                                    continue
                                }
                                
                                $ffEnabled = -not $addon.userDisabled -and $addon.active
                                $ffInstallType = switch ($addon.location) {
                                    'app-profile' { 'User' }
                                    'app-system-share' { 'System' }
                                    'app-global' { 'Policy' }
                                    default { $addon.location }
                                }
                                
                                $Script:BrowserExtensions += [PSCustomObject]@{
                                    Browser        = "Firefox"
                                    UserProfile    = $userName
                                    BrowserProfile = $ffProfileName
                                    ExtensionId    = $addon.id
                                    Name           = $addon.defaultLocale.name
                                    Version        = $addon.version
                                    Description    = if ($addon.defaultLocale.description) { 
                                                        $addon.defaultLocale.description.Substring(0, [Math]::Min(150, $addon.defaultLocale.description.Length))
                                                     } else { "" }
                                    Enabled        = $ffEnabled
                                    InstallType    = $ffInstallType
                                }
                            }
                        }
                    } catch {
                        Write-AuditLog "Could not parse Firefox extensions for $userName/$ffProfileName : $_" -Level "WARN"
                    }
                }
                
                # Also check addons.json as a fallback for name resolution
                $addonsJson = Join-Path $ffProfilePath "addons.json"
                if ((Test-Path $addonsJson) -and -not (Test-Path $extensionsJson)) {
                    try {
                        $addonsData = Get-Content -Path $addonsJson -Raw -ErrorAction Stop | ConvertFrom-Json
                        if ($addonsData.addons) {
                            foreach ($addon in $addonsData.addons) {
                                if ($addon.type -ne 'extension') { continue }
                                
                                $Script:BrowserExtensions += [PSCustomObject]@{
                                    Browser        = "Firefox"
                                    UserProfile    = $userName
                                    BrowserProfile = $ffProfileName
                                    ExtensionId    = $addon.id
                                    Name           = $addon.name
                                    Version        = $addon.version
                                    Description    = ""
                                    Enabled        = $true
                                    InstallType    = "User"
                                }
                            }
                        }
                    } catch { }
                }
            }
        }
    }
    
    # Also check for policy-forced extensions (machine-wide)
    Get-PolicyForcedExtensions
    
    # Sort and report
    $Script:BrowserExtensions = $Script:BrowserExtensions | Sort-Object Browser, UserProfile, Name
    
    $totalExt = $Script:BrowserExtensions.Count
    $chromeCount = @($Script:BrowserExtensions | Where-Object { $_.Browser -eq 'Chrome' }).Count
    $edgeCount = @($Script:BrowserExtensions | Where-Object { $_.Browser -eq 'Edge' }).Count
    $firefoxCount = @($Script:BrowserExtensions | Where-Object { $_.Browser -eq 'Firefox' }).Count
    
    if ($totalExt -gt 0) {
        Add-Finding -Category "Browser Security" -Name "Browser Extensions Inventory" -Risk "Info" `
            -Description "Enumerated $totalExt browser extensions across all user profiles" `
            -Details "Chrome: $chromeCount, Edge: $edgeCount, Firefox: $firefoxCount"
    } else {
        Add-Finding -Category "Browser Security" -Name "Browser Extensions" -Risk "Info" `
            -Description "No browser extensions found or could not access browser profiles" `
            -Details "This may require running as admin to access all user profiles"
    }
}

function Get-ChromiumExtensionInfo {
    param(
        [string]$ExtensionPath,
        [string]$ExtensionId
    )
    
    # Skip the Temp directory
    if ($ExtensionId -eq 'Temp') { return $null }
    
    try {
        # Get the latest version folder
        $versionDirs = Get-ChildItem -Path $ExtensionPath -Directory -ErrorAction SilentlyContinue | 
            Sort-Object Name -Descending
        
        if (-not $versionDirs) { return $null }
        
        $latestVersion = $versionDirs[0]
        $manifestFile = Join-Path $latestVersion.FullName "manifest.json"
        
        if (-not (Test-Path $manifestFile)) { return $null }
        
        $manifest = Get-Content -Path $manifestFile -Raw -ErrorAction Stop | ConvertFrom-Json
        
        # Get extension name - may be a locale key like "__MSG_appName__"
        $extName = $manifest.name
        if ($extName -match '^__MSG_(.+)__$') {
            $msgKey = $Matches[1]
            # Try to resolve from _locales/en/messages.json
            $localeFile = Join-Path $latestVersion.FullName "_locales\en\messages.json"
            if (-not (Test-Path $localeFile)) {
                $localeFile = Join-Path $latestVersion.FullName "_locales\en_US\messages.json"
            }
            if (Test-Path $localeFile) {
                try {
                    $messages = Get-Content -Path $localeFile -Raw -ErrorAction Stop | ConvertFrom-Json
                    if ($messages.$msgKey.message) {
                        $extName = $messages.$msgKey.message
                    }
                } catch { }
            }
        }
        
        # Skip Chrome internal extensions
        if (-not $extName -or $extName -match '^__MSG_') { 
            # Use folder name or ID as fallback
            $extName = "[ID: $ExtensionId]"
        }
        
        $extDescription = ""
        if ($manifest.description) {
            $desc = $manifest.description
            if ($desc -notmatch '^__MSG_') {
                $extDescription = $desc.Substring(0, [Math]::Min(150, $desc.Length))
            }
        }
        
        # Determine install type
        $installType = "User"
        
        # Check Preferences/Secure Preferences for state (simplified)
        $enabled = $true
        
        return @{
            Name        = $extName
            Version     = $manifest.version
            Description = $extDescription
            Enabled     = $enabled
            InstallType = $installType
        }
    } catch {
        return $null
    }
}

function Get-PolicyForcedExtensions {
    # Check for GPO/policy-forced extensions
    
    # Chrome force-installed extensions
    $chromeForceInstall = "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallForcelist"
    if (Test-Path $chromeForceInstall) {
        try {
            $props = Get-ItemProperty -Path $chromeForceInstall -ErrorAction Stop
            $props.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object {
                $value = $_.Value
                $extId = ($value -split ';')[0]
                
                $Script:BrowserExtensions += [PSCustomObject]@{
                    Browser        = "Chrome"
                    UserProfile    = "POLICY"
                    BrowserProfile = "GPO"
                    ExtensionId    = $extId
                    Name           = "[Policy Forced: $extId]"
                    Version        = "N/A"
                    Description    = "Force-installed via Group Policy"
                    Enabled        = $true
                    InstallType    = "Policy"
                }
            }
        } catch { }
    }
    
    # Edge force-installed extensions
    $edgeForceInstall = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist"
    if (Test-Path $edgeForceInstall) {
        try {
            $props = Get-ItemProperty -Path $edgeForceInstall -ErrorAction Stop
            $props.PSObject.Properties | Where-Object { $_.Name -match '^\d+$' } | ForEach-Object {
                $value = $_.Value
                $extId = ($value -split ';')[0]
                
                $Script:BrowserExtensions += [PSCustomObject]@{
                    Browser        = "Edge"
                    UserProfile    = "POLICY"
                    BrowserProfile = "GPO"
                    ExtensionId    = $extId
                    Name           = "[Policy Forced: $extId]"
                    Version        = "N/A"
                    Description    = "Force-installed via Group Policy"
                    Enabled        = $true
                    InstallType    = "Policy"
                }
            }
        } catch { }
    }
    
    # Check for blocked extensions policy
    $chromeBlockList = "HKLM:\SOFTWARE\Policies\Google\Chrome\ExtensionInstallBlocklist"
    if (Test-Path $chromeBlockList) {
        try {
            $props = Get-ItemProperty -Path $chromeBlockList -ErrorAction Stop
            $blockAll = $props.PSObject.Properties | Where-Object { $_.Value -eq '*' }
            if ($blockAll) {
                Add-Finding -Category "Browser Security" -Name "Chrome Extension Allowlist Mode" -Risk "Info" `
                    -Description "Chrome is configured to block all extensions except those explicitly allowed" `
                    -Details "ExtensionInstallBlocklist contains '*' (block all)"
            }
        } catch { }
    }
    
    $edgeBlockList = "HKLM:\SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallBlocklist"
    if (Test-Path $edgeBlockList) {
        try {
            $props = Get-ItemProperty -Path $edgeBlockList -ErrorAction Stop
            $blockAll = $props.PSObject.Properties | Where-Object { $_.Value -eq '*' }
            if ($blockAll) {
                Add-Finding -Category "Browser Security" -Name "Edge Extension Allowlist Mode" -Risk "Info" `
                    -Description "Edge is configured to block all extensions except those explicitly allowed" `
                    -Details "ExtensionInstallBlocklist contains '*' (block all)"
            }
        } catch { }
    }
}

function Get-VSCodeExtensions {
    Write-AuditLog "Enumerating VS Code Extensions..." -Level "INFO"
    
    $Script:VSCodeExtensions = @()
    
    $usersDir = "$env:SystemDrive\Users"
    $userProfiles = @()
    
    try {
        $userProfiles = Get-ChildItem -Path $usersDir -Directory -ErrorAction Stop | 
            Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }
    } catch {
        Write-AuditLog "Could not enumerate user profiles for VS Code: $_" -Level "WARN"
        return
    }
    
    # VSCode variants and their extension paths
    $vsCodeVariants = @(
        @{ Name = "VS Code";         ExtDir = ".vscode\extensions" }
        @{ Name = "VS Code Insiders"; ExtDir = ".vscode-insiders\extensions" }
        @{ Name = "VSCodium";         ExtDir = ".vscode-oss\extensions" }
        @{ Name = "Cursor";           ExtDir = ".cursor\extensions" }
    )
    
    foreach ($profile in $userProfiles) {
        $userName = $profile.Name
        $profilePath = $profile.FullName
        
        foreach ($variant in $vsCodeVariants) {
            $extensionsDir = Join-Path $profilePath $variant.ExtDir
            
            if (-not (Test-Path $extensionsDir)) { continue }
            
            try {
                $extFolders = Get-ChildItem -Path $extensionsDir -Directory -ErrorAction SilentlyContinue |
                    Where-Object { $_.Name -ne '.obsolete' -and $_.Name -ne '.init-default-profile-extensions' }
                
                foreach ($extFolder in $extFolders) {
                    $packageJson = Join-Path $extFolder.FullName "package.json"
                    
                    $extName = $extFolder.Name
                    $extPublisher = ""
                    $extVersion = ""
                    $extDescription = ""
                    $extCategories = ""
                    
                    if (Test-Path $packageJson) {
                        try {
                            $pkg = Get-Content -Path $packageJson -Raw -ErrorAction Stop | ConvertFrom-Json
                            
                            if ($pkg.displayName) { $extName = $pkg.displayName }
                            elseif ($pkg.name) { $extName = $pkg.name }
                            
                            $extPublisher = if ($pkg.publisher) { $pkg.publisher } else { "" }
                            $extVersion = if ($pkg.version) { $pkg.version } else { "" }
                            
                            if ($pkg.description) {
                                $extDescription = $pkg.description
                                if ($extDescription.Length -gt 120) {
                                    $extDescription = $extDescription.Substring(0, 120) + "..."
                                }
                            }
                            
                            if ($pkg.categories) {
                                $extCategories = ($pkg.categories -join ", ")
                            }
                        } catch {
                            # Could not parse package.json, use folder name
                        }
                    }
                    
                    # Parse publisher.name-version from folder name as fallback
                    if (-not $extPublisher -and $extFolder.Name -match '^([^.]+)\.(.+)-(\d+\.\d+.*)$') {
                        $extPublisher = $Matches[1]
                        if (-not $extName -or $extName -eq $extFolder.Name) { $extName = $Matches[2] }
                        if (-not $extVersion) { $extVersion = $Matches[3] }
                    }
                    
                    # Build extension identifier
                    $extId = if ($extPublisher) { "$extPublisher.$($extFolder.Name -replace '^[^.]+\.' -replace '-[\d\.]+$')" } else { $extFolder.Name }
                    
                    $Script:VSCodeExtensions += [PSCustomObject]@{
                        Editor      = $variant.Name
                        UserProfile = $userName
                        FolderName  = $extFolder.Name
                        Name        = $extName
                        Publisher   = $extPublisher
                        Version     = $extVersion
                        Description = $extDescription
                        Categories  = $extCategories
                        ExtensionId = $extId
                        InstallType = "User"
                    }
                }
            } catch {
                Write-AuditLog "Error reading VS Code extensions at $extensionsDir : $_" -Level "WARN"
            }
        }
    }
    
    # Check machine-wide installations
    $machineWidePaths = @(
        @{ Path = "$env:ProgramFiles\Microsoft VS Code\resources\app\extensions"; Name = "VS Code"; Label = "Built-in" }
        @{ Path = "${env:ProgramFiles(x86)}\Microsoft VS Code\resources\app\extensions"; Name = "VS Code (x86)"; Label = "Built-in" }
        @{ Path = "$env:ProgramFiles\Microsoft VS Code Insiders\resources\app\extensions"; Name = "VS Code Insiders"; Label = "Built-in" }
    )
    
    foreach ($mw in $machineWidePaths) {
        if (-not (Test-Path $mw.Path)) { continue }
        
        try {
            $extFolders = Get-ChildItem -Path $mw.Path -Directory -ErrorAction SilentlyContinue
            
            foreach ($extFolder in $extFolders) {
                $packageJson = Join-Path $extFolder.FullName "package.json"
                
                $extName = $extFolder.Name
                $extPublisher = "Microsoft"
                $extVersion = ""
                $extDescription = ""
                $extCategories = ""
                
                if (Test-Path $packageJson) {
                    try {
                        $pkg = Get-Content -Path $packageJson -Raw -ErrorAction Stop | ConvertFrom-Json
                        
                        if ($pkg.displayName) { $extName = $pkg.displayName }
                        elseif ($pkg.name) { $extName = $pkg.name }
                        if ($pkg.publisher) { $extPublisher = $pkg.publisher }
                        if ($pkg.version) { $extVersion = $pkg.version }
                        if ($pkg.description) {
                            $extDescription = $pkg.description
                            if ($extDescription.Length -gt 120) {
                                $extDescription = $extDescription.Substring(0, 120) + "..."
                            }
                        }
                        if ($pkg.categories) { $extCategories = ($pkg.categories -join ", ") }
                    } catch { }
                }
                
                $Script:VSCodeExtensions += [PSCustomObject]@{
                    Editor      = $mw.Name
                    UserProfile = "MACHINE"
                    FolderName  = $extFolder.Name
                    Name        = $extName
                    Publisher   = $extPublisher
                    Version     = $extVersion
                    Description = $extDescription
                    Categories  = $extCategories
                    ExtensionId = "$extPublisher.$($extFolder.Name)"
                    InstallType = $mw.Label
                }
            }
        } catch { }
    }
    
    # Check for policy-managed extensions via registry
    $vscodePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\VSCode"
    if (Test-Path $vscodePolicyPath) {
        Add-Finding -Category "Application Security" -Name "VS Code Managed by Policy" -Risk "Info" `
            -Description "VS Code has Group Policy settings configured" `
            -Details "Policy path exists: $vscodePolicyPath"
    }
    
    # Sort results
    $Script:VSCodeExtensions = $Script:VSCodeExtensions | Sort-Object Editor, UserProfile, Name
    
    # Report findings
    $totalVSExt = $Script:VSCodeExtensions.Count
    $userInstalled = @($Script:VSCodeExtensions | Where-Object { $_.InstallType -eq 'User' }).Count
    $builtIn = @($Script:VSCodeExtensions | Where-Object { $_.InstallType -eq 'Built-in' }).Count
    
    if ($totalVSExt -gt 0) {
        # Check for potentially risky extensions
        $riskyPatterns = @(
            @{ Pattern = 'remote-ssh'; Risk = "Info"; Desc = "Enables remote SSH connections" }
            @{ Pattern = 'remote-tunnel'; Risk = "Info"; Desc = "Enables remote tunnel access" }
            @{ Pattern = 'live-share'; Risk = "Info"; Desc = "Enables live collaboration/sharing" }
            @{ Pattern = 'code-runner'; Risk = "Low"; Desc = "Can execute arbitrary code" }
            @{ Pattern = 'shell-launcher'; Risk = "Low"; Desc = "Can launch shell processes" }
        )
        
        foreach ($risky in $riskyPatterns) {
            $found = @($Script:VSCodeExtensions | Where-Object { 
                $_.FolderName -match $risky.Pattern -or $_.ExtensionId -match $risky.Pattern 
            })
            foreach ($f in $found) {
                Add-Finding -Category "Application Security" -Name "VS Code Extension: $($f.Name)" -Risk $risky.Risk `
                    -Description "$($risky.Desc) - verify if authorized" `
                    -Details "User: $($f.UserProfile), Extension: $($f.ExtensionId) v$($f.Version)" `
                    -Recommendation "Review if this VS Code extension is required and authorized"
            }
        }
        
        Add-Finding -Category "Application Security" -Name "VS Code Extensions Inventory" -Risk "Info" `
            -Description "Enumerated $totalVSExt VS Code extensions across all profiles" `
            -Details "User-installed: $userInstalled, Built-in: $builtIn"
    }
}

function Test-DNSSecurity {
    Write-AuditLog "Checking DNS Security Configuration..." -Level "INFO"
    
    # Check DNS-over-HTTPS
    $dohPolicy = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "DoHPolicy" -Default $null
    
    if ($dohPolicy -eq 3 -or $dohPolicy -eq 2) {
        Add-Finding -Category "DNS Security" -Name "DNS over HTTPS Enabled" -Risk "Info" `
            -Description "DNS over HTTPS is enabled" `
            -Details "DoHPolicy: $dohPolicy"
    }
    
    # Check DNS devolution
    $dnsDevolution = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "UseDomainNameDevolution" -Default 1
    
    if ($dnsDevolution -eq 1) {
        Add-Finding -Category "DNS Security" -Name "DNS Devolution Enabled" -Risk "Low" `
            -Description "DNS devolution is enabled - may leak internal domain names" `
            -Details "UseDomainNameDevolution: 1" `
            -Recommendation "Disable DNS devolution if not required"
    }
    
    # Check configured DNS servers
    try {
        $dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | 
            Where-Object { $_.ServerAddresses.Count -gt 0 } |
            Select-Object -ExpandProperty ServerAddresses -Unique
        
        $publicDns = @{
            "8.8.8.8" = "Google DNS"
            "1.1.1.1" = "Cloudflare DNS"
            "9.9.9.9" = "Quad9 DNS"
        }
        
        $usingPublicDns = $dnsServers | Where-Object { $publicDns.ContainsKey($_) }
        
        if ($usingPublicDns) {
            $dnsNames = ($usingPublicDns | ForEach-Object { "$_ ($($publicDns[$_]))" }) -join ", "
            Add-Finding -Category "DNS Security" -Name "Public DNS Servers" -Risk "Info" `
                -Description "System is using public DNS servers" `
                -Details "Public DNS: $dnsNames"
        }
    } catch { }
}

function Test-FileSystemPermissions {
    Write-AuditLog "Checking File System Security..." -Level "INFO"
    
    # Check for unattend.xml files
    $unattendPaths = @(
        "C:\unattend.xml",
        "C:\Windows\Panther\unattend.xml",
        "C:\Windows\Panther\Unattend\unattend.xml",
        "C:\Windows\System32\Sysprep\unattend.xml"
    )
    
    foreach ($path in $unattendPaths) {
        if (Test-Path $path) {
            Add-Finding -Category "File System" -Name "Unattend.xml Found" -Risk "Medium" `
                -Description "Unattend.xml file found - may contain credentials" `
                -Details "Path: $path" `
                -Recommendation "Remove or secure unattend.xml files after deployment"
        }
    }
    
    # Check for world-writable directories in PATH
    $pathDirs = $env:PATH -split ';' | Where-Object { $_ -and (Test-Path $_) }
    
    foreach ($dir in $pathDirs) {
        if ($dir -match '^C:\\Windows|^C:\\Program Files') { continue }
        
        try {
            $acl = Get-Acl -Path $dir -ErrorAction Stop
            
            foreach ($access in $acl.Access) {
                if ($access.IdentityReference -match 'Everyone' -and $access.FileSystemRights -match 'Write|Modify|FullControl') {
                    Add-Finding -Category "File System" -Name "World-Writable PATH Directory" -Risk "High" `
                        -Description "A directory in system PATH is writable by Everyone" `
                        -Details "Path: $dir" `
                        -Recommendation "Remove Everyone write access from PATH directories"
                    break
                }
            }
        } catch { }
    }
}

function Test-UserRightsAssignments {
    Write-AuditLog "Checking User Rights Assignments..." -Level "INFO"
    
    try {
        $tempFile = [System.IO.Path]::GetTempFileName()
        $null = secedit /export /cfg $tempFile /areas USER_RIGHTS 2>&1
        
        if (Test-Path $tempFile) {
            $content = Get-Content $tempFile -Raw
            
            # Check for dangerous rights
            if ($content -match "SeDebugPrivilege\s*=\s*(.+)") {
                $assigned = $Matches[1].Trim()
                if ($assigned -match '\*S-1-1-0|\*S-1-5-11|Everyone|Authenticated Users') {
                    Add-Finding -Category "User Rights" -Name "Debug Programs Right Broadly Assigned" -Risk "High" `
                        -Description "SeDebugPrivilege assigned to broad group" `
                        -Details "Assigned to: $assigned" `
                        -Recommendation "Restrict to Administrators only" `
                        -Reference "CIS Benchmark 2.2"
                }
            }
            
            if ($content -match "SeTcbPrivilege\s*=\s*(.+)") {
                $assigned = $Matches[1].Trim()
                if ($assigned.Length -gt 0) {
                    Add-Finding -Category "User Rights" -Name "Act as Part of OS Assigned" -Risk "Critical" `
                        -Description "SeTcbPrivilege is assigned - rarely needed" `
                        -Details "Assigned to: $assigned" `
                        -Recommendation "Remove unless specifically required"
                }
            }
            
            Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
        }
    } catch {
        Add-Finding -Category "User Rights" -Name "Rights Check Failed" -Risk "Info" `
            -Description "Could not check user rights assignments" `
            -Details "Requires elevated privileges"
    }
}

function Test-TimeSynchronization {
    Write-AuditLog "Checking Time Synchronization..." -Level "INFO"
    
    $w32timeSvc = Get-Service -Name "W32Time" -ErrorAction SilentlyContinue
    
    if ($w32timeSvc.Status -ne 'Running') {
        Add-Finding -Category "Time Sync" -Name "Windows Time Service Not Running" -Risk "Medium" `
            -Description "Windows Time service is not running" `
            -Details "Service Status: $($w32timeSvc.Status)" `
            -Recommendation "Enable Windows Time service for accurate time synchronization"
    }
    
    $ntpServer = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "NtpServer" -Default ""
    $ntpType = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Services\W32Time\Parameters" -Name "Type" -Default ""
    
    if ([string]::IsNullOrEmpty($ntpServer) -or $ntpType -eq "NoSync") {
        Add-Finding -Category "Time Sync" -Name "NTP Not Configured" -Risk "Medium" `
            -Description "NTP time synchronization is not properly configured" `
            -Details "NtpServer: $ntpServer, Type: $ntpType" `
            -Recommendation "Configure NTP synchronization with reliable time servers"
    } else {
        Add-Finding -Category "Time Sync" -Name "NTP Configuration" -Risk "Info" `
            -Description "NTP is configured" `
            -Details "Server: $ntpServer"
    }
}

function Test-GroupMemberships {
    Write-AuditLog "Checking Privileged Group Memberships..." -Level "INFO"
    
    $privilegedGroups = @(
        @{ Name = "Remote Desktop Users"; Risk = "Medium" }
        @{ Name = "Remote Management Users"; Risk = "Medium" }
        @{ Name = "Backup Operators"; Risk = "Medium" }
        @{ Name = "Hyper-V Administrators"; Risk = "High" }
    )
    
    foreach ($group in $privilegedGroups) {
        try {
            $members = Get-LocalGroupMember -Group $group.Name -ErrorAction Stop
            $memberCount = @($members).Count
            
            if ($memberCount -gt 0) {
                $memberNames = ($members.Name | Select-Object -First 5) -join ", "
                if ($memberCount -gt 5) { $memberNames += "... (+$($memberCount - 5) more)" }
                
                Add-Finding -Category "Group Memberships" -Name "$($group.Name) Group" -Risk "Info" `
                    -Description "Members of $($group.Name) group" `
                    -Details "Member count: $memberCount`nMembers: $memberNames" `
                    -Recommendation "Review membership and apply least privilege"
            }
        } catch { }
    }
}

function Test-DMAProtection {
    Write-AuditLog "Checking DMA Protection Settings..." -Level "INFO"
    
    $blDmaProtection = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\FVE" -Name "DisableExternalDMAUnderLock" -Default $null
    
    if ($blDmaProtection -ne 1) {
        try {
            $tbControllers = Get-PnpDevice -Class "Thunderbolt" -ErrorAction SilentlyContinue
            if ($tbControllers) {
                Add-Finding -Category "DMA Protection" -Name "Thunderbolt DMA Protection" -Risk "Medium" `
                    -Description "Thunderbolt detected but DMA protection may not be fully enabled" `
                    -Details "DisableExternalDMAUnderLock not set to 1" `
                    -Recommendation "Enable Kernel DMA Protection in BIOS and Windows"
            }
        } catch { }
    } else {
        Add-Finding -Category "DMA Protection" -Name "DMA Protection Enabled" -Risk "Info" `
            -Description "DMA protection is configured" `
            -Details "DisableExternalDMAUnderLock: 1"
    }
}

function Test-HotfixStatus {
    Write-AuditLog "Checking Patch Installation History..." -Level "INFO"
    
    $Script:PatchHistory = @()
    
    # Source 1: Get-HotFix (WMI Win32_QuickFixEngineering)
    try {
        $hotfixes = Get-HotFix -ErrorAction Stop
        foreach ($hf in $hotfixes) {
            $installedDate = $null
            if ($hf.InstalledOn) {
                try { $installedDate = [DateTime]$hf.InstalledOn } catch { }
            }
            
            $Script:PatchHistory += [PSCustomObject]@{
                KBArticle    = $hf.HotFixID
                Title        = $hf.Description
                InstalledOn  = $installedDate
                Type         = $hf.Description
                Result       = "Installed"
                Source       = "WMI"
                SupportUrl   = $hf.Caption
                InstalledBy  = $hf.InstalledBy
            }
        }
    } catch {
        Write-AuditLog "Get-HotFix failed: $_" -Level "WARN"
    }
    
    # Source 2: Windows Update session history (COM object - much richer data)
    try {
        $updateSession = New-Object -ComObject Microsoft.Update.Session -ErrorAction Stop
        $updateSearcher = $updateSession.CreateUpdateSearcher()
        $historyCount = $updateSearcher.GetTotalHistoryCount()
        
        if ($historyCount -gt 0) {
            # Cap at 500 to avoid excessive processing
            $maxRecords = [Math]::Min($historyCount, 500)
            $history = $updateSearcher.QueryHistory(0, $maxRecords)
            
            for ($i = 0; $i -lt $history.Count; $i++) {
                $entry = $history.Item($i)
                
                # Skip null/empty entries
                if (-not $entry.Title) { continue }
                
                # Extract KB number from title
                $kb = ""
                if ($entry.Title -match '(KB\d+)') {
                    $kb = $Matches[1]
                }
                
                $resultCode = switch ($entry.ResultCode) {
                    0 { "Not Started" }
                    1 { "In Progress" }
                    2 { "Succeeded" }
                    3 { "Succeeded With Errors" }
                    4 { "Failed" }
                    5 { "Aborted" }
                    default { "Unknown ($($entry.ResultCode))" }
                }
                
                $updateType = switch ($entry.Operation) {
                    1 { "Installation" }
                    2 { "Uninstallation" }
                    3 { "Other" }
                    default { "Unknown" }
                }
                
                # Categorise the update
                $category = "Other"
                $title = $entry.Title
                if ($title -match 'Security|Critical') { $category = "Security" }
                elseif ($title -match 'Cumulative Update|Feature Update') { $category = "Cumulative" }
                elseif ($title -match 'Service Stack') { $category = "Servicing Stack" }
                elseif ($title -match '\.NET Framework') { $category = ".NET" }
                elseif ($title -match 'Definition Update|Security Intelligence') { $category = "Defender Definitions" }
                elseif ($title -match 'Driver|driver') { $category = "Driver" }
                elseif ($title -match 'Malicious Software Removal') { $category = "MSRT" }
                elseif ($title -match 'Preview') { $category = "Preview" }
                elseif ($title -match 'Office|Microsoft 365') { $category = "Office" }
                
                $installedDate = $null
                if ($entry.Date) {
                    try { $installedDate = [DateTime]$entry.Date } catch { }
                }
                
                $Script:PatchHistory += [PSCustomObject]@{
                    KBArticle    = $kb
                    Title        = $title
                    InstalledOn  = $installedDate
                    Type         = $category
                    Result       = $resultCode
                    Source       = "WU-$updateType"
                    SupportUrl   = if ($entry.SupportUrl) { $entry.SupportUrl } else { "" }
                    InstalledBy  = ""
                }
            }
        }
    } catch {
        Write-AuditLog "Windows Update COM history failed: $_" -Level "WARN"
    }
    
    # Source 3: CBS (Component Based Servicing) log packages for additional data
    $cbsRegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
    if (Test-Path $cbsRegPath) {
        try {
            $cbsPackages = Get-ChildItem -Path $cbsRegPath -ErrorAction SilentlyContinue | 
                Where-Object { $_.PSChildName -match 'KB\d+' } |
                Select-Object -First 200
            
            foreach ($pkg in $cbsPackages) {
                $pkgName = $pkg.PSChildName
                if ($pkgName -match '(KB\d+)') {
                    $kb = $Matches[1]
                    # Only add if not already present from other sources
                    $exists = $Script:PatchHistory | Where-Object { $_.KBArticle -eq $kb -and $_.Source -ne 'CBS' } | Select-Object -First 1
                    if (-not $exists) {
                        $installDate = $null
                        try {
                            $installClient = Get-ItemProperty -Path $pkg.PSPath -Name "InstallTimeHigh" -ErrorAction SilentlyContinue
                        } catch { }
                        
                        $currentState = Get-ItemProperty -Path $pkg.PSPath -Name "CurrentState" -ErrorAction SilentlyContinue
                        $stateDesc = switch ($currentState.CurrentState) {
                            0 { "Absent" }
                            5 { "Uninstall Pending" }
                            16 { "Resolving" }
                            32 { "Resolved" }
                            48 { "Staging" }
                            64 { "Staged" }
                            80 { "Superseded" }
                            96 { "Install Pending" }
                            112 { "Installed" }
                            default { "State $($currentState.CurrentState)" }
                        }
                        
                        $Script:PatchHistory += [PSCustomObject]@{
                            KBArticle    = $kb
                            Title        = $pkgName
                            InstalledOn  = $installDate
                            Type         = "CBS Package"
                            Result       = $stateDesc
                            Source       = "CBS"
                            SupportUrl   = ""
                            InstalledBy  = ""
                        }
                    }
                }
            }
        } catch {
            Write-AuditLog "CBS package enumeration failed: $_" -Level "WARN"
        }
    }
    
    # Deduplicate: prefer WU entries over WMI, prefer entries with dates
    # Sort priority: WU first, then WMI, then CBS; entries with dates before those without
    $sortedPatches = $Script:PatchHistory | ForEach-Object {
        $sourcePriority = if ($_.Source -match '^WU') { 0 } elseif ($_.Source -eq 'WMI') { 1 } else { 2 }
        $datePriority = if ($_.InstalledOn) { 0 } else { 1 }
        $_ | Add-Member -NotePropertyName _SrcPri -NotePropertyValue $sourcePriority -PassThru |
             Add-Member -NotePropertyName _DatePri -NotePropertyValue $datePriority -PassThru
    } | Sort-Object _SrcPri, _DatePri
    
    $deduped = @{}
    $seenKBs = @{}
    foreach ($patch in $sortedPatches) {
        # If we already have this KB from a better source, skip
        if ($patch.KBArticle -and $seenKBs.ContainsKey($patch.KBArticle)) { continue }
        
        $key = "$($patch.KBArticle)|$($patch.Title)|$($patch.Source)"
        if (-not $deduped.ContainsKey($key)) {
            $deduped[$key] = $patch
            if ($patch.KBArticle) { $seenKBs[$patch.KBArticle] = $true }
        }
    }
    $Script:PatchHistory = @($deduped.Values | Sort-Object InstalledOn -Descending)
    
    # Generate findings
    $totalPatches = $Script:PatchHistory.Count
    $successPatches = @($Script:PatchHistory | Where-Object { $_.Result -match 'Succeeded|Installed' }).Count
    $failedPatches = @($Script:PatchHistory | Where-Object { $_.Result -eq 'Failed' })
    $securityPatches = @($Script:PatchHistory | Where-Object { $_.Type -eq 'Security' -and $_.Result -match 'Succeeded|Installed' }).Count
    
    # Find most recent successful non-definition patch
    $recentNonDef = $Script:PatchHistory | Where-Object { 
        $_.InstalledOn -and $_.Result -match 'Succeeded|Installed' -and $_.Type -notin @('Defender Definitions', 'MSRT') 
    } | Select-Object -First 1
    
    $daysSincePatch = if ($recentNonDef -and $recentNonDef.InstalledOn) { 
        ((Get-Date) - $recentNonDef.InstalledOn).Days 
    } else { $null }
    
    Add-Finding -Category "Patch History" -Name "Patch Installation Summary" -Risk "Info" `
        -Description "Windows Update installation history" `
        -Details "Total records: $totalPatches`nSuccessful: $successPatches`nSecurity patches: $securityPatches$(if ($daysSincePatch -ne $null) { "`nDays since last non-definition patch: $daysSincePatch" })"
    
    if ($failedPatches.Count -gt 0) {
        $failedList = ($failedPatches | Select-Object -First 10 | ForEach-Object { 
            "$($_.KBArticle) - $($_.Title)" -replace '(.{80}).+', '$1...'
        }) -join "`n"
        
        $risk = if ($failedPatches.Count -ge 5) { "High" } else { "Medium" }
        Add-Finding -Category "Patch History" -Name "Failed Update Installations" -Risk $risk `
            -Description "$($failedPatches.Count) Windows Updates failed to install" `
            -Details "Failed updates (first 10):`n$failedList" `
            -Recommendation "Investigate and resolve failed Windows Update installations" `
            -Reference "Cyber Essentials: Patch Management"
    }
    
    if ($daysSincePatch -and $daysSincePatch -gt 60) {
        Add-Finding -Category "Patch History" -Name "Stale Patch Installation" -Risk "High" `
            -Description "No non-definition patches installed in $daysSincePatch days" `
            -Details "Last patch: $($recentNonDef.KBArticle) on $($recentNonDef.InstalledOn.ToString('yyyy-MM-dd'))" `
            -Recommendation "Check Windows Update and apply pending patches" `
            -Reference "Cyber Essentials: Patch Management"
    }
}

function Test-RegistryPermissions {
    Write-AuditLog "Checking Registry Security..." -Level "INFO"
    
    $autorunKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($keyPath in $autorunKeys) {
        try {
            $acl = Get-Acl -Path $keyPath -ErrorAction Stop
            
            foreach ($access in $acl.Access) {
                if ($access.IdentityReference -match 'BUILTIN\\Users' -and $access.RegistryRights -match 'SetValue|FullControl') {
                    Add-Finding -Category "Registry Security" -Name "Writable AutoRun Key" -Risk "High" `
                        -Description "AutoRun registry key is writable by Users group" `
                        -Details "Key: $keyPath" `
                        -Recommendation "Remove write permissions for Users group"
                }
            }
        } catch { }
    }
}

function Test-ShadowCopies {
    Write-AuditLog "Checking Volume Shadow Copies..." -Level "INFO"
    
    try {
        $shadows = Get-CimInstance -ClassName Win32_ShadowCopy -ErrorAction Stop
        
        if ($shadows) {
            $shadowCount = @($shadows).Count
            Add-Finding -Category "Backup/Recovery" -Name "Shadow Copies Available" -Risk "Info" `
                -Description "Volume Shadow Copies are available" `
                -Details "Shadow copy count: $shadowCount"
        } else {
            Add-Finding -Category "Backup/Recovery" -Name "No Shadow Copies" -Risk "Low" `
                -Description "No Volume Shadow Copies found" `
                -Details "Shadow copies can help recover from ransomware" `
                -Recommendation "Consider enabling System Protection"
        }
    } catch { }
    
    $srDisabled = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore" -Name "DisableSR" -Default 0
    
    if ($srDisabled -eq 1) {
        Add-Finding -Category "Backup/Recovery" -Name "System Restore Disabled" -Risk "Low" `
            -Description "System Restore is disabled by policy" `
            -Details "DisableSR: 1" `
            -Recommendation "Consider enabling System Restore"
    }
}

function Test-DriverSigning {
    Write-AuditLog "Checking Driver Signing Configuration..." -Level "INFO"
    
    try {
        $bcdeditOutput = bcdedit /enum "{current}" 2>&1
        
        if ($bcdeditOutput -match "testsigning\s+Yes") {
            Add-Finding -Category "Driver Security" -Name "Test Signing Enabled" -Risk "High" `
                -Description "Windows test signing mode is enabled" `
                -Details "Test signing allows unsigned drivers" `
                -Recommendation "Disable test signing: bcdedit /set testsigning off"
        }
        
        if ($bcdeditOutput -match "nointegritychecks\s+Yes") {
            Add-Finding -Category "Driver Security" -Name "Integrity Checks Disabled" -Risk "Critical" `
                -Description "Driver integrity checks are disabled" `
                -Details "nointegritychecks is set to Yes" `
                -Recommendation "Enable integrity checks: bcdedit /set nointegritychecks off"
        }
    } catch { }
}

function Test-WindowsSubsystems {
    Write-AuditLog "Checking Windows Subsystems..." -Level "INFO"
    
    # Check WSL
    try {
        $wsl = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Windows-Subsystem-Linux" -ErrorAction SilentlyContinue
        
        if ($wsl.State -eq "Enabled") {
            Add-Finding -Category "Windows Subsystems" -Name "WSL Enabled" -Risk "Info" `
                -Description "Windows Subsystem for Linux is enabled" `
                -Details "May provide additional attack surface" `
                -Recommendation "Disable if not required"
        }
    } catch { }
    
    # Check Hyper-V
    try {
        $hyperv = Get-WindowsOptionalFeature -Online -FeatureName "Microsoft-Hyper-V" -ErrorAction SilentlyContinue
        
        if ($hyperv.State -eq "Enabled") {
            Add-Finding -Category "Windows Subsystems" -Name "Hyper-V Enabled" -Risk "Info" `
                -Description "Hyper-V is enabled" `
                -Details "Virtualization platform is active" `
                -Recommendation "Ensure Hyper-V admin access is properly restricted"
        }
    } catch { }
    
    # Check IIS
    try {
        $iis = Get-WindowsOptionalFeature -Online -FeatureName "IIS-WebServer" -ErrorAction SilentlyContinue
        
        if ($iis.State -eq "Enabled") {
            Add-Finding -Category "Windows Subsystems" -Name "IIS Web Server Enabled" -Risk "Info" `
                -Description "Internet Information Services is enabled" `
                -Details "Web server is installed" `
                -Recommendation "Apply IIS security hardening"
        }
    } catch { }
}

function Test-TelemetryPrivacy {
    Write-AuditLog "Checking Telemetry and Privacy Settings..." -Level "INFO"
    
    # Check Windows Telemetry Level
    $telemetryLevel = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Default $null
    
    if ($null -eq $telemetryLevel) {
        $telemetryLevel = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection" -Name "AllowTelemetry" -Default 3
    }
    
    $levelDesc = switch ($telemetryLevel) {
        0 { "Security (Enterprise only)" }
        1 { "Basic" }
        2 { "Enhanced" }
        3 { "Full" }
        default { "Unknown ($telemetryLevel)" }
    }
    
    if ($telemetryLevel -ge 3) {
        Add-Finding -Category "Privacy" -Name "Full Telemetry Enabled" -Risk "Low" `
            -Description "Windows telemetry is set to Full" `
            -Details "AllowTelemetry: $telemetryLevel ($levelDesc)" `
            -Recommendation "Consider reducing telemetry level for privacy"
    } else {
        Add-Finding -Category "Privacy" -Name "Telemetry Level" -Risk "Info" `
            -Description "Windows telemetry level is configured" `
            -Details "AllowTelemetry: $telemetryLevel ($levelDesc)"
    }
    
    # Check Cortana
    $cortanaEnabled = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search" -Name "AllowCortana" -Default 1
    
    if ($cortanaEnabled -eq 1) {
        Add-Finding -Category "Privacy" -Name "Cortana Enabled" -Risk "Info" `
            -Description "Cortana is enabled" `
            -Details "AllowCortana: 1" `
            -Recommendation "Consider disabling for privacy/security"
    }
    
    # Check Activity History
    $activityHistory = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\System" -Name "PublishUserActivities" -Default 1
    
    if ($activityHistory -eq 1) {
        Add-Finding -Category "Privacy" -Name "Activity History Enabled" -Risk "Info" `
            -Description "Windows Activity History is enabled" `
            -Details "PublishUserActivities: 1"
    }
    
    # Check Error Reporting
    $werDisabled = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" -Name "Disabled" -Default 0
    
    if ($werDisabled -eq 0) {
        Add-Finding -Category "Privacy" -Name "Error Reporting Enabled" -Risk "Info" `
            -Description "Windows Error Reporting is enabled" `
            -Details "Error reports may contain sensitive data"
    }
}

function Test-SystemToolAccess {
    Write-AuditLog "Checking System Tool Access for Low-Privileged Users..." -Level "INFO"
    
    # LOLBins - Living Off The Land Binaries that can be abused for execution, download, or bypass
    $lolbins = @(
        @{ Name = "certutil.exe";    Risk = "High";   Reason = "Can download files, encode/decode, and bypass application controls" }
        @{ Name = "mshta.exe";       Risk = "High";   Reason = "Executes HTA files containing scripts - common initial access vector" }
        @{ Name = "msbuild.exe";     Risk = "High";   Reason = "Can compile and execute arbitrary C# code inline from project files" }
        @{ Name = "regsvr32.exe";    Risk = "Medium"; Reason = "Can load remote scriptlets (SCT) to bypass AppLocker" }
        @{ Name = "rundll32.exe";    Risk = "Medium"; Reason = "Can execute DLL exports and JavaScript via advpack" }
        @{ Name = "cscript.exe";     Risk = "Medium"; Reason = "Windows Script Host - executes VBScript/JScript" }
        @{ Name = "wscript.exe";     Risk = "Medium"; Reason = "Windows Script Host GUI - executes VBScript/JScript" }
        @{ Name = "bitsadmin.exe";   Risk = "Medium"; Reason = "Can download files and create persistent jobs" }
        @{ Name = "certreq.exe";     Risk = "Medium"; Reason = "Can download files via certificate enrollment" }
        @{ Name = "esentutl.exe";    Risk = "Low";    Reason = "Can copy locked files (SAM, NTDS.dit)" }
        @{ Name = "expand.exe";      Risk = "Low";    Reason = "Can extract CAB files, used for payload staging" }
        @{ Name = "extrac32.exe";    Risk = "Low";    Reason = "Can extract CAB files, used for payload staging" }
        @{ Name = "findstr.exe";     Risk = "Low";    Reason = "Can download files via SMB UNC paths" }
        @{ Name = "hh.exe";          Risk = "Medium"; Reason = "HTML Help - can execute scripts from CHM files" }
        @{ Name = "installutil.exe"; Risk = "High";   Reason = "Can execute arbitrary code via .NET assembly uninstall methods" }
        @{ Name = "msconfig.exe";    Risk = "Low";    Reason = "Can be used to access system configuration and startup items" }
        @{ Name = "msiexec.exe";     Risk = "Medium"; Reason = "Can install remote MSI packages including malicious ones" }
        @{ Name = "nltest.exe";      Risk = "Medium"; Reason = "Domain trust enumeration tool useful for reconnaissance" }
        @{ Name = "presentationhost.exe"; Risk = "Medium"; Reason = "Can execute XAML browser applications (XBAPs)" }
        @{ Name = "reg.exe";         Risk = "Low";    Reason = "Can export registry hives including SAM for offline cracking" }
        @{ Name = "sc.exe";          Risk = "Medium"; Reason = "Service control - can create/modify services if permissions allow" }
        @{ Name = "schtasks.exe";    Risk = "Medium"; Reason = "Can create scheduled tasks for persistence" }
    )
    
    $accessible = @()
    $highRiskAccessible = @()
    
    foreach ($tool in $lolbins) {
        $paths = @()
        # Check common locations
        $sysPath = Join-Path $env:SystemRoot "System32\$($tool.Name)"
        $sysWow = Join-Path $env:SystemRoot "SysWOW64\$($tool.Name)"
        
        if (Test-Path $sysPath) { $paths += $sysPath }
        if (Test-Path $sysWow) { $paths += $sysWow }
        
        # For .NET tools, check framework dirs
        if ($tool.Name -in @("msbuild.exe", "installutil.exe")) {
            $fwPaths = @(
                "$env:SystemRoot\Microsoft.NET\Framework\v4.0.30319\$($tool.Name)",
                "$env:SystemRoot\Microsoft.NET\Framework64\v4.0.30319\$($tool.Name)"
            )
            foreach ($fp in $fwPaths) {
                if (Test-Path $fp) { $paths += $fp }
            }
        }
        
        foreach ($toolPath in $paths) {
            try {
                $acl = Get-Acl -Path $toolPath -ErrorAction SilentlyContinue
                if ($acl) {
                    # Check if Users or Everyone can execute
                    $canExecute = $false
                    foreach ($access in $acl.Access) {
                        if ($access.IdentityReference -match 'BUILTIN\\Users|Everyone|Authenticated Users' -and
                            $access.FileSystemRights -match 'ReadAndExecute|FullControl' -and
                            $access.AccessControlType -eq 'Allow') {
                            $canExecute = $true
                            break
                        }
                    }
                    
                    if ($canExecute) {
                        $accessible += [PSCustomObject]@{
                            Name   = $tool.Name
                            Path   = $toolPath
                            Risk   = $tool.Risk
                            Reason = $tool.Reason
                        }
                        if ($tool.Risk -eq "High") {
                            $highRiskAccessible += $tool.Name
                        }
                    }
                }
            } catch { }
        }
    }
    
    if ($highRiskAccessible.Count -gt 0) {
        $uniqueHigh = $highRiskAccessible | Select-Object -Unique
        Add-Finding -Category "System Tool Access" -Name "High-Risk LOLBins Accessible" -Risk "Medium" `
            -Description "$($uniqueHigh.Count) high-risk Living Off The Land Binaries are accessible to standard users" `
            -Details "Accessible high-risk tools:`n$(($uniqueHigh | ForEach-Object { "  $_ - $(($accessible | Where-Object { $_.Name -eq $_ } | Select-Object -First 1).Reason)" }) -join "`n")" `
            -Recommendation "Consider using AppLocker or WDAC to block execution of unnecessary LOLBins for standard users. High-priority targets: certutil, mshta, msbuild, installutil." `
            -Reference "LOLBAS Project - https://lolbas-project.github.io/"
    }
    
    $totalAccessible = ($accessible | Select-Object -ExpandProperty Name -Unique).Count
    Add-Finding -Category "System Tool Access" -Name "LOLBin Inventory" -Risk "Info" `
        -Description "Living Off The Land Binary accessibility assessment" `
        -Details "Total LOLBins checked: $($lolbins.Count)`nAccessible to standard users: $totalAccessible`nHigh risk accessible: $(($highRiskAccessible | Select-Object -Unique).Count)"
    
    # Check if AppLocker or WDAC is providing any mitigation
    $appLockerSvc = Get-Service -Name "AppIDSvc" -ErrorAction SilentlyContinue
    $wdacEnforced = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\CI" -Name "UMCIAuditMode" -Default $null
    
    if ((-not $appLockerSvc -or $appLockerSvc.Status -ne 'Running') -and $null -eq $wdacEnforced) {
        if ($highRiskAccessible.Count -gt 0) {
            Add-Finding -Category "System Tool Access" -Name "No Application Control Active" -Risk "Medium" `
                -Description "Neither AppLocker nor WDAC appears active - LOLBins are unrestricted" `
                -Details "AppLocker service: $(if ($appLockerSvc) { $appLockerSvc.Status } else { 'Not found' })`nWDAC: Not detected" `
                -Recommendation "Deploy AppLocker or WDAC to restrict execution of unnecessary system tools"
        }
    }
}

function Test-WindowsRecall {
    Write-AuditLog "Checking Windows Recall / AI Settings..." -Level "INFO"
    
    # Windows Recall takes periodic screenshots and uses AI to make them searchable
    # Significant privacy and security concern - screenshots can capture passwords, sensitive data
    
    $recallFindings = @()
    
    # Check if Recall feature is present (Windows 11 24H2+ Copilot+ PCs)
    $recallAppPath = "$env:ProgramFiles\WindowsApps"
    $recallPresent = $false
    
    if (Test-Path $recallAppPath) {
        try {
            $recallPkg = Get-ChildItem -Path $recallAppPath -Filter "*Recall*" -Directory -ErrorAction SilentlyContinue
            if ($recallPkg) { $recallPresent = $true }
        } catch { }
    }
    
    # Check via registry - multiple possible locations
    $recallEnabled = Get-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Recall" -Name "Enabled" -Default $null
    $recallDisabledPolicy = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "DisableAIDataAnalysis" -Default 0
    $turnOffSavingSnapshots = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "TurnOffSavingSnapshots" -Default $null
    
    # Check the user-level setting
    $recallUserDisabled = Get-RegistryValue -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Recall" -Name "DisableRecall" -Default $null
    
    # Check for Recall database presence (indicates it has been active)
    $recallDbPaths = @()
    $userProfiles = Get-ChildItem -Path "C:\Users" -Directory -ErrorAction SilentlyContinue | Where-Object { $_.Name -notin @('Public', 'Default', 'Default User', 'All Users') }
    foreach ($profile in $userProfiles) {
        $dbPath = Join-Path $profile.FullName "AppData\Local\CoreAIPlatform.00\UKP"
        if (Test-Path $dbPath) {
            $recallDbPaths += "$($profile.Name): $dbPath"
        }
    }
    
    # Also check for the Recall settings in newer builds
    $screenCapture = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI" -Name "AllowRecallEnablement" -Default $null
    
    if ($recallDisabledPolicy -eq 1 -or $turnOffSavingSnapshots -eq 1) {
        Add-Finding -Category "Privacy" -Name "Windows Recall Disabled by Policy" -Risk "Info" `
            -Description "Windows Recall / AI screenshot capture is disabled via Group Policy" `
            -Details "DisableAIDataAnalysis: $recallDisabledPolicy`nTurnOffSavingSnapshots: $turnOffSavingSnapshots"
    } elseif ($screenCapture -eq 0) {
        Add-Finding -Category "Privacy" -Name "Windows Recall Blocked by Policy" -Risk "Info" `
            -Description "Windows Recall enablement is blocked via AllowRecallEnablement policy" `
            -Details "AllowRecallEnablement: 0"
    } elseif ($recallDbPaths.Count -gt 0) {
        Add-Finding -Category "Privacy" -Name "Windows Recall Database Found" -Risk "High" `
            -Description "Windows Recall snapshot database found - periodic screenshots of all activity are being stored locally" `
            -Details "Recall databases found:`n$($recallDbPaths -join "`n")`n`nRecall captures screenshots every few seconds, including passwords, banking info, private messages, and sensitive documents. The database is stored unencrypted on disk." `
            -Recommendation "Disable Windows Recall via Settings > Privacy & Security > Recall, or enforce via Group Policy: Computer Configuration > Admin Templates > Windows Components > Windows AI > Turn off saving snapshots for Windows. Consider deleting existing snapshot data." `
            -Reference "CVE-2024-5563 - Windows Recall Privacy Concerns"
    } elseif ($recallPresent -or $recallEnabled -eq 1) {
        $status = if ($recallEnabled -eq 1) { "Enabled in registry" } else { "Package present but enablement status unknown" }
        Add-Finding -Category "Privacy" -Name "Windows Recall Present" -Risk "Medium" `
            -Description "Windows Recall feature is present on this system" `
            -Details "Status: $status`nUser disabled: $recallUserDisabled`nPolicy disabled: $recallDisabledPolicy`n`nRecall captures periodic screenshots and uses AI to make them searchable. This can expose passwords, sensitive data, and private communications." `
            -Recommendation "If Recall is not required, disable it via Group Policy: Set 'Turn off saving snapshots for Windows' to Enabled, or set HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI\DisableAIDataAnalysis = 1" `
            -Reference "Microsoft Windows Recall Security Documentation"
    } else {
        Add-Finding -Category "Privacy" -Name "Windows Recall Status" -Risk "Info" `
            -Description "Windows Recall does not appear to be present or active" `
            -Details "Recall package: Not detected`nRecall databases: None found`nDisableAIDataAnalysis policy: $recallDisabledPolicy"
    }
    
    # Check for other AI features that may have privacy implications
    $copilotDisabled = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Default 0
    $copilotUserDisabled = Get-RegistryValue -Path "HKCU:\Software\Policies\Microsoft\Windows\WindowsCopilot" -Name "TurnOffWindowsCopilot" -Default 0
    
    if ($copilotDisabled -ne 1 -and $copilotUserDisabled -ne 1) {
        Add-Finding -Category "Privacy" -Name "Windows Copilot Enabled" -Risk "Info" `
            -Description "Windows Copilot is not disabled by policy" `
            -Details "TurnOffWindowsCopilot (HKLM): $copilotDisabled`nTurnOffWindowsCopilot (HKCU): $copilotUserDisabled" `
            -Recommendation "Consider disabling Windows Copilot via Group Policy if not required for business use"
    } else {
        Add-Finding -Category "Privacy" -Name "Windows Copilot Disabled" -Risk "Info" `
            -Description "Windows Copilot is disabled by policy" `
            -Details "TurnOffWindowsCopilot (HKLM): $copilotDisabled`nTurnOffWindowsCopilot (HKCU): $copilotUserDisabled"
    }
}

function Test-CredentialCaching {
    Write-AuditLog "Checking Credential Caching Settings..." -Level "INFO"
    
    # Check cached logons count
    $cachedLogons = Get-RegistryValue -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -Default "10"
    
    if ([int]$cachedLogons -gt 4) {
        Add-Finding -Category "Credential Security" -Name "High Cached Logons Count" -Risk "Low" `
            -Description "Domain credential cache count is higher than recommended" `
            -Details "CachedLogonsCount: $cachedLogons (recommended: 4 or less)" `
            -Recommendation "Reduce cached logons to minimize offline attack risk"
    }
    
    # Check plain text password storage
    $reversibleEncryption = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "NoLMHash" -Default 1
    
    if ($reversibleEncryption -ne 1) {
        Add-Finding -Category "Credential Security" -Name "LM Hash Storage Enabled" -Risk "High" `
            -Description "LM hashes may be stored (NoLMHash not set)" `
            -Details "NoLMHash: $reversibleEncryption" `
            -Recommendation "Set NoLMHash to 1 to prevent LM hash storage"
    }
    
    # Check for Digest Authentication (WDigest)
    $wdigest = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest" -Name "UseLogonCredential" -Default 0
    
    if ($wdigest -eq 1) {
        Add-Finding -Category "Credential Security" -Name "WDigest Credential Caching" -Risk "High" `
            -Description "WDigest is caching credentials in memory" `
            -Details "UseLogonCredential: 1" `
            -Recommendation "Set UseLogonCredential to 0"
    }
    
    # Check Network Level Authentication for RDP
    $nla = Get-RegistryValue -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -Default 1
    
    if ($nla -ne 1) {
        Add-Finding -Category "Credential Security" -Name "RDP NLA Disabled" -Risk "Medium" `
            -Description "Network Level Authentication is disabled for RDP" `
            -Details "UserAuthentication: $nla" `
            -Recommendation "Enable NLA for RDP connections"
    }
}

# ============================================================================
# HTML REPORT GENERATION
# ============================================================================

function New-HtmlReport {
    Write-AuditLog "Generating HTML Report..." -Level "INFO"
    
    $riskSummary = $Script:Findings | Group-Object Risk | Sort-Object { $Script:RiskLevels[$_.Name] } -Descending
    $categorySummary = $Script:Findings | Group-Object Category | Sort-Object Count -Descending
    
    # Use @() to ensure array context so .Count always returns 0 instead of $null when empty
    $criticalCount = @($Script:Findings | Where-Object { $_.Risk -eq 'Critical' }).Count
    $highCount = @($Script:Findings | Where-Object { $_.Risk -eq 'High' }).Count
    $mediumCount = @($Script:Findings | Where-Object { $_.Risk -eq 'Medium' }).Count
    $lowCount = @($Script:Findings | Where-Object { $_.Risk -eq 'Low' }).Count
    $infoCount = @($Script:Findings | Where-Object { $_.Risk -eq 'Info' }).Count
    
    # Calculate overall score (0-100)
    $totalWeight = ($criticalCount * 25) + ($highCount * 15) + ($mediumCount * 8) + ($lowCount * 3)
    $maxPossible = 100
    $score = [Math]::Max(0, $maxPossible - $totalWeight)
    
    $scoreColor = if ($score -ge 80) { "#28a745" } elseif ($score -ge 60) { "#ffc107" } elseif ($score -ge 40) { "#fd7e14" } else { "#dc3545" }
    $scoreGrade = if ($score -ge 90) { "A" } elseif ($score -ge 80) { "B" } elseif ($score -ge 70) { "C" } elseif ($score -ge 60) { "D" } else { "F" }
    
    # Determine admin status display for header
    $headerAdminStatus = if ($Script:SystemInfo.IsAdmin) {
        "<span style='color: #90EE90;'>[OK] Administrator</span>"
    } else {
        "<span style='color: #ff6b6b; font-weight: bold;'>[!!] NOT ADMIN - LIMITED RESULTS</span>"
    }
    
    # Determine page title
    $pageTitle = if ($Script:SystemInfo.IsAdmin) {
        "Windows Security Audit Report - $($Script:Hostname)"
    } else {
        "[WARN] INCOMPLETE - Windows Security Audit Report - $($Script:Hostname)"
    }
    
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$pageTitle</title>
    <style>
        :root {
            --critical: #dc3545;
            --high: #fd7e14;
            --medium: #ffc107;
            --low: #17a2b8;
            --info: #6c757d;
            --bg-primary: #f8f9fa;
            --bg-secondary: #ffffff;
            --text-primary: #212529;
            --text-secondary: #6c757d;
            --border-color: #dee2e6;
        }
        
        * { box-sizing: border-box; margin: 0; padding: 0; }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 20px;
        }
        
        .container { max-width: 1400px; margin: 0 auto; }
        
        .header {
            background: linear-gradient(135deg, #1e3a5f 0%, #2d5a87 100%);
            color: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 20px;
        }
        
        .header h1 { font-size: 28px; font-weight: 600; }
        .header-meta { font-size: 14px; opacity: 0.9; }
        
        .score-circle {
            width: 120px;
            height: 120px;
            border-radius: 50%;
            background: conic-gradient($scoreColor ${score}%, #ffffff33 0%);
            display: flex;
            align-items: center;
            justify-content: center;
            position: relative;
        }
        
        .score-inner {
            width: 90px;
            height: 90px;
            border-radius: 50%;
            background: rgba(255,255,255,0.95);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            color: var(--text-primary);
        }
        
        .score-value { font-size: 32px; font-weight: 700; color: $scoreColor; }
        .score-label { font-size: 11px; text-transform: uppercase; letter-spacing: 1px; }
        
        .summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }
        
        .summary-card {
            background: var(--bg-secondary);
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            border-left: 4px solid var(--border-color);
        }
        
        .summary-card.critical { border-left-color: var(--critical); }
        .summary-card.high { border-left-color: var(--high); }
        .summary-card.medium { border-left-color: var(--medium); }
        .summary-card.low { border-left-color: var(--low); }
        .summary-card.info { border-left-color: var(--info); }
        
        .summary-card .count {
            font-size: 36px;
            font-weight: 700;
            margin-bottom: 4px;
        }
        
        .summary-card.critical .count { color: var(--critical); }
        .summary-card.high .count { color: var(--high); }
        .summary-card.medium .count { color: var(--medium); }
        .summary-card.low .count { color: var(--low); }
        .summary-card.info .count { color: var(--info); }
        
        .summary-card .label { 
            font-size: 13px; 
            text-transform: uppercase; 
            letter-spacing: 1px;
            color: var(--text-secondary);
        }
        
        .section {
            background: var(--bg-secondary);
            border-radius: 10px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            overflow: hidden;
        }
        
        .section-header {
            background: #f1f3f4;
            padding: 16px 20px;
            font-size: 18px;
            font-weight: 600;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .section-content { padding: 0; }
        
        .finding {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border-color);
            display: grid;
            grid-template-columns: 100px 1fr;
            gap: 16px;
            align-items: start;
        }
        
        .finding:last-child { border-bottom: none; }
        
        .finding:hover { background: #f8f9fa; }
        
        .risk-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            text-align: center;
        }
        
        .risk-critical { background: var(--critical); color: white; }
        .risk-high { background: var(--high); color: white; }
        .risk-medium { background: var(--medium); color: #212529; }
        .risk-low { background: var(--low); color: white; }
        .risk-info { background: var(--info); color: white; }
        
        .finding-content h4 { 
            font-size: 15px; 
            font-weight: 600; 
            margin-bottom: 6px;
        }
        
        .finding-content p { 
            font-size: 14px; 
            color: var(--text-secondary);
            margin-bottom: 8px;
        }
        
        .finding-details {
            background: #f8f9fa;
            border-radius: 6px;
            padding: 10px 14px;
            font-family: 'Consolas', 'Monaco', monospace;
            font-size: 12px;
            white-space: pre-wrap;
            word-break: break-all;
            margin-bottom: 8px;
            max-height: 150px;
            overflow-y: auto;
        }
        
        .recommendation {
            background: #e8f5e9;
            border-left: 3px solid #28a745;
            padding: 8px 12px;
            font-size: 13px;
            margin-bottom: 4px;
        }
        
        .reference {
            font-size: 12px;
            color: var(--text-secondary);
        }
        
        .system-info-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 12px;
            padding: 20px;
        }
        
        .system-info-item {
            display: flex;
            justify-content: space-between;
            padding: 8px 0;
            border-bottom: 1px dashed var(--border-color);
        }
        
        .system-info-item .label { color: var(--text-secondary); font-size: 13px; }
        .system-info-item .value { font-weight: 500; font-size: 13px; text-align: right; }
        
        .toc {
            background: var(--bg-secondary);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        
        .toc h3 { margin-bottom: 12px; font-size: 16px; }
        .toc ul { list-style: none; column-count: 3; column-gap: 20px; }
        .toc li { padding: 4px 0; }
        .toc a { color: #2d5a87; text-decoration: none; font-size: 14px; }
        .toc a:hover { text-decoration: underline; }
        
        .cyber-essentials {
            background: var(--bg-secondary);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        
        .cyber-essentials h3 {
            font-size: 18px;
            margin-bottom: 16px;
            color: #1e3a5f;
        }
        
        .ce-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 16px;
        }
        
        .ce-item {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 16px;
            border-left: 4px solid var(--info);
        }
        
        .ce-item.pass { border-left-color: #28a745; background: #f0fff4; }
        .ce-item.fail { border-left-color: #dc3545; background: #fff5f5; }
        .ce-item.review { border-left-color: #ffc107; background: #fffdf0; }
        
        .ce-item h4 {
            font-size: 14px;
            margin-bottom: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        
        .ce-status {
            font-size: 11px;
            padding: 2px 8px;
            border-radius: 4px;
            font-weight: bold;
        }
        
        .ce-status.pass { background: #28a745; color: white; }
        .ce-status.fail { background: #dc3545; color: white; }
        .ce-status.review { background: #ffc107; color: #212529; }
        .ce-status.unknown { background: #6c757d; color: white; }
        
        .ce-details {
            font-size: 12px;
            color: var(--text-secondary);
            line-height: 1.6;
        }
        
        .ce-details div { margin: 2px 0; }
        
        .software-inventory {
            background: var(--bg-secondary);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        
        .software-inventory h3 {
            font-size: 18px;
            margin-bottom: 16px;
            color: #1e3a5f;
        }
        
        .inventory-table {
            width: 100%;
            border-collapse: collapse;
            font-size: 12px;
        }
        
        .inventory-table th {
            background: #1e3a5f;
            color: white;
            padding: 10px 8px;
            text-align: left;
            position: sticky;
            top: 0;
        }
        
        .inventory-table td {
            padding: 8px;
            border-bottom: 1px solid var(--border-color);
        }
        
        .inventory-table tr:hover { background: #f8f9fa; }
        
        .inventory-table tr.old-software { background: #fff5f5; }
        
        .inventory-wrapper {
            max-height: 400px;
            overflow-y: auto;
            border: 1px solid var(--border-color);
            border-radius: 6px;
        }
        
        .inventory-filter {
            margin-bottom: 12px;
            display: flex;
            gap: 12px;
            flex-wrap: wrap;
        }
        
        .inventory-filter input {
            padding: 8px 12px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            font-size: 13px;
            flex: 1;
            min-width: 200px;
        }
        
        .inventory-filter select {
            padding: 8px 12px;
            border: 1px solid var(--border-color);
            border-radius: 6px;
            font-size: 13px;
        }
        
        .browser-extensions {
            background: var(--bg-secondary);
            border-radius: 10px;
            padding: 20px;
            margin-bottom: 24px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.08);
        }
        
        .browser-extensions h3 {
            font-size: 18px;
            margin-bottom: 16px;
            color: #1e3a5f;
        }
        
        .ext-badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: bold;
        }
        
        .ext-badge.chrome { background: #4285f4; color: white; }
        .ext-badge.edge { background: #0078d4; color: white; }
        .ext-badge.firefox { background: #ff7139; color: white; }
        .ext-badge.policy { background: #6c757d; color: white; }
        .ext-badge.user { background: #e9ecef; color: #495057; }
        .ext-badge.disabled { background: #f8d7da; color: #721c24; }
        
        .footer {
            text-align: center;
            padding: 20px;
            color: var(--text-secondary);
            font-size: 13px;
        }
        
        .admin-warning {
            background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
            color: white;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 20px;
            font-size: 15px;
            box-shadow: 0 4px 12px rgba(220, 53, 69, 0.4);
        }
        
        .admin-warning h2 {
            font-size: 20px;
            margin-bottom: 10px;
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .admin-warning ul {
            margin: 10px 0 0 20px;
        }
        
        .admin-warning li {
            margin: 5px 0;
        }
        
        .disclaimer {
            background: #fff3cd;
            border: 1px solid #ffc107;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            font-size: 13px;
        }
        
        @media print {
            body { background: white; }
            .section { break-inside: avoid; }
            .header { background: #1e3a5f !important; -webkit-print-color-adjust: exact; }
        }
        
        @media (max-width: 768px) {
            .header { flex-direction: column; text-align: center; }
            .finding { grid-template-columns: 1fr; }
            .toc ul { column-count: 1; }
        }
    </style>
</head>
<body>
    <div class="container">
        <header class="header">
            <div>
                <h1> Windows Security Audit Report</h1>
                <div class="header-meta">
                    <div><strong>Hostname:</strong> $($Script:SystemInfo.Hostname)</div>
                    <div><strong>Audit Date:</strong> $($Script:AuditDate)</div>
                    <div><strong>Auditor:</strong> $($Script:SystemInfo.CurrentUser)</div>
                    <div><strong>Tool Version:</strong> $($Script:AuditVersion)</div>
                    <div><strong>Privileges:</strong> $headerAdminStatus</div>
$(if ($Script:PrivacyEnabled) {
    "                    <div><strong>Privacy Mode:</strong> <span style='background: #6f42c1; color: white; padding: 2px 10px; border-radius: 4px; font-size: 12px;'>ENABLED - Data Redacted</span></div>"
})
                </div>
                <div style="margin-top: 10px;">
                    <button onclick="exportJson()" style="background: #28a745; color: white; border: none; padding: 8px 18px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600;">Export JSON</button>
                    <button onclick="window.print()" style="background: #6c757d; color: white; border: none; padding: 8px 18px; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600; margin-left: 6px;">Print Report</button>
                </div>
            </div>
            <div class="score-circle">
                <div class="score-inner">
                    <div class="score-value">$scoreGrade</div>
                    <div class="score-label">Score: $score</div>
                </div>
            </div>
        </header>
        
"@

    # Add prominent warning if not running as admin
    if (-not $Script:SystemInfo.IsAdmin) {
        $html += @"
        <div class="admin-warning">
            <h2>[!!] LIMITED SCAN - NOT RUNNING AS ADMINISTRATOR</h2>
            <p>This audit was executed <strong>without administrative privileges</strong>. The results are <strong>incomplete</strong> and may not reflect the true security posture of this system.</p>
            <p><strong>The following checks are affected or unavailable:</strong></p>
            <ul>
                <li>Security policy and audit policy settings</li>
                <li>Full service and driver enumeration</li>
                <li>BitLocker encryption status</li>
                <li>Credential protection settings (LSA, Credential Guard)</li>
                <li>Windows Defender and ASR configuration</li>
                <li>User rights assignments</li>
                <li>Registry permissions on protected keys</li>
                <li>Hardware security features (Secure Boot, TPM, VBS)</li>
                <li>Many other security-critical settings</li>
            </ul>
            <p style="margin-top: 15px;"><strong>[WARN] ACTION REQUIRED:</strong> Re-run this audit from an elevated PowerShell prompt (Run as Administrator) for complete results.</p>
        </div>
        
"@
    }

    $html += @"
        <div class="disclaimer">
            <strong>[WARN] Disclaimer:</strong> This report is generated for authorized security compliance auditing purposes only. 
            Findings should be validated by qualified security personnel before taking remediation actions.$(if (-not $Script:SystemInfo.IsAdmin) { " <strong>NOTE: This scan was run without admin rights - results are incomplete.</strong>" })
        </div>
        
        <div class="summary-grid">
            <div class="summary-card critical">
                <div class="count">$criticalCount</div>
                <div class="label">Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">$highCount</div>
                <div class="label">High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">$mediumCount</div>
                <div class="label">Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">$lowCount</div>
                <div class="label">Low</div>
            </div>
            <div class="summary-card info">
                <div class="count">$infoCount</div>
                <div class="label">Informational</div>
            </div>
        </div>
        
"@

    # Add Cyber Essentials Summary Section
    $ceFirewallClass = switch ($Script:CyberEssentials.Firewalls.Status) { "PASS" { "pass" } "FAIL" { "fail" } default { "review" } }
    $ceSecConfigClass = switch ($Script:CyberEssentials.SecureConfiguration.Status) { "PASS" { "pass" } "FAIL" { "fail" } default { "review" } }
    $ceUserAccessClass = switch ($Script:CyberEssentials.UserAccessControl.Status) { "PASS" { "pass" } "FAIL" { "fail" } default { "review" } }
    $ceMalwareClass = switch ($Script:CyberEssentials.MalwareProtection.Status) { "PASS" { "pass" } "FAIL" { "fail" } default { "review" } }
    $cePatchClass = switch ($Script:CyberEssentials.PatchManagement.Status) { "PASS" { "pass" } "FAIL" { "fail" } default { "review" } }
    
    $ceScoreColor = if ($Script:CyberEssentialsScore -ge 80) { "#28a745" } elseif ($Script:CyberEssentialsScore -ge 60) { "#ffc107" } else { "#dc3545" }
    
    $html += @"
        <div class="cyber-essentials">
            <h3> Cyber Essentials Assessment Summary <span style="float: right; font-size: 14px; color: $ceScoreColor;">Readiness Score: $($Script:CyberEssentialsScore)%</span></h3>
            <div class="ce-grid">
                <div class="ce-item $ceFirewallClass">
                    <h4> Firewalls <span class="ce-status $ceFirewallClass">$($Script:CyberEssentials.Firewalls.Status)</span></h4>
                    <div class="ce-details">
                        $($Script:CyberEssentials.Firewalls.Details | ForEach-Object { "<div>$_</div>" })
                    </div>
                </div>
                <div class="ce-item $ceSecConfigClass">
                    <h4> Secure Configuration <span class="ce-status $ceSecConfigClass">$($Script:CyberEssentials.SecureConfiguration.Status)</span></h4>
                    <div class="ce-details">
                        $($Script:CyberEssentials.SecureConfiguration.Details | ForEach-Object { "<div>$_</div>" })
                    </div>
                </div>
                <div class="ce-item $ceUserAccessClass">
                    <h4> User Access Control <span class="ce-status $ceUserAccessClass">$($Script:CyberEssentials.UserAccessControl.Status)</span></h4>
                    <div class="ce-details">
                        $($Script:CyberEssentials.UserAccessControl.Details | ForEach-Object { "<div>$_</div>" })
                    </div>
                </div>
                <div class="ce-item $ceMalwareClass">
                    <h4> Malware Protection <span class="ce-status $ceMalwareClass">$($Script:CyberEssentials.MalwareProtection.Status)</span></h4>
                    <div class="ce-details">
                        $($Script:CyberEssentials.MalwareProtection.Details | ForEach-Object { "<div>$_</div>" })
                    </div>
                </div>
                <div class="ce-item $cePatchClass">
                    <h4> Patch Management <span class="ce-status $cePatchClass">$($Script:CyberEssentials.PatchManagement.Status)</span></h4>
                    <div class="ce-details">
                        $($Script:CyberEssentials.PatchManagement.Details | ForEach-Object { "<div>$_</div>" })
                    </div>
                </div>
            </div>
        </div>
        
        <div class="toc">
            <h3> Table of Contents</h3>
            <ul>
"@
    
    # Add TOC entries
    $categories = $Script:Findings | Select-Object -ExpandProperty Category -Unique | Sort-Object
    foreach ($cat in $categories) {
        $catId = $cat -replace '\s+', '-' -replace '[^\w-]', ''
        $html += "                <li><a href='#$catId'>$cat</a></li>`n"
    }
    
    # Add Storage links
    if ($Script:DiskInventory -and $Script:DiskInventory.Count -gt 0) {
        $html += "                <li><a href='#storage-disks'>Physical Disks ($($Script:DiskInventory.Count))</a></li>`n"
    }
    if ($Script:VolumeInventory -and $Script:VolumeInventory.Count -gt 0) {
        $html += "                <li><a href='#storage-volumes'>Storage Volumes ($($Script:VolumeInventory.Count))</a></li>`n"
    }
    
    # Add Windows Features link
    if ($Script:WindowsFeatures -and $Script:WindowsFeatures.Count -gt 0) {
        $wfEnabled = @($Script:WindowsFeatures | Where-Object { $_.State -eq 'Enabled' }).Count
        $html += "                <li><a href='#windows-features'>Windows Features ($wfEnabled enabled / $($Script:WindowsFeatures.Count))</a></li>`n"
    }
    
    # Add Software Inventory link if inventory exists
    if ($Script:SoftwareInventory -and $Script:SoftwareInventory.Count -gt 0) {
        $html += "                <li><a href='#software-inventory'>Software Inventory ($($Script:SoftwareInventory.Count))</a></li>`n"
    }
    
    # Add Browser Extensions link if extensions exist
    if ($Script:BrowserExtensions -and $Script:BrowserExtensions.Count -gt 0) {
        $html += "                <li><a href='#browser-extensions'>Browser Extensions ($($Script:BrowserExtensions.Count))</a></li>`n"
    }
    
    # Add VS Code Extensions link if extensions exist
    if ($Script:VSCodeExtensions -and $Script:VSCodeExtensions.Count -gt 0) {
        $html += "                <li><a href='#vscode-extensions'>VS Code Extensions ($($Script:VSCodeExtensions.Count))</a></li>`n"
    }
    
    # Add Patch History link
    if ($Script:PatchHistory -and $Script:PatchHistory.Count -gt 0) {
        $html += "                <li><a href='#patch-history'>Patch History ($($Script:PatchHistory.Count))</a></li>`n"
    }
    
    $adminStatusHtml = if ($Script:SystemInfo.IsAdmin) {
        "<span style='color: #28a745; font-weight: bold;'>[OK] Yes</span>"
    } else {
        "<span style='color: #dc3545; font-weight: bold;'>[!!] NO - RESULTS INCOMPLETE</span>"
    }
    
    $html += @"
            </ul>
        </div>
        
        <div class="section">
            <div class="section-header"> System Information</div>
            <div class="system-info-grid">
                <div class="system-info-item"><span class="label">Hostname</span><span class="value">$(ConvertTo-HtmlSafe $Script:SystemInfo.Hostname)</span></div>
                <div class="system-info-item"><span class="label">Domain</span><span class="value">$(ConvertTo-HtmlSafe $Script:SystemInfo.Domain)</span></div>
                <div class="system-info-item"><span class="label">Operating System</span><span class="value">$(ConvertTo-HtmlSafe $Script:SystemInfo.OSName)</span></div>
                <div class="system-info-item"><span class="label">OS Build</span><span class="value">$(ConvertTo-HtmlSafe $Script:SystemInfo.OSBuild)</span></div>
                <div class="system-info-item"><span class="label">Architecture</span><span class="value">$(ConvertTo-HtmlSafe $Script:SystemInfo.Architecture)</span></div>
                <div class="system-info-item"><span class="label">PowerShell Version</span><span class="value">$($Script:SystemInfo.PowerShellVer)</span></div>
                <div class="system-info-item"><span class="label">Running as Admin</span><span class="value">$adminStatusHtml</span></div>
            </div>
        </div>
        
        <div class="section">
            <div class="section-header"> Hardware Summary</div>
            <div class="system-info-grid">
                <div class="system-info-item"><span class="label">Platform Type</span><span class="value">$(
                    if ($Script:SystemInfo.IsVirtualMachine) {
                        "<span style='background: #6f42c1; color: white; padding: 2px 10px; border-radius: 4px; font-size: 12px;'>Virtual Machine</span> &nbsp;$(ConvertTo-HtmlSafe $Script:SystemInfo.VMPlatform)"
                    } else {
                        "<span style='background: #28a745; color: white; padding: 2px 10px; border-radius: 4px; font-size: 12px;'>Physical</span>"
                    }
                )</span></div>
                <div class="system-info-item"><span class="label">Form Factor</span><span class="value">$(
                    $ffIcon = switch ($Script:SystemInfo.FormFactor) {
                        'Laptop'    { "&#x1F4BB;" }
                        'Tablet'    { "&#x1F4F1;" }
                        'Server'    { "&#x1F5A5;" }
                        'Mini PC'   { "&#x1F5B3;" }
                        'All-in-One' { "&#x1F5B5;" }
                        default     { "&#x1F5A5;" }
                    }
                    "$ffIcon &nbsp;$($Script:SystemInfo.FormFactor)$(if ($Script:SystemInfo.ChassisType) { " &nbsp;<span style='color: #666; font-size: 12px;'>(Chassis: $($Script:SystemInfo.ChassisType))</span>" })"
                )</span></div>
                <div class="system-info-item"><span class="label">Battery</span><span class="value">$(
                    if ($Script:SystemInfo.HasBattery) {
                        $batHtml = "<span style='background: #28a745; color: white; padding: 2px 10px; border-radius: 4px; font-size: 12px;'>Detected</span>"
                        if ($Script:SystemInfo.BatteryDetails.Count -gt 0) {
                            $batHtml += " &nbsp;<span style='font-size: 12px;'>$(ConvertTo-HtmlSafe ($Script:SystemInfo.BatteryDetails[0]))</span>"
                        }
                        $batHtml
                    } else {
                        "<span style='background: #6c757d; color: white; padding: 2px 10px; border-radius: 4px; font-size: 12px;'>Not detected</span>"
                    }
                )</span></div>
                <div class="system-info-item"><span class="label">Make / Model</span><span class="value">$(ConvertTo-HtmlSafe "$($Script:SystemInfo.Manufacturer) $($Script:SystemInfo.Model)")</span></div>
                <div class="system-info-item"><span class="label">Serial Number</span><span class="value">$(ConvertTo-HtmlSafe $Script:SystemInfo.SerialNumber)</span></div>
                <div class="system-info-item"><span class="label">Baseboard</span><span class="value">$(ConvertTo-HtmlSafe $Script:SystemInfo.Baseboard)</span></div>
                <div class="system-info-item"><span class="label">BIOS Version</span><span class="value">$(ConvertTo-HtmlSafe $Script:SystemInfo.BIOSVersion)</span></div>
                <div class="system-info-item"><span class="label">BIOS Date</span><span class="value">$(ConvertTo-HtmlSafe $Script:SystemInfo.BIOSDate)</span></div>
                <div class="system-info-item"><span class="label">CPU</span><span class="value">$(ConvertTo-HtmlSafe $Script:SystemInfo.CPU)</span></div>
                <div class="system-info-item"><span class="label">CPU Cores / Threads</span><span class="value">$($Script:SystemInfo.CPUCores) Cores / $($Script:SystemInfo.CPUThreads) Threads @ $($Script:SystemInfo.CPUMaxSpeed)</span></div>
                <div class="system-info-item"><span class="label">Total RAM</span><span class="value">$($Script:SystemInfo.TotalMemoryGB) GB$(if ($Script:SystemInfo.RAMModules.Count -gt 0) { " &nbsp;($($Script:SystemInfo.RAMModules.Count) module$(if ($Script:SystemInfo.RAMModules.Count -ne 1){'s'}): $(ConvertTo-HtmlSafe ($Script:SystemInfo.RAMModules -join ' + ')))" })</span></div>
"@

    # Add GPU rows - may have multiple
    if ($Script:SystemInfo.GPUs -and $Script:SystemInfo.GPUs.Count -gt 0) {
        $gpuIndex = 0
        foreach ($gpuItem in $Script:SystemInfo.GPUs) {
            $gpuLabel = if ($Script:SystemInfo.GPUs.Count -gt 1) { "GPU $gpuIndex" } else { "Graphics" }
            $gpuLine = "$(ConvertTo-HtmlSafe $gpuItem.Name)"
            if ($gpuItem.VRAM) { $gpuLine += " ($($gpuItem.VRAM))" }
            if ($gpuItem.Driver -and $gpuItem.Driver -ne "N/A") { $gpuLine += " - Driver: $($gpuItem.Driver)" }
            if ($gpuItem.Resolution -and $gpuItem.Resolution -ne "N/A") { $gpuLine += " @ $($gpuItem.Resolution)" }
            $html += "                <div class=`"system-info-item`"><span class=`"label`">$gpuLabel</span><span class=`"value`">$gpuLine</span></div>`n"
            $gpuIndex++
        }
    } else {
        $html += "                <div class=`"system-info-item`"><span class=`"label`">Graphics</span><span class=`"value`">N/A</span></div>`n"
    }

    $html += @"
                <div class="system-info-item"><span class="label">Uptime</span><span class="value">$($Script:SystemInfo.Uptime) &nbsp;(since $($Script:SystemInfo.LastBoot))</span></div>
"@

    if ($Script:SystemInfo.IsVirtualMachine -and $Script:SystemInfo.VMIndicators.Count -gt 0) {
        $indicatorHtml = ($Script:SystemInfo.VMIndicators | ForEach-Object { ConvertTo-HtmlSafe $_ }) -join '<br>'
        $html += "                <div class=`"system-info-item`" style=`"grid-column: 1 / -1;`"><span class=`"label`">VM Detection Indicators</span><span class=`"value`" style=`"font-size: 12px;`">$indicatorHtml</span></div>`n"
    }

    $html += @"
            </div>
        </div>
"@

    # Add TPM Information Section
    if ($Script:TPMInfo) {
        $tpmStatusBadge = if ($Script:TPMInfo.Present -and $Script:TPMInfo.Ready) {
            "<span style='background: #28a745; color: white; padding: 2px 10px; border-radius: 4px; font-size: 12px;'>Ready</span>"
        } elseif ($Script:TPMInfo.Present) {
            "<span style='background: #ffc107; color: #333; padding: 2px 10px; border-radius: 4px; font-size: 12px;'>Present - Not Ready</span>"
        } else {
            "<span style='background: #dc3545; color: white; padding: 2px 10px; border-radius: 4px; font-size: 12px;'>Not Detected</span>"
        }
        
        $tpmVerBadge = ""
        if ($Script:TPMInfo.Version -match "^2\.") {
            $tpmVerBadge = "<span style='background: #28a745; color: white; padding: 2px 10px; border-radius: 4px; font-size: 12px; margin-left: 6px;'>v$($Script:TPMInfo.Version)</span>"
        } elseif ($Script:TPMInfo.Version -match "^1\.") {
            $tpmVerBadge = "<span style='background: #dc3545; color: white; padding: 2px 10px; border-radius: 4px; font-size: 12px; margin-left: 6px;'>v$($Script:TPMInfo.Version) - Upgrade Recommended</span>"
        }
        
        $html += @"
        
        <div class="section">
            <div class="section-header"> TPM Information &nbsp;$tpmStatusBadge$tpmVerBadge</div>
            <div class="system-info-grid">
                <div class="system-info-item"><span class="label">TPM Present</span><span class="value">$($Script:TPMInfo.Present)</span></div>
                <div class="system-info-item"><span class="label">TPM Ready</span><span class="value">$($Script:TPMInfo.Ready)</span></div>
                <div class="system-info-item"><span class="label">TPM Enabled</span><span class="value">$($Script:TPMInfo.Enabled)</span></div>
                <div class="system-info-item"><span class="label">TPM Activated</span><span class="value">$($Script:TPMInfo.Activated)</span></div>
                <div class="system-info-item"><span class="label">TPM Owned</span><span class="value">$($Script:TPMInfo.Owned)</span></div>
                <div class="system-info-item"><span class="label">TPM Version</span><span class="value">$(ConvertTo-HtmlSafe $Script:TPMInfo.Version)</span></div>
                <div class="system-info-item"><span class="label">Spec Version</span><span class="value">$(ConvertTo-HtmlSafe $Script:TPMInfo.SpecVersion)</span></div>
                <div class="system-info-item"><span class="label">Manufacturer</span><span class="value">$(ConvertTo-HtmlSafe $Script:TPMInfo.Manufacturer)</span></div>
                <div class="system-info-item"><span class="label">Firmware Version</span><span class="value">$(ConvertTo-HtmlSafe $Script:TPMInfo.FirmwareVersion)</span></div>
                <div class="system-info-item"><span class="label">PPI Version</span><span class="value">$(ConvertTo-HtmlSafe $Script:TPMInfo.PPIVersion)</span></div>
                <div class="system-info-item"><span class="label">Owner Authorization</span><span class="value">$(ConvertTo-HtmlSafe $Script:TPMInfo.OwnerAuth)</span></div>
                <div class="system-info-item"><span class="label">Block TPM Clear</span><span class="value">$(if ($null -ne $Script:TPMInfo.BlockClear) { if ($Script:TPMInfo.BlockClear -eq 1) { 'Yes (Policy)' } else { 'No' } } else { 'Not configured' })</span></div>
            </div>
        </div>
"@
    }

    # Add Storage Disks Section
    if ($Script:DiskInventory -and $Script:DiskInventory.Count -gt 0) {
        $html += @"
        
        <div class="section" id="storage-disks">
            <div class="section-header"> Physical Disks ($($Script:DiskInventory.Count))</div>
            <div class="inventory-wrapper">
                <table class="inventory-table">
                    <thead>
                        <tr>
                            <th>Disk #</th>
                            <th>Model</th>
                            <th>Serial Number</th>
                            <th>Type</th>
                            <th>Bus</th>
                            <th>Size (GB)</th>
                            <th>Partitions</th>
                            <th>Firmware</th>
                            <th>Health</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($d in ($Script:DiskInventory | Sort-Object DiskNumber)) {
            $healthClass = switch ($d.Health) {
                "Healthy"   { "background: #d4edda; color: #155724;" }
                "Warning"   { "background: #fff3cd; color: #856404;" }
                "Unhealthy" { "background: #f8d7da; color: #721c24;" }
                default     { "" }
            }
            $typeIcon = switch ($d.MediaType) {
                "SSD" { "SSD" }
                "HDD" { "HDD" }
                default { $d.MediaType }
            }
            $html += "                        <tr>`n"
            $html += "                            <td>$($d.DiskNumber)</td>`n"
            $html += "                            <td>$(ConvertTo-HtmlSafe $d.Model)</td>`n"
            $html += "                            <td style='font-size: 11px;'>$(ConvertTo-HtmlSafe $d.SerialNumber)</td>`n"
            $html += "                            <td>$typeIcon</td>`n"
            $html += "                            <td>$($d.BusType)</td>`n"
            $html += "                            <td>$($d.SizeGB)</td>`n"
            $html += "                            <td>$($d.Partitions)</td>`n"
            $html += "                            <td style='font-size: 11px;'>$(ConvertTo-HtmlSafe $d.FirmwareRev)</td>`n"
            $html += "                            <td><span style='padding: 2px 8px; border-radius: 4px; font-size: 12px; $healthClass'>$($d.Health)</span></td>`n"
            $html += "                        </tr>`n"
        }
        $html += @"
                    </tbody>
                </table>
            </div>
        </div>
"@
    }

    # Add Storage Volumes Section
    if ($Script:VolumeInventory -and $Script:VolumeInventory.Count -gt 0) {
        $html += @"
        
        <div class="section" id="storage-volumes">
            <div class="section-header"> Storage Volumes ($($Script:VolumeInventory.Count))</div>
            <div class="inventory-wrapper">
                <table class="inventory-table">
                    <thead>
                        <tr>
                            <th>Drive</th>
                            <th>Label</th>
                            <th>Type</th>
                            <th>File System</th>
                            <th>Total (GB)</th>
                            <th>Used (GB)</th>
                            <th>Free (GB)</th>
                            <th>Usage</th>
                            <th>BitLocker</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($v in ($Script:VolumeInventory | Sort-Object DriveLetter)) {
            # Usage bar
            $barColor = if ($v.PercentUsed -gt 95) { "#dc3545" } elseif ($v.PercentUsed -gt 85) { "#ffc107" } else { "#28a745" }
            $usageBar = ""
            if ($v.TotalGB -gt 0) {
                $usageBar = "<div style='width: 100px; background: #e9ecef; border-radius: 4px; overflow: hidden; display: inline-block; vertical-align: middle; height: 16px;'><div style='width: $($v.PercentUsed)%; background: $barColor; height: 100%;'></div></div> <span style='font-size: 11px;'>$($v.PercentUsed)%</span>"
            } else {
                $usageBar = "N/A"
            }
            
            # BitLocker status
            $blStatus = ""
            if ($Script:VolumeEncryption.ContainsKey($v.DriveLetter)) {
                $enc = $Script:VolumeEncryption[$v.DriveLetter]
                $blColor = switch ($enc.Protection) {
                    "Protected"   { "background: #28a745; color: white;" }
                    "Unprotected" { "background: #dc3545; color: white;" }
                    default       { "background: #6c757d; color: white;" }
                }
                $blStatus = "<span style='padding: 2px 8px; border-radius: 4px; font-size: 11px; $blColor'>$($enc.Protection)</span><br><span style='font-size: 10px; color: #666;'>$($enc.Method)</span>"
            } else {
                $blStatus = "<span style='font-size: 11px; color: #999;'>N/A</span>"
            }
            
            $html += "                        <tr>`n"
            $html += "                            <td><strong>$($v.DriveLetter)</strong></td>`n"
            $html += "                            <td>$(ConvertTo-HtmlSafe $v.VolumeName)</td>`n"
            $html += "                            <td>$($v.DriveType)</td>`n"
            $html += "                            <td>$($v.FileSystem)</td>`n"
            $html += "                            <td>$($v.TotalGB)</td>`n"
            $html += "                            <td>$($v.UsedGB)</td>`n"
            $html += "                            <td>$($v.FreeGB)</td>`n"
            $html += "                            <td>$usageBar</td>`n"
            $html += "                            <td>$blStatus</td>`n"
            $html += "                        </tr>`n"
        }
        $html += @"
                    </tbody>
                </table>
            </div>
        </div>
"@
    }

    # Add Windows Features Inventory Section
    if ($Script:WindowsFeatures -and $Script:WindowsFeatures.Count -gt 0) {
        $enabledCount = @($Script:WindowsFeatures | Where-Object { $_.State -eq 'Enabled' }).Count
        $html += @"
        
        <div class="section" id="windows-features">
            <div class="section-header"> Windows Optional Features ($($Script:WindowsFeatures.Count) total, $enabledCount enabled)</div>
            <div class="inventory-filter">
                <input type="text" id="featureSearch" placeholder="Search features..." onkeyup="filterFeatures()">
                <select id="featureStateFilter" onchange="filterFeatures()">
                    <option value="">All States</option>
                    <option value="Enabled">Enabled</option>
                    <option value="Disabled">Disabled</option>
                </select>
                <select id="featureRiskFilter" onchange="filterFeatures()">
                    <option value="">All Risk Levels</option>
                    <option value="High">High Risk</option>
                    <option value="Medium">Medium Risk</option>
                    <option value="Low">Low Risk</option>
                    <option value="Info">Info</option>
                    <option value="flagged">Any Flagged</option>
                </select>
            </div>
            <div class="inventory-wrapper">
                <table class="inventory-table" id="featuresTable">
                    <thead>
                        <tr>
                            <th>Feature Name</th>
                            <th>State</th>
                            <th>Security Risk</th>
                            <th>Notes</th>
                            <th>Restart Needed</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        foreach ($feat in ($Script:WindowsFeatures | Sort-Object @{Expression={
            switch ($_.SecurityRisk) { 'High' {0} 'Medium' {1} 'Low' {2} 'Info' {3} default {4} }
        }}, @{Expression={$_.State -eq 'Disabled'}}, FeatureName)) {
            $stateBadge = if ($feat.State -eq 'Enabled') {
                "<span style='background: #28a745; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px;'>Enabled</span>"
            } elseif ($feat.State -eq 'Disabled') {
                "<span style='background: #6c757d; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px;'>Disabled</span>"
            } else {
                "<span style='padding: 2px 8px; border-radius: 4px; font-size: 11px; background: #ffc107; color: #333;'>$($feat.State)</span>"
            }
            
            $riskBadge = switch ($feat.SecurityRisk) {
                'High'   { "<span style='background: #dc3545; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px;'>High</span>" }
                'Medium' { "<span style='background: #ffc107; color: #333; padding: 2px 8px; border-radius: 4px; font-size: 11px;'>Medium</span>" }
                'Low'    { "<span style='background: #17a2b8; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px;'>Low</span>" }
                'Info'   { "<span style='background: #28a745; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px;'>Info</span>" }
                default  { "" }
            }
            
            $rowStyle = ""
            if ($feat.State -eq 'Enabled' -and $feat.SecurityRisk -eq 'High') {
                $rowStyle = " style='background: #f8d7da;'"
            } elseif ($feat.State -eq 'Enabled' -and $feat.SecurityRisk -eq 'Medium') {
                $rowStyle = " style='background: #fff3cd;'"
            }
            
            $html += "                        <tr$rowStyle data-state='$($feat.State)' data-risk='$($feat.SecurityRisk)'>`n"
            $html += "                            <td style='font-family: monospace; font-size: 12px;'>$(ConvertTo-HtmlSafe $feat.FeatureName)</td>`n"
            $html += "                            <td>$stateBadge</td>`n"
            $html += "                            <td>$riskBadge</td>`n"
            $html += "                            <td style='font-size: 12px;'>$(ConvertTo-HtmlSafe $feat.SecurityNote)</td>`n"
            $html += "                            <td>$($feat.RestartNeeded)</td>`n"
            $html += "                        </tr>`n"
        }
        $html += @"
                    </tbody>
                </table>
            </div>
        </div>
"@
    }

    # Add Software Inventory Section
    if ($Script:SoftwareInventory -and $Script:SoftwareInventory.Count -gt 0) {
        $twoYearsAgo = (Get-Date).AddDays(-730)
        
        $html += @"
        
        <div class="software-inventory" id="software-inventory">
            <h3> Software Inventory ($($Script:SoftwareInventory.Count) applications)</h3>
            <div class="inventory-filter">
                <input type="text" id="softwareSearch" placeholder="Search software..." onkeyup="filterSoftware()">
                <select id="archFilter" onchange="filterSoftware()">
                    <option value="">All Architectures</option>
                    <option value="64-bit">64-bit</option>
                    <option value="32-bit">32-bit</option>
                    <option value="User">User-installed</option>
                </select>
                <select id="ageFilter" onchange="filterSoftware()">
                    <option value="">All Ages</option>
                    <option value="old">Older than 2 years</option>
                    <option value="recent">Last 2 years</option>
                </select>
            </div>
            <div class="inventory-wrapper">
                <table class="inventory-table" id="inventoryTable">
                    <thead>
                        <tr>
                            <th>Application Name</th>
                            <th>Publisher</th>
                            <th>Version</th>
                            <th>Install Date</th>
                            <th>Arch</th>
                            <th>Size (MB)</th>
                            <th>Product Code</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        
        foreach ($app in $Script:SoftwareInventory) {
            $isOld = $app.InstallDate -and $app.InstallDate -lt $twoYearsAgo -and -not $app.IsSystemVendor
            $rowClass = if ($isOld) { "old-software" } else { "" }
            $installDateStr = if ($app.InstallDate) { $app.InstallDate.ToString("yyyy-MM-dd") } else { $app.InstallDateRaw }
            $sizeStr = if ($app.EstimatedSizeMB) { $app.EstimatedSizeMB.ToString() } else { "" }
            
            $html += @"
                        <tr class="$rowClass" data-arch="$($app.Architecture)" data-old="$isOld">
                            <td>$(ConvertTo-HtmlSafe $app.DisplayName)</td>
                            <td>$(ConvertTo-HtmlSafe $app.Publisher)</td>
                            <td>$(ConvertTo-HtmlSafe $app.DisplayVersion)</td>
                            <td>$installDateStr</td>
                            <td>$($app.Architecture)</td>
                            <td>$sizeStr</td>
                            <td style="font-size: 10px;">$(ConvertTo-HtmlSafe $app.ProductCode)</td>
                        </tr>
"@
        }
        
        $html += @"
                    </tbody>
                </table>
            </div>
            <p style="font-size: 11px; color: var(--text-secondary); margin-top: 8px;">
                <span style="background: #fff5f5; padding: 2px 6px; border-radius: 3px;">Highlighted rows</span> = Third-party software installed over 2 years ago (review for updates)
            </p>
        </div>
        
        <script>
        function filterFeatures() {
            var search = (document.getElementById('featureSearch') || {}).value || '';
            search = search.toLowerCase();
            var stateFilter = (document.getElementById('featureStateFilter') || {}).value || '';
            var riskFilter = (document.getElementById('featureRiskFilter') || {}).value || '';
            var rows = document.querySelectorAll('#featuresTable tbody tr');
            
            for (var i = 0; i < rows.length; i++) {
                var name = (rows[i].cells[0] || {}).textContent || '';
                var notes = (rows[i].cells[3] || {}).textContent || '';
                var state = rows[i].getAttribute('data-state') || '';
                var risk = rows[i].getAttribute('data-risk') || '';
                
                var show = true;
                if (search && name.toLowerCase().indexOf(search) === -1 && notes.toLowerCase().indexOf(search) === -1) show = false;
                if (stateFilter && state !== stateFilter) show = false;
                if (riskFilter === 'flagged') {
                    if (risk === 'None' || risk === '') show = false;
                } else if (riskFilter && risk !== riskFilter) {
                    show = false;
                }
                
                rows[i].style.display = show ? '' : 'none';
            }
        }
        
        function filterSoftware() {
            var searchText = document.getElementById('softwareSearch').value.toLowerCase();
            var archFilter = document.getElementById('archFilter').value;
            var ageFilter = document.getElementById('ageFilter').value;
            var rows = document.querySelectorAll('#inventoryTable tbody tr');
            
            rows.forEach(function(row) {
                var text = row.textContent.toLowerCase();
                var arch = row.getAttribute('data-arch');
                var isOld = row.getAttribute('data-old') === 'True';
                
                var matchesSearch = text.includes(searchText);
                var matchesArch = !archFilter || arch === archFilter;
                var matchesAge = !ageFilter || 
                    (ageFilter === 'old' && isOld) || 
                    (ageFilter === 'recent' && !isOld);
                
                row.style.display = (matchesSearch && matchesArch && matchesAge) ? '' : 'none';
            });
        }
        </script>
"@
    }
    
    # Add Browser Extensions Section
    if ($Script:BrowserExtensions -and $Script:BrowserExtensions.Count -gt 0) {
        $chromeExtCount = @($Script:BrowserExtensions | Where-Object { $_.Browser -eq 'Chrome' }).Count
        $edgeExtCount = @($Script:BrowserExtensions | Where-Object { $_.Browser -eq 'Edge' }).Count
        $firefoxExtCount = @($Script:BrowserExtensions | Where-Object { $_.Browser -eq 'Firefox' }).Count
        
        $html += @"
        
        <div class="browser-extensions" id="browser-extensions">
            <h3>Browser Extensions ($($Script:BrowserExtensions.Count) total)
                <span style="font-size: 13px; font-weight: normal; margin-left: 10px;">
                    $(if ($chromeExtCount) { "<span class='ext-badge chrome'>Chrome: $chromeExtCount</span>" })
                    $(if ($edgeExtCount) { "<span class='ext-badge edge'>Edge: $edgeExtCount</span>" })
                    $(if ($firefoxExtCount) { "<span class='ext-badge firefox'>Firefox: $firefoxExtCount</span>" })
                </span>
            </h3>
            <div class="inventory-filter">
                <input type="text" id="extSearch" placeholder="Search extensions..." onkeyup="filterExtensions()">
                <select id="browserFilter" onchange="filterExtensions()">
                    <option value="">All Browsers</option>
                    <option value="Chrome">Chrome</option>
                    <option value="Edge">Edge</option>
                    <option value="Firefox">Firefox</option>
                </select>
                <select id="extUserFilter" onchange="filterExtensions()">
                    <option value="">All Users</option>
"@
        
        # Add unique user profiles to dropdown
        $extUsers = $Script:BrowserExtensions | Select-Object -ExpandProperty UserProfile -Unique | Sort-Object
        foreach ($eu in $extUsers) {
            $html += "                    <option value=`"$eu`">$eu</option>`n"
        }
        
        $html += @"
                </select>
                <select id="extTypeFilter" onchange="filterExtensions()">
                    <option value="">All Types</option>
                    <option value="Policy">Policy/GPO</option>
                    <option value="User">User Installed</option>
                </select>
            </div>
            <div class="inventory-wrapper">
                <table class="inventory-table" id="extensionsTable">
                    <thead>
                        <tr>
                            <th>Browser</th>
                            <th>User</th>
                            <th>Profile</th>
                            <th>Extension Name</th>
                            <th>Version</th>
                            <th>Install Type</th>
                            <th>Status</th>
                            <th>Extension ID</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        
        foreach ($ext in $Script:BrowserExtensions) {
            $browserClass = $ext.Browser.ToLower()
            $typeClass = if ($ext.InstallType -eq 'Policy') { "policy" } else { "user" }
            $statusBadge = if ($ext.Enabled) { "Enabled" } else { "<span class='ext-badge disabled'>Disabled</span>" }
            
            $html += @"
                        <tr data-browser="$($ext.Browser)" data-user="$($ext.UserProfile)" data-type="$($ext.InstallType)">
                            <td><span class="ext-badge $browserClass">$($ext.Browser)</span></td>
                            <td>$(ConvertTo-HtmlSafe $ext.UserProfile)</td>
                            <td>$(ConvertTo-HtmlSafe $ext.BrowserProfile)</td>
                            <td><strong>$(ConvertTo-HtmlSafe $ext.Name)</strong>$(if ($ext.Description) { "<br><small style='color: #6c757d;'>$(ConvertTo-HtmlSafe $ext.Description)</small>" })</td>
                            <td>$(ConvertTo-HtmlSafe $ext.Version)</td>
                            <td><span class="ext-badge $typeClass">$($ext.InstallType)</span></td>
                            <td>$statusBadge</td>
                            <td style="font-size: 10px; word-break: break-all;">$(ConvertTo-HtmlSafe $ext.ExtensionId)</td>
                        </tr>
"@
        }
        
        $html += @"
                    </tbody>
                </table>
            </div>
        </div>
        
        <script>
        function filterExtensions() {
            var searchText = document.getElementById('extSearch').value.toLowerCase();
            var browserFilter = document.getElementById('browserFilter').value;
            var userFilter = document.getElementById('extUserFilter').value;
            var typeFilter = document.getElementById('extTypeFilter').value;
            var rows = document.querySelectorAll('#extensionsTable tbody tr');
            
            rows.forEach(function(row) {
                var text = row.textContent.toLowerCase();
                var browser = row.getAttribute('data-browser');
                var user = row.getAttribute('data-user');
                var type = row.getAttribute('data-type');
                
                var matchesSearch = text.includes(searchText);
                var matchesBrowser = !browserFilter || browser === browserFilter;
                var matchesUser = !userFilter || user === userFilter;
                var matchesType = !typeFilter || type === typeFilter;
                
                row.style.display = (matchesSearch && matchesBrowser && matchesUser && matchesType) ? '' : 'none';
            });
        }
        </script>
"@
    }
    
    # Add VS Code Extensions Section
    if ($Script:VSCodeExtensions -and $Script:VSCodeExtensions.Count -gt 0) {
        $userVSExt = @($Script:VSCodeExtensions | Where-Object { $_.InstallType -eq 'User' }).Count
        $builtInVSExt = @($Script:VSCodeExtensions | Where-Object { $_.InstallType -eq 'Built-in' }).Count
        
        # Get unique editors
        $editors = $Script:VSCodeExtensions | Select-Object -ExpandProperty Editor -Unique | Sort-Object
        
        $html += @"
        
        <div class="browser-extensions" id="vscode-extensions">
            <h3>VS Code Extensions ($($Script:VSCodeExtensions.Count) total)
                <span style="font-size: 13px; font-weight: normal; margin-left: 10px;">
                    User: $userVSExt | Built-in: $builtInVSExt
                </span>
            </h3>
            <div class="inventory-filter">
                <input type="text" id="vscSearch" placeholder="Search VS Code extensions..." onkeyup="filterVSCode()">
                <select id="vscEditorFilter" onchange="filterVSCode()">
                    <option value="">All Editors</option>
"@
        foreach ($ed in $editors) {
            $html += "                    <option value=`"$ed`">$ed</option>`n"
        }
        
        $html += @"
                </select>
                <select id="vscUserFilter" onchange="filterVSCode()">
                    <option value="">All Users</option>
"@
        $vscUsers = $Script:VSCodeExtensions | Select-Object -ExpandProperty UserProfile -Unique | Sort-Object
        foreach ($vu in $vscUsers) {
            $html += "                    <option value=`"$vu`">$vu</option>`n"
        }
        
        $html += @"
                </select>
                <select id="vscInstallFilter" onchange="filterVSCode()">
                    <option value="">All Types</option>
                    <option value="User">User Installed</option>
                    <option value="Built-in">Built-in</option>
                </select>
            </div>
            <div class="inventory-wrapper">
                <table class="inventory-table" id="vscodeTable">
                    <thead>
                        <tr>
                            <th>Editor</th>
                            <th>User</th>
                            <th>Extension Name</th>
                            <th>Publisher</th>
                            <th>Version</th>
                            <th>Categories</th>
                            <th>Install Type</th>
                            <th>Extension ID</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        
        foreach ($ext in $Script:VSCodeExtensions) {
            $typeClass = if ($ext.InstallType -eq 'Built-in') { "policy" } else { "user" }
            
            $html += @"
                        <tr data-editor="$($ext.Editor)" data-user="$($ext.UserProfile)" data-type="$($ext.InstallType)">
                            <td>$(ConvertTo-HtmlSafe $ext.Editor)</td>
                            <td>$(ConvertTo-HtmlSafe $ext.UserProfile)</td>
                            <td><strong>$(ConvertTo-HtmlSafe $ext.Name)</strong>$(if ($ext.Description) { "<br><small style='color: #6c757d;'>$(ConvertTo-HtmlSafe $ext.Description)</small>" })</td>
                            <td>$(ConvertTo-HtmlSafe $ext.Publisher)</td>
                            <td>$(ConvertTo-HtmlSafe $ext.Version)</td>
                            <td style="font-size: 11px;">$(ConvertTo-HtmlSafe $ext.Categories)</td>
                            <td><span class="ext-badge $typeClass">$($ext.InstallType)</span></td>
                            <td style="font-size: 10px; word-break: break-all;">$(ConvertTo-HtmlSafe $ext.ExtensionId)</td>
                        </tr>
"@
        }
        
        $html += @"
                    </tbody>
                </table>
            </div>
        </div>
        
        <script>
        function filterVSCode() {
            var searchText = document.getElementById('vscSearch').value.toLowerCase();
            var editorFilter = document.getElementById('vscEditorFilter').value;
            var userFilter = document.getElementById('vscUserFilter').value;
            var typeFilter = document.getElementById('vscInstallFilter').value;
            var rows = document.querySelectorAll('#vscodeTable tbody tr');
            
            rows.forEach(function(row) {
                var text = row.textContent.toLowerCase();
                var editor = row.getAttribute('data-editor');
                var user = row.getAttribute('data-user');
                var type = row.getAttribute('data-type');
                
                var matchesSearch = text.includes(searchText);
                var matchesEditor = !editorFilter || editor === editorFilter;
                var matchesUser = !userFilter || user === userFilter;
                var matchesType = !typeFilter || type === typeFilter;
                
                row.style.display = (matchesSearch && matchesEditor && matchesUser && matchesType) ? '' : 'none';
            });
        }
        </script>
"@
    }
    
    # Add Patch History Section
    if ($Script:PatchHistory -and $Script:PatchHistory.Count -gt 0) {
        $successCount = @($Script:PatchHistory | Where-Object { $_.Result -match 'Succeeded|Installed' }).Count
        $failCount = @($Script:PatchHistory | Where-Object { $_.Result -eq 'Failed' }).Count
        
        # Get unique categories
        $patchTypes = $Script:PatchHistory | Select-Object -ExpandProperty Type -Unique | Sort-Object
        
        $html += @"
        
        <div class="browser-extensions" id="patch-history">
            <h3>Patch Installation History ($($Script:PatchHistory.Count) records)
                <span style="font-size: 13px; font-weight: normal; margin-left: 10px;">
                    <span class="ext-badge" style="background: #28a745; color: white;">Installed: $successCount</span>
                    $(if ($failCount -gt 0) { "<span class='ext-badge' style='background: #dc3545; color: white;'>Failed: $failCount</span>" })
                </span>
            </h3>
            <div class="inventory-filter">
                <input type="text" id="patchSearch" placeholder="Search patches (KB, title)..." onkeyup="filterPatches()">
                <select id="patchTypeFilter" onchange="filterPatches()">
                    <option value="">All Types</option>
"@
        foreach ($pt in $patchTypes) {
            $html += "                    <option value=`"$pt`">$pt</option>`n"
        }
        
        $html += @"
                </select>
                <select id="patchResultFilter" onchange="filterPatches()">
                    <option value="">All Results</option>
                    <option value="success">Succeeded/Installed</option>
                    <option value="failed">Failed</option>
                </select>
                <select id="patchAgeFilter" onchange="filterPatches()">
                    <option value="">All Dates</option>
                    <option value="30">Last 30 Days</option>
                    <option value="90">Last 90 Days</option>
                    <option value="180">Last 6 Months</option>
                    <option value="365">Last Year</option>
                </select>
            </div>
            <div class="inventory-wrapper" style="max-height: 500px;">
                <table class="inventory-table" id="patchTable">
                    <thead>
                        <tr>
                            <th>KB Article</th>
                            <th>Title</th>
                            <th>Date Installed</th>
                            <th>Type</th>
                            <th>Result</th>
                            <th>Source</th>
                            <th>Installed By</th>
                        </tr>
                    </thead>
                    <tbody>
"@
        
        foreach ($patch in $Script:PatchHistory) {
            $dateStr = if ($patch.InstalledOn) { $patch.InstalledOn.ToString('yyyy-MM-dd HH:mm') } else { "Unknown" }
            $dateIso = if ($patch.InstalledOn) { $patch.InstalledOn.ToString('yyyy-MM-dd') } else { "" }
            $resultClass = if ($patch.Result -eq 'Failed') { 
                "style='background: #f8d7da;'" 
            } elseif ($patch.Result -match 'Succeeded|Installed') { 
                "" 
            } else { 
                "style='background: #fff3cd;'" 
            }
            $resultBadge = if ($patch.Result -eq 'Failed') {
                "<span class='ext-badge' style='background: #dc3545; color: white;'>Failed</span>"
            } elseif ($patch.Result -match 'Succeeded|Installed') {
                "<span class='ext-badge' style='background: #28a745; color: white;'>$($patch.Result)</span>"
            } else {
                "<span class='ext-badge' style='background: #ffc107; color: #333;'>$($patch.Result)</span>"
            }
            
            $titleDisplay = ConvertTo-HtmlSafe $patch.Title
            if ($titleDisplay.Length -gt 100) { $titleDisplay = $titleDisplay.Substring(0, 100) + "..." }
            
            $kbLink = if ($patch.KBArticle -and $patch.KBArticle -match 'KB\d+') {
                "<a href='https://support.microsoft.com/help/$($patch.KBArticle -replace 'KB','')' target='_blank' style='color: #0078d4;'>$($patch.KBArticle)</a>"
            } else { 
                ConvertTo-HtmlSafe $patch.KBArticle 
            }
            
            $html += @"
                        <tr $resultClass data-type="$($patch.Type)" data-result="$($patch.Result)" data-date="$dateIso">
                            <td style="white-space: nowrap;">$kbLink</td>
                            <td>$titleDisplay</td>
                            <td style="white-space: nowrap;">$dateStr</td>
                            <td><span class="ext-badge user">$($patch.Type)</span></td>
                            <td>$resultBadge</td>
                            <td style="font-size: 11px;">$(ConvertTo-HtmlSafe $patch.Source)</td>
                            <td style="font-size: 11px;">$(ConvertTo-HtmlSafe $patch.InstalledBy)</td>
                        </tr>
"@
        }
        
        $html += @"
                    </tbody>
                </table>
            </div>
        </div>
        
        <script>
        function filterPatches() {
            var searchText = document.getElementById('patchSearch').value.toLowerCase();
            var typeFilter = document.getElementById('patchTypeFilter').value;
            var resultFilter = document.getElementById('patchResultFilter').value;
            var ageFilter = document.getElementById('patchAgeFilter').value;
            var rows = document.querySelectorAll('#patchTable tbody tr');
            
            var cutoffDate = null;
            if (ageFilter) {
                cutoffDate = new Date();
                cutoffDate.setDate(cutoffDate.getDate() - parseInt(ageFilter));
            }
            
            rows.forEach(function(row) {
                var text = row.textContent.toLowerCase();
                var type = row.getAttribute('data-type');
                var result = row.getAttribute('data-result');
                var dateStr = row.getAttribute('data-date');
                
                var matchesSearch = text.includes(searchText);
                var matchesType = !typeFilter || type === typeFilter;
                
                var matchesResult = true;
                if (resultFilter === 'success') { matchesResult = /Succeeded|Installed/.test(result); }
                else if (resultFilter === 'failed') { matchesResult = result === 'Failed'; }
                
                var matchesAge = true;
                if (cutoffDate && dateStr) {
                    var rowDate = new Date(dateStr);
                    matchesAge = rowDate >= cutoffDate;
                } else if (cutoffDate && !dateStr) {
                    matchesAge = false;
                }
                
                row.style.display = (matchesSearch && matchesType && matchesResult && matchesAge) ? '' : 'none';
            });
        }
        </script>
"@
    }
    
    # Add findings by category
    foreach ($cat in $categories) {
        $catId = $cat -replace '\s+', '-' -replace '[^\w-]', ''
        $catFindings = @($Script:Findings | Where-Object { $_.Category -eq $cat } | Sort-Object RiskValue -Descending)
        $catCritical = @($catFindings | Where-Object { $_.Risk -eq 'Critical' }).Count
        $catHigh = @($catFindings | Where-Object { $_.Risk -eq 'High' }).Count
        
        $html += @"
        
        <div class="section" id="$catId">
            <div class="section-header">
                <span>$(ConvertTo-HtmlSafe $cat)</span>
                <span style="font-size: 14px; font-weight: normal;">
                    $($catFindings.Count) findings
                    $(if ($catCritical) { "<span class='risk-badge risk-critical'>$catCritical Critical</span>" })
                    $(if ($catHigh) { "<span class='risk-badge risk-high'>$catHigh High</span>" })
                </span>
            </div>
            <div class="section-content">
"@
        
        foreach ($finding in $catFindings) {
            $riskClass = "risk-$($finding.Risk.ToLower())"
            $detailsHtml = if ($finding.Details) { "<div class='finding-details'>$(ConvertTo-HtmlSafe $finding.Details)</div>" } else { "" }
            $recHtml = if ($finding.Recommendation) { "<div class='recommendation'>Tip:  $(ConvertTo-HtmlSafe $finding.Recommendation)</div>" } else { "" }
            $refHtml = if ($finding.Reference) { "<div class='reference'>Ref:  Reference: $(ConvertTo-HtmlSafe $finding.Reference)</div>" } else { "" }
            
            $html += @"
                <div class="finding">
                    <div><span class="risk-badge $riskClass">$($finding.Risk)</span></div>
                    <div class="finding-content">
                        <h4>$(ConvertTo-HtmlSafe $finding.Name)</h4>
                        <p>$(ConvertTo-HtmlSafe $finding.Description)</p>
                        $detailsHtml
                        $recHtml
                        $refHtml
                    </div>
                </div>
"@
        }
        
        $html += @"
            </div>
        </div>
"@
    }
    
    $html += @"
        
        <footer class="footer">
            <p>Windows Security Audit Tool v$($Script:AuditVersion) | Generated: $($Script:AuditDate)</p>
            <p>This report is for authorized security compliance auditing purposes only.</p>
        </footer>
    </div>
"@

    # Build embedded JSON for client-side export
    $jsonExport = [ordered]@{
        ReportMetadata = [ordered]@{
            ToolVersion = $Script:AuditVersion
            AuditDate   = $Script:AuditDate
            Hostname    = $Script:Hostname
            RunAsAdmin  = (Test-IsAdmin)
            PrivacyMode = $Script:PrivacyEnabled
        }
        SystemInformation = [ordered]@{
            Hostname     = $Script:SystemInfo.Hostname
            Domain       = $Script:SystemInfo.Domain
            OSName       = $Script:SystemInfo.OSName
            OSBuild      = $Script:SystemInfo.OSBuild
            Architecture = $Script:SystemInfo.Architecture
            Manufacturer = $Script:SystemInfo.Manufacturer
            Model        = $Script:SystemInfo.Model
            SerialNumber = $Script:SystemInfo.SerialNumber
            BIOSVersion  = $Script:SystemInfo.BIOSVersion
            BIOSDate     = $Script:SystemInfo.BIOSDate
            CPU          = $Script:SystemInfo.CPU
            CPUCores     = $Script:SystemInfo.CPUCores
            CPUThreads   = $Script:SystemInfo.CPUThreads
            TotalMemoryGB = $Script:SystemInfo.TotalMemoryGB
            GPUs         = @($Script:SystemInfo.GPUs | ForEach-Object { $_.Name })
            Uptime       = $Script:SystemInfo.Uptime
            LastBoot     = $Script:SystemInfo.LastBoot
            IsVirtualMachine = $Script:SystemInfo.IsVirtualMachine
            VMPlatform   = $Script:SystemInfo.VMPlatform
            VMIndicators = @($Script:SystemInfo.VMIndicators)
            FormFactor   = $Script:SystemInfo.FormFactor
            ChassisType  = $Script:SystemInfo.ChassisType
            HasBattery   = $Script:SystemInfo.HasBattery
            BatteryDetails = @($Script:SystemInfo.BatteryDetails)
        }
        TPM = if ($Script:TPMInfo) {
            [ordered]@{
                Present         = $Script:TPMInfo.Present
                Ready           = $Script:TPMInfo.Ready
                Enabled         = $Script:TPMInfo.Enabled
                Activated       = $Script:TPMInfo.Activated
                Owned           = $Script:TPMInfo.Owned
                Version         = $Script:TPMInfo.Version
                SpecVersion     = $Script:TPMInfo.SpecVersion
                Manufacturer    = $Script:TPMInfo.Manufacturer
                FirmwareVersion = $Script:TPMInfo.FirmwareVersion
                PPIVersion      = $Script:TPMInfo.PPIVersion
                OwnerAuth       = $Script:TPMInfo.OwnerAuth
                BlockClear      = $Script:TPMInfo.BlockClear
                IsVulnerable    = $Script:TPMInfo.IsVulnerable
            }
        } else { $null }
        Summary = [ordered]@{
            TotalFindings = $Script:Findings.Count
            Critical      = @($Script:Findings | Where-Object { $_.Risk -eq 'Critical' }).Count
            High          = @($Script:Findings | Where-Object { $_.Risk -eq 'High' }).Count
            Medium        = @($Script:Findings | Where-Object { $_.Risk -eq 'Medium' }).Count
            Low           = @($Script:Findings | Where-Object { $_.Risk -eq 'Low' }).Count
            Info          = @($Script:Findings | Where-Object { $_.Risk -eq 'Info' }).Count
        }
        Findings = @($Script:Findings | ForEach-Object {
            [ordered]@{
                Category       = $_.Category
                Name           = $_.Name
                Risk           = $_.Risk
                Description    = $_.Description
                Details        = $_.Details
                Recommendation = $_.Recommendation
                Reference      = $_.Reference
            }
        })
        SoftwareInventory = @()
        BrowserExtensions = @()
        VSCodeExtensions  = @()
        PatchHistory      = @()
    }

    if ($Script:CyberEssentials) {
        $ceExport = [ordered]@{ OverallScore = $Script:CyberEssentialsScore }
        foreach ($area in @('Firewalls', 'SecureConfiguration', 'UserAccessControl', 'MalwareProtection', 'PatchManagement')) {
            if ($Script:CyberEssentials.ContainsKey($area)) {
                $ceExport[$area] = [ordered]@{
                    Status  = $Script:CyberEssentials[$area].Status
                    Pass    = $Script:CyberEssentials[$area].Pass
                    Details = $Script:CyberEssentials[$area].Details
                }
            }
        }
        $jsonExport['CyberEssentials'] = $ceExport
    }

    if ($Script:SoftwareInventory) {
        $jsonExport.SoftwareInventory = @($Script:SoftwareInventory | ForEach-Object {
            [ordered]@{
                Name         = $_.DisplayName
                Publisher    = $_.Publisher
                Version      = $_.DisplayVersion
                InstallDate  = if ($_.InstallDate) { $_.InstallDate.ToString('yyyy-MM-dd') } else { $null }
                Architecture = $_.Architecture
                ProductCode  = $_.ProductCode
                IsSystemVendor = $_.IsSystemVendor
            }
        })
    }

    if ($Script:BrowserExtensions) {
        $jsonExport.BrowserExtensions = @($Script:BrowserExtensions | ForEach-Object {
            [ordered]@{
                Browser     = $_.Browser
                User        = $_.UserProfile
                Name        = $_.Name
                ExtensionId = $_.ExtensionId
                Version     = $_.Version
                Enabled     = $_.Enabled
                InstallType = $_.InstallType
            }
        })
    }

    if ($Script:VSCodeExtensions) {
        $jsonExport.VSCodeExtensions = @($Script:VSCodeExtensions | ForEach-Object {
            [ordered]@{
                Editor      = $_.Editor
                User        = $_.UserProfile
                Name        = $_.Name
                Publisher   = $_.Publisher
                Version     = $_.Version
                ExtensionId = $_.ExtensionId
                InstallType = $_.InstallType
            }
        })
    }

    if ($Script:PatchHistory) {
        $jsonExport['PatchHistory'] = @($Script:PatchHistory | ForEach-Object {
            [ordered]@{
                KBArticle   = $_.KBArticle
                Title       = $_.Title
                InstalledOn = if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                Type        = $_.Type
                Result      = $_.Result
                Source      = $_.Source
                InstalledBy = $_.InstalledBy
            }
        })
    }

    if ($Script:DiskInventory -and $Script:DiskInventory.Count -gt 0) {
        $jsonExport['Disks'] = @($Script:DiskInventory | ForEach-Object {
            [ordered]@{
                DiskNumber   = $_.DiskNumber
                Model        = $_.Model
                SerialNumber = $_.SerialNumber
                FirmwareRev  = $_.FirmwareRev
                MediaType    = $_.MediaType
                BusType      = $_.BusType
                SizeGB       = $_.SizeGB
                Partitions   = $_.Partitions
                Health       = $_.Health
                Status       = $_.Status
            }
        })
    }

    if ($Script:VolumeInventory -and $Script:VolumeInventory.Count -gt 0) {
        $jsonExport['Volumes'] = @($Script:VolumeInventory | ForEach-Object {
            $volEnc = $null
            if ($Script:VolumeEncryption.ContainsKey($_.DriveLetter)) {
                $e = $Script:VolumeEncryption[$_.DriveLetter]
                $volEnc = [ordered]@{ Protection = $e.Protection; Conversion = $e.Conversion; Method = $e.Method }
            }
            [ordered]@{
                DriveLetter  = $_.DriveLetter
                VolumeName   = $_.VolumeName
                DriveType    = $_.DriveType
                FileSystem   = $_.FileSystem
                TotalGB      = $_.TotalGB
                UsedGB       = $_.UsedGB
                FreeGB       = $_.FreeGB
                PercentFree  = $_.PercentFree
                PercentUsed  = $_.PercentUsed
                Compressed   = $_.Compressed
                BitLocker    = $volEnc
            }
        })
    }

    if ($Script:WindowsFeatures -and $Script:WindowsFeatures.Count -gt 0) {
        $jsonExport['WindowsFeatures'] = @($Script:WindowsFeatures | ForEach-Object {
            [ordered]@{
                FeatureName   = $_.FeatureName
                State         = $_.State
                SecurityRisk  = $_.SecurityRisk
                SecurityNote  = $_.SecurityNote
                RestartNeeded = $_.RestartNeeded
            }
        })
    }

    # Serialize JSON and sanitize only the </script> sequence to prevent premature tag close
    $embeddedJson = ($jsonExport | ConvertTo-Json -Depth 5) -replace '</script>', '</scr"+"ipt>'

    $html += @"

    <script id="auditJsonData" type="application/json">
$embeddedJson
    </script>
    <script>
    function exportJson() {
        try {
            var dataEl = document.getElementById('auditJsonData');
            var _auditData = JSON.parse(dataEl.textContent);
            var hostname = (_auditData.ReportMetadata && _auditData.ReportMetadata.Hostname) ? _auditData.ReportMetadata.Hostname : 'unknown';
            var now = new Date();
            var ts = now.getFullYear()
                + ('0' + (now.getMonth()+1)).slice(-2)
                + ('0' + now.getDate()).slice(-2)
                + '_' + ('0' + now.getHours()).slice(-2)
                + ('0' + now.getMinutes()).slice(-2)
                + ('0' + now.getSeconds()).slice(-2);
            var filename = 'SecurityAudit_' + hostname + '_' + ts + '.json';
            _auditData.ReportMetadata.ExportDate = now.toISOString();
            var blob = new Blob([JSON.stringify(_auditData, null, 2)], {type: 'application/json'});
            var a = document.createElement('a');
            a.href = URL.createObjectURL(blob);
            a.download = filename;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(a.href);
        } catch(e) {
            alert('JSON export error: ' + e.message);
        }
    }
    </script>
</body>
</html>
"@
    
    return $html
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Export-JsonReport {
    param(
        [Parameter()]
        [string]$JsonOutputPath = $OutputPath
    )
    
    Write-AuditLog "Generating JSON export..." -Level "INFO"
    
    # Ensure output directory exists
    if (-not (Test-Path $JsonOutputPath)) {
        New-Item -ItemType Directory -Path $JsonOutputPath -Force | Out-Null
    }
    
    $jsonHostname = if ($Script:PrivacyEnabled) { "REDACTED" } else { $Script:Hostname }
    $jsonFile = Join-Path $JsonOutputPath "SecurityAudit_${jsonHostname}_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
    
    # Build the export object
    $exportData = [ordered]@{
        ReportMetadata = [ordered]@{
            ToolVersion     = $Script:AuditVersion
            AuditDate       = $Script:AuditDate
            ExportDate      = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
            Hostname        = $Script:Hostname
            RunAsAdmin      = (Test-IsAdmin)
            PrivacyMode     = $Script:PrivacyEnabled
        }
        
        SystemInformation = $Script:SystemInfo
        
        TPM = if ($Script:TPMInfo) { $Script:TPMInfo } else { $null }
        
        Summary = [ordered]@{
            TotalFindings = $Script:Findings.Count
            Critical      = @($Script:Findings | Where-Object { $_.Risk -eq 'Critical' }).Count
            High          = @($Script:Findings | Where-Object { $_.Risk -eq 'High' }).Count
            Medium        = @($Script:Findings | Where-Object { $_.Risk -eq 'Medium' }).Count
            Low           = @($Script:Findings | Where-Object { $_.Risk -eq 'Low' }).Count
            Info          = @($Script:Findings | Where-Object { $_.Risk -eq 'Info' }).Count
            Categories    = @($Script:Findings | Select-Object -ExpandProperty Category -Unique | Sort-Object)
        }
        
        CyberEssentials = $null
        
        Findings = @($Script:Findings | ForEach-Object {
            [ordered]@{
                Category       = $_.Category
                Name           = $_.Name
                Risk           = $_.Risk
                Description    = $_.Description
                Details        = $_.Details
                Recommendation = $_.Recommendation
                Reference      = $_.Reference
            }
        })
        
        SoftwareInventory = @()
        BrowserExtensions = @()
        VSCodeExtensions  = @()
        PatchHistory      = @()
    }
    
    # Add Cyber Essentials if available
    if ($Script:CyberEssentials) {
        $exportData.CyberEssentials = [ordered]@{
            OverallScore = $Script:CyberEssentialsScore
        }
        foreach ($area in @('Firewalls', 'SecureConfiguration', 'UserAccessControl', 'MalwareProtection', 'PatchManagement')) {
            if ($Script:CyberEssentials.ContainsKey($area)) {
                $exportData.CyberEssentials[$area] = [ordered]@{
                    Status  = $Script:CyberEssentials[$area].Status
                    Pass    = $Script:CyberEssentials[$area].Pass
                    Details = $Script:CyberEssentials[$area].Details
                }
            }
        }
    }
    
    # Add Software Inventory
    if ($Script:SoftwareInventory) {
        $exportData.SoftwareInventory = @($Script:SoftwareInventory | ForEach-Object {
            [ordered]@{
                Name           = $_.DisplayName
                Publisher      = $_.Publisher
                Version        = $_.DisplayVersion
                InstallDate    = if ($_.InstallDate) { $_.InstallDate.ToString('yyyy-MM-dd') } else { $null }
                AgeDays        = $_.AgeDays
                Architecture   = $_.Architecture
                ProductCode    = $_.ProductCode
                SizeMB         = $_.EstimatedSizeMB
                IsSystemVendor = $_.IsSystemVendor
            }
        })
    }
    
    # Add Browser Extensions
    if ($Script:BrowserExtensions) {
        $exportData.BrowserExtensions = @($Script:BrowserExtensions | ForEach-Object {
            [ordered]@{
                Browser        = $_.Browser
                UserProfile    = $_.UserProfile
                BrowserProfile = $_.BrowserProfile
                ExtensionId    = $_.ExtensionId
                Name           = $_.Name
                Version        = $_.Version
                Description    = $_.Description
                Enabled        = $_.Enabled
                InstallType    = $_.InstallType
            }
        })
    }
    
    # Add VS Code Extensions
    if ($Script:VSCodeExtensions) {
        $exportData.VSCodeExtensions = @($Script:VSCodeExtensions | ForEach-Object {
            [ordered]@{
                Editor      = $_.Editor
                UserProfile = $_.UserProfile
                Name        = $_.Name
                Publisher   = $_.Publisher
                Version     = $_.Version
                Description = $_.Description
                Categories  = $_.Categories
                ExtensionId = $_.ExtensionId
                InstallType = $_.InstallType
            }
        })
    }
    
    # Add Patch History
    if ($Script:PatchHistory) {
        $exportData['PatchHistory'] = @($Script:PatchHistory | ForEach-Object {
            [ordered]@{
                KBArticle   = $_.KBArticle
                Title       = $_.Title
                InstalledOn = if ($_.InstalledOn) { $_.InstalledOn.ToString('yyyy-MM-dd HH:mm:ss') } else { $null }
                Type        = $_.Type
                Result      = $_.Result
                Source      = $_.Source
                InstalledBy = $_.InstalledBy
            }
        })
    }
    
    if ($Script:DiskInventory -and $Script:DiskInventory.Count -gt 0) {
        $exportData['Disks'] = @($Script:DiskInventory | ForEach-Object {
            [ordered]@{
                DiskNumber = $_.DiskNumber; Model = $_.Model; SerialNumber = $_.SerialNumber
                FirmwareRev = $_.FirmwareRev; MediaType = $_.MediaType; BusType = $_.BusType
                SizeGB = $_.SizeGB; Partitions = $_.Partitions; Health = $_.Health; Status = $_.Status
            }
        })
    }
    
    if ($Script:VolumeInventory -and $Script:VolumeInventory.Count -gt 0) {
        $exportData['Volumes'] = @($Script:VolumeInventory | ForEach-Object {
            $volEnc = $null
            if ($Script:VolumeEncryption.ContainsKey($_.DriveLetter)) {
                $e = $Script:VolumeEncryption[$_.DriveLetter]
                $volEnc = [ordered]@{ Protection = $e.Protection; Conversion = $e.Conversion; Method = $e.Method }
            }
            [ordered]@{
                DriveLetter = $_.DriveLetter; VolumeName = $_.VolumeName; DriveType = $_.DriveType
                FileSystem = $_.FileSystem; TotalGB = $_.TotalGB; UsedGB = $_.UsedGB; FreeGB = $_.FreeGB
                PercentFree = $_.PercentFree; PercentUsed = $_.PercentUsed; Compressed = $_.Compressed
                BitLocker = $volEnc
            }
        })
    }
    
    if ($Script:WindowsFeatures -and $Script:WindowsFeatures.Count -gt 0) {
        $exportData['WindowsFeatures'] = @($Script:WindowsFeatures | ForEach-Object {
            [ordered]@{
                FeatureName = $_.FeatureName; State = $_.State
                SecurityRisk = $_.SecurityRisk; SecurityNote = $_.SecurityNote
            }
        })
    }
    
    # Export - use ConvertTo-Json with sufficient depth
    $exportData | ConvertTo-Json -Depth 5 | Out-File -FilePath $jsonFile -Encoding UTF8
    
    Write-AuditLog "JSON report saved to: $jsonFile" -Level "INFO"
    
    return $jsonFile
}

function Start-SecurityAudit {
    $banner = @"
    
    +===================================================================+
    |     Windows Security Audit Tool - Compliance Edition v$Script:AuditVersion       |
    |                   For Authorized Security Audits                  |
    +===================================================================+
    
"@
    
    if (-not $Quiet) {
        Write-Host $banner -ForegroundColor Cyan
    }
    
    # Privacy mode prompt (unless already set via -PrivacyMode parameter)
    if (-not $PrivacyMode -and -not $Quiet) {
        Write-Host ""
        Write-Host "  Privacy Mode redacts hostnames, usernames, IP addresses," -ForegroundColor White
        Write-Host "  MAC addresses, and serial numbers from the report." -ForegroundColor White
        Write-Host ""
        $privacyChoice = Read-Host "  Enable Privacy Mode? (Y/N) [N]"
        if ($privacyChoice -match '^[Yy]') {
            $Script:PrivacyEnabled = $true
            Write-Host ""
            Write-Host "  [*] Privacy Mode ENABLED - sensitive data will be redacted" -ForegroundColor Green
            Write-Host ""
        }
    } elseif ($PrivacyMode) {
        $Script:PrivacyEnabled = $true
    }
    
    Write-AuditLog "Starting security audit on $($env:COMPUTERNAME)" -Level "INFO"
    Write-AuditLog "Running as: $($env:USERDOMAIN)\$($env:USERNAME)" -Level "INFO"
    Write-AuditLog "Admin privileges: $(Test-IsAdmin)" -Level "INFO"
    if ($Script:PrivacyEnabled) {
        Write-AuditLog "Privacy Mode: ENABLED" -Level "INFO"
    }
    
    if (-not (Test-IsAdmin)) {
        Write-AuditLog "WARNING: Running without admin privileges. Some checks may be limited." -Level "WARN"
    }
    
    # Run all audit modules
    $modules = @(
        { Get-SystemInformation },
        { Test-MDMEnrollment },
        { Get-SoftwareInventory },
        { Test-PasswordPolicy },
        { Test-UserAccounts },
        { Test-AuditPolicy },
        { Test-SecurityOptions },
        { Test-WindowsFeatures },
        { Test-Services },
        { Test-NetworkConfiguration },
        { Test-NetworkProtocols },
        { Test-RemoteAccess },
        { Test-PrivilegeEscalation },
        { Test-SecureBoot },
        { Test-DefenderASR },
        { Test-AppLockerWDAC },
        { Test-ExploitProtection },
        { Test-InstalledSoftware },
        { Test-OfficeSecurity },
        { Test-BrowserSecurity },
        { Get-VSCodeExtensions },
        { Test-PowerShellSecurity },
        { Test-ScheduledTasks },
        { Test-UpdateStatus },
        { Test-HotfixStatus },
        { Test-BitLockerStatus },
        { Test-CredentialStorage },
        { Test-CredentialCaching },
        { Test-LAPS },
        { Test-AutoRunLocations },
        { Test-MediaAutoPlay },
        { Test-EventLogConfiguration },
        { Test-InactivityTimeout },
        { Test-CertificateSecurity },
        { Test-DNSSecurity },
        { Test-FileSystemPermissions },
        { Test-RegistryPermissions },
        { Test-UserRightsAssignments },
        { Test-GroupMemberships },
        { Test-TimeSynchronization },
        { Test-DMAProtection },
        { Test-DriverSigning },
        { Test-ShadowCopies },
        { Test-WindowsSubsystems },
        { Test-TelemetryPrivacy },
        { Test-SystemToolAccess },
        { Test-WindowsRecall }
    )
    
    foreach ($module in $modules) {
        try {
            & $module
        } catch {
            Write-AuditLog "Module failed: $_" -Level "ERROR"
        }
    }
    
    # Generate Cyber Essentials Summary after all modules have run
    Get-CyberEssentialsSummary
    
    # Initialize privacy redactions now that all data has been gathered
    Initialize-PrivacyMode
    
    # Apply privacy redactions to all findings before report generation
    if ($Script:PrivacyEnabled) {
        Write-AuditLog "Privacy Mode: Redacting findings..." -Level "INFO"
        foreach ($finding in $Script:Findings) {
            $finding.Name = Protect-PrivacyString $finding.Name
            $finding.Description = Protect-PrivacyString $finding.Description
            $finding.Details = Protect-PrivacyString $finding.Details
            if ($finding.Recommendation) { $finding.Recommendation = Protect-PrivacyString $finding.Recommendation }
        }
        
        # Redact SystemInfo fields
        $Script:SystemInfo.Hostname = Protect-PrivacyString $Script:SystemInfo.Hostname
        $Script:SystemInfo.Domain = Protect-PrivacyString $Script:SystemInfo.Domain
        $Script:SystemInfo.SerialNumber = Protect-PrivacyString $Script:SystemInfo.SerialNumber
        $Script:Hostname = Protect-PrivacyString $Script:Hostname
        
        # Redact disk serials
        if ($Script:DiskInventory) {
            foreach ($d in $Script:DiskInventory) {
                $d.SerialNumber = Protect-PrivacyString $d.SerialNumber
            }
        }
        
        # Redact VM indicators
        if ($Script:SystemInfo.VMIndicators) {
            $Script:SystemInfo.VMIndicators = @($Script:SystemInfo.VMIndicators | ForEach-Object { Protect-PrivacyString $_ })
        }
        
        # Redact battery details
        if ($Script:SystemInfo.BatteryDetails) {
            $Script:SystemInfo.BatteryDetails = @($Script:SystemInfo.BatteryDetails | ForEach-Object { Protect-PrivacyString $_ })
        }
        
        # Redact software inventory installed-for users
        if ($Script:SoftwareInventory) {
            foreach ($sw in $Script:SoftwareInventory) {
                if ($sw.PSObject.Properties['InstalledFor']) {
                    $sw.InstalledFor = Protect-PrivacyString $sw.InstalledFor
                }
            }
        }
        
        # Redact patch history InstalledBy
        if ($Script:PatchHistory) {
            foreach ($ph in $Script:PatchHistory) {
                if ($ph.InstalledBy) { $ph.InstalledBy = Protect-PrivacyString $ph.InstalledBy }
            }
        }
    }
    
    # Generate HTML report
    $html = New-HtmlReport
    
    # Final pass: redact any remaining occurrences in the full HTML
    if ($Script:PrivacyEnabled) {
        Write-AuditLog "Privacy Mode: Final HTML redaction pass..." -Level "INFO"
        $html = Protect-PrivacyString $html
    }
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $reportHostname = if ($Script:PrivacyEnabled) { "REDACTED" } else { $Script:Hostname }
    $reportFile = Join-Path $OutputPath "SecurityAudit_${reportHostname}_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $html | Out-File -FilePath $reportFile -Encoding UTF8
    
    Write-AuditLog "Audit complete!" -Level "SUCCESS"
    Write-AuditLog "Report saved to: $reportFile" -Level "INFO"
    if ($Script:PrivacyEnabled) {
        Write-AuditLog "Privacy Mode: Report has been redacted" -Level "INFO"
    }
    
    # Export JSON if requested via CLI parameter
    if ($ExportJson) {
        $jsonFile = Export-JsonReport -JsonOutputPath $OutputPath
        # Redact JSON file contents
        if ($Script:PrivacyEnabled -and (Test-Path $jsonFile)) {
            Write-AuditLog "Privacy Mode: Redacting JSON export..." -Level "INFO"
            $jsonContent = Get-Content -Path $jsonFile -Raw -Encoding UTF8
            $jsonContent = Protect-PrivacyString $jsonContent
            $jsonContent | Out-File -FilePath $jsonFile -Encoding UTF8 -Force
        }
        Write-AuditLog "JSON exported to: $jsonFile" -Level "INFO"
    }
    
    # Summary - use @() to ensure 0 instead of $null when no findings
    $criticalCount = @($Script:Findings | Where-Object { $_.Risk -eq 'Critical' }).Count
    $highCount = @($Script:Findings | Where-Object { $_.Risk -eq 'High' }).Count
    $mediumCount = @($Script:Findings | Where-Object { $_.Risk -eq 'Medium' }).Count
    $lowCount = @($Script:Findings | Where-Object { $_.Risk -eq 'Low' }).Count
    
    Write-Host "`n" -NoNewline
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "                         AUDIT SUMMARY                              " -ForegroundColor White
    Write-Host "===================================================================" -ForegroundColor Cyan
    Write-Host "  Total Findings: $($Script:Findings.Count)" -ForegroundColor White
    Write-Host "  Critical: " -NoNewline -ForegroundColor White
    Write-Host "$criticalCount" -ForegroundColor Red
    Write-Host "  High: " -NoNewline -ForegroundColor White
    Write-Host "$highCount" -ForegroundColor DarkYellow
    Write-Host "  Medium: " -NoNewline -ForegroundColor White
    Write-Host "$mediumCount" -ForegroundColor Yellow
    Write-Host "  Low: " -NoNewline -ForegroundColor White
    Write-Host "$lowCount" -ForegroundColor Cyan
    Write-Host "===================================================================" -ForegroundColor Cyan
    
    return $reportFile
}

# Run the audit
Start-SecurityAudit
