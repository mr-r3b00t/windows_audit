<#
.SYNOPSIS
    Windows Security Audit Tool - Compliance Edition v1.1.0
    
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
    
.EXAMPLE
    .\WinSecurityAudit.ps1 -OutputPath "C:\AuditReports"
    
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
    [switch]$Quiet
)

#Requires -Version 5.0

# ============================================================================
# CONFIGURATION & GLOBALS
# ============================================================================

$Script:AuditVersion = "1.1.0"
$Script:AuditDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$Script:Hostname = $env:COMPUTERNAME
$Script:Findings = [System.Collections.ArrayList]::new()

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
    
    $Script:SystemInfo = [PSCustomObject]@{
        Hostname        = $env:COMPUTERNAME
        Domain          = $env:USERDOMAIN
        OSName          = $os.Caption
        OSVersion       = $os.Version
        OSBuild         = $os.BuildNumber
        Architecture    = $os.OSArchitecture
        InstallDate     = $os.InstallDate
        LastBoot        = $os.LastBootUpTime
        Manufacturer    = $cs.Manufacturer
        Model           = $cs.Model
        BIOSVersion     = $bios.SMBIOSBIOSVersion
        SerialNumber    = $bios.SerialNumber
        TotalMemoryGB   = [math]::Round($cs.TotalPhysicalMemory / 1GB, 2)
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
    
    # CRITICAL: Warn if not running as admin
    if (-not $Script:SystemInfo.IsAdmin) {
        Add-Finding -Category "System Info" -Name "⛔ SCAN RUN WITHOUT ADMIN RIGHTS" -Risk "Critical" `
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

function Test-InstalledSoftware {
    Write-AuditLog "Checking Installed Software..." -Level "INFO"
    
    # Get installed software from registry
    $software = @()
    $regPaths = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*"
    )
    
    foreach ($path in $regPaths) {
        $software += Get-ItemProperty $path -ErrorAction SilentlyContinue | 
            Where-Object { $_.DisplayName } |
            Select-Object DisplayName, DisplayVersion, Publisher, InstallDate
    }
    
    $software = $software | Sort-Object DisplayName -Unique
    
    # Check for known vulnerable/risky software patterns
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
    )
    
    foreach ($check in $riskySoftware) {
        $found = $software | Where-Object { $_.DisplayName -match $check.Pattern }
        foreach ($app in $found) {
            Add-Finding -Category "Software" -Name "Risky Software: $($app.DisplayName)" -Risk $check.Risk `
                -Description $check.Desc `
                -Details "Version: $($app.DisplayVersion), Publisher: $($app.Publisher)" `
                -Recommendation "Update or remove this software if not required"
        }
    }
    
    # Check for common remote access tools (informational)
    $remoteAccessTools = @("RemotePC", "Splashtop", "ConnectWise", "ScreenConnect", "GoToMyPC", "Bomgar", "DameWare")
    foreach ($tool in $remoteAccessTools) {
        $found = $software | Where-Object { $_.DisplayName -match $tool }
        if ($found) {
            Add-Finding -Category "Software" -Name "Remote Access Tool: $($found.DisplayName)" -Risk "Info" `
                -Description "Remote access software detected - verify if authorized" `
                -Details "Version: $($found.DisplayVersion), Publisher: $($found.Publisher)" `
                -Recommendation "Verify this remote access tool is authorized by security policy"
        }
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
    Write-AuditLog "Checking Windows Update Status..." -Level "INFO"
    
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
                        -Reference "Patch Management Policy"
                } elseif ($daysSinceUpdate -gt 30) {
                    Add-Finding -Category "Updates" -Name "Outdated Updates" -Risk "High" `
                        -Description "Windows has not been updated in over 30 days" `
                        -Details "Last update: $lastUpdateDate ($daysSinceUpdate days ago)" `
                        -Recommendation "Apply Windows updates" `
                        -Reference "Patch Management Policy"
                } else {
                    Add-Finding -Category "Updates" -Name "Update Status" -Risk "Info" `
                        -Description "Windows updates are relatively current" `
                        -Details "Last update: $lastUpdateDate ($daysSinceUpdate days ago)"
                }
            } catch {
                Write-AuditLog "Could not parse update date: $_" -Level "WARN"
            }
        }
        
        # Check Windows Update service
        $wuService = Get-Service -Name wuauserv -ErrorAction SilentlyContinue
        if ($wuService.StartType -eq 'Disabled') {
            Add-Finding -Category "Updates" -Name "Windows Update Service Disabled" -Risk "High" `
                -Description "The Windows Update service is disabled" `
                -Details "Service Status: $($wuService.Status), StartType: $($wuService.StartType)" `
                -Recommendation "Enable Windows Update service for security patches"
        }
        
        # Check for WSUS configuration (if managed)
        $wsusServer = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer"
        if ($wsusServer) {
            Add-Finding -Category "Updates" -Name "WSUS Configured" -Risk "Info" `
                -Description "System is configured to use WSUS for updates" `
                -Details "WSUS Server: $wsusServer" `
                -Recommendation "Ensure WSUS server is properly maintained"
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
    
    # Check for WSUS HTTP (non-HTTPS) - can be used for privilege escalation
    $wsusServer = Get-RegistryValue -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate" -Name "WUServer" -Default $null
    if ($wsusServer -and $wsusServer -match '^http://') {
        Add-Finding -Category "Privilege Escalation" -Name "WSUS Using HTTP" -Risk "High" `
            -Description "WSUS is configured to use HTTP instead of HTTPS - vulnerable to MITM attacks" `
            -Details "WSUS Server: $wsusServer" `
            -Recommendation "Configure WSUS to use HTTPS" `
            -Reference "WSUSpect Attack"
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
    
    # Check TPM status
    try {
        $tpm = Get-Tpm -ErrorAction Stop
        if ($tpm.TpmPresent -and $tpm.TpmReady) {
            Add-Finding -Category "Hardware Security" -Name "TPM Status" -Risk "Info" `
                -Description "TPM is present and ready" `
                -Details "Present: $($tpm.TpmPresent), Ready: $($tpm.TpmReady), Enabled: $($tpm.TpmEnabled)"
        } elseif ($tpm.TpmPresent) {
            Add-Finding -Category "Hardware Security" -Name "TPM Not Ready" -Risk "Low" `
                -Description "TPM is present but not ready" `
                -Details "Present: $($tpm.TpmPresent), Ready: $($tpm.TpmReady)" `
                -Recommendation "Initialize TPM in BIOS/UEFI settings"
        } else {
            Add-Finding -Category "Hardware Security" -Name "No TPM Detected" -Risk "Low" `
                -Description "No TPM detected on this system" `
                -Details "TPM not present" `
                -Recommendation "TPM is recommended for full disk encryption and attestation"
        }
    } catch {
        Add-Finding -Category "Hardware Security" -Name "TPM Status Unknown" -Risk "Info" `
            -Description "Could not determine TPM status"
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
    Write-AuditLog "Checking Installed Hotfixes..." -Level "INFO"
    
    try {
        $hotfixes = Get-HotFix -ErrorAction Stop | Sort-Object InstalledOn -Descending
        $recentHotfixes = @($hotfixes | Where-Object { $_.InstalledOn -gt (Get-Date).AddDays(-30) })
        
        Add-Finding -Category "Hotfixes" -Name "Installed Hotfixes" -Risk "Info" `
            -Description "System hotfix inventory" `
            -Details "Total hotfixes: $($hotfixes.Count)`nRecent (30 days): $($recentHotfixes.Count)`nLast: $(($hotfixes | Select-Object -First 1).HotFixID)"
        
        if ($hotfixes.Count -gt 0) {
            $lastUpdate = ($hotfixes | Select-Object -First 1).InstalledOn
            if ($lastUpdate -and $lastUpdate -lt (Get-Date).AddDays(-60)) {
                Add-Finding -Category "Hotfixes" -Name "Stale Hotfix Installation" -Risk "High" `
                    -Description "No hotfixes installed in the last 60 days" `
                    -Details "Last hotfix: $lastUpdate" `
                    -Recommendation "Check Windows Update and apply pending patches"
            }
        }
    } catch {
        Add-Finding -Category "Hotfixes" -Name "Hotfix Check Failed" -Risk "Info" `
            -Description "Could not retrieve hotfix information" `
            -Details "Error: $_"
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
        "<span style='color: #90EE90;'>✓ Administrator</span>"
    } else {
        "<span style='color: #ff6b6b; font-weight: bold;'>⛔ NOT ADMIN - LIMITED RESULTS</span>"
    }
    
    # Determine page title
    $pageTitle = if ($Script:SystemInfo.IsAdmin) {
        "Windows Security Audit Report - $($Script:Hostname)"
    } else {
        "⚠️ INCOMPLETE - Windows Security Audit Report - $($Script:Hostname)"
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
                <h1>🛡️ Windows Security Audit Report</h1>
                <div class="header-meta">
                    <div><strong>Hostname:</strong> $($Script:SystemInfo.Hostname)</div>
                    <div><strong>Audit Date:</strong> $($Script:AuditDate)</div>
                    <div><strong>Auditor:</strong> $($Script:SystemInfo.CurrentUser)</div>
                    <div><strong>Tool Version:</strong> $($Script:AuditVersion)</div>
                    <div><strong>Privileges:</strong> $headerAdminStatus</div>
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
            <h2>⛔ LIMITED SCAN - NOT RUNNING AS ADMINISTRATOR</h2>
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
            <p style="margin-top: 15px;"><strong>⚠️ ACTION REQUIRED:</strong> Re-run this audit from an elevated PowerShell prompt (Run as Administrator) for complete results.</p>
        </div>
        
"@
    }

    $html += @"
        <div class="disclaimer">
            <strong>⚠️ Disclaimer:</strong> This report is generated for authorized security compliance auditing purposes only. 
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
        
        <div class="toc">
            <h3>📋 Table of Contents</h3>
            <ul>
"@
    
    # Add TOC entries
    $categories = $Script:Findings | Select-Object -ExpandProperty Category -Unique | Sort-Object
    foreach ($cat in $categories) {
        $catId = $cat -replace '\s+', '-' -replace '[^\w-]', ''
        $html += "                <li><a href='#$catId'>$cat</a></li>`n"
    }
    
    $adminStatusHtml = if ($Script:SystemInfo.IsAdmin) {
        "<span style='color: #28a745; font-weight: bold;'>✓ Yes</span>"
    } else {
        "<span style='color: #dc3545; font-weight: bold;'>⛔ NO - RESULTS INCOMPLETE</span>"
    }
    
    $html += @"
            </ul>
        </div>
        
        <div class="section">
            <div class="section-header">💻 System Information</div>
            <div class="system-info-grid">
                <div class="system-info-item"><span class="label">Hostname</span><span class="value">$(ConvertTo-HtmlSafe $Script:SystemInfo.Hostname)</span></div>
                <div class="system-info-item"><span class="label">Domain</span><span class="value">$(ConvertTo-HtmlSafe $Script:SystemInfo.Domain)</span></div>
                <div class="system-info-item"><span class="label">Operating System</span><span class="value">$(ConvertTo-HtmlSafe $Script:SystemInfo.OSName)</span></div>
                <div class="system-info-item"><span class="label">OS Build</span><span class="value">$(ConvertTo-HtmlSafe $Script:SystemInfo.OSBuild)</span></div>
                <div class="system-info-item"><span class="label">Architecture</span><span class="value">$(ConvertTo-HtmlSafe $Script:SystemInfo.Architecture)</span></div>
                <div class="system-info-item"><span class="label">Last Boot</span><span class="value">$($Script:SystemInfo.LastBoot)</span></div>
                <div class="system-info-item"><span class="label">Total Memory</span><span class="value">$($Script:SystemInfo.TotalMemoryGB) GB</span></div>
                <div class="system-info-item"><span class="label">PowerShell Version</span><span class="value">$($Script:SystemInfo.PowerShellVer)</span></div>
                <div class="system-info-item"><span class="label">Running as Admin</span><span class="value">$adminStatusHtml</span></div>
            </div>
        </div>
"@
    
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
            $recHtml = if ($finding.Recommendation) { "<div class='recommendation'>💡 $(ConvertTo-HtmlSafe $finding.Recommendation)</div>" } else { "" }
            $refHtml = if ($finding.Reference) { "<div class='reference'>📚 Reference: $(ConvertTo-HtmlSafe $finding.Reference)</div>" } else { "" }
            
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
</body>
</html>
"@
    
    return $html
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

function Start-SecurityAudit {
    $banner = @"
    
    ╔═══════════════════════════════════════════════════════════════════╗
    ║     Windows Security Audit Tool - Compliance Edition v$Script:AuditVersion       ║
    ║                   For Authorized Security Audits                  ║
    ╚═══════════════════════════════════════════════════════════════════╝
    
"@
    
    if (-not $Quiet) {
        Write-Host $banner -ForegroundColor Cyan
    }
    
    Write-AuditLog "Starting security audit on $($env:COMPUTERNAME)" -Level "INFO"
    Write-AuditLog "Running as: $($env:USERDOMAIN)\$($env:USERNAME)" -Level "INFO"
    Write-AuditLog "Admin privileges: $(Test-IsAdmin)" -Level "INFO"
    
    if (-not (Test-IsAdmin)) {
        Write-AuditLog "WARNING: Running without admin privileges. Some checks may be limited." -Level "WARN"
    }
    
    # Run all audit modules
    $modules = @(
        { Get-SystemInformation },
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
        { Test-TelemetryPrivacy }
    )
    
    foreach ($module in $modules) {
        try {
            & $module
        } catch {
            Write-AuditLog "Module failed: $_" -Level "ERROR"
        }
    }
    
    # Generate report
    $html = New-HtmlReport
    
    # Ensure output directory exists
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    $reportFile = Join-Path $OutputPath "SecurityAudit_$($Script:Hostname)_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    $html | Out-File -FilePath $reportFile -Encoding UTF8
    
    Write-AuditLog "Audit complete!" -Level "SUCCESS"
    Write-AuditLog "Report saved to: $reportFile" -Level "INFO"
    
    # Summary - use @() to ensure 0 instead of $null when no findings
    $criticalCount = @($Script:Findings | Where-Object { $_.Risk -eq 'Critical' }).Count
    $highCount = @($Script:Findings | Where-Object { $_.Risk -eq 'High' }).Count
    $mediumCount = @($Script:Findings | Where-Object { $_.Risk -eq 'Medium' }).Count
    $lowCount = @($Script:Findings | Where-Object { $_.Risk -eq 'Low' }).Count
    
    Write-Host "`n" -NoNewline
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "                         AUDIT SUMMARY                              " -ForegroundColor White
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    Write-Host "  Total Findings: $($Script:Findings.Count)" -ForegroundColor White
    Write-Host "  Critical: " -NoNewline -ForegroundColor White
    Write-Host "$criticalCount" -ForegroundColor Red
    Write-Host "  High: " -NoNewline -ForegroundColor White
    Write-Host "$highCount" -ForegroundColor DarkYellow
    Write-Host "  Medium: " -NoNewline -ForegroundColor White
    Write-Host "$mediumCount" -ForegroundColor Yellow
    Write-Host "  Low: " -NoNewline -ForegroundColor White
    Write-Host "$lowCount" -ForegroundColor Cyan
    Write-Host "═══════════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    
    return $reportFile
}

# Run the audit
Start-SecurityAudit
