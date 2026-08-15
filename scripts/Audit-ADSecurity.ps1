<#
.SYNOPSIS
    Active Directory Security & Domain Hygiene Auditor
.DESCRIPTION
    Automates assessment of AD domain hygiene: checks privileged groups, stale accounts, and password policies.
#>

$ErrorActionPreference = "Stop"

# Load configuration
$configPath = "$PSScriptRoot\..\configs\audit_config.json"
if (!(Test-Path $configPath)) {
    Write-Error "Configuration file not found at $configPath"
    exit 1
}
$config = Get-Content $configPath | ConvertFrom-Json

# Import AD module
Import-Module ActiveDirectory

$domain = Get-ADDomain
Write-Host "Target Domain: $($domain.DNSRoot)" -ForegroundColor Cyan

$reportData = [PSCustomObject]@{
    audit_timestamp = (Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
    domain = $domain.DNSRoot
    findings = [PSCustomObject]@{
        privileged_group_members = @()
        stale_accounts = @()
        password_never_expires_accounts = @()
    }
}

# 1. Privileged Groups Check
Write-Host "`n--- Privileged Group Membership Review ---" -ForegroundColor Yellow
foreach ($group in $config.privileged_groups) {
    try {
        $members = Get-ADGroupMember -Identity $group -Recursive
        foreach ($member in $members) {
            Write-Host "Group: $group | Member: $($member.Name) ($($member.SamAccountName))" -ForegroundColor Green
            $reportData.findings.privileged_group_members += [PSCustomObject]@{
                Group = $group
                Name = $member.Name
                SamAccountName = $member.SamAccountName
                Class = $member.objectClass
            }
        }
    } catch {
        Write-Warning "Could not resolve group: $group"
    }
}

# 2. Stale Account Detection
Write-Host "`n--- Stale Account Detection ($($config.inactive_account_threshold_days) Days) ---" -ForegroundColor Yellow
$thresholdDate = (Get-Date).AddDays(-$config.inactive_account_threshold_days)
$staleUsers = Get-ADUser -Filter {Enabled -eq $true -and LastLogonDate -lt $thresholdDate} -Properties LastLogonDate

if ($staleUsers) {
    foreach ($user in $staleUsers) {
        Write-Host "Stale User: $($user.Name) (Last Logon: $($user.LastLogonDate))" -ForegroundColor Red
        $reportData.findings.stale_accounts += [PSCustomObject]@{
            Name = $user.Name
            SamAccountName = $user.SamAccountName
            LastLogonDate = $user.LastLogonDate
        }
    }
} else {
    Write-Host "No stale accounts found exceeding threshold." -ForegroundColor Green
}

# 3. Password Never Expires Check
if ($config.password_never_expires_check) {
    Write-Host "`n--- Password Never Expires Review ---" -ForegroundColor Yellow
    $neverExpiresUsers = Get-ADUser -Filter {Enabled -eq $true -and PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires
    if ($neverExpiresUsers) {
        foreach ($user in $neverExpiresUsers) {
            Write-Host "Exempted User: $($user.Name)" -ForegroundColor Magenta
            $reportData.findings.password_never_expires_accounts += [PSCustomObject]@{
                Name = $user.Name
                SamAccountName = $user.SamAccountName
            }
        }
    } else {
        Write-Host "No active users found with password never expires." -ForegroundColor Green
    }
}

# Export to JSON
$reportPath = "$PSScriptRoot\..\data\audit_report.json"
$reportData | ConvertTo-Json -Depth 5 | Set-Content -Path $reportPath -Encoding UTF8
Write-Host "`nAudit complete. Report saved to $reportPath" -ForegroundColor Cyan
