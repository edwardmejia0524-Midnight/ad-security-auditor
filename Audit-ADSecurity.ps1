<#
.SYNOPSIS
    Active Directory Security & Hygiene Auditor
.DESCRIPTION
    Scans the local Active Directory domain for common security misconfigurations:
    - Inactive user accounts (no login in 90+ days)
    - Accounts with passwords set to never expire
    - High-privileged members in Domain Admins
.OUTPUTS
    Generates a CSV report file on the desktop.
#>

Import-Module ActiveDirectory

$ReportPath = "$env:USERPROFILE\Desktop\AD_Security_Audit_Report.csv"
$Results = [System.Collections.Generic.List[PSCustomObject]]::New()

Write-Host "[+] Starting Active Directory Security Audit..." -ForegroundColor Cyan

# 1. Check for Inactive Users (90+ days or never logged in)
$ThresholdDate = (Get-Date).AddDays(-90)
$InactiveUsers = Get-ADUser -Filter {Enabled -eq $true} -Properties LastLogonDate, PasswordNeverExpires

foreach ($User in $InactiveUsers) {
    if (($null -eq $User.LastLogonDate) -or ($User.LastLogonDate -lt $ThresholdDate)) {
        $Results.Add([PSCustomObject]@{
            CheckType         = "Inactive User"
            Identity          = $User.SamAccountName
            Details           = "Last Logon: $(if($User.LastLogonDate){$User.LastLogonDate}else{"Never"})"
            RiskLevel         = "Medium"
        })
    }
}

# 2. Check for Passwords Set to Never Expire
$NeverExpireUsers = Get-ADUser -Filter {Enabled -eq $true -and PasswordNeverExpires -eq $true} -Properties PasswordNeverExpires

foreach ($User in $NeverExpireUsers) {
    $Results.Add([PSCustomObject]@{
        CheckType         = "Password Never Expires"
        Identity          = $User.SamAccountName
        Details           = "Password policy bypass detected"
        RiskLevel         = "Low-Medium"
    })
}

# 3. Check Privileged Group Members (Domain Admins)
$DomainAdmins = Get-ADGroupMember -Identity "Domain Admins" -Recursive

foreach ($Admin in $DomainAdmins) {
    $Results.Add([PSCustomObject]@{
        CheckType         = "Privileged Access"
        Identity          = $Admin.name
        Details           = "Member of Domain Admins group"
        RiskLevel         = "High"
    })
}

# Export Results to CSV
$Results | Export-Csv -Path $ReportPath -NoTypeInformation
Write-Host "[+] Audit complete! Report saved to: $ReportPath" -ForegroundColor Green

# Display summary in console
$Results | Format-Table -AutoSize
