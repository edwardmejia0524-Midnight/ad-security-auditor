# Active Directory Security Auditor

## Overview
A PowerShell utility designed to audit local Active Directory domain hygiene and flag common security risks such as inactive accounts, password expiration bypasses, and unauthorized Domain Admin memberships.

## Usage
Run the script in an elevated PowerShell session with Active Directory module access:
```powershell
Set-ExecutionPolicy RemoteSigned -Scope Process -Force
.\Audit-ADSecurity.ps1
