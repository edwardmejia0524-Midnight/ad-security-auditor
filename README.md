# Home Lab Project: Active Directory Security & Domain Hygiene Auditor

## Repository Structure

```text
ad-security-auditor/
├── configs/
│   └── audit_config.json       # Configuration thresholds for inactive accounts and groups
├── data/
│   └── audit_report.json       # Structured JSON audit report export
├── scripts/
│   └── Audit-ADSecurity.ps1    # PowerShell audit script for domain hygiene checks
├── .gitignore
└── README.md
```

## 1. Project Overview & Architecture

- **Environment**: Windows Server 2022 Active Directory (`DC-Core`) home lab environment managed via Ubuntu Server workspace.
- **Core Tools**: PowerShell ActiveDirectory module, JSON configuration management, Git, and GitHub.
- **Objective**: Automate the assessment of Active Directory domain hygiene. This auditing utility inspects domain security posture by identifying stale/inactive user accounts, checking for risky password policies (such as accounts configured with "Password Never Expires"), and reviewing privileged group memberships (Domain Admins).

## 2. Key Audit Capabilities

- **Privileged Access Review**: Enumerates and validates members of high-privilege groups (`Domain Admins`, `Enterprise Admins`) to detect unauthorized escalations.
- **Stale Account Detection**: Flags user accounts that have been inactive past a configurable threshold (default: 90 days).
- **Password Policy Enforcement**: Identifies active user accounts where password expiration is disabled.
- **Structured Telemetry Export**: Exports findings into standardized JSON reports (`data/audit_report.json`) for tracking and potential SIEM ingestion.

## 3. Usage & Execution

### Execution Steps

1. Log into your Active Directory Domain Controller (`DC-Core`) with administrative privileges.
2. Open PowerShell as Administrator and execute the script:

```powershell
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
.\scripts\Audit-ADSecurity.ps1
```

## 4. File & Directory Descriptions

| Path | Description |
|---|---|
| `configs/` | Contains auditing thresholds and parameters (`audit_config.json`). |
| `data/` | Stores structured security findings and report exports (`audit_report.json`). |
| `scripts/` | Contains core PowerShell auditing automation (`Audit-ADSecurity.ps1`). |
| `README.md` | Comprehensive technical project documentation. |
