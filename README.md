# O365PermissionTools

A comprehensive PowerShell auditing tool for Exchange Online mailboxes.

`Get-All-Mailbox-Permissions` collects mailbox configurations, permissions, delegate access, legal/litigation holds, hidden inbox rules, client protocol settings, mobile devices, Outlook add-ins, Entra ID OAuth grants, and tenant-wide Application Access Policies.

---

## ⚡ Quick Start (1-Liner)

Load the script directly into your current PowerShell session without downloading files or cloning the repo:

```powershell
irm https://raw.githubusercontent.com/skygrip/O365PermissionTools/main/Get-All-Mailbox-Permissions.ps1 | iex
```

Or download it locally:

```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/skygrip/O365PermissionTools/main/Get-All-Mailbox-Permissions.ps1" -OutFile "$HOME\Get-All-Mailbox-Permissions.ps1"
```

---

## 📋 Prerequisites

Before running the tool, connect to Exchange Online:

```powershell
Connect-ExchangeOnline
```

*(Optional)* For Entra ID OAuth application audit data, also connect to Microsoft Graph:

```powershell
Connect-MgGraph -Scopes "DelegatedPermissionGrant.ReadWrite.All", "Directory.Read.All"
```

---

## 🚀 Usage Examples

### 1. Formatted Console Output
Run a comprehensive audit on a single mailbox and display formatted output in the console:

```powershell
Get-All-Mailbox-Permissions -Mailbox "user@domain.com"
```

### 2. Structured Object Output (`-AsObject`)
Return a structured `PSCustomObject` for pipeline processing, filtering, or exports:

```powershell
# Export single mailbox audit to formatted JSON
Get-All-Mailbox-Permissions -Mailbox "user@domain.com" -AsObject | ConvertTo-Json -Depth 5

# Batch audit all mailboxes and view in Out-GridView
Get-Mailbox -ResultSize Unlimited | Get-All-Mailbox-Permissions -AsObject | Out-GridView
```

---

## 🔍 Features & Audited Data Points

- **Mailbox Core Settings & Quotas**: UPN, RecipientTypeDetails, hidden status, forwarding addresses, storage usage, and quota thresholds.
- **Online Archive**: Archive status, state, auto-expanding setting, and archive storage usage.
- **Litigation & Legal Holds**: Litigation hold parameters, InPlaceHolds GUID list, delay hold status, retention policies, and single item recovery.
- **Recoverable Items Audit**: Deep inspection of `DiscoveryHolds`, `SubstrateHolds`, and `Purges` subfolders with item counts and date ranges to detect active/stale holds.
- **Delegation Permissions**: FullAccess (with AutoMapping), SendAs, SendOnBehalfTo (with full identity resolution for MailUser, external, and orphaned accounts).
- **Folder Permissions**: Walks all subfolders to report folder-level access rights.
- **Inbox Rules**: Enumerates all rules including **hidden rules** (`-IncludeHidden`) to catch BEC persistence mechanisms.
- **Client Access Settings (CAS)**: Status of OWA, MAPI, EWS, IMAP, POP, ActiveSync, and SMTP Auth protocols.
- **Calendar Settings**: Calendar processing configuration and resolved resource delegates.
- **Active Mobile Devices**: Associated ActiveSync device statistics.
- **Outlook Add-ins**: Native Outlook web/COM add-ins installed on the mailbox.
- **OAuth Application Grants**: User-consented Entra ID OAuth permissions (via Microsoft Graph).
- **Application Access Policies**: Tenant-wide OAuth app access restrictions (queried once per execution in `begin{}`).