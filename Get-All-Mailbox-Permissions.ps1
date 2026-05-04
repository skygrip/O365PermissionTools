<#
.SYNOPSIS
    Retrieves permission and settings data for an Exchange Online mailboxs.

.DESCRIPTION
    Collects various settings and permissions including folder-level permissions, 
    calendar processing rules, inbox rules, and active mobile devices. 
    It formats the data for human-readable console output.

.PARAMETER Mailbox
    The identity of the mailbox to audit. Accepts pipeline input.
#>
function Get-All-Mailbox-Permissions {
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [string]$Mailbox
    )
    $AllFolderPermissions = @()
    
    # Retrieve base mailbox properties and inbox rules
    $MBX = Get-EXOMailbox -Identity $Mailbox -Properties AuditEnabled, AuditLogAgeLimit, DefaultAuditSet, AuditAdmin, AuditDelegate, AuditOwner
    $MBXCAS = Get-CASMailbox -Identity $Mailbox
    $MBXInboxRules = Get-InboxRule -Mailbox $Mailbox
    
    # Retrieve Tenant-wide Application Access Policies
    $AppAccessPolicies = @()
    if (Get-Command Get-ApplicationAccessPolicy -ErrorAction SilentlyContinue) {
        $policies = Get-ApplicationAccessPolicy -ErrorAction SilentlyContinue
        if ($policies) {
            foreach ($policy in $policies) {
                $appName = "Unknown App"
                if (Get-Command Get-MgServicePrincipal -ErrorAction SilentlyContinue) {
                    try {
                        $sp = Get-MgServicePrincipal -Filter "appId eq '$($policy.AppId)'" -ErrorAction Stop | Select-Object -First 1
                        if ($sp) { $appName = $sp.DisplayName }
                    } catch {}
                }
                
                $AppAccessPolicies += [PSCustomObject]@{
                    AppName = $appName
                    AppId = $policy.AppId
                    Description = $policy.Description
                    AccessRight = $policy.AccessRight
                    PolicyScopeGroupId = $policy.PolicyScopeGroupId
                }
            }
        }
    }
    
    # Retrieve top-level permissions, filtering out NT AUTHORITY\SELF
    $MBXpermission = Get-EXOMailboxPermission -Identity $Mailbox | Where-Object { ($_.User -notlike "NT AUTHORITY\SELF") }
    $MBXSendAs = Get-EXORecipientPermission $MBX | Where-Object { ($_.Trustee -notlike "NT AUTHORITY\SELF") } | Format-Table Identity, Trustee, AccessRights, AccessControlType, Inherited -Wrap -AutoSize
    $MBXSendonBehalf = $MBX.GrantSendOnBehalfTo | Where-Object { ($_) } | Get-User | Where-Object { ($_.RecipientType -notlike "MailUser") } | Format-Table Name, DisplayName, RecipientType -Wrap -AutoSize
    
    # Retrieve calendar processing settings and resource delegates
    $MBXCalendarProcessing = Get-CalendarProcessing $Mailbox
    $MBXCalendarDelegates = $MBXCalendarProcessing.ResourceDelegates | Where-Object { ($_) } | Get-User | Where-Object { ($_.RecipientType -notlike "MailUser") } | Format-Table Name, DisplayName, RecipientType -Wrap -AutoSize
    
    # Retrieve any mobile devices associated with the mailbox
    $MBXMobileDevices = Get-MobileDeviceStatistics -Mailbox $Mailbox
    
    # Retrieve Outlook Add-ins (Native Exchange Online apps)
    $MBXAddins = Get-App -Mailbox $Mailbox
    
    # Retrieve OAuth Apps (Requires Microsoft.Graph module)
    $MBXOAuthApps = $null
    if (Get-Command Get-MgUserOauth2PermissionGrant -ErrorAction SilentlyContinue) {
        try {
            $grants = Get-MgUserOauth2PermissionGrant -UserId $MBX.UserPrincipalName -ErrorAction Stop
            if ($grants) {
                $MBXOAuthApps = @()
                foreach ($grant in $grants) {
                    $appName = "Unknown App"
                    try {
                        $sp = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId -ErrorAction Stop
                        if ($sp) { $appName = $sp.DisplayName }
                    } catch {}
                    
                    $MBXOAuthApps += [PSCustomObject]@{
                        Id = $grant.Id
                        AppName = $appName
                        ClientId = $grant.ClientId
                        ConsentType = $grant.ConsentType
                        Scope = $grant.Scope
                    }
                }
            }
        }
        catch {
            write-error "Failed to retrieve OAuth apps for mailbox: $($MBX.PrimarySmtpAddress) $($_.Exception.Message)"
        }
    }
    else {
        write-error "Microsoft.Graph module is not connected."
        write-error "Run 'Connect-MgGraph -TenantId <YourTenantId> -Scopes \"DelegatedPermissionGrant.ReadWrite.All\", \"Directory.Read.All\"' and try again"
    }
    
    # Retrieve a list of all mailbox folders, excluding the root Information Store
    $MBXfolders = Get-EXOMailboxFolderStatistics $Mailbox | Select-Object FolderPath | Where-Object { ($_.FolderPath -notlike "/Top of Information Store") }
    
    # Get Top-level folder permissions
    $allfolderpermissions += Get-EXOMailboxFolderPermission $Mailbox | Where-Object { ($_.AccessRights -notlike "None") } | Where-Object { ($_.User -notlike "NT AUTHORITY\SELF") }
    # Loop over every folder
    Foreach ($MBXfolder in $MBXfolders) {
        try {
            $folder = $MBX.PrimarySmtpAddress + ":" + $MBXfolder.FolderPath -replace '/', '\'
            $folderpermissions = Get-EXOMailboxFolderPermission -Identity $folder -ErrorAction Stop | Where-Object { ($_.AccessRights -notlike "None") } | Where-Object { ($_.User -notlike "NT AUTHORITY\SELF") }
            $allfolderpermissions += $folderpermissions
        }
        catch {
            Write-Output "Error: failed to read permissions on folder: $folder"
            Continue
        }
    }
    # ------------------------------------------------------------------------
    #  Output
    # ------------------------------------------------------------------------
    
    Write-Output "========== Mailbox Settings ========="
    Write-Output "Mailbox: $($MBX.PrimarySmtpAddress)"
    Write-Output "UPN: $($MBX.UserPrincipalName)"   
    Write-Output "ForwardingSmtpAddress: $($MBX.ForwardingSmtpAddress)"
    Write-Output "ForwardingAddress: $($MBX.ForwardingAddress)"
    Write-Output "DeliverToMailboxAndForward: $($MBX.DeliverToMailboxAndForward)"
    Write-Output ""
    Write-Output "========= Mailbox Auditing ========="
    Write-Output "These settings can be modified using Set-Mailbox"
    Write-Output "AuditEnabled: $($MBX.AuditEnabled)"
    Write-Output "AuditLogAgeLimit: $($MBX.AuditLogAgeLimit)"
    Write-Output "DefaultAuditSet: $($MBX.DefaultAuditSet -join ', ')"
    Write-Output "AuditAdmin: $($MBX.AuditAdmin -join ', ')"
    Write-Output "AuditDelegate: $($MBX.AuditDelegate -join ', ')"
    Write-Output "AuditOwner: $($MBX.AuditOwner -join ', ')"
    Write-Output ""
    Write-Output "========= Client Access Settings (Protocols) ========="
    Write-Output "These settings can be modified using Set-CASMailbox"
    Write-Output "ActiveSyncEnabled: $($MBXCAS.ActiveSyncEnabled)"
    Write-Output "EwsEnabled: $($MBXCAS.EwsEnabled)"
    Write-Output "ImapEnabled: $($MBXCAS.ImapEnabled)"
    Write-Output "PopEnabled: $($MBXCAS.PopEnabled)"
    Write-Output "OwaEnabled: $($MBXCAS.OwaEnabled)"
    Write-Output "MAPIEnabled: $($MBXCAS.MAPIEnabled)"
    Write-Output "SmtpClientAuthenticationDisabled: $($MBXCAS.SmtpClientAuthenticationDisabled)"
    Write-Output ""
    Write-Output "========= Calendar Permissions ========="
    Write-Output "ForwardRequestsToDelegates: $($MBXCalendarProcessing.ForwardRequestsToDelegates)"
    Write-Output "ResourceDelegates"
    Write-Output $MBXCalendarDelegates
    Write-Output ""
    Write-Output "========= Send As Permissions ========="
    Write-Output "These settings can be modified with the following command"
    Write-Output "#Remove-RecipientPermission -AccessRights SendAs -Identity $($MBX.PrimarySmtpAddress)"
    Write-Output $MBXSendAs
    Write-Output ""
    Write-Output "========= Send On Behalf Permissions ========="
    Write-Output "These settings can be modified with the following command"
    Write-Output "#Set-Mailbox $($MBX.PrimarySmtpAddress) -GrantSendOnBehalfTo @{Remove=""USER""}"
    Write-Output $MBXSendonBehalf
    Write-Output ""
    Write-Output "========= Mailbox Permissions ========="
    Write-Output "These settings can be modified with the following command"
    Write-Output "#Remove-MailboxPermission $($MBX.PrimarySmtpAddress) -AccessRights FullAccess -InheritanceType All"
    Write-Output $MBXpermission
    Write-Output ""
    Write-Output "========= Folder Permissions ========="
    Write-Output "These settings can be modified with the following command"
    Write-Output "#Remove-MailboxFolderPermission"
    Write-Output ($allfolderpermissions | Format-Table -Wrap -AutoSize)
    Write-Output ""
    Write-Output "========= Inbox Rules ========="
    Write-Output "These settings can be modified with the following command"
    Write-Output "#Remove-InboxRule"
    Write-Output ($MBXInboxRules | Format-Table -Wrap -AutoSize)
    Write-Output ""
    Write-Output "========= Mobile Devices ========="
    Write-Output "These settings can be modified with the following command"
    Write-Output "#Remove-MobileDevice"
    Write-Output ($MBXMobileDevices | Format-Table -Wrap -AutoSize)
    Write-Output ""
    Write-Output "========= Outlook Add-ins ========="
    Write-Output "These are native Outlook add-ins installed for the mailbox."
    Write-Output "These settings can be modified with the following command:"
    Write-Output "#Remove-App -Mailbox $($MBX.PrimarySmtpAddress) -Identity <AppId>"
    Write-Output ($MBXAddins | Format-Table DisplayName, AppId, Enabled, AppVersion, DefaultStateForUser -Wrap -AutoSize)
    Write-Output ""
    Write-Output "========= OAuth Apps (User Consents) ========="
    Write-Output "These are Azure AD OAuth permissions consented to by the user."
    Write-Output "Requires Microsoft.Graph module and Connect-MgGraph."
    Write-Output "#Revoke-MgUserOauth2PermissionGrant -UserId $($MBX.UserPrincipalName) -OAuth2PermissionGrantId <Id>"
    if ($MBXOAuthApps) {
        Write-Output ($MBXOAuthApps | Format-Table AppName, ClientId, Scope, ConsentType, Id -Wrap -AutoSize)
    }
    else {
        Write-Output "None found or Microsoft.Graph module is not connected."
    }
    Write-Output ""
    Write-Output "========= Application Access Policies (Tenant-Wide) ========="
    Write-Output "These policies restrict or grant OAuth app access to mailboxes based on groups."
    Write-Output "Note: This lists all tenant policies. You must check if this mailbox is in the PolicyScopeGroupId."
    if ($AppAccessPolicies) {
        Write-Output ($AppAccessPolicies | Format-Table AppName, AccessRight, PolicyScopeGroupId, AppId, Description -Wrap -AutoSize)
    }
    else {
        Write-Output "No Application Access Policies found in this tenant."
    }
    Write-Output ""
}