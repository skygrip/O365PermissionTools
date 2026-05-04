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
    $MBX = Get-EXOMailbox -Identity $Mailbox
    $MBXInboxRules = Get-InboxRule -Mailbox $Mailbox
    
    # Retrieve top-level permissions, filtering out NT AUTHORITY\SELF
    $MBXpermission = Get-EXOMailboxPermission -Identity $Mailbox | Where-Object { ($_.User -notlike "NT AUTHORITY\SELF") }
    $MBXSendAs = Get-EXORecipientPermission $MBX | Where-Object { ($_.Trustee -notlike "NT AUTHORITY\SELF") } | Format-Table Identity, Trustee, AccessRights, AccessControlType, Inherited -Wrap -AutoSize
    $MBXSendonBehalf = $MBX.GrantSendOnBehalfTo | Where-Object { ($_) } | Get-User | Where-Object { ($_.RecipientType -notlike "MailUser") } | Format-Table Name, DisplayName, RecipientType -Wrap -AutoSize
    
    # Retrieve calendar processing settings and resource delegates
    $MBXCalendarProcessing = Get-CalendarProcessing $Mailbox
    $MBXCalendarDelegates = $MBXCalendarProcessing.ResourceDelegates | Where-Object { ($_) } | Get-User | Where-Object { ($_.RecipientType -notlike "MailUser") } | Format-Table Name, DisplayName, RecipientType -Wrap -AutoSize
    
    # Retrieve any mobile devices associated with the mailbox
    $MBXMobileDevices = Get-MobileDeviceStatistics -Mailbox $Mailbox
    
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
}