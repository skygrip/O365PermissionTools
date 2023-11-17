function Get-All-Mailbox-Permissions {
    param(
        [Parameter(Mandatory)]
        [string]$Mailbox
    )
    $AllFolderPermissions = @()
    $MBX = Get-Mailbox $Mailbox
    $MBXInboxRules = Get-InboxRule -Mailbox $Mailbox
    $MBXpermission = get-mailboxpermission $Mailbox | where { ($_.User -notlike "NT AUTHORITY\SELF") }
    $MBXSendAs = Get-EXORecipientPermission $MBX | where { ($_.Trustee -notlike "NT AUTHORITY\SELF") } | ft Identity, Trustee, AccessRights, AccessControlType, Inherited
    $MBXSendonBehalf = $MBX.GrantSendOnBehalfTo | where { ($_) } | get-user | where { ($_.RecipientType -notlike "MailUser") } | ft Name, DisplayName, RecipientType
    $MBXCalendarProcessing = Get-CalendarProcessing $Mailbox
    $MBXCalendarDelegates = $MBXCalendarProcessing.ResourceDelegates | where { ($_) } | get-user | where { ($_.RecipientType -notlike "MailUser") } | ft Name, DisplayName, RecipientType
    # get a list of all folders
    $MBXfolders = Get-EXOMailboxFolderStatistics $Mailbox | select FolderPath | where { ($_.FolderPath -notlike "/Top of Information Store") }
    # Get Top permissions
    $allfolderpermissions += Get-EXOMailboxFolderPermission $Mailbox | where { ($_.AccessRights -notlike "None") } | where { ($_.User -notlike "NT AUTHORITY\SELF") }
    # Loop over every folder
    Foreach ($MBXfolder in $MBXfolders) {
        try {
            $folder = $MBX.PrimarySmtpAddress + ":" + $MBXfolder.FolderPath -replace '/', '\'
            $folderpermissions = Get-EXOMailboxFolderPermission -Identity $folder -ErrorAction Stop | where { ($_.AccessRights -notlike "None") } | where { ($_.User -notlike "NT AUTHORITY\SELF") }
            $allfolderpermissions += $folderpermissions
        }
        catch {
            Write-Output "Error: failed to read permissions on folder: $folder"
            Continue
        }
    }
    Write-Output "========== Mailbox Settings ========="
    Write-Output "Mailbox: $($MBX.PrimarySmtpAddress)"
    Write-Output "UPN: $($MBX.UserPrincipalName)"   
    Write-Output "ForwardingSmtpAddress: $($MBX.ForwardingSmtpAddress)"
    Write-Output "DeliverToMailboxAndForward: $($MBX.DeliverToMailboxAndForward)"
    Write-Output ""
    Write-Output "========= Calendar Permissions ========="
    Write-Output "ForwardRequestsToDelegates: $($CalendarProcessing.ForwardRequestsToDelegates)"
    Write-Output "ResourceDelegates"
    Write-Output $MBXCalendarDelegates
    Write-Output ""
    Write-Output "========= Send As Permissions ========="
    Write-Output "These settings can be modified with the following command"
    Write-Output "#Remove-RecipientPermission -AccessRights SendAs -Identity $($MBX.PrimarySmtpAddress)"
    write-output $MBXSendAs
    write-output ""
    Write-Output "========= Send On Behalf Permissions ========="
    Write-Output "These settings can be modified with the following command"
    Write-Output "#Set-Mailbox $($MBX.PrimarySmtpAddress) -GrantSendOnBehalfTo @{Remove=""USER""}"
    write-output $MBXSendonBehalf
    write-output ""
    Write-Output "========= Mailbox Permissions ========="
    Write-Output "These settings can be modified with the following command"
    Write-Output "#Remove-MailboxPermission $($MBX.PrimarySmtpAddress) -AccessRights FullAccess -InheritanceType All"
    write-output $MBXpermission
    write-output ""
    Write-Output "========= Folder Permissions ========="
    Write-Output "These settings can be modified with the following command"
    Write-Output "#Remove-MailboxFolderPermission"
    Write-Output ($allfolderpermissions | ft)
    write-output ""
    Write-Output "========= Inbox Rules ========="
    Write-Output "These settings can be modified with the following command"
    Write-Output "#Remove-InboxRule"
    write-output ($MBXInboxRules | ft)
}