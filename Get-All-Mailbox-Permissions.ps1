<#
.SYNOPSIS
    Retrieves permission and settings data for Exchange Online mailboxes.

.DESCRIPTION
    Collects comprehensive mailbox settings, including mailbox type/visibility,
    storage statistics, online archive status, folder-level permissions, calendar
    processing rules, inbox rules (including hidden rules), active mobile devices,
    litigation/legal holds, and recoverable items audit with item timestamps.
    It supports structured object output for CSV/JSON export via -AsObject,
    or formatted console output by default.

.PARAMETER Mailbox
    The identity of the mailbox to audit. Accepts pipeline input by value and
    by property name, so the output of Get-Mailbox or Get-EXOMailbox can be
    piped directly: Get-Mailbox -ResultSize Unlimited | Get-All-Mailbox-Permissions

.PARAMETER AsObject
    Returns the complete mailbox audit report as a structured PSCustomObject
    suitable for pipeline filtering, CSV, or JSON exports. When omitted, the
    function outputs formatted human-readable console text.

    Examples:
        # Export a single mailbox audit to JSON
        Get-All-Mailbox-Permissions -Mailbox user@domain.com -AsObject | ConvertTo-Json -Depth 5

        # Batch audit all mailboxes and open in GridView
        Get-Mailbox -ResultSize Unlimited | Get-All-Mailbox-Permissions -AsObject | Out-GridView

.NOTES
    Prerequisites:
        - Exchange Online PowerShell module (Connect-ExchangeOnline)
        - Microsoft.Graph module is optional; required only for OAuth app data
          (Connect-MgGraph -Scopes "DelegatedPermissionGrant.ReadWrite.All", "Directory.Read.All")
#>
function Get-All-Mailbox-Permissions {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory, ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [ValidateNotNullOrEmpty()]
        [string]$Mailbox,

        [Parameter()]
        [switch]$AsObject
    )

    begin {
        # Verify the ExchangeOnline module is loaded and an active session exists before
        # processing any mailboxes. Get-ConnectionInformation was introduced in EXO v3;
        # the first check guards against older module versions where the cmdlet doesn't exist.
        if (-not (Get-Command Get-ConnectionInformation -ErrorAction SilentlyContinue) -or -not (Get-ConnectionInformation -ErrorAction SilentlyContinue)) {
            Throw "Not connected to Exchange Online. Please run 'Connect-ExchangeOnline' before executing this script."
        }

        # Application Access Policies are tenant-wide, not per-mailbox, so we fetch them
        # once in begin{} rather than on every iteration of process{}. On tenants with many
        # policies this avoids potentially dozens of redundant API calls when auditing
        # multiple mailboxes via pipeline.
        $AppAccessPolicies = [System.Collections.Generic.List[psobject]]::new()
        if (Get-Command Get-ApplicationAccessPolicy -ErrorAction SilentlyContinue) {
            $policies = Get-ApplicationAccessPolicy -ErrorAction SilentlyContinue
            if ($policies) {
                foreach ($policy in $policies) {
                    # Attempt to resolve the AppId to a human-readable display name via
                    # Graph. This requires the Microsoft.Graph module to be connected.
                    # If it isn't available or the lookup fails, we fall back to "Unknown App"
                    # but still record the policy with its AppId intact.
                    $appName = "Unknown App"
                    if (Get-Command Get-MgServicePrincipal -ErrorAction SilentlyContinue) {
                        try {
                            $sp = Get-MgServicePrincipal -Filter "appId eq '$($policy.AppId)'" -ErrorAction Stop | Select-Object -First 1
                            if ($sp) { $appName = $sp.DisplayName }
                        } catch {
                            Write-Verbose "Could not resolve ServicePrincipal for AppId $($policy.AppId): $_"
                        }
                    }

                    $AppAccessPolicies.Add([PSCustomObject]@{
                        AppName            = $appName
                        AppId              = $policy.AppId
                        Description        = $policy.Description
                        AccessRight        = $policy.AccessRight  # RestrictAccess or AllowAccess
                        PolicyScopeGroupId = $policy.PolicyScopeGroupId
                    })
                }
            }
        }
    }

    process {
        # Use a generic list to collect folder permissions across all user folders
        $AllFolderPermissions = [System.Collections.Generic.List[object]]::new()

        # -----------------------------------------------------------------------
        # Phase 1: Data Gathering
        # All Exchange Online and Graph queries are made here and stored in
        # $MailboxReport. The output phase reads exclusively from $MailboxReport,
        # which means the same data is available whether the caller uses -AsObject
        # or the default console output format.
        # -----------------------------------------------------------------------

        # Request only the specific extended properties we need. Get-EXOMailbox returns
        # a limited default property set; audit, hold, archive, and quota fields are
        # non-default and must be explicitly requested via -Properties.
        # Note: Quota limits (IssueWarningQuota, ProhibitSend*) live on the mailbox
        # object, NOT on Get-EXOMailboxStatistics. Fetching them here avoids the need
        # for a separate Get-Mailbox call later.
        # GrantSendOnBehalfTo is part of the default property set today but is listed
        # explicitly here so the intent is clear and the script remains correct if
        # Microsoft moves it to the non-default set in a future module version.
        $MBX = Get-EXOMailbox -Identity $Mailbox -Properties AuditEnabled, AuditLogAgeLimit, DefaultAuditSet, AuditAdmin, AuditDelegate, AuditOwner, `
            LitigationHoldEnabled, LitigationHoldDate, LitigationHoldOwner, LitigationHoldDuration, InPlaceHolds, `
            DelayHoldApplied, ComplianceTagHoldApplied, SingleItemRecoveryEnabled, `
            RetentionPolicy, RetentionHoldEnabled, ElcProcessingDisabled, `
            RecipientTypeDetails, HiddenFromAddressListsEnabled, ArchiveStatus, ArchiveState, AutoExpandingArchiveEnabled, `
            IssueWarningQuota, ProhibitSendQuota, ProhibitSendReceiveQuota, GrantSendOnBehalfTo, `
            SharingPolicy, EmailAddresses, ExternalDirectoryObjectId

        # CAS settings control which client protocols (OWA, MAPI, EWS, IMAP, POP, ActiveSync,
        # SMTP Auth, Outlook Mobile, Mac Outlook) are enabled. Disabling unused protocols reduces attack surface.
        $MBXCAS = Get-CASMailbox -Identity $Mailbox

        # Check if the mailbox is set to bypass mailbox audit logging. If AuditBypassEnabled is $true,
        # all actions by this account are silently excluded from Exchange audit logs.
        $MBXAuditBypass = Get-MailboxAuditBypassAssociation -Identity $Mailbox -ErrorAction SilentlyContinue

        # -IncludeHidden surfaces rules created by malicious actors or legacy tools that
        # set the hidden flag to avoid appearing in the standard Outlook UI. Hidden rules
        # are a common BEC (Business Email Compromise) persistence mechanism.
        $MBXInboxRules = Get-InboxRule -Mailbox $Mailbox -IncludeHidden

        # Usage statistics (item counts and sizes). SilentlyContinue because statistics
        # may be temporarily unavailable for newly created or inactive mailboxes.
        # Quota limits are NOT available from this cmdlet — they come from $MBX above.
        $MBXStats = Get-EXOMailboxStatistics -Identity $Mailbox -ErrorAction SilentlyContinue | `
            Select-Object TotalItemSize, ItemCount, TotalDeletedItemSize, DeletedItemCount

        # Only fetch archive statistics if an archive is actually provisioned.
        # ArchiveState covers both cloud-hosted (HostedProvisioned) and on-premises (Local) archives.
        $MBXArchiveStats = if ($MBX.ArchiveStatus -eq "Active" -or $MBX.ArchiveState -eq "Local" -or $MBX.ArchiveState -eq "HostedProvisioned") {
            Get-EXOMailboxStatistics -Identity $Mailbox -Archive -ErrorAction SilentlyContinue | Select-Object TotalItemSize, ItemCount
        } else { $null }

        # Recoverable Items is a hidden folder tree used by Exchange to preserve deleted
        # and hold-retained data. Inspecting its subfolders reveals whether an active hold
        # is actually retaining content, regardless of what LitigationHoldEnabled reports.
        # -IncludeOldestAndNewestItems gives us item age ranges to identify stale holds.
        # Note: This call uses -FolderScope RecoverableItems which is a separate, targeted
        # request from the full folder list fetched below for permissions — they cannot be merged.
        $RecoverableItemsStats = Get-EXOMailboxFolderStatistics -Identity $Mailbox -FolderScope RecoverableItems -IncludeOldestAndNewestItems | Where-Object { $_.ItemsInFolder -gt 0 } | Select-Object Name, ItemsInFolder, FolderSize, OldestItemReceivedDate, NewestItemReceivedDate

        # DiscoveryHolds = eDiscovery holds applied via Purview/Security & Compliance Center
        # SubstrateHolds = Microsoft 365 retention policy holds applied at the substrate layer
        # Purges         = items awaiting permanent deletion after their hold period expires
        # Items in any of these subfolders indicate an active or recently released hold,
        # even if LitigationHoldEnabled is $false (e.g. a Purview policy is running instead).
        $hasHoldItems = $false
        if ($RecoverableItemsStats) {
            $discoveryOrSubstrate = $RecoverableItemsStats | Where-Object { $_.Name -in @('DiscoveryHolds', 'SubstrateHolds', 'Purges') -and $_.ItemsInFolder -gt 0 }
            if ($discoveryOrSubstrate) {
                $hasHoldItems = $true
            }
        }

        # NT AUTHORITY\SELF is the mailbox owner's implicit self-permission entry and is
        # present on every mailbox. Filtering it out keeps output focused on delegated access.
        $MBXPermission = Get-EXOMailboxPermission -Identity $Mailbox | Where-Object { ($_.User -notlike "NT AUTHORITY\SELF") }
        $MBXSendAs = Get-EXORecipientPermission $MBX | Where-Object { ($_.Trustee -notlike "NT AUTHORITY\SELF") }

        # GrantSendOnBehalfTo stores identities as DN/GUID strings. We resolve each entry
        # via Get-Recipient (which covers all recipient types: UserMailbox, MailUser,
        # MailContact, SharedMailbox, Groups, etc.) rather than Get-User, which would
        # silently drop external/guest users and contacts. Unresolvable identities (e.g.
        # deleted accounts whose references were not cleaned up) are surfaced explicitly
        # as "Unknown/Unresolved" rather than being silently discarded.
        $MBXSendOnBehalf = if ($MBX.GrantSendOnBehalfTo) {
            $MBX.GrantSendOnBehalfTo | Where-Object { $_ } | ForEach-Object {
                $identityStr = $_.ToString()
                $recipient = Get-Recipient -Identity $identityStr -ErrorAction SilentlyContinue
                if ($recipient) {
                    $recipient
                } else {
                    [PSCustomObject]@{
                        Name          = $identityStr
                        DisplayName   = $identityStr
                        RecipientType = "Unknown/Unresolved"
                    }
                }
            }
        } else { $null }

        # Calendar processing settings are primarily relevant for room/equipment resource
        # mailboxes (AutoAccept, ForwardRequestsToDelegates, etc.) but can also reveal
        # delegate configurations on shared or user mailboxes. SilentlyContinue because
        # certain mailbox types (e.g. public folder mailboxes, system mailboxes) do not
        # support calendar processing and will throw if not guarded.
        $MBXCalendarProcessing = Get-CalendarProcessing $Mailbox -ErrorAction SilentlyContinue

        # ResourceDelegates are resolved via Get-Recipient for the same reason as
        # GrantSendOnBehalfTo — to include MailUser/external recipients and surface
        # any unresolvable orphaned references.
        $MBXCalendarDelegates = if ($MBXCalendarProcessing.ResourceDelegates) {
            $MBXCalendarProcessing.ResourceDelegates | Where-Object { $_ } | ForEach-Object {
                $identityStr = $_.ToString()
                $recipient = Get-Recipient -Identity $identityStr -ErrorAction SilentlyContinue
                if ($recipient) {
                    $recipient
                } else {
                    [PSCustomObject]@{
                        Name          = $identityStr
                        DisplayName   = $identityStr
                        RecipientType = "Unknown/Unresolved"
                    }
                }
            }
        } else { $null }

        # SilentlyContinue on both of these because resource/shared mailboxes and certain
        # service accounts may not support mobile device partnerships or the add-ins endpoint,
        # and we don't want a non-critical failure to abort the entire audit.
        # Retrieve Outlook Add-ins (Native Exchange Online apps) and correlate against known default Microsoft AppIDs
        $knownDefaultAppIds = @(
            '9fd38622-d9b4-4401-b1b9-1ce14c5e435a', # Viva Insights
            'fe93bfe1-7947-460a-a5e0-7a5906b51360', # Viva Insights
            'c88ddf0b-47e0-47b2-a42e-efc7d779a528', # Viva Insights / Analytics
            '39352e85-5b4d-453d-82d8-fd2b7a95632a', # Viva Insights
            'f60b8ac7-c3e3-4e42-8dad-e4e1fea59ff7', # Action Items
            '2643a6d4-8d48-43da-91ef-fbc3e9b110f0', # Action Items
            '7a774f0c-7a6f-11e0-85ad-07fb4824019b', # Bing Maps
            'e51b1a0e-030e-4631-b2e5-7e1088d8b67f', # Bing Maps
            'a216ceed-7791-4635-a752-5a4ac0a5eb93', # My Templates
            'bc172159-20ff-4e78-be75-d227b9c9f6d6', # My Templates
            'd39dee0e-fdc3-4015-af8d-94d4d49294b3', # Unsubscribe
            'afde34e6-58a4-4122-8a52-ef402180a878', # Polls
            '6b47614e-0125-454b-9f76-bd5aef85ac7b', # Send to OneNote
            '1b008d51-9252-47d9-b003-7a9d06b5278c'  # Suggested Meetings
        )

        $rawAddins = Get-App -Mailbox $Mailbox -ErrorAction SilentlyContinue
        $MBXAddins = if ($rawAddins) {
            foreach ($app in $rawAddins) {
                [PSCustomObject]@{
                    DisplayName         = $app.DisplayName
                    AppId               = $app.AppId
                    Enabled             = $app.Enabled
                    IN_HARDCODEDLIST    = ($app.AppId -in $knownDefaultAppIds)
                    AppVersion          = $app.AppVersion
                    DefaultStateForUser = $app.DefaultStateForUser
                }
            }
        } else { $null }

        # OAuth permission grants represent third-party apps that have been granted access
        # to the mailbox by the user (e.g. via browser consent prompts). These are separate
        # from native Exchange add-ins and are stored in Entra ID, not Exchange Online.
        # Requires the Microsoft.Graph module; gracefully skipped if unavailable.
        $MBXOAuthApps = $null
        if (Get-Command Get-MgUserOauth2PermissionGrant -ErrorAction SilentlyContinue) {
            try {
                $grants = Get-MgUserOauth2PermissionGrant -UserId $MBX.UserPrincipalName -ErrorAction Stop
                if ($grants) {
                    $MBXOAuthApps = [System.Collections.Generic.List[psobject]]::new()
                    foreach ($grant in $grants) {
                        # Resolve the ClientId (service principal object ID) to a display name
                        # so the output is human-readable without needing to look up GUIDs manually.
                        $appName = "Unknown App"
                        try {
                            $sp = Get-MgServicePrincipal -ServicePrincipalId $grant.ClientId -ErrorAction Stop
                            if ($sp) { $appName = $sp.DisplayName }
                        } catch {
                            Write-Verbose "Could not resolve ServicePrincipal for ClientId $($grant.ClientId): $_"
                        }

                        $MBXOAuthApps.Add([PSCustomObject]@{
                            Id          = $grant.Id        # Use this ID to revoke the grant
                            AppName     = $appName
                            ClientId    = $grant.ClientId  # Service principal object ID
                            ConsentType = $grant.ConsentType  # "AllPrincipals" = admin consent, "Principal" = user consent
                            Scope       = $grant.Scope     # Space-delimited list of OAuth scopes granted
                        })
                    }
                }
            }
            catch {
                Write-Verbose "Could not retrieve OAuth apps for mailbox: $($MBX.PrimarySmtpAddress) - $($_.Exception.Message)"
            }
        }
        else {
            Write-Verbose "Microsoft.Graph module is not connected. Skipping OAuth app retrieval."
        }

        # Retrieve a list of all user-visible (IPM) mailbox subfolders. We filter specifically for
        # "/Top of Information Store/*" because non-IPM system folders (Recoverable Items, Audits,
        # Calendar Logging, DiscoveryHolds, Purges, etc.) do not support Get-EXOMailboxFolderPermission
        # and throw 'ManagementObjectNotFoundException' if queried.
        $MBXFolders = Get-EXOMailboxFolderStatistics $Mailbox | Where-Object { $_.FolderPath -like "/Top of Information Store/*" } | Select-Object FolderPath

        # The mailbox root-level permissions (no folder path qualifier) are separate from
        # individual subfolder permissions and must be retrieved with a standalone call.
        $topLevelPerms = Get-EXOMailboxFolderPermission $Mailbox -ErrorAction SilentlyContinue | Where-Object { ($_.AccessRights -notlike "None") } | Where-Object { ($_.User -notlike "NT AUTHORITY\SELF") }
        if ($topLevelPerms) {
            foreach ($perm in $topLevelPerms) {
                $AllFolderPermissions.Add($perm)
            }
        }

        # Walk every user subfolder and collect non-default, non-self permissions.
        # FolderPath from Get-EXOMailboxFolderStatistics uses forward-slash notation
        # (e.g. /Top of Information Store/Inbox/Subfolder); the Exchange folder identity format requires
        # backslash notation prefixed with the SMTP address (e.g. user@domain.com:\Inbox\Subfolder).
        foreach ($MBXFolder in $MBXFolders) {
            try {
                $relativePath = $MBXFolder.FolderPath -replace '^/Top of Information Store', '' -replace '/', '\'
                $folder = $MBX.PrimarySmtpAddress + ":" + $relativePath
                $folderpermissions = Get-EXOMailboxFolderPermission -Identity $folder -ErrorAction Stop | Where-Object { ($_.AccessRights -notlike "None") } | Where-Object { ($_.User -notlike "NT AUTHORITY\SELF") }
                if ($folderpermissions) {
                    foreach ($perm in $folderpermissions) {
                        $AllFolderPermissions.Add($perm)
                    }
                }
            }
            catch {
                # Log a warning for any subfolder permission query failure and continue
                Write-Warning "Failed to read permissions on folder: $folder - $($_.Exception.Message)"
                continue
            }
        }

        # -----------------------------------------------------------------------
        # Build the unified $MailboxReport PSCustomObject.
        # All data collected above is assembled here into a single structured object.
        # The console output phase (below) reads exclusively from $MailboxReport so
        # that -AsObject and console modes are guaranteed to present identical data.
        # -----------------------------------------------------------------------
        $MailboxReport = [PSCustomObject]@{
            Mailbox                     = $MBX.PrimarySmtpAddress
            UserPrincipalName           = $MBX.UserPrincipalName
            ExternalDirectoryObjectId   = $MBX.ExternalDirectoryObjectId  # Entra ID User Object GUID for log correlation
            RecipientTypeDetails        = $MBX.RecipientTypeDetails  # e.g. UserMailbox, SharedMailbox, RoomMailbox
            HiddenFromAddressLists      = $MBX.HiddenFromAddressListsEnabled
            SharingPolicy               = $MBX.SharingPolicy        # External calendar/contact sharing policy applied
            EmailAddresses              = $MBX.EmailAddresses       # All primary and secondary SMTP aliases assigned
            ForwardingSmtpAddress       = $MBX.ForwardingSmtpAddress   # SMTP forwarding set directly on the mailbox
            ForwardingAddress           = $MBX.ForwardingAddress        # Forwarding to an internal recipient object
            DeliverToMailboxAndForward  = $MBX.DeliverToMailboxAndForward  # $true = keep a copy + forward; $false = forward only

            # StorageStats merges live usage data from Get-EXOMailboxStatistics with quota
            # limits from Get-EXOMailbox. Quota properties (IssueWarningQuota, ProhibitSend*)
            # do not exist on Get-EXOMailboxStatistics — they must be sourced from the mailbox object.
            # Usage fields (TotalItemSize, ItemCount, etc.) may be $null if statistics
            # retrieval failed (e.g. a newly created mailbox with no data), but quota limits
            # will always be populated from $MBX.
            StorageStats                = [PSCustomObject]@{
                TotalItemSize            = $MBXStats.TotalItemSize
                ItemCount                = $MBXStats.ItemCount
                TotalDeletedItemSize     = $MBXStats.TotalDeletedItemSize   # Size of Recoverable Items (soft-deleted)
                DeletedItemCount         = $MBXStats.DeletedItemCount
                IssueWarningQuota        = $MBX.IssueWarningQuota           # Threshold at which a warning is sent to the mailbox owner
                ProhibitSendQuota        = $MBX.ProhibitSendQuota           # Threshold at which sending is blocked
                ProhibitSendReceiveQuota = $MBX.ProhibitSendReceiveQuota    # Threshold at which sending and receiving are both blocked
            }

            ArchiveStatus               = $MBX.ArchiveStatus    # None, Active, Pending
            ArchiveState                = $MBX.ArchiveState      # None, Local (on-prem), HostedProvisioned, HostedPending
            AutoExpandingArchiveEnabled = $MBX.AutoExpandingArchiveEnabled  # Allows archive to grow beyond 100 GB
            ArchiveStats                = $MBXArchiveStats       # $null if no archive is provisioned

            RecoverableItemsStats       = $RecoverableItemsStats  # Per-subfolder breakdown; $null if all subfolders are empty
            HasHoldItems                = $hasHoldItems            # $true if DiscoveryHolds, SubstrateHolds, or Purges contain items

            # LitigationHold covers the classic per-mailbox hold. InPlaceHolds lists all
            # hold GUIDs (eDiscovery, Purview retention, etc.) applied to this mailbox.
            # DelayHoldApplied means a hold was recently removed but the delay period
            # has not yet expired — data is still being preserved in the background.
            LitigationHold              = [PSCustomObject]@{
                Enabled                  = $MBX.LitigationHoldEnabled
                Date                     = $MBX.LitigationHoldDate
                Owner                    = $MBX.LitigationHoldOwner
                Duration                 = $MBX.LitigationHoldDuration   # Unlimited or a specific number of days
                InPlaceHolds             = $MBX.InPlaceHolds              # Array of hold GUIDs; prefix indicates hold type
                DelayHoldApplied         = $MBX.DelayHoldApplied          # $true = hold removal is in a 30-day grace period
                ComplianceTagHoldApplied = $MBX.ComplianceTagHoldApplied  # $true = a compliance tag/label is preserving content
                SingleItemRecovery       = $MBX.SingleItemRecoveryEnabled  # Preserves purged items for the hold duration
                RetentionPolicy          = $MBX.RetentionPolicy            # MRM/ELC retention policy tag applied to the mailbox
                RetentionHoldEnabled     = $MBX.RetentionHoldEnabled       # $true = MRM processing is paused (e.g. during migration)
                ElcProcessingDisabled    = $MBX.ElcProcessingDisabled      # $true = Managed Folder Assistant skips this mailbox
            }

            # AuditEnabled should be $true and DefaultAuditSet should be populated for
            # all modern Exchange Online mailboxes. If AuditEnabled is $false, mailbox
            # activity (admin, delegate, owner actions) is not being logged.
            # BypassEnabled = $true indicates all actions by this user bypass audit logging.
            AuditSettings               = [PSCustomObject]@{
                Enabled       = $MBX.AuditEnabled
                BypassEnabled = if ($MBXAuditBypass) { [bool]$MBXAuditBypass.AuditBypassEnabled } else { $false }
                LogAgeLimit   = $MBX.AuditLogAgeLimit   # How long audit log entries are retained
                DefaultSet    = $MBX.DefaultAuditSet     # Which role groups use the tenant-default audit action set
                Admin         = $MBX.AuditAdmin           # Actions logged when an admin accesses the mailbox
                Delegate      = $MBX.AuditDelegate         # Actions logged for delegate (e.g. FullAccess) access
                Owner         = $MBX.AuditOwner            # Actions logged for the mailbox owner themselves
            }

            ClientAccess                = $MBXCAS           # Full CAS object; contains all protocol enable/disable flags
            CalendarProcessing          = $MBXCalendarProcessing  # Full CalendarProcessing object; relevant for resource mailboxes
            CalendarDelegates           = $MBXCalendarDelegates   # Resolved ResourceDelegates list

            # Permissions groups all delegation-related access into one sub-object.
            # FullAccess = can open the mailbox in Outlook and read/send all items
            # SendAs     = can send mail that appears to originate from this mailbox
            # SendOnBehalf = can send mail "on behalf of" this mailbox (sender visible in headers)
            # Folders    = explicit permissions on individual mailbox folders (calendar, inbox, etc.)
            Permissions                 = [PSCustomObject]@{
                FullAccess   = $MBXPermission
                SendAs       = $MBXSendAs
                SendOnBehalf = $MBXSendOnBehalf
                Folders      = $AllFolderPermissions
            }

            InboxRules                  = $MBXInboxRules    # Includes hidden rules; flag IsHidden = $true for covert rules
            MobileDevices               = $MBXMobileDevices  # ActiveSync device partnerships
            OutlookAddins               = $MBXAddins         # Native Exchange/Outlook add-ins (COM/web add-ins installed per-mailbox)
            OAuthApps                   = $MBXOAuthApps      # Entra ID OAuth2 permission grants (third-party app consents)
            ApplicationAccessPolicies   = $AppAccessPolicies  # Tenant-wide app access policy set; pre-fetched in begin{}
        }

        # -----------------------------------------------------------------------
        # Phase 2: Output Decision
        # -AsObject: emit the raw $MailboxReport object for pipeline/export use.
        # Default:   render human-readable console sections from $MailboxReport.
        # -----------------------------------------------------------------------
        if ($AsObject) {
            Write-Output $MailboxReport
        } else {
            Write-Host "========== Mailbox Settings & Type =========" -ForegroundColor Cyan
            Write-Output "Mailbox: $($MailboxReport.Mailbox)"
            Write-Output "UPN: $($MailboxReport.UserPrincipalName)"
            Write-Output "ExternalDirectoryObjectId: $($MailboxReport.ExternalDirectoryObjectId)"
            Write-Output "RecipientTypeDetails: $($MailboxReport.RecipientTypeDetails)"
            Write-Output "HiddenFromAddressListsEnabled: $($MailboxReport.HiddenFromAddressLists)"
            Write-Output "SharingPolicy: $($MailboxReport.SharingPolicy)"
            Write-Output "EmailAddresses: $($MailboxReport.EmailAddresses -join ', ')"
            Write-Output "ForwardingSmtpAddress: $($MailboxReport.ForwardingSmtpAddress)"
            Write-Output "ForwardingAddress: $($MailboxReport.ForwardingAddress)"
            Write-Output "DeliverToMailboxAndForward: $($MailboxReport.DeliverToMailboxAndForward)"
            Write-Output ""
            Write-Host "========= Mailbox Storage & Quota Statistics =========" -ForegroundColor Cyan
            Write-Output "TotalItemSize: $($MailboxReport.StorageStats.TotalItemSize)"
            Write-Output "ItemCount: $($MailboxReport.StorageStats.ItemCount)"
            Write-Output "TotalDeletedItemSize (Recoverable Items): $($MailboxReport.StorageStats.TotalDeletedItemSize)"
            Write-Output "DeletedItemCount: $($MailboxReport.StorageStats.DeletedItemCount)"
            Write-Output "IssueWarningQuota: $($MailboxReport.StorageStats.IssueWarningQuota)"
            Write-Output "ProhibitSendQuota: $($MailboxReport.StorageStats.ProhibitSendQuota)"
            Write-Output "ProhibitSendReceiveQuota: $($MailboxReport.StorageStats.ProhibitSendReceiveQuota)"
            Write-Output ""
            Write-Host "========= Online Archive Status =========" -ForegroundColor Cyan
            Write-Output "ArchiveStatus: $($MailboxReport.ArchiveStatus)"
            Write-Output "ArchiveState: $($MailboxReport.ArchiveState)"
            Write-Output "AutoExpandingArchiveEnabled: $($MailboxReport.AutoExpandingArchiveEnabled)"
            if ($MailboxReport.ArchiveStats) {
                Write-Output "Archive TotalItemSize: $($MailboxReport.ArchiveStats.TotalItemSize)"
                Write-Output "Archive ItemCount: $($MailboxReport.ArchiveStats.ItemCount)"
            }
            Write-Output ""
            Write-Host "========= Litigation & Legal Hold Settings =========" -ForegroundColor Cyan
            Write-Host "These settings can be modified using Set-Mailbox" -ForegroundColor DarkGray
            Write-Output "LitigationHoldEnabled: $($MailboxReport.LitigationHold.Enabled)"
            Write-Output "LitigationHoldDate: $($MailboxReport.LitigationHold.Date)"
            Write-Output "LitigationHoldOwner: $($MailboxReport.LitigationHold.Owner)"
            Write-Output "LitigationHoldDuration: $($MailboxReport.LitigationHold.Duration)"
            Write-Output "InPlaceHolds: $($MailboxReport.LitigationHold.InPlaceHolds -join ', ')"
            Write-Output "DelayHoldApplied: $($MailboxReport.LitigationHold.DelayHoldApplied)"
            Write-Output "ComplianceTagHoldApplied: $($MailboxReport.LitigationHold.ComplianceTagHoldApplied)"
            Write-Output "SingleItemRecoveryEnabled: $($MailboxReport.LitigationHold.SingleItemRecovery)"
            Write-Output "RetentionPolicy: $($MailboxReport.LitigationHold.RetentionPolicy)"
            Write-Output "RetentionHoldEnabled: $($MailboxReport.LitigationHold.RetentionHoldEnabled)"
            Write-Output "ElcProcessingDisabled: $($MailboxReport.LitigationHold.ElcProcessingDisabled)"
            Write-Output ""
            Write-Host "========= Recoverable Items & Active Hold Audit =========" -ForegroundColor Cyan
            Write-Host "Inspects hidden hold subfolders to verify if items are actively being preserved." -ForegroundColor DarkGray

            # Flag the mismatch case: LitigationHold is off but hold subfolders have content.
            # This typically means a Purview retention policy or eDiscovery hold is active
            # rather than the classic per-mailbox litigation hold — important for compliance teams.
            if (-not $MailboxReport.LitigationHold.Enabled -and $MailboxReport.HasHoldItems) {
                Write-Output ""
                Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Yellow
                Write-Host "[WARNING] LitigationHoldEnabled is FALSE, but hold subfolder(s) contain items!" -ForegroundColor Yellow
                Write-Host "This indicates an active/pending Purview Retention Policy, eDiscovery Hold, or" -ForegroundColor Yellow
                Write-Host "un-synced background policy may be preserving data on this mailbox." -ForegroundColor Yellow
                Write-Host "--------------------------------------------------------------------------------" -ForegroundColor Yellow
                Write-Output ""
            }

            if ($MailboxReport.RecoverableItemsStats) {
                Write-Output ($MailboxReport.RecoverableItemsStats | Format-Table Name, ItemsInFolder, FolderSize, OldestItemReceivedDate, NewestItemReceivedDate -Wrap -AutoSize)
            } else {
                Write-Output "No items found in Recoverable Items."
            }
            Write-Output ""
            Write-Host "========= Mailbox Auditing =========" -ForegroundColor Cyan
            Write-Host "These settings can be modified using Set-Mailbox" -ForegroundColor DarkGray
            Write-Output "AuditEnabled: $($MailboxReport.AuditSettings.Enabled)"
            Write-Output "AuditBypassEnabled: $($MailboxReport.AuditSettings.BypassEnabled)"
            Write-Output "AuditLogAgeLimit: $($MailboxReport.AuditSettings.LogAgeLimit)"
            Write-Output "DefaultAuditSet: $($MailboxReport.AuditSettings.DefaultSet -join ', ')"
            Write-Output "AuditAdmin: $($MailboxReport.AuditSettings.Admin -join ', ')"
            Write-Output "AuditDelegate: $($MailboxReport.AuditSettings.Delegate -join ', ')"
            Write-Output "AuditOwner: $($MailboxReport.AuditSettings.Owner -join ', ')"
            Write-Output ""
            Write-Host "========= Client Access Settings (Protocols) =========" -ForegroundColor Cyan
            Write-Host "These settings can be modified using Set-CASMailbox" -ForegroundColor DarkGray
            if ($MailboxReport.ClientAccess) {
                Write-Output "ActiveSyncEnabled: $($MailboxReport.ClientAccess.ActiveSyncEnabled)"
                Write-Output "EwsEnabled: $($MailboxReport.ClientAccess.EwsEnabled)"
                Write-Output "ImapEnabled: $($MailboxReport.ClientAccess.ImapEnabled)"
                Write-Output "PopEnabled: $($MailboxReport.ClientAccess.PopEnabled)"
                Write-Output "OwaEnabled: $($MailboxReport.ClientAccess.OwaEnabled)"
                Write-Output "MAPIEnabled: $($MailboxReport.ClientAccess.MAPIEnabled)"
                Write-Output "OutlookMobileEnabled: $($MailboxReport.ClientAccess.OutlookMobileEnabled)"
                Write-Output "MacOutlookEnabled: $($MailboxReport.ClientAccess.MacOutlookEnabled)"
                Write-Output "OWAforDevicesEnabled: $($MailboxReport.ClientAccess.OWAforDevicesEnabled)"
                Write-Output "ECPEnabled: $($MailboxReport.ClientAccess.ECPEnabled)"
                Write-Output "SmtpClientAuthenticationDisabled: $($MailboxReport.ClientAccess.SmtpClientAuthenticationDisabled)"
            }
            Write-Output ""
            Write-Host "========= Calendar Permissions =========" -ForegroundColor Cyan
            if ($MailboxReport.CalendarProcessing) {
                Write-Output "ForwardRequestsToDelegates: $($MailboxReport.CalendarProcessing.ForwardRequestsToDelegates)"
            }
            Write-Output "ResourceDelegates"
            if ($MailboxReport.CalendarDelegates) { Write-Output ($MailboxReport.CalendarDelegates | Format-Table Name, DisplayName, RecipientType -Wrap -AutoSize) }
            Write-Output ""
            Write-Host "========= Send As Permissions =========" -ForegroundColor Cyan
            Write-Host "These settings can be modified with the following command" -ForegroundColor DarkGray
            Write-Host "#Remove-RecipientPermission -AccessRights SendAs -Identity $($MailboxReport.Mailbox)" -ForegroundColor DarkGray
            if ($MailboxReport.Permissions.SendAs) { Write-Output ($MailboxReport.Permissions.SendAs | Format-Table Identity, Trustee, AccessRights, AccessControlType, Inherited -Wrap -AutoSize) }
            Write-Output ""
            Write-Host "========= Send On Behalf Permissions =========" -ForegroundColor Cyan
            Write-Host "These settings can be modified with the following command" -ForegroundColor DarkGray
            Write-Host "#Set-Mailbox $($MailboxReport.Mailbox) -GrantSendOnBehalfTo @{Remove=""USER""}" -ForegroundColor DarkGray
            if ($MailboxReport.Permissions.SendOnBehalf) { Write-Output ($MailboxReport.Permissions.SendOnBehalf | Format-Table Name, DisplayName, RecipientType -Wrap -AutoSize) }
            Write-Output ""
            Write-Host "========= Mailbox Permissions (Delegation & AutoMapping) =========" -ForegroundColor Cyan
            Write-Host "These settings can be modified with the following command" -ForegroundColor DarkGray
            Write-Host "#Remove-MailboxPermission $($MailboxReport.Mailbox) -AccessRights FullAccess -InheritanceType All" -ForegroundColor DarkGray
            if ($MailboxReport.Permissions.FullAccess) { Write-Output ($MailboxReport.Permissions.FullAccess | Format-Table User, AccessRights, AutoMapping, IsValid -Wrap -AutoSize) }
            Write-Output ""
            Write-Host "========= Folder Permissions =========" -ForegroundColor Cyan
            Write-Host "These settings can be modified with the following command" -ForegroundColor DarkGray
            Write-Host "#Remove-MailboxFolderPermission" -ForegroundColor DarkGray
            if ($MailboxReport.Permissions.Folders.Count -gt 0) { Write-Output ($MailboxReport.Permissions.Folders | Format-Table -Wrap -AutoSize) }
            Write-Output ""
            Write-Host "========= Inbox Rules (Including Hidden Rules) =========" -ForegroundColor Cyan
            Write-Host "These settings can be modified with the following command" -ForegroundColor DarkGray
            Write-Host "#Remove-InboxRule" -ForegroundColor DarkGray
            if ($MailboxReport.InboxRules) { Write-Output ($MailboxReport.InboxRules | Format-Table Name, Enabled, Priority, RuleIdentity, IsHidden -Wrap -AutoSize) }
            Write-Output ""
            Write-Host "========= Mobile Devices =========" -ForegroundColor Cyan
            Write-Host "These settings can be modified with the following command" -ForegroundColor DarkGray
            Write-Host "#Remove-MobileDevice" -ForegroundColor DarkGray
            if ($MailboxReport.MobileDevices) { Write-Output ($MailboxReport.MobileDevices | Format-Table -Wrap -AutoSize) }
            Write-Output ""
            Write-Host "========= Outlook Add-ins =========" -ForegroundColor Cyan
            Write-Host "These are native Outlook add-ins installed for the mailbox." -ForegroundColor DarkGray
            Write-Host "IsKnownDefault indicates whether the AppID matches a known standard Microsoft default add-in." -ForegroundColor DarkGray
            Write-Host "These settings can be modified with the following command:" -ForegroundColor DarkGray
            Write-Host "#Remove-App -Mailbox $($MailboxReport.Mailbox) -Identity <AppId>" -ForegroundColor DarkGray
            if ($MailboxReport.OutlookAddins) { Write-Output ($MailboxReport.OutlookAddins | Format-Table DisplayName, AppId, Enabled, IsKnownDefault, AppVersion, DefaultStateForUser -Wrap -AutoSize) }
            Write-Output ""
            Write-Host "========= OAuth Apps (User Consents) =========" -ForegroundColor Cyan
            Write-Host "These are Azure AD OAuth permissions consented to by the user." -ForegroundColor DarkGray
            Write-Host "Requires Microsoft.Graph module and Connect-MgGraph." -ForegroundColor DarkGray
            Write-Host "#Revoke-MgUserOauth2PermissionGrant -UserId $($MailboxReport.UserPrincipalName) -OAuth2PermissionGrantId <Id>" -ForegroundColor DarkGray
            if ($MailboxReport.OAuthApps) {
                Write-Output ($MailboxReport.OAuthApps | Format-Table AppName, ClientId, Scope, ConsentType, Id -Wrap -AutoSize)
            } else {
                Write-Output "None found or Microsoft.Graph module is not connected."
            }
            Write-Output ""
            Write-Host "========= Application Access Policies (Tenant-Wide) =========" -ForegroundColor Cyan
            Write-Host "These policies restrict or grant OAuth app access to mailboxes based on groups." -ForegroundColor DarkGray
            Write-Host "Note: This lists all tenant policies. You must check if this mailbox is in the PolicyScopeGroupId." -ForegroundColor DarkGray
            if ($MailboxReport.ApplicationAccessPolicies.Count -gt 0) {
                Write-Output ($MailboxReport.ApplicationAccessPolicies | Format-Table AppName, AccessRight, PolicyScopeGroupId, AppId, Description -Wrap -AutoSize)
            } else {
                Write-Output "No Application Access Policies found in this tenant."
            }
            Write-Output ""
        }
    }
}