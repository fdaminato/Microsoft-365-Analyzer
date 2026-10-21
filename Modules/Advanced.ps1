# Advanced read-only workload collectors and assessment rules. Loaded inside main script scope.
function Invoke-AdvancedAssessments {
 Invoke-Control 'Entra ID' 'Conditional Access deeper assessments' {
  if (-not $inventory.Contains('ConditionalAccess')) { throw 'Conditional Access inventory missing' }
  foreach ($p in $inventory.ConditionalAccess) {
   $state=[string]$p.State; $cond=$p.Conditions; $grant=$p.GrantControls
   $incs=@(Get-Field $cond 'users.includeUsers'); $exusers=@(Get-Field $cond 'users.excludeUsers');$exgroups=@(Get-Field $cond 'users.excludeGroups')
   $apps=@(Get-Field $cond 'applications.includeApplications'); $controls=@(Get-Property $grant 'builtInControls')
   if($state -eq 'enabledForReportingButNotEnforced') { Add-Finding 'ITICA-001' 'Entra ID' 'Info' 'Conditional Access policy is report-only' $p.Name 'Confirm testing period, owner and production-enforcement plan.' 'Governance' $p.Id }
   if($state -eq 'enabled' -and (($exusers.Count -gt 0 -and $exusers[0]) -or ($exgroups.Count -gt 0 -and $exgroups[0]))) { Add-Finding 'ITICA-002' 'Entra ID' 'Medium' 'Conditional Access has exclusions' "$($p.Name): excluded users=$($exusers.Count), groups=$($exgroups.Count)" 'Review necessity, membership and compensating controls for excluded identities.' 'Security' $p.Id }
   if($state -eq 'enabled' -and $null -eq $grant -and (@(Get-Property (Get-Property $cond 'applications') 'includeUserActions').Count -eq 0)) { Add-Finding 'ITICA-003' 'Entra ID' 'Info' 'Conditional Access lacks grant controls' $p.Name 'Review session controls and policy purpose before treating as a deviation.' 'Governance' $p.Id }
   if($state -eq 'enabled' -and $apps -contains 'All' -and $controls -contains 'block' -and @($exgroups | Where-Object {$_}).Count -gt 3) { Add-Finding 'ITICA-004' 'Entra ID' 'Medium' 'Broad blocking policy with multiple exemptions' "$($p.Name): $($exgroups.Count) excluded groups" 'Confirm each exemption is approved and documented.' 'Security' $p.Id }
  }
 }
 Invoke-Control 'Entra ID' 'Identity lifecycle and user metadata' {
  if (-not $inventory.Contains('Users')) {throw 'Users inventory missing'}
  foreach($u in $inventory.Users){
   if ($u.Enabled -and $u.UserType -eq 'Member' -and $u.LicenseCount -gt 0 -and -not $u.Department) {Add-Finding 'ITIUSR-001' 'Entra ID' 'Low' 'Licensed user missing department' $u.UPN 'Verify HR source attributes and identity lifecycle requirements.' 'Governance' $u.Id}
   if ($u.Enabled -and $u.UserType -eq 'Member' -and $u.LicenseCount -gt 0 -and -not $u.JobTitle) {Add-Finding 'ITIUSR-002' 'Entra ID' 'Low' 'Licensed user missing job title' $u.UPN 'Validate HR data consistency and directory attribute ownership.' 'Governance' $u.Id}
  }
 }
 Invoke-Control 'Entra ID' 'Privileged role governance review' {
  if (-not $inventory.Contains('RoleAssignments')) {throw 'Role assignments missing'}
  $ga=@($inventory.RoleAssignments| Where-Object {$_.RoleName -eq 'Global Administrator'})
  if($ga.Count -gt 5){ Add-Finding 'ITIPRIV-001' 'Entra ID' 'Medium' 'More than five permanent Global Administrator assignments observed' "$($ga.Count) directory role assignments; PIM eligibility is not captured here." 'Validate break-glass design, PIM status, approval of permanent assignments and least privilege.' 'Governance' 'GlobalAdministrator' }
 }
 Invoke-Control 'Entra ID' 'Administrative changes and consent events' {
  if(-not $inventory.Contains('DirectoryAudits')){throw 'Directory audit missing'}
  $patterns='(?i)Add member to role|Add eligible member|Remove member from role|Update conditional access|Delete conditional access|Add delegated permission grant|Consent to application|Add app role assignment grant|Add service principal'
  $inventory.NotableAudits=@($inventory.DirectoryAudits|Where-Object {$_.Activity -match $patterns})
  foreach($e in $inventory.NotableAudits){ Add-Finding 'ITIAUD-001' 'Entra ID' 'Info' 'Review security-relevant administration activity' "$($e.Time) | $($e.Activity) | $($e.Actor)" 'Confirm change ticket, approval, and expected privileges; audit event alone is not evidence of wrongdoing.' 'Governance' $e.Id }
 }
 Invoke-Control 'Entra ID' 'Application credentials expiry' {
  $apps=Get-GraphItems 'https://graph.microsoft.com/v1.0/applications?$select=id,appId,displayName,passwordCredentials,keyCredentials&$top=999'
  $inventory.Applications=@($apps|ForEach-Object {[pscustomobject]@{Id=(Get-Property $_ 'id');AppId=(Get-Property $_ 'appId');Name=(Get-Property $_ 'displayName');PasswordCredentials=(Get-Property $_ 'passwordCredentials');KeyCredentials=(Get-Property $_ 'keyCredentials')}})
  $now=(Get-Date).ToUniversalTime()
  foreach($a in $inventory.Applications){foreach($cred in @($a.PasswordCredentials)+@($a.KeyCredentials)){if($null -eq $cred){continue};$expiry=Get-Property $cred 'endDateTime';if(-not $expiry){continue};$days=([datetime]$expiry-$now).TotalDays;if($days -lt 0){$sev='High'}elseif($days -lt 30){$sev='Medium'}else{continue};$cid=Get-Property $cred 'keyId';Add-Finding 'ITIAPP-001' 'Entra ID' $sev 'Application credential expired or expiring within 30 days' "$($a.Name) | expiry $expiry" 'Validate application usage, owner, secure rotation plan and managed-identity alternatives.' 'Security' "$($a.Id)|$cid"}}
 }
 Invoke-Control 'Entra ID' 'Service principal permissions inventory' {
  $sps=Get-GraphItems 'https://graph.microsoft.com/v1.0/servicePrincipals?$select=id,appId,displayName,accountEnabled,servicePrincipalType&$top=999'
  $inventory.ServicePrincipals=@($sps|ForEach-Object {[pscustomobject]@{Id=(Get-Property $_ 'id');AppId=(Get-Property $_ 'appId');Name=(Get-Property $_ 'displayName');Enabled=(Get-Property $_ 'accountEnabled');Type=(Get-Property $_ 'servicePrincipalType')}})
 }
 Invoke-Control 'Intune' 'Device compliance, stale synchronization and data integrity' {
  if(-not $inventory.Contains('ManagedDevices')){throw 'Managed device inventory missing'}
  if(@($inventory.ManagedDevices|Where-Object {-not $_.Id}).Count -gt 0){throw 'Invalid managed-device response: record with missing device ID (do not count as assessed).'}
  foreach($d in $inventory.ManagedDevices){
   if($d.Compliance -in @('unknown','notEvaluated','error','conflict')){Add-Finding 'ITIINT-003' 'Intune' 'Medium' 'Managed device compliance not established' "$($d.Name): $($d.Compliance)" 'Investigate compliance state, policies and reporting lag.' 'Security' $d.Id}
   if($d.LastSync -and ([datetime]$d.LastSync -lt (Get-Date).ToUniversalTime().AddDays(-30))){Add-Finding 'ITIINT-004' 'Intune' 'Low' 'Device has not synced to Intune in over 30 days' "$($d.Name): $($d.LastSync)" 'Validate whether this device should remain managed; consider lifecycle cleanup.' 'Governance' $d.Id}
  }
 }
 Invoke-Control 'Intune' 'Configuration profiles inventory' {
  $profiles=Get-GraphItems 'https://graph.microsoft.com/beta/deviceManagement/configurationPolicies?$top=200'
  $inventory.ConfigurationPolicies=@($profiles|ForEach-Object {[pscustomobject]@{Id=(Get-Property $_ 'id');Name=(Get-Property $_ 'name');Platforms=(Get-Property $_ 'platforms');Technologies=(Get-Property $_ 'technologies')}})
 }
 Invoke-Control 'Intune' 'Legacy device configuration profiles' {
  $profiles=Get-GraphItems 'https://graph.microsoft.com/v1.0/deviceManagement/deviceConfigurations'
  $inventory.DeviceConfigurations=@($profiles|ForEach-Object {[pscustomobject]@{Id=(Get-Property $_ 'id');Name=(Get-Property $_ 'displayName');Type=(Get-Property $_ '@odata.type')}})
 }
 Invoke-Control 'Intune' 'Mobile application protection policies' {
  $ios=Get-GraphItems 'https://graph.microsoft.com/v1.0/deviceAppManagement/iosManagedAppProtections';$android=Get-GraphItems 'https://graph.microsoft.com/v1.0/deviceAppManagement/androidManagedAppProtections'
  $inventory.AppProtectionPolicies=@(@($ios)+@($android)|ForEach-Object {[pscustomobject]@{Id=(Get-Property $_ 'id');Name=(Get-Property $_ 'displayName');Type=(Get-Property $_ '@odata.type')}})
 }
 Invoke-Control 'Microsoft Defender' 'Incident triage and status inventory' {
  if(-not $inventory.Contains('DefenderIncidents')){throw 'Defender incidents API inaccessible; verify SecurityIncident.Read.All, Entra role and licensing.'}
  $open=@($inventory.DefenderIncidents|Where-Object {$_.Status -notin @('resolved','redirected')});$inventory.DefenderIncidentSummary=[pscustomobject]@{Total=$inventory.DefenderIncidents.Count;Open=$open.Count}
 }
 Invoke-Control 'Governance' 'License capacity and utilization' {
  if(-not $inventory.Contains('Licenses')){throw 'License SKUs missing'}
  foreach($sku in $inventory.Licenses){if($null -eq $sku.Enabled -or $null -eq $sku.Consumed){continue};if([int]$sku.Enabled -gt 0 -and [int]$sku.Consumed -gt [int]$sku.Enabled){Add-Finding 'ITILIC-001' 'Governance' 'Medium' 'SKU consumption above prepaid enabled licenses' "$($sku.SKU) consumed=$($sku.Consumed), enabled=$($sku.Enabled)" 'Investigate licensing entitlements and subscription state.' 'Optimization' $sku.SKU}}
 }
}
function Invoke-OptionalCollectors {
 param([switch]$Exchange,[switch]$Teams,[switch]$SharePoint,[switch]$Purview,[string]$SharePointAdminUrl)
 if($Exchange){
  Invoke-Control 'Exchange Online' 'Mailbox forwarding and SMTP forwarding' {
   Import-Module ExchangeOnlineManagement -ErrorAction Stop
   Connect-ExchangeOnline -ShowBanner:$false -ErrorAction Stop
   $mail=Get-EXOMailbox -ResultSize Unlimited -Properties ForwardingAddress,ForwardingSmtpAddress,DeliverToMailboxAndForward,PrimarySmtpAddress,RecipientTypeDetails
   $inventory.ExchangeMailboxes=@($mail|ForEach-Object {[pscustomobject]@{Id=$_.ExternalDirectoryObjectId;PrimarySmtpAddress=[string]$_.PrimarySmtpAddress;Type=[string]$_.RecipientTypeDetails;ForwardingAddress=[string]$_.ForwardingAddress;ForwardingSmtpAddress=[string]$_.ForwardingSmtpAddress;DeliverToMailboxAndForward=$_.DeliverToMailboxAndForward}})
   foreach($m in $inventory.ExchangeMailboxes){if($m.ForwardingSmtpAddress -match '^smtp:' -or $m.ForwardingSmtpAddress -match '@'){Add-Finding 'ITIEXO-001' 'Exchange Online' 'High' 'Mailbox SMTP forwarding configured' "$($m.PrimarySmtpAddress) -> $($m.ForwardingSmtpAddress)" 'Verify destination domain, approval and exfiltration controls.' 'Security' $m.Id}}
  }
  Invoke-Control 'Exchange Online' 'Transport rules and organizational policy inventory' {
   $inventory.TransportRules=@(Get-TransportRule|ForEach-Object {[pscustomobject]@{Name=$_.Name;State=[string]$_.State;Mode=[string]$_.Mode;Priority=$_.Priority;Description=[string]$_.Description}})
   $inventory.TransportConfig=[pscustomobject]@{ExternalPostmasterAddress=[string](Get-TransportConfig).ExternalPostmasterAddress}
  }
  Invoke-Control 'Exchange Online' 'Accepted domains and outbound spam policies' {
   $inventory.AcceptedDomains=@(Get-AcceptedDomain|ForEach-Object {[pscustomobject]@{Name=$_.Name;DomainName=[string]$_.DomainName;Type=[string]$_.DomainType}})
   $inventory.OutboundSpamPolicies=@(Get-HostedOutboundSpamFilterPolicy|ForEach-Object {[pscustomobject]@{Name=$_.Name;AutoForwardingMode=[string]$_.AutoForwardingMode}})
   foreach($p in $inventory.OutboundSpamPolicies){if($p.AutoForwardingMode -eq 'On'){Add-Finding 'ITIEXO-002' 'Exchange Online' 'Medium' 'Outbound spam policy permits automatic forwarding' $p.Name 'Confirm policy targeting and exceptions; consider disabling external automatic forwarding.' 'Security' $p.Name}}
  }
  Invoke-Control 'Exchange Online' 'Anti-phishing, anti-spam and Safe Links/Safe Attachments inventory' {
   $inventory.AntiPhishPolicies=@(Get-AntiPhishPolicy|Select-Object Name,Enabled,PhishThresholdLevel,EnableMailboxIntelligence)
   $inventory.HostedContentPolicies=@(Get-HostedContentFilterPolicy|Select-Object Name,SpamAction,HighConfidenceSpamAction,PhishSpamAction)
   $inventory.SafeLinksPolicies=@(Get-SafeLinksPolicy|Select-Object Name,EnableSafeLinksForEmail,EnableSafeLinksForTeams,TrackClicks)
   $inventory.SafeAttachmentPolicies=@(Get-SafeAttachmentPolicy|Select-Object Name,Enable,Action)
  }
 }
 if($Teams){
  Invoke-Control 'Teams' 'Federation and meeting policy inventory' {
   Import-Module MicrosoftTeams -ErrorAction Stop;Connect-MicrosoftTeams -ErrorAction Stop|Out-Null
   $inventory.TeamsFederation=@(Get-CsTenantFederationConfiguration|Select-Object AllowFederatedUsers,AllowPublicUsers,AllowedDomains,BlockedDomains)
   $inventory.TeamsMeetingPolicies=@(Get-CsTeamsMeetingPolicy|Select-Object Identity,AllowAnonymousUsersToJoinMeeting,AllowExternalParticipantGiveRequestControl,AllowCloudRecording,AllowTranscription)
   foreach($p in $inventory.TeamsMeetingPolicies){if($p.Identity -eq 'Global' -and $p.AllowAnonymousUsersToJoinMeeting -eq $true){Add-Finding 'ITITEAMS-001' 'Teams' 'Info' 'Anonymous meeting access allowed in global policy' 'Global Teams meeting policy' 'Validate business requirements, lobby configuration and meeting organizer guidance.' 'Governance' 'Global'}}
  }
 }
 if($SharePoint){
  Invoke-Control 'SharePoint Online' 'Tenant sharing and site inventory' {
   if(-not $SharePointAdminUrl){throw 'Supply -SharePointAdminUrl https://tenant-admin.sharepoint.com'}
   Import-Module Microsoft.Online.SharePoint.PowerShell -ErrorAction Stop
   Connect-SPOService -Url $SharePointAdminUrl -ErrorAction Stop
   $tenant=Get-SPOTenant
   $inventory.SharePointTenant=[pscustomobject]@{SharingCapability=[string]$tenant.SharingCapability;OneDriveSharingCapability=[string]$tenant.OneDriveSharingCapability;RequireAcceptingAccountMatchInvitedAccount=$tenant.RequireAcceptingAccountMatchInvitedAccount}
   $sites=Get-SPOSite -Limit All
   $inventory.SharePointSites=@($sites|ForEach-Object {[pscustomobject]@{Url=$_.Url;Title=$_.Title;SharingCapability=[string]$_.SharingCapability;Owner=[string]$_.Owner;StorageUsageCurrent=$_.StorageUsageCurrent;Template=[string]$_.Template}})
   foreach($s in $inventory.SharePointSites){if($s.SharingCapability -eq 'ExternalUserAndGuestSharing'){Add-Finding 'ITISPO-001' 'SharePoint Online' 'Medium' 'Anonymous sharing enabled at site level' $s.Url 'Review site sensitivity, external sharing links and expiration governance.' 'Security' $s.Url}}
   $inventory.OneDriveSites=@($inventory.SharePointSites|Where-Object {$_.Template -match 'SPSPERS'})
  }
  Invoke-Control 'OneDrive' 'Tenant OneDrive external sharing configuration' {
   if(-not $inventory.Contains('SharePointTenant')){throw 'SharePoint tenant settings unavailable'}
   if($inventory.SharePointTenant.OneDriveSharingCapability -eq 'ExternalUserAndGuestSharing'){Add-Finding 'ITIOD-001' 'OneDrive' 'Medium' 'Anonymous OneDrive sharing potentially permitted' 'Tenant-level OneDriveSharingCapability=ExternalUserAndGuestSharing' 'Review policy requirements, link settings and sharing defaults.' 'Security' 'Tenant'}
  }
 }
 if($Purview){
  Invoke-Control 'Microsoft Purview' 'DLP, retention and sensitivity label policy inventory' {
   Import-Module ExchangeOnlineManagement -ErrorAction Stop
   Connect-IPPSSession -ErrorAction Stop | Out-Null
   $inventory.DlpPolicies=@(Get-DlpCompliancePolicy|Select-Object Name,Enabled,Mode)
   $inventory.RetentionPolicies=@(Get-RetentionCompliancePolicy|Select-Object Name,Enabled,Mode)
   $inventory.SensitivityLabels=@(Get-Label|Select-Object Name,DisplayName,Disabled)
  }
 }
}
