#Requires -Version 7.2
<#!
.SYNOPSIS
  ITI Microsoft 365 Security & Governance Assessment - v0.2
.DESCRIPTION
  Read-only Graph assessment with optional Maester integration, self-contained HTML,
  machine-readable findings, and snapshot-to-snapshot delta detection.
  Unavailable collection is reported as NotAssessed, never as Passed.
.EXAMPLE
  ./Invoke-ITIM365Assessment.ps1 -TenantId 'YOUR-TENANT-GUID' -RunMaester -MaesterTestsPath './maester-tests' -OpenReport
.EXAMPLE
  ./Invoke-ITIM365Assessment.ps1 -TenantId 'YOUR-TENANT-GUID' -SkipConnect -OutputRoot './exports'
#>
[CmdletBinding()]
param(
 [Parameter(Mandatory)][guid]$TenantId,
 [string]$ClientName = 'Microsoft 365 tenant',
 [string]$OutputRoot = (Join-Path $PSScriptRoot 'exports'),
 [int]$InactiveDays = 90,
 [int]$AuditDays = 30,
 [switch]$SkipConnect,
 [switch]$RunMaester,
 [string]$MaesterTestsPath,
 [switch]$OpenReport,
 [switch]$IncludeExchange,
 [switch]$IncludeTeams,
 [switch]$IncludeSharePoint,
 [switch]$IncludePurview,
 [string]$SharePointAdminUrl
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($InactiveDays -lt 1 -or $AuditDays -lt 1 -or $AuditDays -gt 180) { throw 'Invalid age parameters: InactiveDays >=1, AuditDays 1..180.' }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$tenantRoot = Join-Path $OutputRoot $TenantId.ToString()
$runRoot = Join-Path $tenantRoot $stamp
New-Item -Path $runRoot -ItemType Directory -Force | Out-Null
$findings = [System.Collections.Generic.List[object]]::new()
$coverage = [System.Collections.Generic.List[object]]::new()
$inventory = [ordered]@{}
$changes = [System.Collections.Generic.List[object]]::new()
$script:seenIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
function Add-Finding {
 param([string]$Id,[string]$Workload,[string]$Severity,[string]$Title,[string]$Evidence,[string]$Recommendation,[string]$Category='Security',[string]$ObjectId='')
 $key = "$Id|$ObjectId"
 if (-not $script:seenIds.Add($key)) { return }
 $findings.Add([pscustomobject]@{ Id=$Id; Key=$key; Workload=$Workload; Severity=$Severity; Category=$Category; Title=$Title; Evidence=$Evidence; Recommendation=$Recommendation; ObjectId=$ObjectId; Status='Existing' })
}
function Add-Coverage { param([string]$Workload,[string]$Control,[string]$State,[string]$Details='')
 $coverage.Add([pscustomobject]@{Workload=$Workload; Control=$Control; State=$State; Details=$Details})
}
function Get-Property($obj, [string]$name) {
 if ($null -eq $obj) { return $null }
 if ($obj -is [System.Collections.IDictionary]) {
  if ($obj.Contains($name)) { return $obj[$name] }
  return $null
 }
 $prop = $obj.PSObject.Properties[$name]
 if ($null -ne $prop) { return $prop.Value }
 return $null
}
function Get-Field($obj, [string]$path) {
 $value = $obj
 foreach ($part in $path.Split('.')) {
  $value = Get-Property $value $part
  if ($null -eq $value) { return $null }
 }
 return $value
}
function Get-GraphItems {
 param([Parameter(Mandatory)][string]$Uri,[int]$MaxItems=10000)
 $all = [System.Collections.Generic.List[object]]::new()
 $next=$Uri
 $pages=0
 $visited=[System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
 while (-not [string]::IsNullOrWhiteSpace($next) -and $all.Count -lt $MaxItems) {
  if (-not $visited.Add($next)) { throw 'Microsoft Graph pagination returned a repeated nextLink.' }
  $pages++
  if ($pages -gt 1000) { throw 'Microsoft Graph pagination safety limit reached.' }
  $res = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject -ErrorAction Stop
  $values = Get-Property $res 'value'
  if ($null -ne $values) {
   foreach ($item in @($values)) {
    if ($null -ne $item) { $all.Add($item) }
    if ($all.Count -ge $MaxItems) { break }
   }
   $next = [string](Get-Property $res '@odata.nextLink')
  } else {
   if ($null -ne $res) { $all.Add($res) }
   $next=$null
  }
 }
 if ($all.Count -ge $MaxItems) { Write-Warning "Graph collection reached MaxItems=$MaxItems for $Uri. Results could be incomplete." }
 return ,$all.ToArray()
}
function Invoke-Control {
 param([string]$Workload,[string]$Name,[scriptblock]$Script)
 try { & $Script; Add-Coverage $Workload $Name 'Assessed' }
 catch { Add-Coverage $Workload $Name 'NotAssessed' $_.Exception.Message; Write-Warning "$Workload / $Name : $($_.Exception.Message)" }
}
function Save-Json { param($Data,[string]$Path)
 $Data | ConvertTo-Json -Depth 35 | Set-Content -LiteralPath $Path -Encoding utf8
}
Write-Host "[ITI] Starting assessment for tenant $TenantId" -ForegroundColor Cyan
if (-not (Get-Module -ListAvailable Microsoft.Graph.Authentication)) { throw 'Install-Module Microsoft.Graph.Authentication -Scope CurrentUser' }
Import-Module Microsoft.Graph.Authentication
$scopes=@('Organization.Read.All','User.Read.All','Directory.Read.All','AuditLog.Read.All','Policy.Read.All','RoleManagement.Read.Directory','Application.Read.All','DeviceManagementManagedDevices.Read.All','DeviceManagementConfiguration.Read.All','SecurityIncident.Read.All','Reports.Read.All','Sites.Read.All','TeamSettings.Read.All','DeviceManagementApps.Read.All')
if (-not $SkipConnect) { Connect-MgGraph -TenantId $TenantId -Scopes $scopes -NoWelcome | Out-Null }
$context=Get-MgContext
if (-not $context -or [string]$context.TenantId -ne [string]$TenantId) { throw 'Microsoft Graph is not connected to the requested tenant.' }
# Each section can fail independently; failure never earns a passing score.
Invoke-Control 'Entra ID' 'Tenant organization' {
 $org=Get-GraphItems 'https://graph.microsoft.com/v1.0/organization?$select=id,displayName,verifiedDomains'
 $inventory.Organization=@($org | ForEach-Object { [pscustomobject]@{Id=(Get-Property $_ 'id');Name=(Get-Property $_ 'displayName')} })
}
Invoke-Control 'Entra ID' 'Accounts, licensing and last sign-in' {
 $users=Get-GraphItems 'https://graph.microsoft.com/v1.0/users?$select=id,displayName,userPrincipalName,accountEnabled,assignedLicenses,signInActivity,userType,department,jobTitle&$top=999'
 $inventory.Users=@($users | ForEach-Object { [pscustomobject]@{Id=(Get-Property $_ 'id');UPN=(Get-Property $_ 'userPrincipalName');Name=(Get-Property $_ 'displayName');Enabled=(Get-Property $_ 'accountEnabled');LicenseCount=@((Get-Property $_ 'assignedLicenses') | Where-Object { $null -ne $_ }).Count;UserType=(Get-Property $_ 'userType');Department=(Get-Property $_ 'department');JobTitle=(Get-Property $_ 'jobTitle');LastSignIn=(Get-Field $_ 'signInActivity.lastSuccessfulSignInDateTime')} })
 $threshold=(Get-Date).ToUniversalTime().AddDays(-$InactiveDays)
 foreach($u in $inventory.Users) {
  if (-not $u.Enabled -and $u.LicenseCount -gt 0) { Add-Finding 'ITIGOV-001' 'Entra ID' 'Medium' 'Disabled user retains licenses' $u.UPN 'Review service dependencies and reclaim unnecessary licenses.' 'Optimization' $u.Id }
  if ($u.Enabled -and $u.LicenseCount -gt 0 -and $u.LastSignIn) {
   if ([datetime]$u.LastSignIn -lt $threshold) { Add-Finding 'ITIGOV-002' 'Entra ID' 'Low' 'Licensed account with old successful sign-in' "$($u.UPN): $($u.LastSignIn)" 'Validate workload activity and business need before removing licenses.' 'Optimization' $u.Id }
  }
 }
}
Invoke-Control 'Entra ID' 'Conditional Access configuration' {
 $policies=Get-GraphItems 'https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies'
 $inventory.ConditionalAccess=@($policies | ForEach-Object { [pscustomobject]@{Id=(Get-Property $_ 'id');Name=(Get-Property $_ 'displayName');State=(Get-Property $_ 'state');ModifiedDateTime=(Get-Property $_ 'modifiedDateTime');Conditions=(Get-Property $_ 'conditions');GrantControls=(Get-Property $_ 'grantControls')} })
 if (@($policies).Count -eq 0) { Add-Finding 'ITIENA-001' 'Entra ID' 'High' 'No Conditional Access policies returned' 'Policy collection returned 0 policies.' 'Verify tenant identity protection design, licensing and policy permissions.' }
 foreach($p in $inventory.ConditionalAccess) {
  if ($p.State -eq 'disabled') { Add-Finding 'ITIENA-002' 'Entra ID' 'Info' 'Conditional Access policy disabled' $p.Name 'Confirm the disabled state is intentional and documented.' 'Governance' $p.Id }
 }
}
Invoke-Control 'Entra ID' 'Privileged directory role assignments' {
 $roles=Get-GraphItems 'https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?$expand=roleDefinition'
 $inventory.RoleAssignments=@($roles | ForEach-Object { [pscustomobject]@{Id=(Get-Property $_ 'id');PrincipalId=(Get-Property $_ 'principalId');RoleDefinitionId=(Get-Property $_ 'roleDefinitionId');RoleName=(Get-Field $_ 'roleDefinition.displayName');DirectoryScopeId=(Get-Property $_ 'directoryScopeId')} })
 foreach($r in $inventory.RoleAssignments) {
  if ($r.RoleName -eq 'Global Administrator') { Add-Finding 'ITIENA-003' 'Entra ID' 'Info' 'Global Administrator role assignment' "Principal: $($r.PrincipalId)" 'Review necessity, PIM eligibility, emergency access design and authentication assurance.' 'Governance' $r.Id }
 }
}
Invoke-Control 'Entra ID' 'Directory administration audit (recent events)' {
 $since=(Get-Date).ToUniversalTime().AddDays(-$AuditDays).ToString('yyyy-MM-ddTHH:mm:ssZ')
 $audit=Get-GraphItems "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=activityDateTime ge $since&`$top=500" 10000
 $inventory.DirectoryAudits=@($audit | ForEach-Object { [pscustomobject]@{Id=(Get-Property $_ 'id');Time=(Get-Property $_ 'activityDateTime');Activity=(Get-Property $_ 'activityDisplayName');Category=(Get-Property $_ 'category');Result=(Get-Property $_ 'result');Actor=(Get-Field $_ 'initiatedBy.user.userPrincipalName');TargetIds=(@((Get-Property $_ 'targetResources') | ForEach-Object {(Get-Property $_ 'id')}) -join ', ')} })
}
Invoke-Control 'Intune' 'Managed-device compliance' {
 $devices=Get-GraphItems 'https://graph.microsoft.com/v1.0/deviceManagement/managedDevices?$select=id,deviceName,operatingSystem,complianceState,lastSyncDateTime,managementAgent,azureADDeviceId&$top=1000'
 $inventory.ManagedDevices=@($devices | Where-Object { (Get-Property $_ 'id') } | ForEach-Object { [pscustomobject]@{Id=(Get-Property $_ 'id');Name=(Get-Property $_ 'deviceName');OS=(Get-Property $_ 'operatingSystem');Compliance=(Get-Property $_ 'complianceState');LastSync=(Get-Property $_ 'lastSyncDateTime');EntraDeviceId=(Get-Property $_ 'azureADDeviceId')} })
 foreach($d in $inventory.ManagedDevices) { if ($d.Compliance -eq 'noncompliant') { Add-Finding 'ITIINT-001' 'Intune' 'High' 'Noncompliant managed device' "$($d.Name): $($d.OS)" 'Review the device compliance status and remediate failing policies.' 'Security' $d.Id } }
}
Invoke-Control 'Intune' 'Device compliance policy inventory' {
 $p=Get-GraphItems 'https://graph.microsoft.com/v1.0/deviceManagement/deviceCompliancePolicies'
 $inventory.CompliancePolicies=@($p | ForEach-Object { [pscustomobject]@{Id=(Get-Property $_ 'id');Name=(Get-Property $_ 'displayName');Type=(Get-Property $_ '@odata.type')} })
 if (@($p).Count -eq 0) { Add-Finding 'ITIINT-002' 'Intune' 'Medium' 'No device compliance policies returned' 'Zero compliance policies returned.' 'Review coverage and assignments, and verify Intune licensing.' }
}
Invoke-Control 'Microsoft Defender' 'Security incidents' {
 $incidents=Get-GraphItems 'https://graph.microsoft.com/v1.0/security/incidents?$top=100'
 $inventory.DefenderIncidents=@($incidents | ForEach-Object { [pscustomobject]@{Id=(Get-Property $_ 'id');Name=(Get-Property $_ 'displayName');Severity=(Get-Property $_ 'severity');Status=(Get-Property $_ 'status');Created=(Get-Property $_ 'createdDateTime')} })
 foreach($incident in $inventory.DefenderIncidents) { if ($incident.Status -notin @('resolved','redirected') -and $incident.Severity -in @('high','critical')) { Add-Finding 'ITIDEF-001' 'Microsoft Defender' 'High' 'Open high-severity Defender incident' $incident.Name 'Investigate incident and record incident response progress.' 'Security' $incident.Id } }
}
Invoke-Control 'Governance' 'Subscribed license SKU inventory' {
 $skus=Get-GraphItems 'https://graph.microsoft.com/v1.0/subscribedSkus'
 $inventory.Licenses=@($skus | ForEach-Object { [pscustomobject]@{SKU=(Get-Property $_ 'skuPartNumber');Enabled=(Get-Field $_ 'prepaidUnits.enabled');Consumed=(Get-Property $_ 'consumedUnits');Suspended=(Get-Field $_ 'prepaidUnits.suspended')} })
}
. (Join-Path $PSScriptRoot 'Modules/Advanced.ps1')
Invoke-AdvancedAssessments
Invoke-OptionalCollectors -Exchange:$IncludeExchange -Teams:$IncludeTeams -SharePoint:$IncludeSharePoint -Purview:$IncludePurview -SharePointAdminUrl $SharePointAdminUrl
if(-not $IncludeExchange){Add-Coverage 'Exchange Online' 'Exchange collectors' 'NotAssessed' 'Run with -IncludeExchange'}
if(-not $IncludeTeams){Add-Coverage 'Teams' 'Teams collectors' 'NotAssessed' 'Run with -IncludeTeams'}
if(-not $IncludeSharePoint){Add-Coverage 'SharePoint Online' 'SPO site and sharing collectors' 'NotAssessed' 'Run with -IncludeSharePoint -SharePointAdminUrl'};
if(-not $IncludeSharePoint){Add-Coverage 'OneDrive' 'OneDrive settings' 'NotAssessed' 'Run with -IncludeSharePoint -SharePointAdminUrl'}
if(-not $IncludePurview){Add-Coverage 'Microsoft Purview' 'Purview policies' 'NotAssessed' 'Run with -IncludePurview'}
Add-Coverage 'Microsoft Sentinel' 'Sentinel workspace analytics' 'NotAssessed' 'Requires explicit subscription/workspace scope and Azure RBAC; collector not yet implemented'
$maester=[ordered]@{State='NotRun';Tests=0;Passed=0;Failed=0;Skipped=0;Report='';Details=''}
if ($RunMaester) {
 try {
  Import-Module Maester -ErrorAction Stop
  $maesterPath=Join-Path $runRoot 'Maester.html'
  $maesterJson=Join-Path $runRoot 'Maester.json'
  $args=@{OutputHtmlFile=$maesterPath;OutputJsonFile=$maesterJson;NonInteractive=$true}
  if ($MaesterTestsPath) { $args.Path=(Resolve-Path -LiteralPath $MaesterTestsPath).Path }
  else { throw 'Set -MaesterTestsPath to an existing Maester tests folder, to avoid running from an unintended working directory.' }
  $res=Invoke-Maester @args
  $maester.State='Completed'; $maester.Report='Maester.html'; if(Test-Path $maesterJson){$mj=Get-Content $maesterJson -Raw|ConvertFrom-Json; $maester.Details='Test results written to Maester.json'}
  if ($res -and $res.PSObject.Properties.Name -contains 'PassedCount') {
   $maester.Passed=[int]$res.PassedCount; $maester.Failed=[int]$res.FailedCount; $maester.Skipped=[int]$res.SkippedCount
   $maester.Tests=$maester.Passed+$maester.Failed+$maester.Skipped
  }
 } catch { $maester.State='NotAssessed'; $maester.Details=$_.Exception.Message; Write-Warning "Maester: $($_.Exception.Message)" }
}
# Deterministic delta: the comparison is of findings observed in two snapshots,
# not a claim of real-time administrative attribution.
$previousFile=Join-Path $tenantRoot 'latest-snapshot.json'
$previous=@()
if(Test-Path -LiteralPath $previousFile) {
 try { $p=Get-Content -LiteralPath $previousFile -Raw | ConvertFrom-Json; $previous=@($p.Findings) }
 catch { Write-Warning 'Previous snapshot cannot be read; delta comparison skipped.' }
}
$priorKeys=@{};foreach($p in $previous){$priorKeys[[string]$p.Key]=$true}
$currentKeys=@{};foreach($f in $findings){$currentKeys[[string]$f.Key]=$true;if(-not $priorKeys.ContainsKey([string]$f.Key)){$f.Status='New'}}
foreach($p in $previous){if(-not $currentKeys.ContainsKey([string]$p.Key)){$changes.Add([pscustomobject]@{Key=$p.Key;Title=$p.Title;Workload=$p.Workload;Status='Unverified';Caveat='Not proof of remediation. Confirm the corresponding control and its coverage in both runs.'})}}
$report=[ordered]@{SchemaVersion='0.2';TenantId=$TenantId.ToString();Client=$ClientName;Generated=(Get-Date).ToUniversalTime().ToString('o');Parameters=@{InactiveDays=$InactiveDays;AuditDays=$AuditDays};Findings=@($findings.ToArray());Coverage=@($coverage.ToArray());Inventory=$inventory;Changes=@($changes.ToArray());Maester=$maester}
Save-Json $report (Join-Path $runRoot 'Assessment.json')
Save-Json ([ordered]@{TenantId=$TenantId.ToString();Generated=$report.Generated;Findings=@($findings.ToArray())}) (Join-Path $runRoot 'Snapshot.json')
if($findings.Count){$findings | Export-Csv (Join-Path $runRoot 'Findings.csv') -NoTypeInformation -Encoding utf8} else {'Id,Key,Workload,Severity,Category,Title,Evidence,Recommendation,ObjectId,Status' | Set-Content (Join-Path $runRoot 'Findings.csv') -Encoding utf8}
# HTML is static and self-contained; JSON is embedded as text, never as executable code.
$payload=($report | ConvertTo-Json -Depth 35 -Compress).Replace('<','\u003c').Replace('>','\u003e').Replace('&','\u0026')
$template=@'
<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ITI | Microsoft 365 Security & Governance</title><style>
:root{color-scheme:light;--ink:#18263b;--muted:#657387;--brand:#e66e3b;--bg:#f5f7fa;--border:#dfe5ec}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.55 Segoe UI,Arial,sans-serif}.layout{display:grid;grid-template-columns:230px 1fr;min-height:100vh}aside{background:#122338;color:#fff;padding:26px 18px}aside h2{font-size:19px;line-height:1.2;margin:2px 0 26px}aside a{display:block;color:#cdd7e5;text-decoration:none;padding:11px 10px;border-radius:8px}aside a:hover{background:#2a425e;color:#fff}main{padding:26px 32px;max-width:1500px;width:100%}.eyebrow{text-transform:uppercase;letter-spacing:.12em;color:var(--brand);font-size:11px;font-weight:800}h1{font-size:28px;margin:6px 0}h2{font-size:20px;margin:30px 0 12px}.sub{color:var(--muted)}.cards{display:grid;grid-template-columns:repeat(4,minmax(160px,1fr));gap:14px;margin:22px 0}.card,.panel{background:white;border:1px solid var(--border);border-radius:12px;padding:18px}.metric{font-size:32px;font-weight:800}.panel{margin-bottom:18px;overflow:auto}.table{width:100%;border-collapse:collapse}.table th{text-align:left;background:#f2f5f9;color:#42536a;font-size:12px}.table td,.table th{border-bottom:1px solid #e8edf2;padding:11px;vertical-align:top}.badge{border-radius:99px;display:inline-block;padding:2px 9px;background:#eaf0f5;font-size:11px;font-weight:700}.Critical,.High{background:#ffe2df;color:#9c2319}.Medium{background:#fff0d6;color:#8b5407}.Low,.Info{background:#e4f0fc;color:#174b88}.New{background:#e1f4e8;color:#186539}input,select{padding:11px 12px;border:1px solid #d5dce5;border-radius:8px;background:white;font:inherit}#filter{min-width:270px}.filters{display:flex;flex-wrap:wrap;gap:10px;margin-bottom:14px}a.link{color:#bc502c}small{color:var(--muted)}.status-not{color:#a4591e}.status-ok{color:#157549}@media(max-width:900px){.layout{display:block}aside{padding:15px}aside a{display:inline-block}main{padding:20px}.cards{grid-template-columns:repeat(2,minmax(120px,1fr))}}@media print{aside,.filters{display:none}.layout{display:block}body{background:white}main{padding:0}.panel{break-inside:avoid}}
</style></head><body><div class="layout"><aside><div class="eyebrow">ITI INC.</div><h2>Security &<br>Governance</h2><a href="#overview">Overview</a><a href="#findings">Findings</a><a href="#coverage">Coverage</a><a href="#changes">Historical changes</a><a href="#inventory">Inventories</a><a href="#details">Detailed tables</a><a href="#maester">Maester</a></aside><main><div class="eyebrow">Microsoft 365 / Governance assessment</div><h1 id="overview">Security Posture Review</h1><div id="context" class="sub"></div><div class="cards" id="metrics"></div><div class="panel"><strong>Methodology and limitations</strong><p class="sub">Only completed controls are assessed. A missing permission, unsupported API, license limitation or unfinished collector is NotAssessed, not Passed. Severity is an initial triage suggestion; a risk acceptance and evidence review are required. This version does not compute a tenant security score. This report can contain personal and sensitive security metadata.</p></div><h2 id="findings">Prioritized findings</h2><div class="filters"><input type="search" id="filter" placeholder="Search findings, objects, evidence"><select id="severity"><option value="">All severities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>Info</option></select><select id="workload"><option value="">All workloads</option></select></div><div class="panel"><table class="table"><thead><tr><th>Priority</th><th>Workload</th><th>Finding and evidence</th><th>Recommended action</th><th>Status</th></tr></thead><tbody id="findingsBody"></tbody></table></div><h2 id="coverage">Assessment coverage</h2><div class="panel"><table class="table"><thead><tr><th>Workload</th><th>Control</th><th>Status</th><th>Notes</th></tr></thead><tbody id="coverageBody"></tbody></table></div><h2 id="changes">Delta from previous assessment</h2><div class="panel" id="changesPanel"></div><h2 id="inventory">Collected inventories</h2><div class="panel" id="inventoryPanel"></div><h2 id="details">Detailed inventories</h2><div class="panel"><div class="filters"><select id="inventoryName"></select><input id="inventorySearch" type="search" placeholder="Search selected inventory"></div><div id="detailTable"></div></div><h2 id="maester">Maester execution</h2><div class="panel" id="maesterPanel"></div><small>ITI Microsoft 365 Security & Governance Assessment v0.2 • Read-only assessment</small></main></div><script type="application/json" id="reportData">__JSON__</script><script>
const data=JSON.parse(document.getElementById('reportData').textContent);const el=id=>document.getElementById(id);const h=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));const findings=data.Findings||[],coverage=data.Coverage||[],inventory=data.Inventory||{};el('context').textContent=`${data.Client}  •  Tenant ${data.TenantId}  •  ${new Date(data.Generated).toLocaleString()}`;const assessed=coverage.filter(x=>x.State==='Assessed').length,missing=coverage.filter(x=>x.State!=='Assessed').length;[['Findings',findings.length],['High / Critical',findings.filter(x=>['High','Critical'].includes(x.Severity)).length],['Controls assessed',assessed],['Not assessed',missing]].forEach(([l,n])=>el('metrics').insertAdjacentHTML('beforeend',`<div class="card"><div class="sub">${h(l)}</div><div class="metric">${n}</div></div>`));const rows=()=>{let q=el('filter').value.toLowerCase(),s=el('severity').value,w=el('workload').value;const items=findings.filter(x=>(!s||x.Severity===s)&&(!w||x.Workload===w)&&JSON.stringify(x).toLowerCase().includes(q)).sort((a,b)=>['Critical','High','Medium','Low','Info'].indexOf(a.Severity)-['Critical','High','Medium','Low','Info'].indexOf(b.Severity));el('findingsBody').innerHTML=items.map(x=>`<tr><td><span class="badge ${h(x.Severity)}">${h(x.Severity)}</span></td><td>${h(x.Workload)}</td><td><strong>${h(x.Title)}</strong><br><small>${h(x.Id)} • ${h(x.Evidence)}</small></td><td>${h(x.Recommendation)}</td><td><span class="badge ${h(x.Status)}">${h(x.Status)}</span></td></tr>`).join('')||'<tr><td colspan="5">No matching findings. Check assessment coverage before concluding there are no risks.</td></tr>'}; [...new Set(findings.map(x=>x.Workload))].sort().forEach(x=>el('workload').insertAdjacentHTML('beforeend',`<option>${h(x)}</option>`));['filter','severity','workload'].forEach(x=>el(x).addEventListener(x==='filter'?'input':'change',rows));rows();el('coverageBody').innerHTML=coverage.map(x=>`<tr><td>${h(x.Workload)}</td><td>${h(x.Control)}</td><td class="${x.State==='Assessed'?'status-ok':'status-not'}">${h(x.State)}</td><td>${h(x.Details)}</td></tr>`).join('');const changes=data.Changes||[];el('changesPanel').innerHTML=changes.length?`<p>${changes.length} previously observed findings were not found in this run. They are unverified until coverage is confirmed.</p><ul>${changes.map(x=>`<li>${h(x.Workload)} — ${h(x.Title)} (${h(x.Status)})</li>`).join('')}</ul>`:'<p class="sub">No previously observed findings disappeared, or this is the first snapshot.</p>';el('inventoryPanel').innerHTML=Object.entries(inventory).map(([k,v])=>`<p><strong>${h(k)}:</strong> ${Array.isArray(v)?v.length:1} collected records <small>(full details in Assessment.json)</small></p>`).join('');const invSelect=el('inventoryName'), invFilter=el('inventorySearch'),invTable=el('detailTable');Object.keys(inventory).sort().forEach(k=>{const op=document.createElement('option');op.value=k;op.textContent=k;invSelect.appendChild(op)});function drawInventory(){const v=inventory[invSelect.value],arr=Array.isArray(v)?v:(v?[v]:[]);const q=invFilter.value.toLowerCase();const matched=arr.filter(x=>JSON.stringify(x).toLowerCase().includes(q)).slice(0,500);const keys=[...new Set(matched.flatMap(x=>Object.keys(x||{})))].slice(0,12);invTable.innerHTML='<p class="sub">'+matched.length+' displayed records (max 500). Complete data: Assessment.json</p><table class="table"><thead><tr>'+keys.map(k=>'<th>'+h(k)+'</th>').join('')+'</tr></thead><tbody>'+matched.map(x=>'<tr>'+keys.map(k=>'<td>'+h(typeof x[k]==='object'?JSON.stringify(x[k]):x[k])+'</td>').join('')+'</tr>').join('')+'</tbody></table>'}invSelect.addEventListener('change',drawInventory);invFilter.addEventListener('input',drawInventory);drawInventory();const m=data.Maester||{};el('maesterPanel').innerHTML=`<p>Status: <strong>${h(m.State)}</strong>; Passed: ${h(m.Passed)}; Failed: ${h(m.Failed)}; Skipped: ${h(m.Skipped)}.</p>${m.Report?'<a class="link" href="Maester.html">Open original Maester report</a>':''}<p class="sub">${h(m.Details)}</p>`;
</script></body></html>
'@
$html=$template.Replace('__JSON__',$payload)
$htmlPath=Join-Path $runRoot 'Assessment.html'
[System.IO.File]::WriteAllText($htmlPath,$html,[System.Text.UTF8Encoding]::new($false))
# Atomic-enough latest replacement; keep dated original snapshot separately.
if (@($coverage | Where-Object State -eq 'Assessed').Count -gt 0) {
 Copy-Item -LiteralPath (Join-Path $runRoot 'Snapshot.json') -Destination $previousFile -Force
} else {
 Write-Warning 'No controls assessed; previous baseline snapshot was NOT overwritten.'
}
Write-Host "[ITI] HTML: $htmlPath" -ForegroundColor Green
Write-Host "[ITI] Findings: $($findings.Count); assessed controls: $(@($coverage | Where-Object State -eq 'Assessed').Count); not assessed: $(@($coverage | Where-Object State -ne 'Assessed').Count)" -ForegroundColor Green
if ($OpenReport) { Start-Process -FilePath $htmlPath }
[pscustomobject]@{Report=$htmlPath;Findings=$findings.Count;Assessed=@($coverage | Where-Object State -eq 'Assessed').Count;NotAssessed=@($coverage | Where-Object State -ne 'Assessed').Count}
