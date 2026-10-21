# ITI Microsoft 365 Security & Governance Assessment v0.2

Read-only PowerShell 7.2+ tenant assessment, evolving from v0.1.1. Includes Graph collectors, security posture findings, granular inventory tables in a standalone ITI HTML dashboard, JSON, CSV, snapshot comparisons, optional Exchange Online / Teams / SharePoint / Purview sessions and optional Maester.

## Requirements

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Maester -Scope CurrentUser
# Optional depending on switches:
Install-Module ExchangeOnlineManagement -Scope CurrentUser
Install-Module MicrosoftTeams -Scope CurrentUser
Install-Module Microsoft.Online.SharePoint.PowerShell -Scope CurrentUser
```

## Run

```powershell
.\Invoke-ITIM365Assessment.ps1 -TenantId 'TENANT-GUID' -OpenReport
# Full accessible workloads (separate service sign-ins and admin permissions may be required)
.\Invoke-ITIM365Assessment.ps1 -TenantId 'TENANT-GUID' -ClientName 'Customer' -IncludeExchange -IncludeTeams -IncludeSharePoint -SharePointAdminUrl 'https://customer-admin.sharepoint.com' -IncludePurview -OpenReport
# Optional Maester tests; set path to the existing Maester test directory
.\Invoke-ITIM365Assessment.ps1 -TenantId 'TENANT-GUID' -RunMaester -MaesterTestsPath 'C:\Maester\tests' -OpenReport
```

Graph sign-in requests multiple delegated read scopes; admins must grant consent as appropriate. Do not grant broad privileges solely to clear an optional test; each missing permission is shown as **NotAssessed**. Defender incidents require `SecurityIncident.Read.All` **and** an appropriate Microsoft Entra role (Security Reader or Global Reader, for instance) and product access. Some Microsoft Graph beta API properties may change; configuration-policy inventory uses beta. Some PowerShell modules and tenants may have different command availability, reported per control.

## Assessment scope

- Entra: users, sign-in age (when returned), disabled licensed accounts, identity metadata, Conditional Access policy state and exclusion triage, directory roles, admin activity, application secret/certificate expiry, enterprise applications, subscriptions.
- Intune: managed devices, compliance states and last sync, compliance policies, Settings Catalog inventory, legacy configuration policies, mobile app protection policies.
- Defender: incidents (with permission), open high severity incident triage.
- Exchange (optional): mailbox forwarding, transport rules, domains, outbound auto-forwarding, anti-phish/spam, Safe Links, Safe Attachments.
- Teams (optional): federation and meeting policy inventory.
- SharePoint/OneDrive (optional): tenant/site sharing and selected OneDrive settings.
- Purview (optional): DLP, retention, labels (policy presence only).
- Sentinel: explicitly *NotAssessed* (Azure subscription/workspace integration remains a separate extension).
- Maester (optional): invoke native test suite and link native HTML; runs only when explicitly requested.

## Important limitations

1. Collected inventories do not imply configuration compliance. Rule-based findings are **triage candidates** that require human review, not a certified audit.
2. `Assessment.json` and the self-contained `Assessment.html` may include sensitive identity, policies and event details; protect and limit access to exports.
3. 403, absent license, incomplete permissions and unavailable modules are **NotAssessed**, not Passed.
4. Graph returns may vary depending on API, licensing and delegated role. Verify completeness before publishing client reports.
5. Snapshot `Existing` / `New` tracks issue keys only; missing findings are **Unverified**, never automatically called Remediated.
6. A first run without Maester is *not* a comprehensive Maester security benchmark. Use `-RunMaester` to add the official test pack.
7. This v0.2 is an expanded implementation, not literally every Microsoft 365 control; some controls (Sentinel, advanced Defender hunting, detailed Purview DLP events, Intune policy assignments) remain planned.
8. No write commands to Microsoft 365 are performed. Export files are written locally. Some optional module sign-in commands can create local connection state.

## Validation

Open `Assessment.html` and review `Coverage` **before** interpreting the findings. Validate `ManagedDevices` inventory count and licensing with tenant admin portals. Test on a non-production tenant first. No live tenant execution was possible during development.

Microsoft Graph API: https://learn.microsoft.com/graph/api/security-list-incidents?view=graph-rest-1.0
Maester: https://maester.dev/
