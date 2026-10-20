# ITI Microsoft 365 Security & Governance Assessment — v0.1

**Initial functional foundation / proof of concept.** This does **not** yet satisfy the complete nine-workload customer statement of work. Modules with no collector are clearly shown as `NotAssessed` in the HTML; no fake compliance score is generated.

## What works in this version

- Microsoft Graph **read-only** collection of Entra users, assigned license count, sign-in data when authorized, Conditional Access policies, current directory-role assignments, Entra directory audit events.
- Intune managed-device compliance and compliance policy inventory.
- Microsoft Defender incidents, and license SKU inventory.
- Initial actionable findings and recommendations for selected observations, tagged by workload and priority.
- Self-contained **light-themed HTML dashboard**, search, priority/workload filters, collected inventory counts and coverage states.
- Separate machine-readable `Assessment.json`, `Findings.csv`, `Snapshot.json` and preserved per-run exports.
- Comparison to previous tenant snapshot: **New** finding statuses and **Not observed** old findings. This is not equivalent to an audited historical change or proven remediation.
- Optional Maester invocation and link to native Maester HTML, preserving its existing tests.

## Limitations / deliberate safeguards

- **Exchange Online, Teams, SharePoint, OneDrive, Purview and Sentinel** collectors require specialized administrative connections, APIs and permissions; they are explicitly marked **NotAssessed** in v0.1.
- No overall posture score in v0.1: results with partial coverage must not look complete.
- Microsoft Graph endpoints may return 403 due to admin roles, consent or license restrictions. Every such collector is marked NotAssessed with its error message.
- Some attributes (including sign-in activity) can be absent and must not be interpreted as inactivity. Check actual usage, integrations, and shared mailboxes before recovering a license.
- Role assignments are an inventory, not a claim of misconfiguration; 'Global Administrator' assignments are for review.
- No changes are performed to the tenant. The tool writes only local output files and updates a local latest snapshot.
- A snapshot may contain personal data / audit actor IDs and must be safeguarded accordingly. Report is offline and embeds its findings.
- Historical audit events have retention/permission limits. The collector provides a sample of recent Entra directory audit data, not a full unified audit export.
- Endpoint/device collection defaults to 10,000 records per endpoint; this needs paging/truncation reporting for very large tenants.
- Run Maester only with a correct, existing tests directory; use the same Maester version as your approved baseline.

## Requirements

- PowerShell 7.2 or later, Windows/macOS/Linux.
- `Microsoft.Graph.Authentication` PowerShell module.
- Optional `Maester` module (2.x) and a downloaded test directory.
- An operator with the appropriate Microsoft Entra permissions and consent for requested Graph scopes.

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
Install-Module Maester -Scope CurrentUser

# Standard first run (authentication prompt)
./Invoke-ITIM365Assessment.ps1 `
  -TenantId '00000000-0000-0000-0000-000000000000' `
  -ClientName 'Client ABC' -OpenReport

# With Maester tests (existing folder)
./Invoke-ITIM365Assessment.ps1 `
  -TenantId '00000000-0000-0000-0000-000000000000' `
  -ClientName 'Client ABC' `
  -RunMaester -MaesterTestsPath 'C:\Maester\tests' -OpenReport

# Reuse already-authenticated Graph session for a matching tenant
./Invoke-ITIM365Assessment.ps1 -TenantId '00000000-0000-0000-0000-000000000000' -SkipConnect
```

**Important:** the sample TenantId is a placeholder; replace it with a real tenant GUID. To run Maester, first obtain and prepare its tests folder per https://maester.dev/.

## Output

`exports/<tenant GUID>/<YYYYMMDD-HHMMSS>/Assessment.html` is the main report. `Maester.html` is created only if requested and Maester succeeds. `latest-snapshot.json` at tenant root stores the last assessment snapshot.

## Recommended next iterations

1. Add Exchange Online anti-spam/phish rules, forwarding, mail-flow, delegated access and administrative role collectors.
2. Add Teams/SharePoint/OneDrive policy and governance collectors.
3. Add Defender posture (MDE onboarding, security configuration coverage, DFO policies), Purview and Sentinel.
4. Add explicit baseline policies and object-level normalized diffs, permission probes, event attribution, acceptance workflow and an executive scoring model only for well-covered domains.
5. Unit/integration tests in a tenant laboratory before production client usage.

### Sources

- Maester `Invoke-Maester`: https://maester.dev/docs/commands/Invoke-Maester/
- Microsoft Graph directory audit: https://learn.microsoft.com/en-us/powershell/module/microsoft.graph.reports/get-mgauditlogdirectoryaudit
