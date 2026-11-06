# Client B – Tuning Analytics Rules Deployment

## Change summary

This change deploys 27 Microsoft-provided Sentinel analytics rule templates as active rules. All of them are set to **Informational** and named with a `[Tuning]` prefix.

A companion automation rule tags their incidents `Tuning` and closes them automatically, so the SOC queue isn't affected. The rules are under review to confirm alert volumes before they're promoted.

No data connectors, data collection or other workspace settings change.

## Files

| File | Purpose | Deployment |
| --- | --- | --- |
| `CB_Tuning_Analytics_Rules.json` | 27 analytics rules (ARM template) | Sentinel → Analytics → Import |
| `CB_Tuning_AutoClose_AutomationRule.json` | Auto-close automation rule (ARM template) | Azure portal → Deploy a custom template (after the rules) |

## Rules

| # | Rule | What it detects | Data source | Runs |
| --- | --- | --- | --- | --- |
| 1 | Excessive Windows Logon Failures | Accounts with over 50 Windows logon failures today, at least a third of the previous 7 days' total | Windows Security events | Daily |
| 2 | Lateral Movement via DCOM | Use of Windows DCOM (MMC20.Application) to run commands on another computer | Windows event logs | Hourly |
| 3 | Security Event log cleared | Windows Security log being cleared (event 1102) | Windows Security events | Daily |
| 4 | Brute force attack against an Entra-authenticated Windows device | Multiple failed sign-ins followed by a success on Entra-joined, hybrid-joined or Cloud PC devices | Entra ID sign-in logs | Daily |
| 5 | Suspicious Powershell Commandlet Executed | PowerShell commands commonly used by attackers for lateral movement, privilege escalation or exfiltration | Defender for Endpoint | Hourly |
| 6 | Office365 Sharepoint File transfer above threshold | A user transferring an unusually high number of SharePoint files in 15 minutes | Microsoft 365 audit (OfficeActivity) | Every 15 min |
| 7 | Audit policy manipulation using auditpol utility | Attempts to change Windows audit policy with auditpol | Defender for Endpoint, Windows events | Daily |
| 8 | Windows Binaries Executed from Non-Default Directory | Built-in Windows binaries run from outside their normal folders (a common evasion trick) | Windows Security events | Hourly |
| 9 | SharePointFileOperation via previously unseen IPs | Significant increases in SharePoint uploads/downloads from IP addresses not seen before for the user | Microsoft 365 audit | Daily |
| 10 | Scheduled Task Hide | Scheduled tasks being hidden by deleting their security descriptor (Tarrask malware technique) | Windows Security events (needs registry auditing) | Daily |
| 11 | Non Domain Controller Active Directory Replication | Non-DC accounts requesting AD replication (DCSync-style credential theft) | Windows Security events (DCs) | Daily |
| 12 | LaZagne Credential Theft | Execution of the LaZagne password-recovery tool | Defender for Endpoint | Hourly |
| 13 | Credential added after admin consented to Application | Credentials added to an app by one user after another user granted it admin consent | Entra ID audit logs | Daily |
| 14 | Password spray attack against ADFSSignInLogs | Failed AD FS sign-ins across many accounts from one IP | AD FS sign-in logs | Every 30 min |
| 15 | New access credential added to Application or Service Principal | A new credential added to an app or service principal that already had one | Entra ID audit logs | Hourly |
| 16 | Potential Password Spray Attack (Uses Authentication Normalization) | Failed logons for more than 15 users from one source within 5 minutes, across all normalised authentication sources | ASIM authentication (Windows, Entra ID, Linux etc.) | Hourly |
| 17 | Detect Potential Kerberoast Activities | An account requesting a high number of Kerberos service tickets (Kerberoasting) | Defender for Identity | Hourly |
| 18 | Failed AzureAD logons but success logon to host | IPs with 5 or more failed Entra ID sign-ins that then log on successfully to a host | Entra ID sign-in logs, Windows Security events | Daily |
| 19 | Remote File Creation with PsExec | PsExec creating files on remote devices, as used to spread ransomware | Defender for Endpoint | Hourly |
| 20 | Correlate Unfamiliar sign-in properties & atypical travel alerts | Both Entra ID Protection alerts for the same user within 10 minutes | Entra ID Protection alerts, UEBA | Daily |
| 21 | Gain Code Execution on ADFS Server via SMB + Remote Service or Scheduled Task | Code execution on an AD FS server via SMB plus a remote service or scheduled task | Windows Security events | Daily |
| 22 | New country signIn with correct password | A correct password entered from a country the user hasn't signed in from in 7 days, even if MFA stopped the sign-in | Entra ID sign-in logs | Daily |
| 23 | Privileged Accounts - Sign in Failure Spikes | Spikes in failed sign-ins for privileged accounts against their historical baseline | Entra ID sign-in logs, UEBA | Daily |
| 24 | Authentication Methods Changed for Privileged Account | Authentication methods (e.g. MFA) changed on a privileged account | Entra ID audit logs, UEBA | Every 2 hours |
| 25 | NRT Security Event log cleared | Near-real-time version of rule 3 | Windows Security events | Near real time |
| 26 | NRT Privileged Role Assigned Outside PIM | A privileged Entra ID role assigned outside Privileged Identity Management | Entra ID audit logs | Near real time |
| 27 | Privileged User Logon from new ASN | A privileged account signing in from a network (ASN) not used in the last 14 days | Entra ID sign-in logs, UEBA | Daily |

## Automation rule

**CB - Auto-close [Tuning] analytics**: when an incident is created by any of the 27 rules above, it:

1. Adds the tag `Tuning`.
2. Closes the incident as **Benign Positive – suspicious but expected**, with the comment "Tuning rule - auto-closed while under review".

Incidents that Defender correlates with alerts from other rules may not be auto-closed. That's intended, because a correlated incident should be reviewed.

## Changes from the Microsoft templates

- **All 27 rules:** severity set to Informational, and `[Tuning]` added to the rule and alert names.
- **Rule 16:** updated to the current built-in ASIM parser (`_Im_Authentication`) and field name (`SrcIpAddr`). The template's originals don't work in this workspace.
- Each rule stays linked to its original template, so Sentinel continues to offer template updates.

## Prerequisites and notes

- Rules 20, 23, 24 and 27 need UEBA enabled, because they use the `IdentityInfo` table. The import fails for these four if the table doesn't exist.
- Rules 3 and 25 detect the same event, one daily and one in near real time. Both will be compared before one is kept.
- Rule 11: the domain controller list in the query is commented out and still needs populating.
- Rule 17: the `MaxCount` threshold (default 70 requests in 2 minutes) needs tuning to the environment.
- Rule 10 only returns results if registry auditing is enabled on the Task Scheduler `TaskCache\Tree` key.

## Review

Run this query weekly to see which tuning rules are firing:

```kql
SecurityAlert
| where TimeGenerated > ago(7d)
| where AlertName startswith "[Tuning]"
| summarize Alerts = count(), LastSeen = max(TimeGenerated) by AlertName
| order by Alerts desc
```

To promote a rule to production, remove the `[Tuning]` prefix, set the intended severity, and remove the rule from the automation rule's conditions.

## Rollback

Delete the `[Tuning]` rules and the automation rule from the workspace. No other configuration is changed.
