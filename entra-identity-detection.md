# Microsoft Entra ID Identity Detection Add-On

## Purpose

This add-on expands the Microsoft Sentinel honeypot lab beyond Windows VM telemetry by adding identity-focused monitoring from Microsoft Entra ID.

The core honeypot detects RDP attacks against a Windows host. Entra ID logging adds visibility into cloud identity activity such as failed sign-ins, audit events, service principal activity, and risky user signals.

## Diagnostic Setting

A diagnostic setting named `send-to-sentinel` was created in Microsoft Entra ID and pointed to the existing Log Analytics workspace:

`law-sentinel-lab`

Enabled log categories included:

- `AuditLogs`
- `SignInLogs`
- `NonInteractiveUserSignInLogs`
- `ServicePrincipalSignInLogs`
- `RiskyUsers`
- `UserRiskEvents`
- `RiskyServicePrincipals`

## Verification Queries

Use these in Log Analytics to verify whether Entra ID logs are arriving.

```kql
SigninLogs
| sort by TimeGenerated desc
| take 20
```

```kql
AuditLogs
| sort by TimeGenerated desc
| take 20
```

```kql
AADServicePrincipalSignInLogs
| sort by TimeGenerated desc
| take 20
```

If the tables return no rows, the diagnostic setting may still be waiting for new Entra activity, or the tenant may not have enough identity activity to produce useful results yet.

## Optional Detection Rule

If `SigninLogs` returns data, create this scheduled analytics rule.

**Rule name:** Entra ID - Repeated Failed Sign-Ins  
**Severity:** Medium  
**MITRE ATT&CK:** `T1110` Brute Force  
**Tactic:** Credential Access  

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count(), FailureReasons = make_set(ResultDescription, 5) by UserPrincipalName, IPAddress
| where FailedAttempts >= 5
| sort by FailedAttempts desc
```

## Entity Mapping

**Account entity**

- Identifier: `FullName`
- Value: `UserPrincipalName`

**IP entity**

- Identifier: `Address`
- Value: `IPAddress`

## Schedule

Recommended schedule:

- Run query every: 1 hour
- Lookup data from last: 24 hours
- Alert threshold: greater than 0
- Create incidents from alerts: enabled

## Portfolio Note

This step is optional for the core honeypot project. The main SOC lab is complete with Windows Security Events, Sentinel analytics rules, incidents, SOAR automation, MITRE coverage, workbook dashboards, and controlled validation.

The Entra ID add-on is included to show identity monitoring awareness and IAM-related Sentinel expansion.
