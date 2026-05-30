# KQL Query Reference

All Kusto Query Language used in the Microsoft Sentinel Cloud Honeypot SOC Lab, grouped by purpose.

## Privacy Note

For public screenshots, controlled tester IP addresses should be blurred or replaced with placeholders. In queries below, use placeholders such as `TESTER_IP_1` and `TESTER_IP_2` instead of publishing personal or VPN IPs.

## Pipeline Verification

Confirm logs are arriving from the honeypot:

```kql
SecurityEvent
| take 10
```

Confirm active tables in the workspace:

```kql
search *
| where TimeGenerated > ago(7d)
| summarize Count=count() by $table
| sort by Count desc
```

## Dashboard and Analysis Queries

### Total Failed Login Attempts

```kql
let MyIPs = dynamic(["TESTER_IP_1", "TESTER_IP_2"]);
SecurityEvent
| where EventID == 4625
| where IpAddress !in (MyIPs)
| summarize ['Total Failed Login Attempts'] = count()
```

### Failed Logons Per Source IP

```kql
let MyIPs = dynamic(["TESTER_IP_1", "TESTER_IP_2"]);
SecurityEvent
| where EventID == 4625
| where IpAddress != "-" and isnotempty(IpAddress)
| where IpAddress !in (MyIPs)
| summarize FailedAttempts = count() by IpAddress
| sort by FailedAttempts desc
```

### Attacks Over Time

```kql
let MyIPs = dynamic(["TESTER_IP_1", "TESTER_IP_2"]);
SecurityEvent
| where EventID == 4625
| where IpAddress !in (MyIPs)
| summarize Attempts = count() by bin(TimeGenerated, 1h)
| render timechart
```

### Most Targeted Usernames

```kql
let MyIPs = dynamic(["TESTER_IP_1", "TESTER_IP_2"]);
SecurityEvent
| where EventID == 4625
| where IpAddress !in (MyIPs)
| summarize Attempts = count() by Account
| sort by Attempts desc
| take 10
```

### Attacker IPs Enriched With Geolocation

```kql
let MyIPs = dynamic(["TESTER_IP_1", "TESTER_IP_2"]);
SecurityEvent
| where EventID == 4625
| where IpAddress != "-" and isnotempty(IpAddress)
| where IpAddress !in (MyIPs)
| summarize Attempts = count() by IpAddress
| extend GeoInfo = geo_info_from_ip_address(IpAddress)
| extend Country = tostring(GeoInfo.country), City = tostring(GeoInfo.city), Latitude = todouble(GeoInfo.latitude), Longitude = todouble(GeoInfo.longitude)
| project IpAddress, Attempts, Country, City, Latitude, Longitude
| sort by Attempts desc
```

### Top Attacker Countries

```kql
let MyIPs = dynamic(["TESTER_IP_1", "TESTER_IP_2"]);
SecurityEvent
| where EventID == 4625
| where IpAddress != "-" and isnotempty(IpAddress)
| where IpAddress !in (MyIPs)
| extend Country = tostring(geo_info_from_ip_address(IpAddress).country)
| summarize Attempts = count() by Country
| sort by Attempts desc
```

### Top Attacker Source IPs

```kql
let MyIPs = dynamic(["TESTER_IP_1", "TESTER_IP_2"]);
SecurityEvent
| where EventID == 4625
| where IpAddress != "-" and isnotempty(IpAddress)
| where IpAddress !in (MyIPs)
| extend Country = tostring(geo_info_from_ip_address(IpAddress).country)
| summarize Attempts = count() by IpAddress, Country
| sort by Attempts desc
| take 10
```

## Detection Rules

### Rule 1: Brute Force - Failed RDP Logins

MITRE: `T1110` Brute Force  
Tactic: Credential Access  
Severity: Medium

```kql
SecurityEvent
| where EventID == 4625
| where IpAddress != "-" and isnotempty(IpAddress)
| summarize FailedAttempts = count() by IpAddress, Computer
| where FailedAttempts >= 10
```

Entity mapping:

- IP: Address = `IpAddress`
- Host: HostName = `Computer`

### Rule 2: Successful Login After Brute Force

MITRE: `T1078` Valid Accounts  
Tactic: Initial Access  
Severity: High

```kql
SecurityEvent
| where EventID in (4624, 4625)
| where IpAddress != "-" and isnotempty(IpAddress)
| summarize FailedAttempts = countif(EventID == 4625), SuccessfulLogins = countif(EventID == 4624), AccountsSeen = make_set(Account, 20) by IpAddress, Computer
| where FailedAttempts >= 5 and SuccessfulLogins >= 1
| sort by FailedAttempts desc
```

Entity mapping:

- IP: Address = `IpAddress`
- Host: HostName = `Computer`

Note: The query groups by `IpAddress` and `Computer`, not `Account`, because Windows may log failed and successful RDP activity with different account formats. Account values are preserved in `AccountsSeen`.

### Rule 3: Username Spraying Against RDP

MITRE: `T1110.003` Password Spraying  
Tactic: Credential Access  
Severity: Medium

```kql
SecurityEvent
| where EventID == 4625
| where IpAddress != "-" and isnotempty(IpAddress)
| summarize DistinctUsernames = dcount(Account), TotalAttempts = count(), UsernamesTried = make_set(Account, 20) by IpAddress, Computer
| where DistinctUsernames >= 5
| sort by DistinctUsernames desc
```

Entity mapping:

- IP: Address = `IpAddress`
- Host: HostName = `Computer`

## Threat Hunting Queries

### Top Attacker IPs

```kql
let MyIPs = dynamic(["TESTER_IP_1", "TESTER_IP_2"]);
SecurityEvent
| where EventID == 4625
| where IpAddress != "-" and isnotempty(IpAddress)
| where IpAddress !in (MyIPs)
| summarize Attempts = count() by IpAddress
| sort by Attempts desc
```

### Top Targeted Accounts

```kql
let MyIPs = dynamic(["TESTER_IP_1", "TESTER_IP_2"]);
SecurityEvent
| where EventID == 4625
| where IpAddress !in (MyIPs)
| summarize Attempts = count() by Account
| sort by Attempts desc
```

### Remote Successful Logons

```kql
SecurityEvent
| where EventID == 4624
| where IpAddress != "-" and isnotempty(IpAddress)
| project TimeGenerated, Account, IpAddress, Computer, LogonType
| sort by TimeGenerated desc
```

## Validation Queries

### Controlled Breach Test

Confirms the controlled tester created the expected pattern of failed logons followed by successful logons.

```kql
SecurityEvent
| where EventID in (4624,4625)
| where IpAddress != "-" and isnotempty(IpAddress)
| summarize Failed=countif(EventID==4625), Success=countif(EventID==4624) by IpAddress
| where Failed >= 5 and Success >= 1
```

### Controlled Breach Test With Accounts Preserved

```kql
SecurityEvent
| where EventID in (4624,4625)
| where IpAddress != "-" and isnotempty(IpAddress)
| summarize Failed=countif(EventID==4625), Success=countif(EventID==4624), AccountsSeen=make_set(Account, 20) by IpAddress, Computer
| where Failed >= 5 and Success >= 1
| sort by Failed desc
```

### Compromise Check Excluding Controlled Tester IPs

An empty result means no external source IP successfully logged into the VM besides the controlled tester IPs.

```kql
let MyIPs = dynamic(["TESTER_IP_1", "TESTER_IP_2"]);
SecurityEvent
| where EventID == 4624
| where IpAddress != "-" and isnotempty(IpAddress)
| where IpAddress !in (MyIPs)
| project TimeGenerated, Account, IpAddress, Computer, LogonType
| sort by TimeGenerated desc
```

## Optional: Microsoft Entra ID Identity Detection

If Entra ID sign-in logs are connected, this query detects repeated failed sign-ins.

MITRE: `T1110` Brute Force  
Tactic: Credential Access  
Severity: Medium

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count(), Reasons = make_set(ResultDescription, 5) by UserPrincipalName, IPAddress
| where FailedAttempts >= 5
| sort by FailedAttempts desc
```

Entity mapping:

- Account: FullName = `UserPrincipalName`
- IP: Address = `IPAddress`
