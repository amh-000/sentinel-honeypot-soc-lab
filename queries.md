# KQL Query Reference

All Kusto Query Language used in the Cloud Honeypot SOC Lab, grouped by purpose.

## Pipeline Verification

Confirm logs are arriving from the honeypot:

```kql
SecurityEvent
| take 10
```

## Analysis Queries

Failed logons per source IP:

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress
| sort by FailedAttempts desc
```

Attacks over time:

```kql
SecurityEvent
| where EventID == 4625
| summarize count() by bin(TimeGenerated, 1h)
| render timechart
```

Most targeted usernames:

```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by Account
| sort by Attempts desc
| take 10
```

Attacker IPs enriched with geolocation (powers the dashboard map):

```kql
SecurityEvent
| where EventID == 4625
| summarize Attempts = count() by IpAddress
| extend GeoInfo = geo_info_from_ip_address(IpAddress)
| extend Country = tostring(GeoInfo.country), City = tostring(GeoInfo.city), Latitude = todouble(GeoInfo.latitude), Longitude = todouble(GeoInfo.longitude)
| project IpAddress, Attempts, Country, City, Latitude, Longitude
| sort by Attempts desc
```

## Detection Rules

### Rule 1: Brute Force, Failed RDP Logins
MITRE T1110 Brute Force, Credential Access, Medium severity.

```kql
SecurityEvent
| where EventID == 4625
| summarize FailedAttempts = count() by IpAddress, Computer
| where FailedAttempts >= 10
```

Entity mapping: IP (Address = IpAddress), Host (HostName = Computer).

### Rule 2: Successful Login After Brute Force
MITRE T1078 Valid Accounts, Initial Access, High severity.

```kql
SecurityEvent
| where EventID in (4624, 4625)
| where IpAddress != "-" and isnotempty(IpAddress)
| summarize FailedAttempts = countif(EventID == 4625), SuccessfulLogins = countif(EventID == 4624) by IpAddress, Computer, Account
| where FailedAttempts >= 5 and SuccessfulLogins >= 1
| sort by FailedAttempts desc
```

Entity mapping: IP (Address = IpAddress), Host (HostName = Computer), Account (Name = Account).

### Rule 3: Username Spraying Against RDP
MITRE T1110.003 Password Spraying, Credential Access, Medium severity.

```kql
SecurityEvent
| where EventID == 4625
| where IpAddress != "-" and isnotempty(IpAddress)
| summarize DistinctUsernames = dcount(Account), TotalAttempts = count(), UsernamesTried = make_set(Account, 20) by IpAddress, Computer
| where DistinctUsernames >= 5
| sort by DistinctUsernames desc
```

Entity mapping: IP (Address = IpAddress), Host (HostName = Computer).

## Threat Hunting Queries

Top attacker IPs:

```kql
SecurityEvent
| where EventID == 4625
| summarize count() by IpAddress
| sort by count_ desc
```

Top targeted accounts:

```kql
SecurityEvent
| where EventID == 4625
| summarize count() by Account
| sort by count_ desc
```

Any remote successful logon (compromise watch):

```kql
SecurityEvent
| where EventID == 4624
| where IpAddress != "-"
| project TimeGenerated, Account, IpAddress, Computer, LogonType
```

## Validation Queries

Confirm the controlled breach test produced the expected pattern:

```kql
SecurityEvent
| where EventID in (4624,4625)
| where IpAddress != "-"
| summarize Failed = countif(EventID==4625), Success = countif(EventID==4624) by IpAddress
| where Failed >= 5 and Success >= 1
```

Compromise check that excludes the controlled tester IP (replace the value with your own):

```kql
let MyIP = "YOUR_TEST_IP_HERE";
SecurityEvent
| where EventID == 4624
| where IpAddress != "-" and isnotempty(IpAddress)
| where IpAddress != MyIP
| project TimeGenerated, Account, IpAddress, Computer, LogonType
| sort by TimeGenerated desc
```

An empty result confirms no external attacker successfully logged in.

## Optional: Microsoft Entra ID Identity Detection

If Entra ID sign in logs are connected, this rule detects repeated failed sign ins (MITRE T1110 Brute Force):

```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count(), Reasons = make_set(ResultDescription, 5) by UserPrincipalName, IPAddress
| where FailedAttempts >= 5
| sort by FailedAttempts desc
```

Entity mapping: Account (FullName = UserPrincipalName), IP (Address = IPAddress).
