# Incident Investigation Writeup

## Alert

**Incident types:** Brute Force - Failed RDP Logins and Username Spraying Against RDP  
**Asset:** `honeypot-vm`  
**Primary log source:** Windows Security Events in Microsoft Sentinel  
**Main event IDs:** `4625` failed logon and `4624` successful logon  
**MITRE ATT&CK mapping:** `T1110` Brute Force, `T1110.003` Password Spraying, and `T1078` Valid Accounts as the possible compromise condition.

## What I Saw

The honeypot VM was exposed to the internet over RDP in a controlled Azure lab environment. After exposure, it quickly began receiving automated login attempts from many public source IPs.

The final dashboard showed more than **77,000 failed RDP login attempts**. Romania was the highest-volume source country, with one source IP generating more than **46,000 attempts** by itself. Other major source countries included Russia, India, the United Kingdom, Taiwan, Brazil, the United States, Germany, Colombia, and Vietnam.

The most targeted usernames were predictable administrative or cloud-related account names, including:

- `HONEYPOT\Administrator`
- `Administrator`
- `ADMINISTRADOR`
- `ADMIN`
- `admin`
- `USER`
- `AZUREUSER`

This activity looked automated rather than manual. The username pattern suggests that bots were trying common Windows, administrator, and Azure VM style account names.

## Assessment

The activity is consistent with public internet RDP brute force and username spraying. Repeated failed logons from the same sources map to **MITRE ATT&CK T1110 Brute Force**. Repeated attempts against many different usernames map to **T1110.003 Password Spraying**.

The volume and repetition suggest commodity bot or scanner activity. A small number of sources generated a large percentage of the total attempts, which is common in cloud honeypots exposed to RDP.

## Did It Succeed?

I checked for successful remote logons using Event ID `4624`.

I also ran a compromise check that excluded my controlled tester IPs. This returned **no external successful logons**, meaning there was no evidence that a real attacker successfully accessed the VM.

Separately, I performed a controlled validation test by intentionally entering wrong RDP passwords several times and then logging in successfully with the correct credential. That produced the expected detection pattern of multiple failed logons followed by successful logons from the same tester source IP against `honeypot-vm`.

The controlled tester IPs should be blurred or replaced with placeholders in public screenshots.

## Response

In a production environment, I would respond by:

1. Confirming whether any successful logons occurred from suspicious external IPs.
2. Reviewing the targeted account names and checking whether privileged accounts were involved.
3. Blocking high-volume attacker IPs at the firewall or network security group.
4. Confirming account lockout, strong password, and MFA controls where applicable.
5. Reviewing the host for signs of persistence, new users, suspicious processes, or unusual services.
6. Keeping the high severity `Successful Login After Brute Force` rule enabled because it represents the possible compromise condition.
7. Tuning brute force and username spraying thresholds to reduce noise while preserving high-confidence alerts.

## Conclusion

The honeypot successfully captured real RDP brute force and username spraying activity from the public internet. The attacks did not result in a confirmed real compromise. The lab validated a full SOC workflow: log collection, KQL analysis, MITRE mapped detection rules, incident generation, SOAR automation, workbook dashboards, and analyst investigation.
