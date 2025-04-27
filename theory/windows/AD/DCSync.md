---
title: DCSync - Active Directory Replication
description: DCSync is a technique used by attackers to extract password hashes and other sensitive information from Active Directory domain controllers. This technique allows attackers to impersonate domain controllers and request replication data, which can include password hashes for all users in the domain.
layout: post
date: 2025-04-25
---

# DCSync - Active Directory Replication
DCSync is a technique used by attackers to extract password hashes and other sensitive information from Active Directory domain controllers. This technique allows attackers to impersonate domain controllers and request replication data, which can include password hashes for all users in the domain.

## Overview
By impersonating a domain controller, an attacker can request replication data, which may include password hashes for all users in the domain. This technique is particularly effective against environments that do not have proper security measures in place, or the attacker was able to get hold to a very privileged account.

## Requirements
- An account with the `Replicating Directory Changes` permission. Meaning the account must be a member of the `Domain Admins` group or have been delegated the `Replicating Directory Changes` permission or With both GetChanges and GetChangesAll permissions on the domain object. 

## Attacking With DCSync

### From Linux
- Impacket's `secretsdump.py` is a popular tool for performing DCSync attacks. It can be used to extract password hashes and other sensitive information from Active Directory.

```bash
secretsdump.py <DOMAIN>/<USERNAME>@<DOMAIN_CONTROLLER>
```

### From Windows
- Mimikatz is a powerful tool that can be used to perform DCSync attacks on Windows systems. The `lsadump::dcsync` command can be used to extract password hashes and other sensitive information from Active Directory.

```powershell
mimikatz # lsadump::dcsync /domain:<DOMAIN>  /user:<USERNAME>
```

## References
- [Bloodhound](https://bloodhound.readthedocs.io/en/latest/data-analysis/edges.html#allowedtodelegate)
