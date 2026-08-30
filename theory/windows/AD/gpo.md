---
title: Group Policy Object (GPO) Abuse
layout: post
date: 2026-08-30
description: "A Group Policy Object is half an LDAP object and half a folder on SYSVOL. Write access to either half is code execution as SYSTEM on every machine the policy is linked to, which is why a single ACE on the Default Domain Controllers Policy is a domain compromise."
permalink: /theory/windows/AD/gpo/
---

# Group Policy Object (GPO) Abuse

## Overview

Group Policy is the mechanism Active Directory uses to push configuration to domain-joined machines. Every domain member periodically asks the directory "which policies apply to me?", downloads them, and applies them **locally, as `NT AUTHORITY\SYSTEM`**. There is no negotiation and no user consent: applying a policy is what a domain member is for.

That design has a direct consequence for an attacker. If you can change what a policy says, you are not escalating privileges on the domain controller, you are asking every machine in the policy's scope to run your code as SYSTEM, voluntarily, on its next refresh. Write access to a GPO is therefore not "a configuration permission", it is remote code execution against a set of hosts.

## The two halves of a GPO

A GPO is stored in two places at once, and both have to be considered.

| Half | Where it lives | What it holds |
|---|---|---|
| GPC (Group Policy Container) | LDAP: `CN={GUID},CN=Policies,CN=System,DC=...` | Metadata, version number, extension list |
| GPT (Group Policy Template) | SYSVOL: `\\<domain>\SYSVOL\<domain>\Policies\{GUID}\` | The actual settings, as files |

The LDAP object is the index card; the SYSVOL folder is the content. A client reads the GPC to learn which client-side extensions (CSEs) to invoke and what version it last saw, then reads the matching files out of the GPT.

The permissions on the two halves are usually, but not always, kept in sync: `nTSecurityDescriptor` on the GPC and the NTFS ACL on the SYSVOL folder are separate objects. An attack needs write access to the SYSVOL folder (to plant the setting) and to the GPC (to bump `versionNumber` and register the CSE, so clients notice the change at all).

### Scope: what a GPO actually reaches

A GPO is inert until it is **linked** to a site, a domain, or an OU, via the `gPLink` attribute on that container. The set of machines that will run your payload is the set of computer objects under the linked container.

Two links matter more than any other because they exist in every domain by default:

| GPO | GUID | Linked to |
|---|---|---|
| Default Domain Policy | `{31B2F340-016D-11D2-945F-00C04FB984F9}` | The domain root |
| Default Domain Controllers Policy | `{6AC1786C-016F-11D2-945F-00C04FB984F9}` | The `Domain Controllers` OU |

Write access to the second one is a domain compromise by itself: its scope is every domain controller, and SYSTEM on a domain controller is `NTDS.dit`.

> A finding of "non-admin group has WriteOwner on a GPO" reads as a medium-severity ACL issue in a report. Which GPO it is decides everything. On a test OU it is a local privilege escalation on a handful of workstations. On `{6AC1786C-...}` it is Domain Admin, and no other step is required.
{: .prompt-danger }

## Which rights are enough

Any right that lets you rewrite the object or its security descriptor eventually collapses into full control:

- **`GenericAll` / `GenericWrite`** on the GPC: write the attributes directly.
- **`WriteDacl`**: grant yourself `GenericAll`, then write.
- **`WriteOwner`**: take ownership, and an owner can always rewrite the DACL, so this reduces to the previous case in two steps.
- **Write access to the SYSVOL folder** without any LDAP right: you can change the settings, but clients will not re-read them until `versionNumber` changes, so this is usually paired with one of the above.

BloodHound surfaces these as `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner` and `Owns` edges pointing at a `GPO` node, and the useful query is always "what does that GPO link to".

Taking ownership and then writing a DACL is the standard two-command sequence:

```bash
bloodyAD --host $DC -d $DOMAIN -u $USER -p $PASS \
  set owner "CN={<GPO-GUID>},CN=POLICIES,CN=SYSTEM,DC=<dc>,DC=<dc>" $USER

dacledit.py -action write -rights FullControl -inheritance \
  -principal $USER \
  -target-dn "CN={<GPO-GUID>},CN=POLICIES,CN=SYSTEM,DC=<dc>,DC=<dc>" \
  $DOMAIN/$USER:$PASS
```

## What you can make a GPO do

Group Policy is a large surface, and several branches of it are equivalent to code execution:

| Setting | Effect | Runs as |
|---|---|---|
| Immediate Scheduled Task (GPP) | One-shot command at next refresh | SYSTEM (machine) or the user |
| Startup / shutdown script | Command at boot | SYSTEM |
| Logon / logoff script | Command at logon | The user |
| Restricted Groups | Adds a principal to a local group | Applied by SYSTEM |
| User Rights Assignment | Grants `SeDebugPrivilege`, `SeImpersonatePrivilege`, ... | Applied by SYSTEM |
| Software Installation | Installs an MSI from a UNC path | SYSTEM |
| Registry preference | Writes any value under `HKLM` | SYSTEM |

The **immediate scheduled task** is what the tooling uses, because it is the only one that fires without a reboot or a logon and then removes itself.

### The immediate task, concretely

An immediate task is a Group Policy Preferences item. The tooling writes:

```
\\<domain>\SYSVOL\<domain>\Policies\{GUID}\Machine\Preferences\ScheduledTasks\ScheduledTasks.xml
```

with a `<ImmediateTaskV2>` element naming the command, the principal to run it as (`NT AUTHORITY\System` for a machine-scoped task), and `<RemoveObjectWhenNoLongerApplies>` so the task deletes itself after one run.

Two LDAP writes on the GPC make clients act on it:

1. `versionNumber` is incremented. Clients cache the last version they applied and skip a GPO whose version has not moved, so without this nothing happens.
2. `gPCMachineExtensionNames` is extended with the GUID pair for the Group Policy Preferences **Scheduled Tasks** client-side extension. A client only invokes the CSEs listed here, so a `ScheduledTasks.xml` in a GPO that never advertises the scheduled-tasks CSE is a file nobody reads.

[`pyGPOAbuse`](https://github.com/Hackndo/pyGPOAbuse) does all three steps:

```bash
pygpoabuse -gpo-id "<GPO-GUID>" $DOMAIN/$USER -hashes :$NTHASH \
  -command "net localgroup administrators $USER /add"
```

Its Windows counterpart is [`SharpGPOAbuse`](https://github.com/FSecureLABS/SharpGPOAbuse), which does the same from an existing session.

> `pyGPOAbuse` refuses to run a second time against a GPO that already has a `ScheduledTasks.xml`, printing `The GPO already includes a ScheduledTasks.xml` and listing the existing tasks. That is a safety check, not a failure: it exists so you do not silently clobber a legitimate preferences file. `-f` appends instead, and `-v` lists what is already there.
{: .prompt-warning }

## Timing: why nothing appears to happen

Writing the task is instant. Its effect is not, because the client decides when to refresh.

| Client | Refresh interval |
|---|---|
| Member workstations and servers | 90 minutes, plus a random 0 to 30 minute offset |
| Domain controllers | 5 minutes |

The short DC interval is what makes the Default Domain Controllers Policy a practical target rather than a theoretical one: the payload lands within minutes. On member machines, expect to wait, or to have a session on the host and force it with `gpupdate /force`.

The usual mistake at this point is to assume the write failed and start adding more permissions. Re-check the primitive itself before escalating: a successful `ScheduledTask ... created!` line means the GPO is already poisoned and the only remaining variable is time.

## Cleanup

An immediate task with `RemoveObjectWhenNoLongerApplies` deletes the scheduled task on the client, but it does **not** delete `ScheduledTasks.xml` from SYSVOL. Anything left behind stays in the policy and applies to every machine in scope, forever, so remove the file and revert `gPCMachineExtensionNames` and any DACL or owner change after the engagement. `dacledit.py` writes a `.bak` of the original descriptor for exactly this reason.

## Detection and defence

- **Treat GPO ACLs as tier-0.** Delegating "manage this GPO" to a helpdesk or automation group hands that group SYSTEM on every machine in scope. Audit `nTSecurityDescriptor` on every object under `CN=Policies,CN=System` and the NTFS ACLs under SYSVOL, not just the ones on user and computer objects.
- **Alert on `versionNumber` and `gPCMachineExtensionNames` changes.** Legitimate GPO edits happen through GPMC, from an administrative workstation, during change windows. An LDAP write to those attributes from anything else is worth a page.
- **Watch SYSVOL for new preference files.** A `ScheduledTasks.xml` appearing under a policy that never had one is a high-fidelity signal; file auditing on the SYSVOL share catches it.
- **Event ID 4739 / 4735** on the DCs catch the local-group change that the payload usually performs, and Event ID 4698 (scheduled task created) fires on each client that applies the task.
- **Never link a delegated GPO at the domain or Domain Controllers level.** Scope is the only thing standing between a delegated permission and a domain compromise.

## Examples on this site

Boxes on this site that abuse Group Policy, listed automatically from their tags (add a matching tag to `gpo_tags` below to include a new one):

{% assign gpo_tags = "gpo,sysvol" | split: "," -%}
{% for post in site.posts -%}
{%- assign match = false -%}
{%- for t in post.tags -%}
{%- if gpo_tags contains t -%}{%- assign match = true -%}{%- endif -%}
{%- endfor -%}
{%- if match %}
- [{{ post.title }}]({{ post.url }}){% endif -%}
{%- endfor %}

## References

- [Microsoft - Group Policy processing and precedence](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/jj573586(v=ws.11))
- [Microsoft - Configure Group Policy refresh interval for domain controllers](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/cc735023(v=ws.11))
- [Hackndo - pyGPOAbuse](https://github.com/Hackndo/pyGPOAbuse)
- [F-Secure Labs - SharpGPOAbuse](https://github.com/FSecureLABS/SharpGPOAbuse)
- [SpecterOps - A Red Teamer's Guide to GPOs and OUs](https://posts.specterops.io/a-red-teamers-guide-to-gpos-and-ous-f0d03976a31e)
