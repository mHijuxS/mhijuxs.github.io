---
title: Group Policy Object (GPO) Abuse
layout: post
date: 2026-08-30
description: "A Group Policy Object is half an LDAP object and half a folder on SYSVOL. Control of both halves can become code execution as SYSTEM on every machine the policy is linked to, which is why delegated control of the Default Domain Controllers Policy can compromise a domain."
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

Effective write access to both halves of the second one is a domain-compromise path: its scope is every domain controller, and SYSTEM on a domain controller means access to `NTDS.dit`.

> A finding of "non-admin group has WriteOwner on a GPO" can read like a medium-severity ACL issue in a report. Which GPO it is and whether the principal can also modify its SYSVOL template decide the impact. On a test OU the complete path may yield SYSTEM on a handful of workstations; on `{6AC1786C-...}` the complete path reaches every domain controller. `WriteOwner` is not itself a policy-content write: it is the first step in an LDAP ownership-to-DACL chain.
{: .prompt-danger }

## Which rights are enough

The following edges concern the LDAP Group Policy Container (GPC). They can provide or lead to control of that directory object:

- **`GenericAll` / `GenericWrite`** on the GPC: write the relevant attributes directly.
- **`WriteDacl`** on the GPC: grant yourself the required GPC rights, then write its attributes.
- **`WriteOwner`** on the GPC: take ownership; the owner has implicit `WriteDACL`, so this reduces to the previous case in two steps.
- **`Owns`** on the GPC: skip the ownership change and start with the DACL write.

None of those LDAP rights automatically proves write access to the separate Group Policy Template (GPT) directory in SYSVOL. Conversely, write access to the SYSVOL folder alone lets you alter settings files, but not bump the GPC's `versionNumber` or register a client-side extension. A conventional GPO payload therefore needs effective write access to **both** halves. Their ACLs are commonly aligned by normal administration, but they are separate security descriptors and can drift; verify both instead of inferring one from the other.

BloodHound surfaces `GenericAll`, `GenericWrite`, `WriteDacl`, `WriteOwner`, and `Owns` edges pointing at a `GPO` node. Those edges explain the directory-side path and help answer "what does that GPO link to," but an edge alone is not evidence of the corresponding NTFS permission on SYSVOL.

When `WriteOwner` is the starting LDAP right, taking ownership and then writing the GPC DACL is the standard two-command sequence:

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

The **immediate scheduled task** is what the tooling uses, because it fires without a reboot or a logon and removes the local scheduled-task object after running. That local removal does not remove the preference item from the GPO; while the XML remains deployed, later policy processing can create and execute it again.

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

> `pyGPOAbuse` refuses to run a second time against a GPO that already has a `ScheduledTasks.xml`, printing `The GPO already includes a ScheduledTasks.xml` and listing the existing tasks. That is a safety check: it prevents silently clobbering an existing preferences file. In a troubleshooting sequence, finding the task from an earlier run also proves that the earlier SYSVOL write succeeded. `-f` appends instead, and `-v` lists what is already there.
{: .prompt-warning }

## Timing: why nothing appears to happen

Writing the task is instant. Its effect is not, because the client decides when to refresh.

| Client | Refresh interval |
|---|---|
| Member workstations and servers | 90 minutes, plus a random 0 to 30 minute offset |
| Domain controllers | 5 minutes |

The short DC interval is what makes the Default Domain Controllers Policy a practical target rather than a theoretical one: the payload lands within minutes. On member machines, expect to wait, or to have a session on the host and force it with `gpupdate /force`.

The usual mistake at this point is to assume the write failed and start adding more permissions. Re-check the primitive before escalating: a successful `ScheduledTask ... created!` line means the tool completed its GPO modifications, so first allow for refresh and verify the target is in scope. If the effect still does not appear, investigate replication, security/WMI filtering, GPO precedence, and client-side processing rather than assuming another ACL write is required.

## Cleanup

An immediate task deletes its local scheduled-task object after execution, but it does **not** delete `ScheduledTasks.xml` from SYSVOL. The preference item remains available to later policy processing on machines in scope, so remove only the injected item, restore any extension metadata that the tool added, and increment the appropriate GPC/GPT version so clients notice the cleanup. Restore a pre-existing XML file rather than deleting it wholesale, and revert any owner or DACL change. `dacledit.py` writes a `.bak` of the original LDAP security descriptor for that part of the cleanup.

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
