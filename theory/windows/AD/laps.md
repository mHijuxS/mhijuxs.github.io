---
title: LAPS - Local Administrator Password Solution
layout: post
date: 2026-09-29
description: "LAPS rotates unique local administrator passwords per machine and stores them in AD. Legacy LAPS writes plaintext into a readable attribute; Windows LAPS adds DPAPI-NG encryption that ties decryption to a Kerberos principal, making credential access an AD ACL problem either way."
permalink: /theory/windows/AD/laps/
---

# Local Administrator Password Solution (LAPS)

## Overview

LAPS exists to solve a single problem: organizations deploy images with the same local administrator password on every machine, and that password never changes. Compromise one workstation and you can pass-the-hash to every other host that shares it.

LAPS makes each machine's local administrator password **unique and rotated**. The DC stores the password (or an encrypted blob containing it) in an attribute on the computer object, and AD ACLs control who can read it. The security question shifts from "who has the shared password" to "who has read access to the attribute."

Two versions exist in the wild. They differ in where and how the password is stored, but both reduce to the same attack surface: **AD read permissions on computer objects**.

## Legacy LAPS (Microsoft LAPS, pre-2023)

Legacy LAPS uses two attributes on the computer object:

| Attribute | Purpose |
|---|---|
| `ms-Mcs-AdmPwd` | The password, in **plaintext** |
| `ms-Mcs-AdmPwdExpirationTime` | When the password expires |

These are schema extensions added by the LAPS installer. The password sits in the directory as a readable string, so any principal with `ReadProperty` on `ms-Mcs-AdmPwd` gets the current local admin credential.

```bash
nxc ldap '<DC>' -u '<user>' -p '<pass>' --module laps
```

```bash
bloodyAD -u '<user>' -p '<pass>' -d '<DOMAIN>' --host '<DC>' \
    get search --filter '(ms-Mcs-AdmPwd=*)' \
    --attr sAMAccountName,ms-Mcs-AdmPwd,ms-Mcs-AdmPwdExpirationTime
```

> Legacy LAPS stores passwords in cleartext. The only barrier between an attacker and every local admin password in the domain is the ACL on each computer object's `ms-Mcs-AdmPwd` attribute.
{: .prompt-danger}

## Windows LAPS (April 2023+)

Windows LAPS is built into the OS from Windows Server 2025 and backported to Server 2019/2022 and Windows 10/11. It replaces the schema extension with native attributes and adds two capabilities legacy LAPS lacked: **encrypted passwords** and **password history**.

### Attributes

| Attribute | Purpose |
|---|---|
| `msLAPS-Password` | Plaintext JSON (name, password, timestamp) |
| `msLAPS-EncryptedPassword` | DPAPI-NG encrypted blob |
| `msLAPS-PasswordExpirationTime` | Rotation deadline |
| `msLAPS-EncryptedPasswordHistory` | Array of prior encrypted passwords |
| `msLAPS-CurrentPasswordVersion` | Integer tracking rotation generation |

A policy chooses between `msLAPS-Password` (cleartext, like legacy) and `msLAPS-EncryptedPassword`. When encryption is enabled, the plaintext attribute stays empty.

### The administrator account name

Windows LAPS can manage a named account rather than the built-in RID 500. The GPO setting `AdministratorAccountName` specifies the target. If it is set to `lab-admin`, the password LAPS rotates belongs to that account, not `Administrator`. This matters during lateral movement: the credential from LAPS pairs with whatever name the policy configured, and using it with the wrong account fails silently.

### Encrypted mode and DPAPI-NG

When `ADPasswordEncryptionEnabled` is set, the machine encrypts the password with [DPAPI-NG](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi) (also called CNG DPAPI) before writing it to `msLAPS-EncryptedPassword`. The encryption is bound to a **protection descriptor** that names an AD principal:

```
ADPasswordEncryptionPrincipal = DOMAIN\GroupName
```

Only members of that principal can decrypt the blob. The machine calls `NCryptProtectSecret` with the descriptor `SID=S-1-5-21-...-<group RID>`, and the resulting blob can only be unwrapped by a caller who holds a Kerberos ticket proving membership in that SID.

The decryption path works through **MS-GKDI** (Group Key Distribution Protocol). The caller authenticates to the DC via Kerberos, proves group membership through the PAC, and receives the decryption key material. No KDS root key access is needed, just membership in the designated group.

```python
import dpapi_ng

data = base64.b64decode(encrypted_blob)
plaintext = dpapi_ng.ncrypt_unprotect_secret(
    data,
    server=dc_hostname,
    username=user,
    password=password,
    auth_protocol="kerberos",
)
password_json = json.loads(plaintext.decode("utf-16-le").rstrip("\x00"))
```

> The encryption does not remove the AD ACL requirement. You need both: `ReadProperty` on the attribute **and** membership in the encryption principal. In practice, administrators often assign both rights to the same group, so a single group membership is enough.
{: .prompt-info}

### Password history

When `ADBackupDSRMPassword` or password history is enabled, each rotation appends the previous encrypted password to `msLAPS-EncryptedPasswordHistory`. This is an array of blobs, each independently encrypted with the same descriptor.

Password history creates a subtle attack window: when a password expires but the machine has not yet rotated (because it is offline, or the rotation task failed), the **current** attribute holds an expired password, while the **history** may contain a password the machine still accepts. LAPS updates the attribute from the machine side during rotation; until that happens, the old password remains valid for local authentication even though its expiration time has passed.

> If the current LAPS password is expired and fails, check the history. An expired timestamp means LAPS *wants* to rotate, not that the machine has already done so. The previous password often still works for local logon.
{: .prompt-tip}

## Reading LAPS passwords

### Cleartext (legacy or unencrypted Windows LAPS)

```bash
nxc ldap '<DC>' -u '<user>' -p '<pass>' -M laps
```

```bash
bloodyAD -u '<user>' -p '<pass>' -d '<DOMAIN>' --host '<DC>' \
    get search --filter '(ms-Mcs-AdmPwd=*)' \
    --attr sAMAccountName,ms-Mcs-AdmPwd
```

### Encrypted Windows LAPS

Decryption requires Kerberos authentication to the DC (NTLM will not work for DPAPI-NG). The caller must be a member of the encryption principal.

```bash
bloodyAD -u '<user>' -p '<pass>' -d '<DOMAIN>' --host '<DC>' -k \
    get search --filter '(msLAPS-EncryptedPassword=*)' \
    --attr sAMAccountName,msLAPS-EncryptedPassword
```

For the history attribute:

```bash
bloodyAD -u '<user>' -p '<pass>' -d '<DOMAIN>' --host '<DC>' -k \
    get search --filter '(msLAPS-EncryptedPasswordHistory=*)' \
    --attr sAMAccountName,msLAPS-EncryptedPasswordHistory
```

The Python `dpapi-ng` library handles the MS-GKDI exchange and decryption. A standalone script can iterate through the history array and decrypt each entry, producing a list of (password, timestamp) pairs.

## Who can read LAPS attributes

LAPS does not introduce its own authorization layer. It relies entirely on **AD property-level ACLs**:

- `ReadProperty` on `ms-Mcs-AdmPwd` (legacy) or `msLAPS-Password`/`msLAPS-EncryptedPassword` (Windows LAPS) on the computer object.
- For encrypted mode, additionally: membership in the DPAPI-NG encryption principal.

These ACLs are set per-OU or per-computer, typically through `Set-AdmPwdReadPasswordPermission` (legacy) or GPO-deployed ACLs. Common misconfigurations:

1. **Granting read to a broad group** (IT Admins, Help Desk) that includes accounts that do not need local admin access to every machine in the OU.
2. **Nesting the read group inside other groups**, creating indirect read paths that BloodHound surfaces but manual review misses.
3. **Setting the encryption principal to the same group that has ReadProperty**, which makes the encryption layer redundant: a single compromise gives both the encrypted blob and the decryption capability.

## Identifying LAPS configuration

LAPS configuration lives in Group Policy. The registry keys are written to each machine, but the source of truth is the GPO:

```
HKLM\SOFTWARE\Policies\Microsoft Services\AdmPwd     (legacy)
HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\LAPS  (Windows LAPS)
```

From the domain side, the GPO's `Registry.pol` file in SYSVOL contains the settings. Parse it to discover:

- Whether LAPS is enabled and which variant
- The managed account name
- Whether encryption is on and which principal holds the key
- The password complexity and length policy
- The rotation interval

```bash
smbclient.py '<DOMAIN>/<user>:<pass>@<DC>' \
    -c 'get <GPO-path>/Machine/Registry.pol'
```

```bash
python3 -c "
from samba.ndr import ndr_unpack
from samba.dcerpc import preg
with open('Registry.pol','rb') as f: pol = ndr_unpack(preg.file, f.read())
for e in pol.entries:
    if 'LAPS' in e.valuename or 'AdmPwd' in e.valuename:
        print(f'{e.valuename} = {e.data}')
"
```

## Detection

- **Event ID 4662** on computer objects for reads of `ms-Mcs-AdmPwd`, `msLAPS-Password`, or `msLAPS-EncryptedPassword`. Legitimate reads come from help desk tools and follow predictable patterns (same source, same time of day).
- **Event ID 330** (Windows LAPS operational log) on the machine itself, recording password updates and policy processing.
- Bulk reads across many computer objects from a single source are almost always adversarial. Legitimate LAPS clients read one machine at a time.

## Prevention

1. **Use encrypted mode.** It adds a second factor (group membership verified through Kerberos) beyond the property ACL.
2. **Scope read permissions narrowly.** Grant per-OU, to groups that contain only the accounts that actually need local admin on those specific machines.
3. **Separate the encryption principal from the read-ACL group** so that compromising one group is not enough.
4. **Monitor for bulk reads.** A single account reading `ms-Mcs-AdmPwd` across 50 computer objects in a minute is not help desk behavior.
5. **Rotate after compromise.** If a LAPS-managed password is used in an incident, trigger an immediate rotation (`Reset-LapsPassword` or `Invoke-LapsPolicyProcessing`) rather than waiting for the scheduled interval.

## References

- [Microsoft - Windows LAPS overview](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [Microsoft - Key concepts in Windows LAPS](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-concepts)
- [Microsoft - DPAPI-NG (CNG DPAPI)](https://learn.microsoft.com/en-us/windows/win32/seccng/cng-dpapi)
- [The Hacker Recipes - LAPS](https://www.thehacker.recipes/ad/movement/credentials/dumping/laps)
- [dpapi-ng Python library](https://github.com/jborean93/dpapi-ng)
