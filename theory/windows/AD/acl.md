---
title: ACL - Access Control List
layout: post
date: 2025-04-25
description: "Access Control List (ACL) is a list of permissions attached to an object. It specifies which users or system processes are granted access to objects, as well as what operations are allowed on given objects."
permalink: /theory/windows/AD/acl/
---

# Access Control List (ACL)
Access Control List (ACL) is a list of permissions attached to an object. It specifies which users or system processes are granted access to objects, as well as what operations are allowed on given objects.

An ACL is a data structure that contains a list of Access Control Entries (ACEs). Each ACE specifies a security principal (such as a user or group) and the permissions that are granted or denied to that principal for the object.

## Types of ACLs
There are two types of ACLs in Windows:
1. **Discretionary Access Control List (DACL)**: This type of ACL specifies the permissions that are granted or denied to users and groups for an object. If a DACL is present, access to the object is denied by default unless explicitly granted by an ACE in the DACL.
2. **System Access Control List (SACL)**: This type of ACL is used for auditing purposes. It specifies which access attempts should be audited, such as successful or failed access attempts. The SACL does not control access to the object but rather logs access attempts for security monitoring.

## DACL Enumeration (Discretionary Access Control List)

### Access Rights
Access rights are the permissions that can be granted to a user or group for an object. 
#### Access Rights Bits

| Display Name | Interpretation | Hexadecimal / Rights-GUID Value | Common Name |
|:-------------|:----------------|:-------------------------------|:------------|
| GenericAll | Allows creating/deleting child objects, deleting subtree, reading/writing properties, examining child objects and object itself, adding/removing the object from directory, and extended rights. Equivalent to (DE, RC, WD, WO, CC, DC, DT, RP, WP, LC, LO, CR, VW) for AD objects. | 0x10000000 | GA / RIGHT_GENERIC_ALL |
| GenericExecute | Allows reading permissions and listing contents of a container. Equivalent to (RC, LC) for AD objects. | 0x20000000 | GX / RIGHT_GENERIC_EXECUTE |
| GenericWrite | Allows reading permissions, writing all properties, performing all validated writes. Equivalent to (RC, WP, VW) for AD objects. | 0x40000000 | GW / RIGHT_GENERIC_WRITE |
| GenericRead | Allows reading permissions, all properties, listing object name and contents. Equivalent to (RC, LC, RP, LO) for AD objects. | 0x80000000 | GR / RIGHT_GENERIC_READ |
| WriteDacl | Allows modifying the object's security descriptor's discretionary ACL. | 0x00040000 | WD / RIGHT_WRITE_DAC |
| WriteOwner | Allows modifying the object's owner. A user can only take ownership but not transfer it. | 0x00080000 | WO / RIGHT_WRITE_OWNER |
| ReadControl | Allows reading the object's security descriptor (excluding SACL data). | 0x00020000 | RC / RIGHT_READ_CONTROL |
| Delete | Allows deleting the object. | 0x00010000 | DE / RIGHT_DELETE |
| Reset Password | Allows resetting a user's password without knowing the old password. | 00299570-246d-11d0-a768-00aa006e0529 | User-Force-Change-Password |
| Replicating Directory Changes | Required to replicate changes from a naming context (needed for DCSync attack). | 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 | DS-Replication-Get-Changes |
| Replicating Directory Changes All | Allows replication of secret domain data (needed for DCSync attack). | 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 | DS-Replication-Get-Changes-All |
| Add/Remove self as member | Allows modifying the member attribute (group membership changes). | bf9679c0-0de6-11d0-a285-00aa003049e2 | Self-Membership |
| Validated write to service principal name | Allows modifying the Service Principal Name (SPN) attribute. | f3a64788-5306-11d1-a9c5-0000f80367c1 | Validated-SPN |

## References
- [Microsoft Docs - Access Control Lists](https://learn.microsoft.com/en-us/windows/win32/secmgr/access-control-lists)
- [HackTheBox](https://www.academy.hackthebox.com)
