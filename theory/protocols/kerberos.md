---
title: Kerberos Protocol
layout: default
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
- **Resource**: The asset or service that the client wants to access, such as .

> What is a realm?
A realm is a logical network or domain that uses Kerberos for authentication. It is typically associated with a specific organization or administrative domain. Each realm has its own KDC, which manages the authentication process for users and services within that realm. Realms can be interconnected, allowing users from one realm to access resources in another realm through trust relationships. On Windows, domains are often used in conjunction with Kerberos to define security boundaries and manage user accounts, permissions, and policies.
{: .prompt-info}

## Kerberos Tickets
Kerberos uses tickets to authenticate users and services. A ticket is a time-limited credential that contains two encryption keys:
- **Session Key**: A temporary key used for encrypting communication between the client and the service.
- **The ticket key**: Shared between the Kerberos infrastructure and the service.

## Kerberos Authentication Process
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
- **🚨 The target account must have pre-authentication disabled.**

**Enumeration From Linux:**

To enumerate users with pre-authentication disabled, you can use the `GetUserSPNs` command from the Impacket library. This command will query the KDC for all users in the domain and check if they have pre-authentication disabled.

```
GetNPUsers.py DOMAIN/ 
```

**Enumeration From Windows:**

To enumerate users with pre-authentication disabled, you can use:

- The defualt `ActiveDirectory` powershell module

```

Get-ADUser -Filter * -Properties userAccountControl | Where-Object {
    $_.userAccountControl -band 4194304
} | Select-Object Name, SamAccountName, DistinguishedName

```

- `Powerview.ps1` from the PowerSploit library. This command will query the KDC for all users in the domain and check if they have pre-authentication disabled.

```
Get-DomainUser -PreauthNotRequired -verbose #List vuln users using PowerView
```

**Attack:**

We can add the flag `-request` to the `GetNPUsers.py` command to request the TGT for the user with pre-authentication disabled. This will return the encrypted TGT and the session key.

```
GetNPUsers.py DOMAIN/ -request
```

If you have a list of possible users, while enumerating with Kerbrute, it will automatically request the TGT for each user with pre-authentication disabled.

```
kerbrute  -d DOMAIN --dc DC userenum USERLIST
```


We can use the `Rubeus` tool to request the TGT for the user with pre-authentication disabled. This will return the encrypted TGT and the session key.

```
Rubeus.exe asreproast 
```

## 📚 References

- https://learn.microsoft.com/en-us/windows-server/security/kerberos/
- https://www.optiv.com/insights/source-zero/blog/kerberos-domains-achilles-heel
- https://www.picussecurity.com/resource/blog/as-rep-roasting-attack-explained-mitre-attack-t1558.004
- https://www.hackthebox.com/blog/what-is-kerberos-authentication
- https://book.hacktricks.wiki/en/windows-hardening/active-directory-methodology/asreproast.html
