---
title: Planning
categories: [HackTheBox]
tags: [cve,cron,portforward]
media_subpath: /images/hackthebox_planning/
image:
  path: 'https://labs.hackthebox.com/storage/avatars/c9efb253e7d1d9b407113e11afdaa905.png'
---

# HackTheBox Planning - Complete Walkthrough

## Overview

Planning is a Medium Linux machine that demonstrates web application exploitation, container escape techniques, and privilege escalation through cron job manipulation. The machine features a Grafana instance vulnerable to CVE-2024-9264, leading to container escape and eventual root access.

**Difficulty:** Medium  
**OS:** Linux  
**Key Techniques:** CVE exploitation, Container escape, Port forwarding, Cron job abuse

### Attacks Used in This Box

This machine demonstrates several critical attack techniques:

- **Web Application Enumeration** - Virtual host discovery and service identification
- **CVE Exploitation** - Exploiting Grafana CVE-2024-9264 for remote code execution
- **Port Forwarding** - SSH tunneling for accessing internal services
- **Cron Job Manipulation** - Abusing cron jobs for privilege escalation

---

## Initial Reconnaissance

### Port Scanning

Let's start by scanning the target machine to identify open services:

```bash
nmap -sC -sV -oA planning 10.129.190.26
```

**Results:**
```bash
22/tcp open  ssh     syn-ack OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.24.0 (Ubuntu)
```

We can see two open ports:
- **Port 22:** SSH service running OpenSSH 9.6p1
- **Port 80:** HTTP service running nginx 1.24.0

### Web Application Discovery

When we attempt to access the web service, we're redirected to `planning.htb`. We need to add this to our `/etc/hosts` file:

```bash
curl -I http://10.129.190.26
```

![Hosts file configuration](file-20250912183836992.png)

```bash
echo "10.129.190.26 planning.htb" | sudo tee -a /etc/hosts
```

---

## Web Application Analysis

### Virtual Host Enumeration

Let's perform virtual host enumeration to discover hidden subdomains:

```bash
ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/n0kovo_subdomains.txt -u http://planning.htb -H "Host: FUZZ.planning.htb" -fs 178
```

**Results:**
```bash
grafana.planning.htb
```

![Virtual host enumeration results](file-20250912174858441.png)

We discovered a Grafana subdomain. Let's add this `grafana.planning.htb` to our line inside `/etc/hosts`:

### Grafana Service Analysis

Accessing the Grafana instance, we can see it's running and requires authentication, which we can login with our initial credentials on this assumed breached scenario:

![Grafana login page](file-20250912174830744.png)

Let's check the Grafana version by looking at the help section:

![Grafana version information](file-20250912175037439.png)

**Key Finding:** Grafana version 11.0.0 is running.

---

## Vulnerability Research and Exploitation

### CVE-2024-9264 Research

Researching Grafana 11.0.0 for known vulnerabilities, we discover **CVE-2024-9264**, a critical vulnerability that allows remote code execution.

**CVE Details:**
- **CVE ID:** CVE-2024-9264
- **Severity:** Critical
- **Type:** Remote Code Execution
- **Affected Versions:** Grafana 11.0.0 and earlier

**Exploit Reference:** https://github.com/nollium/CVE-2024-9264

### CVE-2024-9264 Exploitation

Using the CVE-2024-9264 exploit, we can achieve remote code execution on the Grafana instance:

![CVE exploitation](file-20250912183640755.png)

**Exploitation Steps:**
1. Use the CVE-2024-9264 exploit script
2. Set up a reverse shell payload
3. Execute the exploit to gain remote code execution

**Result:** We obtain a shell as root, but we're inside a Docker container.

---

## Container Escape

### Credential Discovery

After successful exploitation, we gain access to a root shell inside a Docker container:


Examining the environment variables, we discover credentials for the `enzo` user:

```bash
env
```

![Container shell access](file-20250912180545510.png)

**Discovered Credentials:** `enzo:password123`

### SSH Access to Host

Using the discovered credentials, we can SSH into the host system:

```bash
ssh enzo@10.10.11.229
```


![Environment variables with credentials](file-20250912180531545.png)

We now have access to the host system as the `enzo` user.

---

## Privilege Escalation

### Cron Job Analysis

Exploring the `/opt/` directory, we discover a `cronjob.db` file that contains interesting information:


```bash
enzo@planning:/opt$ ls
containerd  crontabs

enzo@planning:/opt$ cd crontabs
enzo@planning:/opt/crontabs$ ls
crontab.db

enzo@planning:/opt/crontabs$
```

![SSH access to host](file-20250912180835164.png)



**Key Findings:**
- Grafana backup configuration
- Password for Grafana zip file

### Port Forwarding Setup

Checking local ports, we discover that there is a service running on port 8000 locally:

```bash
ss -lntp
```

![Cron job database file](file-20250912183345236.png)


We can set up SSH port forwarding to access the local Grafana instance:

```bash
# In SSH session, press ~C to open SSH command line
ssh> -L 8000:127.0.0.1:8000
```

> **Note:** If the `~C` escape sequence doesn't work, you may need to enable it. You can do this by:
> - Using the `-o EnableEscapeCommandline=yes` option when connecting: `ssh -o EnableEscapeCommandline=yes user@host`
> - Or by adding `EnableEscapeCommandline yes` to your SSH client configuration file (`~/.ssh/config`)
{: .prompt-info}

![Port forwarding setup](file-20250912183406980.png)

We can get a successfully login by authenticating as `root` and the password the same as the one found for the `zip` file.

- **Username:** root
- **Password:** [from cronjob.db file]

### Cronjob Administration Access

![Grafana admin access](file-20250912181514012.png)

### Cron Job Creation

In the Grafana interface, we can create new cron jobs. We'll create a cron job to set the SUID bit on `/bin/bash`:

**Cron Job Command:** `chmod +s /bin/bash`

![Cron job creation](file-20250912183439017.png)

![Cron job configuration](file-20250912181603354.png)

### Cron Job Execution

Clicking "Run Now" executes our cron job immediately:

![Cron job execution](file-20250912181603354.png)

### Root Access

Returning to our SSH session, we can verify that `/bin/bash` now has the SUID bit set:

```bash
ls -la /bin/bash
```

We can now spawn a root shell using the SUID bash binary:

```bash
/bin/bash -p
```

![Root shell access](file-20250912181745155.png)

---

## Understanding the Attack Chain

This attack demonstrates several important security concepts:

1. **Web Application Enumeration:** Virtual host discovery revealed hidden services
2. **CVE Exploitation:** CVE-2024-9264 provided initial access to Grafana
3. **Container Escape:** Environment variable analysis revealed host credentials
4. **Port Forwarding:** SSH tunneling enabled access to internal services
5. **Cron Job Abuse:** Misconfigured cron job system allowed privilege escalation

### Key Concepts

- **CVE-2024-9264:** Critical RCE vulnerability in Grafana
- **Container Escape:** Techniques to escape from containerized environments
- **SSH Port Forwarding:** Tunneling local services through SSH connections
- **Cron Job Manipulation:** Abusing scheduled tasks for privilege escalation
- **SUID Binary Exploitation:** Using setuid binaries for privilege escalation

---

## Conclusion

The Planning machine demonstrates several critical security concepts:

1. **CVE Management:** The importance of keeping software updated to prevent CVE exploitation
2. **Container Security:** Proper isolation and credential management in containerized environments
3. **Network Segmentation:** The risks of exposing internal services through port forwarding
4. **Cron Job Security:** Proper access controls on scheduled task management systems
5. **SUID Binary Management:** Careful management of setuid binaries

**Key Takeaways:**
- Always keep software updated to prevent CVE exploitation
- Implement proper container isolation and credential management
- Monitor and restrict cron job creation capabilities
- Regularly audit SUID binaries and their permissions
- Implement network segmentation to prevent lateral movement
- Regular security assessments can identify these vulnerabilities before attackers do

