---
title: Underpass
categories:
  - HackTheBox
tags: [passwordcracking, snmp, linux]
media_subpath: /images/hackthebox_underpass/
image:
  path: https://labs.hackthebox.com/storage/avatars/456a4d2e52f182847fb0a2dba0420a44.png
---

## Box Summary

Underpass was an easy linux machine where enumeration was key to find the right path to get a shell as `root`. Starting of with the normal TCP scan showed only a web server and SSH service running on the host, further enumeration of the web server didn't yield any interesting attack vector. Enumerating the UDP port, we could find an open `SNMP` port, that showed us that the box was running a daloradius server, which is a web-based application for managing RADIUS servers. With that, we were able to find the daloradius` endpoint, login with default credentials, crack an exposed hash and then abuse a permissive use of a `mosh-server` binary to get a root shell.

## Port Scan

We started the box with a port scan using nmap to find open ports and services.

```shell
nmap -sVC -Pn -oN nmap -vv 10.10.10.161
```
> Command breakdown:
- `nmap` : This command is used to run the nmap tool.
- `-sVC` : This flag is the combination of the `-sV` and `-sC` flags, which specifies that we want to run a service version scan and a script scan, respectively.
{: .prompt-info}

### Open Ports

### TCP Scan
```
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.52 ((Ubuntu))
```

#### Nmap Script

```bash
PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 48:b0:d2:c7:29:26:ae:3d:fb:b7:6b:0f:f5:4d:2a:ea (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBK+kvbyNUglQLkP2Bp7QVhfp7EnRWMHVtM7xtxk34WU5s+lYksJ07/lmMpJN/bwey1SVpG0FAgL0C/+2r71XUEo=
|   256 cb:61:64:b8:1b:1b:b5:ba:b8:45:86:c5:16:bb:e2:a2 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIJ8XNCLFSIxMNibmm+q7mFtNDYzoGAJ/vDNa6MUjfU91
80/tcp open  http    syn-ack ttl 63 Apache httpd 2.4.52 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-title: Apache2 Ubuntu Default Page: It works
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Enumerating the web server on port 80, we find a default Apache page, not much more than that. Without any other information, we tried enumerating the `UDP` ports.

### UDP Scan

 ```bash
sudo nmap -sU --top-ports 100 10.10.11.48 --min-rate 10000
```
> Command breakdown:
- `-sU`: This flag specifies that we want to run a UDP scan.
- `--top-ports 100`: This flag specifies that we want to scan the top 100 most common UDP ports.
- `--min-rate 10000`: This flag specifies that we want to send packets at a minimum rate of 10,000 packets per second.
{: .prompt-info}

#### UDP Scan Results

```
Starting Nmap 7.95 ( https://nmap.org ) at 2025-05-07 21:45 UTC
Nmap scan report for 10.10.11.48
Host is up (0.23s latency).
Not shown: 95 open|filtered udp ports (no-response)
PORT      STATE  SERVICE
161/udp   open   snmp
445/udp   closed microsoft-ds
2049/udp  closed nfs
49153/udp closed unknown
49193/udp closed unknown
```

## 161 - SNMP

To enumerate the `SNMP` service, we can use the `snmpbulkwalk` command. This command allows us to query the SNMP service for information about the system.

```bash
snmpbulkwalk -v2c -c public 10.10.11.48 -m all | tee -a snmp_dump.txt
```
> Command breakdown:
- `snmpbulkwalk`: This command is used to query the SNMP service for information about the system.
- `-v2c`: This flag specifies that we want to use SNMP version 2c.
- `-c public`: This flag specifies the community string to use for authentication. In this case, we are using the default community string `public`, we could brute force for others if it wasn't the one valid.
- `-m all`: This flag specifies that we want to load all MIBs (Management Information Bases) for the SNMP query. MIBs are files that define the structure of the data that can be retrieved from the SNMP service.
- `tee -a snmp_dump.txt`: `tee` command is used to duplicate the piped output, one for the `stdout` visible to use and the other into a file called `snmp_dump.txt` for later reference. The `-a` flag specifies that we want to append the output to the file, rather than overwriting it.
{: .prompt-info}

> Usually we can use `snmpwalk` but in this case we used the `snmpbulkwalk` because it is faster and more efficient for large amounts of data. The `snmpbulkwalk` command is similar to `snmpwalk`, but it retrieves multiple OIDs in a single request, which can reduce the number of network round trips required to retrieve the data.
{: .prompt-info}


![](file-20250507214645340.png)

From the output of the `snmpbulkwalk`, we can infer that there is a daloradius server running and a possible username `steve@underpass.htb`.

We can also add the found hostname to our hosts files for further use if needed.

```
cat /etc/hosts

10.10.11.48 underpass.htb
```

## 80 - HTTP

From the web server, we can see the default apache page when requesting the server. 

![](file-20250507214759505.png)

Running the `dirsearch` tool, we didn't find any interesting files or directories. From the information gathered from the `snmpbulkwalk`, we can search for the `seclist` wordlist for daloradius.

```bash
grep -Ri daloradius

common.txt:daloradius
combined_directories.txt:daloradius
combined_words.txt:daloradius
```

Running the `feroxbuster` tool on this directory we get more directories to search for: 

![](file-20250507215409750.png)

Looking for `daloradius` on google, we can find the source repository at [github-daloradius](https://github.com/lirantal/daloradius), where we can find all the files and directories for the service.

We can find a `login.php` file in `/daloradius/apps/users/login.php` and also on the `operators` directory. `/daloradius/apps/operators/login.php`.

Without any credentials, we search online for default credentials for daloradius and we find the following:

![](file-20250507230827047.png)

Default credentials `administrator:radius`.

Trying to login on the `users` directory, we were unable to successfully login, so, we tried at the `login.php` on the operators directory and we were redirected to the dashboard.

![](file-20250507215718225.png)

![](file-20250507220003326.png)

Looking around on the page, we can list all users and conveniently, it brings their hashed password as well

![](file-20250507220032674.png)

Saving the hash to a file, we can crack it with hashcat 

> If we tried hashcat auto suggestion, it would suggest `md4` and `md5` as top guesses, the hash was md5
{: .prompt-info}

After cracking tha password, we were able to ssh into the box.

## 22 - SSH 
Enumerating our user's permission, we tried the command `sudo -l` to list if we can run any binary as a more privileged user, turns out that we can run `mosh-server` as sudo

![](file-20250507220415834.png)

Without any lead on how the `mosh-server` binary works, we can take a look at its `man` page to figure out what does the binary do and if there are any possible ways to escalate our privileges since we can run as `root` without passing any password.

```bash
man mosh-server

NAME
       mosh-server - server-side helper for mosh

SYNOPSIS
       mosh-server new [-s] [-v] [-i IP] [-p PORT[:PORT2]] [-c COLORS] [-- command...]

DESCRIPTION
       mosh-server is a helper program for the mosh(1) remote terminal application.

       mosh-server binds to a high UDP port and chooses an encryption key to protect the session. It prints both on standard output, detaches
       from the terminal, and waits for the mosh-client to establish a connection. It will exit if no client has contacted it within 60  sec‐
       onds.

       By default, mosh-server binds to a port between 60000 and 61000 and executes the user's login shell.

       On platforms with utempter, mosh-server maintains an entry in the utmp(5) file to indicate its process ID, whether the session is con‐
       nected, and the client's current IP address.

       mosh-server exits when the client terminates the connection.

```

We can see it starts a server on the box and we can connect to it with a client, so we try exactly that
1. Run the `mosh-server` binary to start the server
2. Connect to the server with a client

```bash
svcMosh@underpass:~$ sudo /usr/bin/mosh-server


MOSH CONNECT 60001 tdxgPzLRJM1JL/fSTnS71Q
svcMosh@underpass:~$

─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
svcMosh@underpass:~$ mosh-client 127.0.0.1 60001
MOSH_KEY environment variable not found.
svcMosh@underpass:~$ MOSH_KEY=tdxgPzLRJM1JL/fSTnS71Q mosh-client 127.0.0.1 60001
```

Looking for `mosh` related binaries we found a `mosh-client`, trying to connect to the session at the open port, we get a variable not found error, telling us we need to set the key as `MOSH_KEY` environment variable, doing just that, we are able to get a shell as `root`.

![](file-20250507220651383.png)

![](file-20250507220634161.png)

## Lessons for learning/refresh 

- Don't take UDP ports for granted
- Look for directories of the services running on different wordlists
- Read `man` pages to better understanding of unknown binaries

