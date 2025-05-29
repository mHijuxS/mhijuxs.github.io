---
title: Request Smuggling
layout: post
date: 2025-05-29
description: "A brief overview of HTTP request smuggling and its techniques."
permalink: /theory/misc/request-smuggling
---

# Request Smuggling
HTTP request smuggling is a technique used to exploit discrepancies in how different web servers interpret HTTP requests. It allows an attacker to "smuggle" a malicious request through a web server, which may then be processed by a backend server that is not aware of the malicious intent.

# Techniques

## CL.TE (Content-Length and Transfer-Encoding)
The attack exploits the difference in how the front-end and back-end servers interpret the `Content-Length` and `Transfer-Encoding` headers. The front-end server may process the request based on the `Content-Length`, while the back-end server may rely on the `Transfer-Encoding`, leading to a desynchronization.

### CL.TE Exploitation Steps
- **Send a Request with Both Headers**: Craft a request that includes both `Content-Length` and `Transfer-Encoding` headers, where the `Content-Length` is shorter than the actual body length.

```bash
POST /search HTTP/1.1 
Host: example.com 
Content-Length: 130 
Transfer-Encoding: chunked  

0  
POST /update HTTP/1.1 
Host: example.com 
Content-Length: 13 
Content-Type: application/x-www-form-urlencoded  

isadmin=true`
```
> **Request Breakdown**: The front-end server processes the first part of the request based on `Content-Length` of 130 bytes, believing the request ends after the `isadmin=true`, while the back-end server processes it based on `Transfer-Encoding`, understanding that the request ends after the `0` chunk. This allows the attacker to inject a second request (`POST /update`) that is processed by the back-end server.
{: .prompt-info}


> **Attention:**: The `Content-Length` header must be equal to the length of the body, otherwise the server might process only the portion matching the `Content-Length`, leading to a malformed request.
{: .prompt-warning}

## TE.CL (Transfer-Encoding and Content-Length)
This technique is similar to CL.TE but reverses the order of the headers. The front-end server may process the request based on `Transfer-Encoding`, while the back-end server relies on `Content-Length`.

### TE.CL Exploitation Steps
- **Send a Request with Both Headers**: Craft a request that includes both `Transfer-Encoding` and `Content-Length` headers, where the `Transfer-Encoding` is set to `chunked`.

```bash
POST / HTTP/1.1 
Host: example.com 
Content-Length: 4 
Transfer-Encoding: chunked  

78 
POST /update HTTP/1.1 
Host: example.com 
Content-Type: application/x-www-form-urlencoded 
Content-Length: 15  

isadmin=true 
0
```

In this case, the front-end server processes the request based on `Transfer-Encoding`, so it will read the 78 (120 bytes in decimal) bytes of the body, untill the `0` chunk, while the back-end server processes it based on `Content-Length`, interpreting the request as having a body of 4 bytes (`78\r\n`), not including the second request. This allows the attacker to inject a second request that is processed by the back-end server as if it was a legitimate request.

## TE.TE (Transfer-Encoding and Transfer-Encoding)

This technique exploits the fact that both the front-end and back-end servers depends on the `Transfer-Encoding` header, but they may interpret it differently, often involves a single malformed `Transfer-Encodig` header. The front-end server may ignore or remove malformed parts of the header and process the request normally and the back-end server might interpret the request differently, leading to request smuggling.

### TE.TE Exploitation Steps
- **Send a Request with Malformed Transfer-Encoding**: Craft a request that includes a malformed `Transfer-Encoding` header, which the front-end server processes normally, while the back-end server interprets it differently.

```bash
POST / HTTP/1.1 
Host: example.com 
Content-length: 4 
Transfer-Encoding: chunked 
Transfer-Encoding: chunked1  

4e 
POST /update HTTP/1.1 
Host: example.com 
Content-length: 15  

isadmin=true 
0
```

Depending on the front-end configuration, it could process the request as if it was a valid `Transfer-Encoding` header, ignoring the invalid one, interpreting the entire request up to the `0`, While the back-end server might interpret it differently, if it falls back to process only the `4` bytes from the `Content-Length`, the remaining part of the request starting from the `POST` is treated as a separate request.

## Request Smuggling Through Web Sockets

We could also try to trick the server into sending a malformed websocket connection upgrade request, which is a request that is sent to the server to upgrade the connection to a WebSocket connection. This can be done by sending a request that contains both `Upgrade` and `Connection` headers, where the `Upgrade` header is set to `websocket`, and the `Connection` header is set to `Upgrade`.

Some proxies assume that the upgrade is always complete, regardless of the response. This can be abused to smuggle HTTP requests by following the following steps:

1. **Send a Malformed Upgrade Request**: Start by sending a request that contains both `Upgrade` and `Connection` headers, where the `Upgrade` header is set to `websocket`, and the `Connection` header is set to `Upgrade`.

2. **Send a Invalid Version number**: The request should contain an invalid version number in the `Sec-WebSocket-Version` header, which is used to specify the version of the WebSocket protocol that the client supports.

```bash
GET /socket HTTP/1.1\r\n
Host: example.com\r\n
Upgrade: websocket\r\n
Sec-WebSocket-Version: 777\r\n
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n
\r\n
```

If the proxy does not properly handle the upgrade request, it may interpret the request as a valid WebSocket upgrade request, making the tunnel open for further requests directly to the back-end server, while this doesn't let us smuggle requests, it allows us to send arbitrary requests to the back-end server, which can be used to exploit other vulnerabilities or bypass restrictions.

### Defeating a Secure Proxy

The proxy could be configured to determine if the WebSocket connection was established or not, and if it was not established, it would close the connection. 

To bypass this, we need a way to force the backend server to reply our upgrade request with a fake `101 Switching Protocols` response, which is the response that is sent by the server to indicate that it has accepted the upgrade request and is switching to the WebSocket protocol. For that, we would need to chain another vulnerability such as SSRF (Server-Side Request Forgery) to our own hosted web server that would reply with status code `101 Switching Protocols` and the required headers to establish the WebSocket connection.

#### 101 Response Server

```python
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler

if len(sys.argv)-1 != 1:
    print("""
Usage: {}
    """.format(sys.argv[0]))
    sys.exit()

class Redirect(BaseHTTPRequestHandler):
   def do_GET(self):
       self.protocol_version = "HTTP/1.1"
       self.send_response(101)
       self.end_headers()

HTTPServer(("", int(sys.argv[1])), Redirect).serve_forever()
```


## HTTP/2 Desync

When we have a front-end server that supports HTTP/2 and a back-end server that does not, we can exploit the differences in how they handle requests. The front-end server may process the request as an HTTP/2 request, while the back-end server processes it as an HTTP/1.1 request. Ideally, the proxy should safely convert an HTTP/2 request to an HTTP/1.1 equivalent, which is not always the case, leading to HTTP desynchronization. 
### H2.CL (HTTP/2 and Content-Length)

The `Content-Length` header is not used in the HTTP/2 request because the length of the request body is specified unambiguously in the HTTP/2 frame. However, if the front-end server processes the request as HTTP/2 and downgrades it to HTTP/1.1, the proxy will pass the `Content-Length` header from the HTTP/2 to the HTTP/1.1 connection and this request will interprate the header.

#### H2.CL Exploitation Steps
If we sent in the following request:

```bash
:method GET
:path /
:scheme https
:authority tryhackme.com
user-agent Mozilla/5.0
content-length 0
HELLO
```

When the front-end server processes this request as HTTP/2, it will ignore the `Content-Length` header, but when it is downgraded to HTTP/1.1, the proxy will pass the `Content-Length` header to the back-end server, which will interpret it as a request with a body of length 0. This could lead to a desynchronization where the front-end server processes the request as if it had no body, while the back-end server expects a body of length 0, where will stay open, awaiting for the body to be sent. When another request come through the server, this request will be appended to the `HELLO`, altering the original request from the victim user.

For example, if the victim user sends a request to `/other`, the back-end server will interpret it as:

```bash
HELLOGET /other HTTP/1.1
Host: tryhackme.com
...
...
```

### H2.TE (HTTP/2 and Transfer-Encoding)

We could also have done it with the `Transfer-Encoding` header, where the front-end server processes the request as HTTP/2 and ignores the `Transfer-Encoding` header, while the back-end server processes it as HTTP/1.1 and interprets the `Transfer-Encoding` header. 

```bash
:method GET
:path /
:scheme https
:authority tryhackme.com
user-agent Mozilla/5.0
transfer-encoding chunked
0\r\n
\r\n
GET /other HTTP/1.1\r\n
Foo: s
```

The effect will be similar to the previous example, where the front-end server processes the request as if it had no body, while the back-end server expects a body of length 0, leading to a desynchronization. The back-end server will wait for the body to be sent, and when another request comes through, it will be appended to the `GET /other HTTP/1.1\r\nFoo: s`, altering the original request from the victim user.

For example, if the victim user sends a request to `/original`, the back-end server will interpret it as:

```bash
GET /other HTTP/1.1
Foo: sGET /original HTTP/1.1
Host: tryhackme.com
...
...
```
## H2C (HTTP/2 over cleartext)

HTTP/2 can also be used over cleartext, which is known as H2C. In this case, the front-end server processes the request as HTTP/2 over cleartext. When negotiating a cleartext connection, the client sends an `Upgrade: h2c` header to the server, indicating that it wants to upgrade the connection to HTTP/2, alongside with `HTTP2-Settings header` with some negotiation parameters. The server responds with a `101 Switching Protocols` response, indicating that it has accepted the upgrade request and is switching to HTTP/2.

When this connection upgrade is attempted via a reverse proxy, it directly forwards the upgrade headers to the back-end server. After the upgrade, the proxy will tunnel any further communications between client and server but will not check their contents anymore, since HTTP2 are persistent by default, we could send request directly to the backend server, known as **h2c smuggling**.

### H2C Requirements
- Proxy must forward the `h2c` upgrade to the backend

### Exploitation

The tool [`h2csmuggler`](https://github.com/BishopFox/h2csmuggler) is used to exploit this vulnerability, which allows us to send arbitrary requests to the back-end server after the upgrade. The tool works by sending a request with the `Upgrade: h2c` header and the `HTTP2-Settings` header, which is used to negotiate the HTTP/2 connection.

# References
- [TryHackMe](https://tryhackme.com)
- [PortSwigger](https://portswigger.net/web-security/request-smuggling)

