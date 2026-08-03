---
title: Server-Side Request Forgery (SSRF)
layout: post
date: 2025-05-29
description: "Server-Side Request Forgery (SSRF) is a security vulnerability that allows an attacker to make requests from the server-side application, potentially accessing internal resources or services."
permalink: /theory/misc/ssrf
---

## Server-Side Request Forgery (SSRF)

SSRF occurs when an application takes a URL (or a host, or a path that gets turned into a URL) from user input and fetches it server-side without validating where it points. The bug is not that the server makes a request. It is that the attacker chooses the destination.

The value of the primitive is **position, not content**. The server sits somewhere the attacker does not: inside the VPC, behind the firewall, on the loopback interface, next to a cloud metadata endpoint. Services in those positions are routinely deployed with no authentication at all, on the assumption that the network boundary is the control. SSRF turns the vulnerable application into a proxy that crosses that boundary.

> A useful way to scope the impact: ask what the server could reach if you had a shell on it, then ask which of those things answer a plain HTTP `GET`. That intersection is roughly what SSRF gives you.
{: .prompt-info}

## Variants

Which variant you have determines the whole methodology, so establish it first.

| Variant | What comes back | Typical use |
|---|---|---|
| **In-band** | Full response body reflected | Read internal services directly |
| **Semi-blind** | Status code, timing or length | Port and host scanning |
| **Blind** | Nothing | Out-of-band callback only |

**In-band SSRF** reflects the fetched response into the page. This is the strongest form: internal services can simply be read.

**Semi-blind SSRF** hides the body but leaks something correlated with it. A different error for "connection refused" versus "connection timed out" is enough to map internal hosts and open ports, because a closed port fails fast and a filtered one hangs until the timeout.

**Blind SSRF** returns nothing distinguishable. Confirm it with an out-of-band callback (a server you control, Burp Collaborator, `interactsh`) and watch for the DNS lookup, which arrives even when the HTTP request is blocked. A DNS hit with no HTTP hit is itself a finding: it proves the input reaches a resolver.

## Where to Look

Any parameter that names a resource is a candidate:

```
url=  uri=  link=  src=  dest=  destination=  redirect=  redirect_uri=
next=  continue=  return=  target=  path=  file=  feed=  host=  port=
domain=  site=  page=  data=  reference=  callback=  proxy=  fetch=
```

Features that are SSRF by design, and therefore worth auditing first:

- **Webhooks.** The user supplies a URL and the server posts to it. This is SSRF with a specification.
- **Document and image converters.** HTML-to-PDF renderers fetch `<img>`, `<link>` and `<script>` from inside the document you submit. So do thumbnailers and image proxies.
- **Link previews and unfurlers.** Chat and social platforms fetch a URL to build a preview card.
- **Import from URL.** Any "load this file from a link" feature, including RSS, oEmbed, OPML, SAML metadata and OpenID discovery.
- **XML parsers.** An external entity is a server-side fetch, so XXE is an SSRF delivery mechanism.
- **Health checks, uptime monitors and admin "test connection" buttons.**

> Do not stop at parameters that look like URLs. A `host` and `port` pair joined into a URL server-side is the same bug, and a bare hostname field often skips the URL validation entirely because the developer never thought of it as a URL.
{: .prompt-tip}

## Common Targets

### Loopback and internal services

The loopback interface is the first place to look, because services bound to `127.0.0.1` are unreachable from outside by design and are therefore very often unauthenticated.

| Port | Service | Why it matters |
|---|---|---|
| 22 | SSH | Banner confirms a live host |
| 3306 | MySQL | Reachable via `gopher://` |
| 5432 | PostgreSQL | Reachable via `gopher://` |
| 6379 | Redis | Unauthenticated by default |
| 8080 / 8000 | App or admin backend | Often no auth on internal port |
| 9200 | Elasticsearch | Full read over HTTP |
| 11211 | Memcached | Unauthenticated by default |
| 15672 | RabbitMQ management | Default credentials common |

### Cloud metadata endpoints

This is usually the highest-value target, because the metadata service hands out the instance's cloud credentials to anything that can reach it. Each provider differs in whether a header is required, which matters enormously for SSRF: a primitive that can only issue a plain `GET` cannot set one.

| Provider | Endpoint | Header required |
|---|---|---|
| AWS (IMDSv1) | `http://169.254.169.254/latest/meta-data/` | None |
| AWS (IMDSv2) | `http://169.254.169.254/latest/meta-data/` | `X-aws-ec2-metadata-token` |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | `Metadata-Flavor: Google` |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | `Metadata: true` |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | None |
| Oracle Cloud | `http://169.254.169.254/opc/v2/instance/` | `Authorization: Bearer Oracle` |
| Alibaba | `http://100.100.100.200/latest/meta-data/` | None |

On AWS, credentials live two levels down and the role name must be discovered first:

```bash
# list the attached role names (the trailing slash is a directory listing)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# then read the credentials for one
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

The response contains an `ASIA`-prefixed access key, a secret, a session token and an expiry. See [AWS](/theory/misc/aws#ec2-instance-metadata-service-imds) for the full endpoint map and what to do with the credentials.

**IMDSv2 is the mitigation that actually targets SSRF.** It requires a session token obtained by a `PUT`, then sent back as a custom request header:

```bash
TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/
```

A typical SSRF primitive cannot switch the method to `PUT`, cannot set an arbitrary header, and cannot carry a value from one response into the next request. Requiring all three defeats the class. The instance attribute to check is `MetadataOptions.HttpTokens`: `optional` means IMDSv1 still answers, `required` means IMDSv2 is enforced.

> IMDSv2 stops SSRF. It does **not** stop an attacker with command execution on the instance, who can perform the handshake normally. Treat `HttpTokens: required` as SSRF hardening, not as protection for the role itself.
{: .prompt-warning}

## Filter Bypasses

Most SSRF defences are string checks against a denylist, and denylists lose. The same address can be written many ways.

### Alternate IP encodings

| Form | `127.0.0.1` | `169.254.169.254` |
|---|---|---|
| Decimal | `2130706433` | `2852039166` |
| Hexadecimal | `0x7f000001` | `0xa9fea9fe` |
| Octal | `0177.0.0.1` | `0251.0376.0251.0376` |
| Shortened | `127.1` | |
| IPv6 mapped | `[::ffff:127.0.0.1]` | `[::ffff:a9fe:a9fe]` |
| IPv6 loopback | `[::1]` | |

### DNS that resolves inward

A hostname passes a "must not be an IP" check and then resolves to exactly the address you wanted. Wildcard DNS services (`nip.io`, `sslip.io`) map an embedded address, and `localtest.me` resolves to loopback. A domain you own can simply have an `A` record pointing at `169.254.169.254`.

### Redirects

If the fetcher follows redirects, point it at a host you control that answers `302 Location: http://169.254.169.254/...`. The validation runs against your URL; the fetch lands on the internal one.

### DNS rebinding

When the application validates the hostname and then connects separately, the two operations each resolve the name. Serve a short-TTL record that returns a public address to the validator and an internal address to the connector. This defeats validation that is not paired with connecting to the exact IP that was checked.

### URL parser confusion

Different parsers disagree about where the host ends. These often reach the second host while a naive check reads the first:

```
http://expected.com@169.254.169.254/
http://169.254.169.254#expected.com/
http://expected.com:pass@169.254.169.254/
http://169.254.169.254\@expected.com/
```

### Scheme abuse

If the fetcher is a general-purpose library rather than an HTTP client, non-HTTP schemes may be available:

| Scheme | Effect |
|---|---|
| `file://` | Read local files (`file:///etc/passwd`) |
| `gopher://` | Send arbitrary bytes to a TCP port |
| `dict://` | Simple banner and key retrieval |
| `ftp://` | Reach internal FTP, useful for OOB |

`gopher://` is the strongest of these. Because it lets you write raw bytes to an arbitrary TCP port, it converts SSRF into "speak any plaintext protocol", which is the usual route from SSRF to remote code execution through an unauthenticated Redis, an SMTP server or a database.

## Mitigation

- **Allowlist destinations, never denylist them.** Enumerate the hosts the feature legitimately needs. Every bypass above exists because a denylist tried to describe "internal" with string matching.
- **Resolve, validate, then connect to the validated IP.** Validating a hostname and then handing the hostname to the HTTP client re-resolves it and reopens DNS rebinding. Pin the connection to the address that passed the check.
- **Reject the reserved ranges after resolution**, including `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `::1` and `fc00::/7`.
- **Disable every scheme except `http` and `https`**, explicitly, in the client library.
- **Do not follow redirects**, or re-run the full validation on each hop.
- **Enforce IMDSv2** (`HttpTokens: required`) and set `HttpPutResponseHopLimit: 1`. If the workload needs no role credentials, disable the metadata endpoint entirely.
- **Put egress controls in the network**, not only in the application. An application tier that has no route to the metadata address or to internal management ports cannot be tricked into reaching them.

## References

- [PortSwigger: SSRF](https://portswigger.net/web-security/ssrf)
- [OWASP: Server Side Request Forgery Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [PayloadsAllTheThings: SSRF](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
- [AWS: Use IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-instance-metadata-service.html)
