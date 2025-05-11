---
title: Tunneling, Pivoting, and Port Forwarding
layout: post
date: 2025-04-25
description: "A brief overview of tunneling, pivoting, and port forwarding techniques in networking."
permalink: /theory/misc/portforward/
---

## Overview
Tunneling, pivoting, and port forwarding are techniques used in networking to facilitate communication between devices across different networks. These methods are often employed in penetration testing, network security, and remote access scenarios.

## Pivoting
## Tunneling
## Port Forwarding
Port forwarding is a method of redirecting network traffic from one IP address and port number combination to another. This is often used to allow external devices to access services hosted on a private network.

> One of the most confusing and misunderstood aspects of port forwarding, at least for me, was the difference between local and remote port forwarding and their respective syntax.
{: .prompt-warning }

### Local Port Forwarding

Local port forwarding allows you to forward a port on your local machine to a port on a remote server. This is useful for accessing services that are not directly accessible from your local network. 

In general, we use local port forwarding when we want that "everything that goes through my local port should be forwarded to the remote server." Based on this, on our local machine we will not have a port listening, but we will have a port that we can use to connect to the remote server. 

### Remote Port Forwarding
Remote port forwarding allows you to forward a port on a remote server to a port on your local machine. This is useful for allowing external devices to access services hosted on your local machine. 

In general, we use remote port forwarding when we want that "everything that goes through the remote server should be forwarded to my local machine." Based on this, we will have a port listening, and we will have a port that we can use to connect to our local machine from the remote host.

### Dynamic Port Forwarding
Dynamic port forwarding allows you to create a SOCKS proxy server that can forward traffic to multiple destinations. This is useful for routing traffic through a secure tunnel without specifying individual ports. 

In general, we use dynamic port forwarding when we want that "everything that goes through my local port should be forwarded to the remote server." Based on this, we will have to configure a SOCKS proxy on our local machine, with a port that we can use to communicate with the remote server. 

## Tools
- **SSH**: Secure Shell (SSH) is a protocol that provides a secure channel over an unsecured network. It is commonly used for remote administration and secure file transfers. SSH supports local, remote, and dynamic port forwarding.
- [**Ligolo-ng**](https://github.com/nicocha30/ligolo-ng): Advanced, yet simple, tunneling/pivoting tool that uses a TUN interface.
- [**Chisel**](https://github.com/jpillora/chisel): Fast TCP/UDP tunnel over HTTP
- [**sshuttle**](https://github.com/sshuttle/sshuttle): Transparent proxy server that works as a VPN over SSH. It forwards all traffic from your local machine to the remote server, allowing you to access services on the remote network as if you were directly connected to it, only needing ssh credentials.

## SSH Cheat Sheet
### SSH Local Port Forwarding
```bash
ssh -L <local_port>:<remote_ip>:<remote_port> <user>@<remote_ip>
```
> Command breakdown:
> - `-L`: Specifies local port forwarding.
> - `<local_port>`: The port on your local machine that you want to forward.
> - `<remote_ip>`: The IP address of the remote server.
> - `<remote_port>`: The port on the remote server that you want to forward to.
{: .prompt-info }

### SSH Remote Port Forwarding
```bash
ssh -R <remote_port>:<local_ip>:<local_port> <user>@<remote_ip>
```
> Command breakdown:
> - `-R`: Specifies remote port forwarding.
> - `<remote_port>`: The port on the remote server that you want to forward.
> - `<local_ip>`: The IP address of your local machine.
> - `<local_port>`: The port on your local machine that you want to forward to.
{: .prompt-info }

### SSH Dynamic Port Forwarding
```bash
ssh -D <local_port> <user>@<remote_ip>
```
> Command breakdown:
> - `-D`: Specifies dynamic port forwarding.
> - `<local_port>`: The port on your local machine that you want to use as a SOCKS proxy.
{: .prompt-info }

## Chisel Cheat Sheet

### Chisel Local Port Forwarding
On the remote server, run the following command to start a Chisel server:
```bash
chisel server --reverse --port <remote_port>
```

On the victim, now local machine, run the following command to create a local port forward:

```bash
chisel client <remote_ip>:<remote_port> R:<remote_port>:<target_ip>:<target_port>
```

Now from our machine running the server, we can connect to the forwarded port on the target machine normally as if it was a local port. For example, if we forwarded port 80 on the target machine, we can access it using `curl` or a web browser:

```bash
curl http://localhost:<remote_port>
```

> Remember, the server is not on the victim machine, but on the remote server. The client is on the victim machine, and it connects to the server. So the syntax is a bit different than the one we are used to with SSH.
{: .prompt-info }

