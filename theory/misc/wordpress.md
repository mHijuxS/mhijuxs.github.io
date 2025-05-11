---
title: Wordpress -- Pentesting Wordpress
layout: post
date: 2025-04-25
description: "Wordpress is a popular content management system (CMS) used by many websites. This post covers various aspects of pentesting Wordpress installations" 
permalink: /theory/misc/wordpress
---
## Wordpress Discovery

- Wappalyzer plugin for browser is useful for identifying Wordpress sites.

![[file-20250506020701461.png]]
- Presence of default `wordpress` folders like `wp-admin`, `wp-content`, and etc.
- Searching for wordpress references on the source code of the page
```bash
curl -s http://wordpressblog.local | grep -i wordpress
```
## Enumerating the Wordpress
- `grep` for `themes`, `plugins` from the source code
- Use automatic tool like [WPScan](https://wpscan.com/) to automate the process, enumerating the plugins, themes, users, and etc.


