---
title: LDAP Protocol
layout: default
permalink: /theory/protocols/ldap/
---

# LDAP (Lightweight Directory Access Protocol)

LDAP is used to access and maintain distributed directory information services.

## 🔧 Enum Techniques

- `ldapsearch`, `nmap -p 389 --script ldap*`

```bash
ldapsearch -x -H ldap://ip -b "DC=domain,DC=com"
```

## 📚 References

- https://ldap.com
