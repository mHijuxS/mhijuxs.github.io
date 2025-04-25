---
title: DCSync
layout: default
permalink: /theory/windows/AD/dcsync/
---

# DCSync Attack

DCSync allows an attacker to simulate a Domain Controller and request password data.

## ⚙️ Requirements

- Replication rights on domain object
- Usually via `Get-ADReplAccount` or `secretsdump.py`

## 🧰 Tools

```bash
impacket-secretsdump -just-dc USER@dc
```

## 📚 References

- https://adsecurity.org/?p=1729
