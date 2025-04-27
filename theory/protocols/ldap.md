---
title: LDAP Protocol
layout: post
date: 2025-04-25
permalink: /theory/protocols/ldap/
---

# LDAP (Lightweight Directory Access Protocol)

Open, vendor-neutral, industry standard protocol for accessing and maintaining distributed directory information services over an Internet Protocol (IP) network.

> LDAP is the protocol that Microsoft Exchange, Active Directory, and other directory services use to communicate with each other.
{: .prompt-info }

The most common use of LDAP is to authenticate users and authorize access to resources in a network.

### Levels of LDAP directory

LDAP is organized in a hierarchical tree structure, as follows: 
- **Root Directory**: The top level of the tree.
- **Countries:** Branch out to organizations, each country is represented by a two-letter ISO code (e.g., US for the United States).
- **Organizations:** Branch out to organizational units, each organization is represented by a unique name.
- **Organizational Units (OUs):** Branch out to individuals, groups, and other OUs. Each OU is represented by a unique name.
- **Entries:** The leaf nodes of the tree, representing individual users, groups, or resources. Each entry has a unique Distinguished Name (DN) that identifies its position in the tree.

### LDAP Query Structure
The search criteria for LDAP searches must be specified in a specific format, they must be put in parentheses and follow the syntax of the LDAP filter. The basic structure of an LDAP query is as follows:

```
(sAMAccountName=USERNAME)
```

Which will filter for the `USERNAME` in the `sAMAccountName` attribute.

#### Operators
- **AND**: `&` operator is used to combine multiple search criteria. For example, to search for a user with a specific username and email address:
```
(&(sAMAccountName=USERNAME)(mail=EMAIL))
```
- **OR**: `|` operator is used to search for entries that match any of the specified criteria. For example, to search for a user with a specific username or email address:

```
(|(sAMAccountName=USERNAME)(mail=EMAIL))
```
- **Nested Queries**: You can nest queries to create more complex search criteria. For example, to search for a user with a specific username and either a specific email address or phone number:

```
(&(sAMAccountName=USERNAME)(|(mail=EMAIL)(telephoneNumber=PHONE)))
```
Where will search for a user with the `sAMAccountName` of `USERNAME` and either the `mail` of `EMAIL` or the `telephoneNumber` of `PHONE`.

- **NOT**: `!` operator is used to exclude entries that match a specific criterion. For example, to search for all users except those with a specific username:

```
(!(sAMAccountName=USERNAME))
```

- **Greater Than**: `>` operator is used to search for entries with an attribute value greater than a specified value. For example, to search for users with a `lastLogin` date greater than `2023-01-01`:

```
(&(objectClass=user)(lastLogin>2023-01-01))
```

- **Less Than**: `<` operator is used to search for entries with an attribute value less than a specified value. For example, to search for users with a `lastLogin` date less than `2023-01-01`:

```
(&(objectClass=user)(lastLogin<2023-01-01))
```

## Enumerating the Service 

> LDAP default port is 389 for unencrypted connections and 636 for SSL/TLS connections. Along with 3268 and 3269 for Global Catalog (GC) queries on Active Directory.
{: .prompt-warning }

- `nmap` has a series of scripts for LDAP enumeration.

```bash
nmap -n -sV --script "ldap* and not brute" <IP> #Using anonymous credentials
```
> Command Breakdown:
 - `-n`: No DNS resolution.
 - `-sV`: Service version detection.
 - `--script "ldap* and not brute"`: Run all LDAP scripts except brute-force scripts.
{: .prompt-info }

- `ldapsearch` is a command-line tool for querying LDAP directories. It can be used to search for specific entries, retrieve attributes, and perform various operations on the directory.

```bash
ldapsearch -LLL -H ldap://ldap.server -D "" -b "OU=Service Accounts,DC=FOREST,DC=local"  dn 
```
> Command Breakdown:
 - `-LLL`: Suppress the printing of the LDAP version number and other information.
 - `-H ldap://ldap.server`: Specify the LDAP server to connect to.
 - `-D ""`: Bind DN, if set empty will try an anonymous bind (no credentials).
 - `-b "OU=Service Accounts,DC=FOREST,DC=local"`: Base DN for the search.
 - `dn`: Attribute to retrieve (Distinguished Name).
{: .prompt-info }

## Attackinkg LDAP

### Anonymous Bind
LDAP servers can be configured to allow anonymous binds, which means that users can connect to the server without providing any credentials. This can be useful for public directories, but it can also pose a security risk, allowing any user to enumerate the directory and access sensitive information. 

## 📚 References

- [LDAP](https://ldap.com)
- [Okta](https://www.okta.com/identity-101/what-is-ldap/)
- [Wikipedia](https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol)
- [Hacktricks](https://book.hacktricks.wiki/en/network-services-pentesting/pentesting-ldap.html?highlight=ldap#ldap-anonymous-binds)
- [ldapexplorer](https://www.ldapexplorer.com/en/manual/109010000-ldap-filter-syntax.htm)
