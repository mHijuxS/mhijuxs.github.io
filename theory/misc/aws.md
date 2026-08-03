---
title: AWS
layout: post
date: 2025-05-31
description: "A collection of AWS-related resources and notes."
permalink: /theory/misc/aws
---

# AWS Overview
AWS (Amazon Web Services) is a comprehensive cloud computing platform provided by Amazon. It offers a wide range of services including computing power, storage options, and networking capabilities, allowing businesses to scale and grow efficiently, which if not done properly can lead to significant costs.

# AWS Pentesting

## AWS Pentesting Tools
- [**AWS CLI**](https://aws.amazon.com/cli/): Command Line Interface for managing AWS services.
- [**Pacu**](https://github.com/RhinoSecurityLabs/pacu): An open-source AWS exploitation framework.

## Credential Types and Identifier Prefixes

Every AWS unique ID and access key ID carries a four-character prefix that tells you
what kind of object you are holding. Read it before anything else, because it
decides whether a session token is required and what the ARN will look like.

| Prefix | Identifier type |
|---|---|
| `AKIA` | Long-term IAM user access key ID |
| `ASIA` | Temporary STS access key ID (needs a session token) |
| `AIDA` | IAM user unique ID |
| `AROA` | IAM role unique ID |
| `AIPA` | Instance profile unique ID |
| `ANPA` | Managed policy unique ID |

`sts:GetCallerIdentity` is always permitted for any valid signature, so it is the
correct first call for every credential you obtain:

```bash
aws sts get-caller-identity
```

- An IAM user answers with `arn:aws:iam::<account>:user/<name>` and an `AIDA` id.
- An assumed role answers with `arn:aws:sts::<account>:assumed-role/<role>/<session>`
  and a `<AROA id>:<session name>` user id.

> `ASIA` credentials are useless without their session token. Export it as
> `AWS_SESSION_TOKEN` (or `aws_session_token` in `~/.aws/credentials`); omitting it
> fails with `InvalidClientTokenId`, an error that never mentions the real cause.
{: .prompt-warning }

An access key carries no region. Global services (IAM, STS, `s3:ListAllMyBuckets`)
resolve without one, but every regional call needs `AWS_DEFAULT_REGION` or an
explicit `--region`. AWS CLI v2 also pipes output through a pager by default, which
breaks piping into `jq`:

```bash
export AWS_DEFAULT_REGION=us-east-1 AWS_PAGER=""
```

## Lambda Pentesting

### Environment variables are a plaintext credential store

`lambda:ListFunctions` does not return a list of names. It returns an array of full
`FunctionConfiguration` objects, and that structure includes `Environment.Variables`:

```bash
aws lambda list-functions | jq '.Functions[] | {FunctionName, Environment}'
aws lambda get-function-configuration --function-name <name>
```

Lambda encrypts environment variables at rest, by default with the AWS-managed
`aws/lambda` KMS key. That protects the bytes in Lambda's storage and does nothing
against an authorised reader: the service decrypts them and returns plaintext to any
principal whose policy allows reading the configuration, including the AWS-managed
`ReadOnlyAccess` and `AWSLambda_ReadOnlyAccess` policies.

> Treat anything in a Lambda environment variable as readable by every principal
> holding `lambda:ListFunctions` or `lambda:GetFunctionConfiguration`. Secrets belong
> in Secrets Manager or SSM Parameter Store, fetched at runtime by the function's own
> execution role. The only variant that changes this is client-side encryption, where
> the variable holds ciphertext and the function calls `kms:Decrypt` itself.
{: .prompt-danger }

### Reading the function code

`lambda:GetFunction` returns a `Code.Location` field: a presigned S3 URL to the
deployment package, valid for about ten minutes. It is presigned, so downloading it
needs no S3 permission and no signature of your own.

```bash
aws lambda get-function --function-name <name> \
  | jq -r '.Code.Location' \
  | xargs -I{} wget -q "{}" -O function.zip
unzip -o function.zip
```

A leaked `Code.Location` value (in a ticket, a log, a screenshot) discloses the whole
function package for the life of the URL, to anybody at all.

## EC2 Instance Metadata Service (IMDS)

Every EC2 instance can reach a link-local HTTP service at `169.254.169.254`. The
`169.254.0.0/16` range is never routed: the address is answered by the hypervisor for
that one instance and is unreachable from anywhere else, including other instances in
the same subnet. There is no authentication, because the network path *is* the
authentication, so **any process running as any user on the host can query it**.

When an instance profile is attached, IMDS exposes the role's temporary credentials.
This is how the AWS SDKs get credentials on EC2 with no configuration, and it is why
code execution on an EC2 instance is usually equivalent to holding that instance's
IAM role.

### IMDSv1

```bash
# list the role names (the trailing slash matters, it is a directory listing)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# then fetch the credentials for one of them
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

The response is JSON with `AccessKeyId` (an `ASIA` key), `SecretAccessKey`, `Token`
and `Expiration` (roughly six hours out). IMDS refreshes them automatically, so
re-read the endpoint if they lapse while you still have the shell.

> The role name is **not** the instance profile name. A profile can wrap a role with
> an unrelated name, so always list the directory before guessing.
{: .prompt-tip }

Other useful paths:

```bash
curl -s http://169.254.169.254/latest/meta-data/instance-id
curl -s http://169.254.169.254/latest/meta-data/iam/info
curl -s http://169.254.169.254/latest/dynamic/instance-identity/document
curl -s http://169.254.169.254/latest/user-data          # often holds bootstrap secrets
```

### IMDSv2

IMDSv2 requires a two-step session handshake:

```bash
TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

The design targets [SSRF](/theory/misc/ssrf#cloud-metadata-endpoints) specifically. A
classic SSRF primitive can usually only make the server issue a `GET` to a URL you
control; it typically cannot switch the method to `PUT`, cannot set a custom request
header, and cannot carry a value from one request into the next. Requiring all three
defeats it. It does not stop an attacker with real command execution on the host.

### Reading IMDS posture from the control plane

`ec2:DescribeInstances` reports the metadata configuration before you ever touch the
host, which tells you in advance whether code execution there converts into AWS
credentials:

```bash
aws ec2 describe-instances --query \
  'Reservations[].Instances[].{Id:InstanceId,IP:PublicIpAddress,Profile:IamInstanceProfile.Arn,Meta:MetadataOptions}'
```

| Field | Meaning |
|---|---|
| `IamInstanceProfile` | Present means the host carries AWS credentials |
| `HttpEndpoint: enabled` | IMDS is reachable from inside the instance |
| `HttpTokens: optional` | IMDSv1 accepted; a plain `GET` works |
| `HttpTokens: required` | IMDSv2 enforced; this is the real mitigation |
| `HttpPutResponseHopLimit: 1` | Confined to the host network namespace |
| `HttpPutResponseHopLimit: 2` | Containers and pods can also reach IMDS |

## Secrets Manager

```bash
aws secretsmanager list-secrets --region <region>
aws secretsmanager get-secret-value --secret-id <name-or-arn> --region <region>
```

Secrets Manager appends six random characters to every secret ARN
(`...:secret:my-secret-AbC123`). A secret deleted and recreated under the same name
gets a different ARN, so an IAM statement or resource policy written against the old
ARN does not silently reattach to a new, unrelated secret. The practical consequence
is that the ARN cannot be guessed from the name, which makes `list-secrets` the call
worth having. `--secret-id` accepts either the full ARN or the friendly name.

> `GetSecretValue` writes a CloudTrail event with the secret ARN, the calling
> principal and the source IP, and updates the secret's `LastAccessedDate`. The value
> itself is not logged. It is one of the cheapest cloud detections to build.
{: .prompt-info }

## S3 Buckets Pentesting

Buckets in AWS S3 (Simple Storage Service) are used to store data. They can be publicly accessible or private, and misconfigurations can lead to data leaks.

### S3 Bucket Misconfigurations
- **Public Access**: Buckets that are publicly accessible can be exploited to retrieve sensitive data.
- **Bucket Policies**: Misconfigured bucket policies can allow unauthorized access to data.
- **CORS Configuration**: Cross-Origin Resource Sharing (CORS) misconfigurations can lead to data exposure.

### S3 Bucket Cheatsheet

> Note: The following commands, if the bucket is public, could be used with the `--no-sign-request` option to avoid authentication.
{: .prompt-info}

- **List Buckets**: `aws s3 ls`
- **List Buckets**: `aws s3 ls`
- **List Objects in a Bucket**: `aws s3 ls s3://bucket-name`
- **Download an Object**: `aws s3 cp s3://bucket-name/object-key local-file`
- **Upload an Object**: `aws s3 cp local-file s3://bucket-name/object-key`
- **Delete an Object**: `aws s3 rm s3://bucket-name/object-key`
- **Check Bucket Policy**: `aws s3api get-bucket-policy --bucket bucket-name`
- **Check Bucket ACL**: `aws s3api get-bucket-acl --bucket bucket-name`
- **Check CORS Configuration**: `aws s3api get-bucket-cors --bucket bucket-name`
- **Check Public Access Block**: `aws s3api get-public-access-block --bucket bucket-name`
