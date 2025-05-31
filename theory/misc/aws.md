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
