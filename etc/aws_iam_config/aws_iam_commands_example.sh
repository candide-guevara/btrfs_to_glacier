#! /bin/bash

aws iam list-users
aws iam list-attached-user-policies \
  --user-name=btrfs_experimental
aws iam get-policy \
  --policy-arn=arn:aws:iam::096187466395:policy/btrfs_experimental_s3_policy
aws iam get-policy-version \
  --policy-arn=arn:aws:iam::096187466395:policy/btrfs_experimental_s3_policy \
  --version-id=v1

