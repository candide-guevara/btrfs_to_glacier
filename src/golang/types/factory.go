package types

import (
  "context"

  "github.com/aws/aws-sdk-go-v2/aws"
)

// Factory is not only used to choose a particular implementation.
// Caller is responsible for invokingSetup/TearDown. For example setup routines to create cloud infrastructure.
type Factory interface {
  BuildCodec() (Codec, error)
  BuildBackupManagerAdmin(context.Context, string) (BackupManagerAdmin, error)
  BuildRestoreManagerAdmin(context.Context, string) (RestoreManagerAdmin, error)
  BuildBackupRestoreCanary(context.Context, string) (BackupRestoreCanary, error)
}

// Wrapper around aws.Config to tag it with an ID taken from pb.Config.
// This is useful to cache clients for different users.
type AwsConf struct {
  C   *aws.Config
  Id  string
}

