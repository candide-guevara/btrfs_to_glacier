package types

import (
  "context"
)

// Factory is not only used to choose a particular implementation.
// Caller is responsible for invokingSetup/TearDown. For example setup routines to create cloud infrastructure.
type Factory interface {
  BuildCodec() (Codec, error)
  BuildBackupManagerAdmin(context.Context, string) (BackupManagerAdmin, error)
  BuildRestoreManagerAdmin(context.Context, string) (RestoreManagerAdmin, error)
  BuildBackupRestoreCanary(context.Context, string) (BackupRestoreCanary, error)
}

