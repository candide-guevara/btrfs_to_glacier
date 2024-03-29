package main

import (
  "context"
  "fmt"
  fpmod "path/filepath"
  "time"

  "btrfs_to_glacier/encryption"
  "btrfs_to_glacier/factory"
  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"

  "github.com/google/uuid"
)

func InMem_CreateRootAndCanaryConf() (string, *pb.Config) {
  root_path := fpmod.Join("/tmp", uuid.NewString())
  source := &pb.Source{
    Type: pb.Source_BTRFS,
    Name: uuid.NewString(),
    Paths: []*pb.Source_VolSnapPathPair{
      &pb.Source_VolSnapPathPair{
        VolPath: fpmod.Join(root_path, "subvol"),
        SnapPath: fpmod.Join(root_path, "snaps"),
      },
    },
    History: &pb.Source_SnapHistory{
      DaysKeepAll: 30,
      KeepOnePeriodDays: 30,
    },
  }
  backup := &pb.Backup{
    Type: pb.Backup_MEM_EPHEMERAL,
    Name: uuid.NewString(),
  }
  restore := &pb.Restore{
    Type: pb.Restore_BTRFS,
    Name: uuid.NewString(),
    RootRestorePath: fpmod.Join(root_path, "restores"),
  }
  workflow := &pb.Workflow{
    Name: uuid.NewString(),
    Source: source.Name,
    Backup: backup.Name,
    Restore: restore.Name,
  }
  encryption := &pb.Encryption{
    Type: pb.Encryption_NOOP,
  }
  conf := &pb.Config {
    Sources: []*pb.Source{ source, },
    Backups: []*pb.Backup{ backup, },
    Restores: []*pb.Restore{ restore, },
    Workflows: []*pb.Workflow{ workflow, },
    Encryption: encryption,
  }
  //util.PbInfof("Canary conf:\n%s", conf)
  return root_path, conf
}

func InMem_CreateRootAndCanaryConf_WithEncryption() (string, *pb.Config) {
  encryption.TestOnlyResetGlobalKeyringState()
  root_path, conf := InMem_CreateRootAndCanaryConf()
  conf.Encryption = &pb.Encryption{
    Type: pb.Encryption_AES_ZLIB,
    Keys: []string{ "OC0aSSg2woV0bUfw0Ew1+ej5fYCzzIPcTnqbtuKXzk8=", },
    Hash: "Wi2mJKi43luJgGn/dAxDAYbJrifsb9jdJdvd+r2MEKQoOPxcLnRXWnZSPC2mQQEC73cNeV7YDD+NI48O8T8dtw==",
  }
  return root_path, conf
}

func InMem_CreateAndRunCanary(ctx context.Context, conf *pb.Config) (types.BackupRestoreCanary, error) {
  builder, err := factory.TestOnlyNewFactory(conf, encryption.TestOnlyFixedPw)
  if err != nil { util.Fatalf("NewFactory: %v", err) }
  canary_mgr, err := builder.BuildBackupRestoreCanary(ctx, conf.Workflows[0].Name)
  if err != nil { util.Fatalf("NewBackupRestoreCanary: %v", err) }

  token, err := canary_mgr.Setup(ctx)
  if err != nil {
    return canary_mgr, fmt.Errorf("Canary Setup: %v", err)
  }

  for i := 0; i < 5; i++ {
    _, err = canary_mgr.RestoreChainAndValidate(ctx, token)
    if err != nil {
      return canary_mgr, fmt.Errorf("%d RestoreChainAndValidate: %w", i, err)
    }
    _, err = canary_mgr.AppendSnapshotToValidationChain(ctx, token)
    if err != nil {
      return canary_mgr, fmt.Errorf("%d AppendSnapshotToValidationChain: %w", i, err)
    }
  }
  return canary_mgr, nil
}

func InMem_NoEncryption(ctx context.Context) {
  util.Infof("RUN InMem_NoEncryption")
  defer util.Infof("DONE InMem_NoEncryption")
  root_path, conf := InMem_CreateRootAndCanaryConf()

  canary_mgr, run_err := InMem_CreateAndRunCanary(ctx, conf)
  //util.Fatalf("boom: %v", run_err)
  tear_err := canary_mgr.TearDown(ctx)

  err := util.RemoveAll(root_path)
  if err != nil { util.Warnf("Cannot remove loop device mount point: %v", err) }
  if run_err != nil || tear_err != nil {
    util.Fatalf("\nRun: %v\nTearDown: %v", run_err, tear_err)
  }
}

func InMem_WithEncryption(ctx context.Context) {
  util.Infof("RUN InMem_WithEncryption")
  defer util.Infof("DONE InMem_WithEncryption")
  root_path, conf := InMem_CreateRootAndCanaryConf_WithEncryption()

  canary_mgr, run_err := InMem_CreateAndRunCanary(ctx, conf)
  //util.Fatalf("boom: %v", run_err)
  tear_err := canary_mgr.TearDown(ctx)

  err := util.RemoveAll(root_path)
  if err != nil { util.Warnf("Cannot remove loop device mount point: %v", err) }
  if run_err != nil || tear_err != nil {
    util.Fatalf("\nRun: %v\nTearDown: %v", run_err, tear_err)
  }
}

func InMemMain() {
  ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

  InMem_NoEncryption(ctx)
  InMem_WithEncryption(ctx)
  util.Infof("InMemMain ALL DONE")
}

