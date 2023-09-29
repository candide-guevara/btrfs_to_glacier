package main

import (
  "context"
  "fmt"
  "io/fs"
  fpmod "path/filepath"
  "os"
  "time"

  "btrfs_to_glacier/encryption"
  "btrfs_to_glacier/factory"
  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"

  "github.com/google/uuid"
)

func CreateRootAndCanaryConf() (string, *pb.Config) {
  root_path := fpmod.Join("/tmp", uuid.NewString())
  err := os.Mkdir(root_path, fs.ModePerm)
  if err != nil { util.Fatalf("Cannot create loop device mount point: %v", err) }

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

func CreateRootAndCanaryConf_WithEncryption() (string, *pb.Config) {
  encryption.TestOnlyResetGlobalKeyringState()
  root_path, conf := CreateRootAndCanaryConf()
  conf.Encryption = &pb.Encryption{
    Type: pb.Encryption_AES_ZLIB_FOR_TEST,
    Keys: []string{ "FyCp61aaFPP4LFBcCET5t/LjFNgRbhOyy/nA5AiPi4c=", },
    Hash: "s/K9/iqVtJUGO8c63vBm5RKURXd5RgM7lzSN6OukwiWV3pi6baA7NUTLKS/T9sUTdFYuPf06st3kTtEBZ5OZkg==",
  }
  return root_path, conf
}

func CreateAndRunCanary(ctx context.Context, conf *pb.Config) (types.BackupRestoreCanary, error) {
  builder, err := factory.NewFactory(conf)
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
  root_path, conf := CreateRootAndCanaryConf()

  canary_mgr, run_err := CreateAndRunCanary(ctx, conf)
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
  root_path, conf := CreateRootAndCanaryConf_WithEncryption()

  canary_mgr, run_err := CreateAndRunCanary(ctx, conf)
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

