package main

import (
  "context"
  "fmt"
  "io/fs"
  fpmod "path/filepath"
  "os"
  "time"

  "btrfs_to_glacier/factory"
  "btrfs_to_glacier/shim"
  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"

  "github.com/google/uuid"
)

func LoadCanaryConf(root_path string) *pb.Config {
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
  util.PbInfof("Canary conf:\n%s", conf)
  return conf
}

func RunCanary(ctx context.Context, canary_mgr types.BackupRestoreCanary) error {
  util.Infof("RUN backup_restore_canary/in_mem_integration")
  token, err := canary_mgr.Setup(ctx)
  if err != nil { return fmt.Errorf("Canary Setup: %v", err) }

  for i := 0; i < 3; i++ {
    _, err = canary_mgr.RestoreChainAndValidate(ctx, token)
    if err != nil { return fmt.Errorf("%d RestoreChainAndValidate: %v", i, err) }
    _, err = canary_mgr.AppendSnapshotToValidationChain(ctx, token)
    if err != nil { return fmt.Errorf("%d AppendSnapshotToValidationChain: %v", i, err) }
  }
  return nil
}

func main() {
  ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

  root_path := fpmod.Join("/tmp", uuid.NewString())
  conf := LoadCanaryConf(root_path)
  linuxutil, err := shim.NewLinuxutil(conf)
  if err != nil || !linuxutil.IsCapSysAdmin() {
    util.Fatalf("Canary integration test needs CAP_SYS_ADMIN: %v", err)
  }
  get_root, err := linuxutil.DropRoot()
  if err != nil { util.Fatalf("DropRoot: %v", err) }

  err = os.Mkdir(root_path, fs.ModePerm)
  if err != nil { util.Fatalf("Cannot create loop device mount point: %v", err) }

  builder, err := factory.NewFactory(conf)
  if err != nil { util.Fatalf("NewFactory: %v", err) }
  canary_mgr, err := builder.BuildBackupRestoreCanary(ctx, conf.Workflows[0].Name)
  if err != nil { util.Fatalf("NewBackupRestoreCanary: %v", err) }

  run_err := RunCanary(ctx, canary_mgr)
  tear_err := canary_mgr.TearDown(ctx)
  get_root()
  err = util.RemoveAll(root_path)
  if err != nil { util.Warnf("Cannot remove loop device mount point: %v", err) }
  if run_err != nil || tear_err != nil {
    util.Fatalf("Run: %v, TearDown: %v", run_err, tear_err)
  }
  util.Infof("ALL DONE")
}

