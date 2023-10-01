package main

import (
  "context"
  "fmt"
  fsmod "io/fs"
  fpmod "path/filepath"
  "os"
  "time"

  "btrfs_to_glacier/factory"
  "btrfs_to_glacier/encryption"
  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"

  "github.com/google/uuid"
)

const BackupLoopDevSizeMb = 32

func LocalFs_CreateRootAndCanaryConf(fs *types.Filesystem) (string, *pb.Config) {
  encryption.TestOnlyResetGlobalKeyringState()
  root_path := fpmod.Join("/tmp", uuid.NewString())
  err := os.Mkdir(root_path, fsmod.ModePerm)
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
    Type: pb.Backup_FILESYSTEM,
    Name: uuid.NewString(),
    Fs:   &pb.Backup_Fs{
      Sinks: []*pb.Backup_Partition{ &pb.Backup_Partition{
        FsUuid: fs.Uuid,
        MountRoot: fs.Mounts[0].MountedPath,
        MetadataDir: "metadata",
        StorageDir: "storage",
      }},
    },
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

func LocalFs_SetupSingleExt4(
    ctx context.Context, linuxutil types.Linuxutil) (*types.Filesystem, error) {
  tmp_fs := &types.Filesystem{}
  path := fpmod.Join("/tmp", uuid.NewString())
  err := os.Mkdir(path, fsmod.ModePerm)
  if err != nil { util.Fatalf("Cannot create loop device mount point: %v", err) }

  drop_f := linuxutil.GetRootOrDie()
  defer drop_f()
  dev, err := linuxutil.CreateLoopDevice(ctx, BackupLoopDevSizeMb)
  if err != nil { return tmp_fs, err }
  tmp_fs.Devices = append(tmp_fs.Devices, dev)

  fs, err := linuxutil.CreateExt4Filesystem(ctx, dev, uuid.NewString())
  if err != nil { return tmp_fs, err }

  mnt, err := linuxutil.Mount(ctx, fs.Uuid, path)
  if err != nil { return fs, err }
  fs.Mounts = append(fs.Mounts, mnt)

  get_root := linuxutil.DropRootOrDie()
  defer get_root()

  if err := os.Mkdir(fpmod.Join(path, "metadata"), 0775); err != nil { return fs, err }
  if err := os.Mkdir(fpmod.Join(path, "storage"), 0775); err != nil { return fs, err }
  return fs, nil
}

func LocalFs_SetupSingleExt4_OrDie(
    ctx context.Context, linuxutil types.Linuxutil) *types.Filesystem {
  fs, err := LocalFs_SetupSingleExt4(ctx, linuxutil)
  if err != nil {
    tear_err := LocalFs_TearDownSinglePart(ctx, fs, linuxutil)
    util.Fatalf("LocalFs_SetupSingleExt4_OrDie: %v, TearDown: %v", err, tear_err)
  }
  return fs
}

func LocalFs_TearDownSinglePart(
    ctx context.Context, fs *types.Filesystem, linuxutil types.Linuxutil) error {
  var umount_err, deldev_err, deldir_err error
  drop_f := linuxutil.GetRootOrDie()
  defer drop_f()

  if len(fs.Mounts) > 0 {
    umount_err = linuxutil.UMount(ctx, fs.Uuid)
  }
  if len(fs.Devices) > 0 {
    deldev_err = linuxutil.DeleteLoopDevice(ctx, fs.Devices[0])
  }
  deldir_err = util.RemoveAll(fs.Mounts[0].MountedPath)
  return util.Coalesce(umount_err, deldev_err, deldir_err)
}

func LocalFs_TearDown_OrDie(ctx context.Context,
    conf *pb.Config, fs *types.Filesystem, canary_mgr types.BackupRestoreCanary, linuxutil types.Linuxutil) {
  root_path := fpmod.Dir(conf.Restores[0].RootRestorePath)
  can_err := canary_mgr.TearDown(ctx)
  err := util.RemoveAll(root_path)
  if err != nil { util.Warnf("Cannot remove loop device mount point: %v", err) }

  fs_err := LocalFs_TearDownSinglePart(ctx, fs, linuxutil)
  if fs_err != nil || can_err != nil {
    util.Fatalf("TearDown\nCanary: %v\nFsSetup: %v", can_err, fs_err)
  }
  util.Infof("LocalFs_TearDown_OrDie no err")
}

func LocalFs_CreateCanary_OrDie(ctx context.Context,
    conf *pb.Config, fs *types.Filesystem, linuxutil types.Linuxutil) (types.Factory, types.BackupRestoreCanary, types.CanaryToken) {
  builder, err := factory.NewFactory(conf)
  if err != nil {
    fs_err := LocalFs_TearDownSinglePart(ctx, fs, linuxutil)
    util.Fatalf("NewFactory: %v, fs_err: %v", err, fs_err)
  }
  canary_mgr, err := builder.BuildBackupRestoreCanary(ctx, conf.Workflows[0].Name)
  if err != nil {
    fs_err := LocalFs_TearDownSinglePart(ctx, fs, linuxutil)
    util.Fatalf("NewBackupRestoreCanary: %v, fs_err: %v", err, fs_err)
  }

  token, err := canary_mgr.Setup(ctx)
  if err != nil {
    LocalFs_TearDown_OrDie(ctx, conf, fs, canary_mgr, linuxutil)
    util.Fatalf("Canary Setup: %v", err)
  }
  return builder, canary_mgr, token
}

func LocalFs_RunCanaryOnce_OrDie(
    ctx context.Context, canary_mgr types.BackupRestoreCanary, token types.CanaryToken, clean_f func()) {
  _, err := canary_mgr.RestoreChainAndValidate(ctx, token)
  if err != nil {
    clean_f()
    util.Fatalf("RestoreChainAndValidate: %w", err)
  }
  _, err = canary_mgr.AppendSnapshotToValidationChain(ctx, token)
  if err != nil {
    clean_f()
    util.Fatalf("AppendSnapshotToValidationChain: %w", err)
  }
  //util.Fatalf("boom: %v", err)
}

func LocalFs_NoEncryption(
    ctx context.Context, test_name string, linuxutil types.Linuxutil) {
  const rounds = 5
  util.Infof("RUN %s", test_name)
  defer util.Infof("DONE %s", test_name)
  fs := LocalFs_SetupSingleExt4_OrDie(ctx, linuxutil)
  _, conf := LocalFs_CreateRootAndCanaryConf(fs)

  builder, canary_mgr, token := LocalFs_CreateCanary_OrDie(ctx, conf, fs, linuxutil)
  clean_f := func() { LocalFs_TearDown_OrDie(ctx, conf, fs, canary_mgr, linuxutil) }

  for i := 0; i < rounds; i++ {
    LocalFs_RunCanaryOnce_OrDie(ctx, canary_mgr, token, clean_f)
  }
  restore_mgr, err := builder.BuildRestoreManagerAdmin(ctx, conf.Workflows[0].Name)
  if err == nil { err = restore_mgr.Setup(ctx) }
  if err != nil {
    clean_f()
    util.Fatalf("BuildRestoreManagerAdmin: %v", err)
  }
  head_to_seq, err := restore_mgr.ReadHeadAndSequenceMap(ctx)
  if err != nil {
    clean_f()
    util.Fatalf("ReadHeadAndSequenceMap: %v", err)
  }
  util.Debugf("HeadAndSequenceMap: %s", util.AsJson(head_to_seq))

  if len(head_to_seq) != 1 { err = fmt.Errorf("Bad HeadAndSequenceMap len") }
  for _,head_seq := range head_to_seq {
    snap_uuids := head_seq.Cur.SnapUuids
    if len(snap_uuids) != rounds + 1 { err = fmt.Errorf("Bad head_seq.Cur.SnapUuids len") }
  }
  // util.Fatalf("boom")
  clean_f()
  if err != nil { util.Fatalf("%v", err) }
}

func LocalFsMain(linuxutil types.Linuxutil) {
  ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
  defer cancel()

  LocalFs_NoEncryption(ctx, "LocalFs_NoEncryption", linuxutil)
  //LocalFs_NoEncryption_RefreshCanary(ctx)
  //LocalFs_WithEncryption(ctx)
  //LocalFs_WithEncryption_ChangeKey(ctx)
  util.Infof("InMemMain ALL DONE")
}

