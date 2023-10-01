package local_fs

import (
  "context"
  "testing"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types/mocks"
  "btrfs_to_glacier/util"
)

func buildTestRoundRobinSetupWithState(
    t *testing.T, state *pb.AllMetadata) (*RoundRobinSetup, *mocks.Linuxutil, func()) {
  local_fs, clean_f := util.LoadTestMultiSinkBackupConf(3, state != nil)
  conf := util.LoadTestConfWithLocalFs(local_fs)
  PutStateInAllParts(local_fs, state)
  lu := mocks.NewLinuxutil()
  setup, err := NewRoundRobinSetup(conf, lu, conf.Backups[0].Name)
  if err != nil { t.Fatalf("NewRoundRobinSetup %v", err) }
  return setup, lu, clean_f
}

func TestSetupMountAllSinkPartitions_Idempotent(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  setup,lu,clean_f := buildTestRoundRobinSetupWithState(t, &pb.AllMetadata{})
  defer clean_f()
  expect_mounts := len(setup.Sinks)

  err := setup.MountAllSinkPartitions(ctx)
  if err != nil { t.Fatalf("MountAllSinkPartitions err: %v", err) }
  err = setup.MountAllSinkPartitions(ctx)
  if err != nil { t.Fatalf("MountAllSinkPartitions err: %v", err) }
  err = setup.MountAllSinkPartitions(ctx)
  if err != nil { t.Fatalf("MountAllSinkPartitions err: %v", err) }
  util.EqualsOrFailTest(t, "Bad mount count", lu.ObjCounts().Mounts, expect_mounts)
}

func TestSetupUMountAllSinkPartitions_Idempotent(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  setup,lu,clean_f := buildTestRoundRobinSetupWithState(t, &pb.AllMetadata{})
  defer clean_f()
  expect_umounts := len(setup.Sinks)

  err := setup.MountAllSinkPartitions(ctx)
  if err != nil { t.Fatalf("MountAllSinkPartitions err: %v", err) }

  err = setup.UMountAllSinkPartitions(ctx)
  if err != nil { t.Fatalf("UMountAllSinkPartitions err: %v", err) }
  err = setup.UMountAllSinkPartitions(ctx)
  if err != nil { t.Fatalf("UMountAllSinkPartitions err: %v", err) }
  err = setup.UMountAllSinkPartitions(ctx)
  if err != nil { t.Fatalf("UMountAllSinkPartitions err: %v", err) }

  util.EqualsOrFailTest(t, "Bad mount count", lu.ObjCounts().UMounts, expect_umounts)
}

func TestSetupFindOldestPartition_Idempotent_NoState(t *testing.T) {
  setup,_,clean_f := buildTestRoundRobinSetupWithState(t, nil)
  defer clean_f()
  parts_found := make(map[string]bool)

  for i:=0; i<3; i+=1 {
    part, err := setup.FindOldestPartition()
    if err != nil { t.Fatalf("FindOldestPartition err: %v", err) }
    parts_found[part.FsUuid] = true
  }
  util.EqualsOrFailTest(t, "Partition should stay the same", len(parts_found), 1)
}

func TestSetupFindOldestPartition_Idempotent(t *testing.T) {
  setup,_,clean_f := buildTestRoundRobinSetupWithState(t, &pb.AllMetadata{})
  defer clean_f()
  parts_found := make(map[string]bool)

  for i:=0; i<3; i+=1 {
    part, err := setup.FindOldestPartition()
    if err != nil { t.Fatalf("FindOldestPartition err: %v", err) }
    parts_found[part.FsUuid] = true
  }
  util.EqualsOrFailTest(t, "Partition should stay the same", len(parts_found), 1)
}

