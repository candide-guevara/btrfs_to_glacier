package backup_restore_canary

import (
  "context"
  "errors"
  "fmt"
  fpmod "path/filepath"
  "os"
  "strings"
  "testing"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/types/mocks"
  "btrfs_to_glacier/util"

  "github.com/google/uuid"
)

var ErrPopulateRestoreFail = errors.New("populate_restore_failed")
var ErrPopulateCloneFail = errors.New("populate_clone_failed")

type Mocks struct {
  Conf        *pb.Config
  Btrfs       *mocks.Btrfsutil
  Lnxutil     *mocks.Linuxutil
  BackupMgr   *mocks.BackupManager
  RestoreMgr  *mocks.RestoreManager
  InitBackup  func(*mocks.BackupManager) error
}

func (self *Mocks) BuildBackupAndRestoreMgr(
    ctx context.Context, wf_name string) (types.BackupManagerAdmin, types.RestoreManagerAdmin, error) {
  if wf_name != self.Conf.Workflows[0].Name {
    return nil, nil, fmt.Errorf("bad wf name: %s", wf_name)
  }
  parsed_wf, err := util.WorkflowByName(self.Conf, self.Conf.Workflows[0].Name)
  if err != nil { return nil, nil, err }

  self.BackupMgr.InitFromConfSource(parsed_wf.Source)
  if self.InitBackup != nil {
    err := self.InitBackup(self.BackupMgr)
    if err != nil { return nil, nil, err }
  }
  self.RestoreMgr.InitFromConfRestore(parsed_wf.Restore)
  return self.BackupMgr, self.RestoreMgr, nil
}

func (self *Mocks) BuildBackupRestoreCanary(
    ctx context.Context, wf_name string) (types.BackupRestoreCanary, error) {
  util.Fatalf(`Mocks should only need to implement creation of Restore and Backup managers
               for the purposes of this test file`)
  return nil, nil
}

// Populates new clones with the copy from `rest_sv`.
func (self *Mocks) SetCloneCallbackToCopyFrom(ctx context.Context, rest_sv *pb.SubVolume) {
  self.Btrfs.SubvolCreateCallback = func(sv *pb.SubVolume) error {
    copy_targets := []string{
      mocks.UuidFile(rest_sv),
      mocks.NewDir(rest_sv),
      mocks.DelDir(rest_sv),
    }
    if err := util.RecursiveCopy(ctx, sv.MountedPath, copy_targets); err != nil {
      return fmt.Errorf("%w: %v", ErrPopulateCloneFail, err)
    }
    return nil
  }
}

// Fails test if clone is called.
func (self *Mocks) SetCloneCallbackToFail(t *testing.T) {
  self.Btrfs.SubvolCreateCallback = func(sv *pb.SubVolume) error {
    t.Fatal("SetCloneCallbackToFail")
    return nil
  }
}

func LoadCanaryTestConf() *pb.Config {
  nonce := uuid.NewString()
  source := &pb.Source{
    Type: pb.Source_BTRFS,
    Name: nonce,
    Paths: []*pb.Source_VolSnapPathPair{
      &pb.Source_VolSnapPathPair{
        VolPath: fmt.Sprintf("/tmp/canary-%s/subvol", nonce),
        SnapPath: fmt.Sprintf("/tmp/canary-%s/snaps", nonce),
      },
    },
  }
  backup := &pb.Backup{
    Type: pb.Backup_AWS,
    Name: uuid.NewString(),
  }
  restore := &pb.Restore{
    Type: pb.Restore_BTRFS,
    Name: uuid.NewString(),
    RootRestorePath: fmt.Sprintf("/tmp/canary-%s/restores", nonce), 
  }
  workflow := &pb.Workflow{
    Name: "wf_name",
    Source: source.Name,
    Backup: backup.Name,
    Restore: restore.Name,
  }
  conf := &pb.Config {
    Sources: []*pb.Source{ source, },
    Backups: []*pb.Backup{ backup, },
    Restores: []*pb.Restore{ restore, },
    Workflows: []*pb.Workflow{ workflow, },
  }
  return conf
}

func buildBackupRestoreCanary(hist_len int) (*BackupRestoreCanary, *Mocks) {
  bkp := mocks.NewBackupManager()
  conf := LoadCanaryTestConf()
  mock := &Mocks{
    Conf: conf,
    Btrfs: &mocks.Btrfsutil{},
    Lnxutil: mocks.NewLinuxutil(),
    BackupMgr: bkp,
    RestoreMgr: mocks.NewRestoreManager(bkp),
  }
  mock.Btrfs.CreateDirs = true
  mock.RestoreMgr.PopulateRestore = mocks.PopulateRestoreCorrect
  mock.InitBackup = func(bkp *mocks.BackupManager) error {
    for range make([]int, hist_len) {
      _, err := bkp.BackupAllToCurrentSequences(context.Background(), bkp.AllSrcVols())
      if err != nil { return err }
    }
    return nil 
  }
  canary,err := NewBackupRestoreCanary(conf, conf.Workflows[0].Name,
                                       mock.Btrfs, mock.Lnxutil, mock)
  if err != nil { util.Fatalf("NewBackupRestoreCanary: %v", err) }
  return canary.(*BackupRestoreCanary), mock
}

func TestBackupRestoreCanary_Setup_OK(t *testing.T) {
  const hist_len = 3
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  canary, mock := buildBackupRestoreCanary(hist_len)
  defer mock.Lnxutil.CleanMountDirs()
  expect_linux_counts := mock.Lnxutil.ObjCounts().Increment(1,1,0,1)
  expect_btrfs_counts := mock.Btrfs.ObjCounts().Increment(0,0)
  expect_restore_counts := mock.RestoreMgr.ObjCounts()

  err := canary.Setup(ctx)
  if err != nil { t.Fatalf("Setup: %v", err) }
  util.EqualsOrFailTest(t, "No subvolume should be created", mock.Btrfs.ObjCounts(),
                                           expect_btrfs_counts)
  util.EqualsOrFailTest(t, "Bad fs state", mock.Lnxutil.ObjCounts(),
                                           expect_linux_counts)
  util.EqualsOrFailTest(t, "State is not new", canary.State.New, false)
  util.EqualsOrFailTest(t, "BackupMgr should not be called",
                        len(mock.BackupMgr.SeqForUuid(canary.State.Uuid)), hist_len)
  util.EqualsOrFailTest(t, "RestoreMgr should not be called",
                        mock.RestoreMgr.ObjCounts(), expect_restore_counts)
  util.EqualsOrFailTest(t, "BackupMgr setup should be called",
                        mock.BackupMgr.SetupCalled, true)
}

func TestBackupRestoreCanary_Setup_Noop(t *testing.T) {
  const hist_len = 3
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  canary, mock := buildBackupRestoreCanary(hist_len)
  defer mock.Lnxutil.CleanMountDirs()
  expect_linux_counts := mock.Lnxutil.ObjCounts().Increment(1,1,0,1)

  err := canary.Setup(ctx)
  if err != nil { t.Fatalf("Setup: %v", err) }
  err = canary.Setup(ctx)
  if err != nil { t.Fatalf("Setup: %v", err) }
  util.EqualsOrFailTest(t, "Bad fs state", mock.Lnxutil.ObjCounts(),
                                           expect_linux_counts)
}

func TestBackupRestoreCanary_Setup_NewChain(t *testing.T) {
  const hist_len = 0
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  canary, mock := buildBackupRestoreCanary(hist_len)
  defer mock.Lnxutil.CleanMountDirs()
  expect_linux_counts := mock.Lnxutil.ObjCounts().Increment(1,1,0,1)
  expect_btrfs_counts := mock.Btrfs.ObjCounts().Increment(1,0)
  expect_restore_counts := mock.RestoreMgr.ObjCounts()

  err := canary.Setup(ctx)
  if err != nil { t.Fatalf("Setup: %v", err) }
  util.EqualsOrFailTest(t, "Bad fs state", mock.Lnxutil.ObjCounts(),
                                           expect_linux_counts)
  // Most of the actions are intercepted by higher level mocks except cloning
  // and the first subvolume creation for a canary chain.
  util.EqualsOrFailTest(t, "Only 1 subvolume should be created", mock.Btrfs.ObjCounts(),
                                           expect_btrfs_counts)
  util.EqualsOrFailTest(t, "State is not new", canary.State.New, true)
  util.EqualsOrFailTest(t, "Should create a new snapshot",
                        len(mock.BackupMgr.SeqForUuid(canary.State.Uuid)), 1)
  util.EqualsOrFailTest(t, "RestoreMgr should not be called",
                        mock.RestoreMgr.ObjCounts(), expect_restore_counts)
}

func TestBackupRestoreCanary_TearDown_Noop(t *testing.T) {
  const hist_len = 0
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  canary, mock := buildBackupRestoreCanary(hist_len)
  defer mock.Lnxutil.CleanMountDirs()
  mock.Lnxutil.ForAllErrMsg("Should not get called")
  mock.Btrfs.Err = fmt.Errorf("Should not get called")

  err := canary.TearDown(ctx)
  if err != nil { t.Fatalf("TearDown: %v", err) }
}

func TestBackupRestoreCanary_TearDown_OK(t *testing.T) {
  const hist_len = 0
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  canary, mock := buildBackupRestoreCanary(hist_len)
  defer mock.Lnxutil.CleanMountDirs()
  expect_linux_counts := mock.Lnxutil.ObjCounts().Increment(1,0,1,0)

  err := canary.Setup(ctx)
  if err != nil { t.Fatalf("Setup: %v", err) }
  err = canary.TearDown(ctx)
  if err != nil { t.Fatalf("TearDown: %v", err) }

  util.EqualsOrFailTest(t, "Bad fs state", mock.Lnxutil.ObjCounts(),
                                           expect_linux_counts)
  util.EqualsOrFailTest(t, "Backup not destroyed", mock.BackupMgr.TearCalled, true)
}

func TestBackupRestoreCanary_TearDown_Partial(t *testing.T) {
  const hist_len = 0
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  canary, mock := buildBackupRestoreCanary(hist_len)
  defer mock.Lnxutil.CleanMountDirs()
  mock.Lnxutil.ForMethodErrMsg(mock.Lnxutil.CreateBtrfsFilesystem, "injected_err")
  expect_linux_counts := mock.Lnxutil.ObjCounts().Increment(1,0,0,1)

  err := canary.Setup(ctx)
  if err == nil { t.Fatalf("expected error") }
  util.EqualsOrFailTest(t, "Bad fs state", mock.Lnxutil.ObjCounts(),
                                           expect_linux_counts)

  expect_linux_counts = mock.Lnxutil.ObjCounts().Increment(0,0,0,-1)
  err = canary.TearDown(ctx)
  if err != nil { t.Fatalf("TearDown: %v", err) }
  util.EqualsOrFailTest(t, "Backup destroyed", mock.BackupMgr.TearCalled, false)
  util.EqualsOrFailTest(t, "Bad fs state", mock.Lnxutil.ObjCounts(),
                                           expect_linux_counts)
}

func TestRestoreChainAndValidate_NewChain(t *testing.T) {
  const hist_len = 0
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  canary, mock := buildBackupRestoreCanary(hist_len)
  defer mock.Lnxutil.CleanMountDirs()
  if err := canary.Setup(ctx); err != nil { t.Fatalf("Setup: %v", err) }
  expect_restore_counts := mock.RestoreMgr.ObjCounts().Increment(1,1)

  pairs, err := canary.RestoreChainAndValidate(ctx)
  if err != nil { t.Fatalf("RestoreChainAndValidate: %v", err) }
  util.EqualsOrFailTest(t, "Bad pair len", len(pairs), 1)
  util.EqualsOrFailTest(t, "RestoreMgr should be called once",
                        mock.RestoreMgr.ObjCounts(), expect_restore_counts)
}

func TestRestoreChainAndValidate_ExistingChain(t *testing.T) {
  const hist_len = 3
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  canary, mock := buildBackupRestoreCanary(hist_len)
  defer mock.Lnxutil.CleanMountDirs()
  if err := canary.Setup(ctx); err != nil { t.Fatalf("Setup: %v", err) }
  expect_restore_counts := mock.RestoreMgr.ObjCounts().Increment(1,hist_len)

  pairs, err := canary.RestoreChainAndValidate(ctx)
  if err != nil { t.Fatalf("RestoreChainAndValidate: %v", err) }
  util.EqualsOrFailTest(t, "Bad pair len", len(pairs), hist_len)
  util.EqualsOrFailTest(t, "RestoreMgr should be called once",
                        mock.RestoreMgr.ObjCounts(), expect_restore_counts)
}

func TestRestoreChainAndValidate_CannotCallTwice(t *testing.T) {
  const hist_len = 3
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  canary, mock := buildBackupRestoreCanary(hist_len)
  defer mock.Lnxutil.CleanMountDirs()
  if err := canary.Setup(ctx); err != nil { t.Fatalf("Setup: %v", err) }

  _, err := canary.RestoreChainAndValidate(ctx)
  if err != nil { t.Fatalf("RestoreChainAndValidate: %v", err) }
  _, err = canary.RestoreChainAndValidate(ctx)
  if err == nil { t.Fatalf("Cannot call twice: %v", err) }
}

func TestRestoreChainAndValidate_InjectRestoreErr(t *testing.T) {
  const hist_len = 1
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  canary, mock := buildBackupRestoreCanary(hist_len)
  defer mock.Lnxutil.CleanMountDirs()
  if err := canary.Setup(ctx); err != nil { t.Fatalf("Setup: %v", err) }

  mock.RestoreMgr.ForMethodErrMsg(mock.RestoreMgr.RestoreCurrentSequence, "injected_err")
  _, err := canary.RestoreChainAndValidate(ctx)
  if err == nil { t.Fatalf("Expected error") }
}

func testRestoreFailValidation_Helper(
    t *testing.T, hist_len int, popf mocks.PopulateRestoreF, expect_err error) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  canary, mock := buildBackupRestoreCanary(hist_len)
  popf_wrap := func(orig *pb.SubVolume, pairs []types.RestorePair) error {
    if err := mocks.PopulateRestoreCorrect(orig, pairs); err != nil { return ErrPopulateRestoreFail }
    err := popf(orig, pairs)
    if err != nil { return fmt.Errorf("%w: %v", ErrPopulateRestoreFail, err) }
    return nil
  }
  mock.RestoreMgr.PopulateRestore = popf_wrap
  defer mock.Lnxutil.CleanMountDirs()
  if err := canary.Setup(ctx); err != nil { t.Fatalf("Setup: %v", err) }

  _, err := canary.RestoreChainAndValidate(ctx)
  if err == nil { t.Errorf("Expected error") }
  if errors.Is(err, ErrPopulateRestoreFail) { t.Errorf("Populate should not fail: %v", err) }
  if !errors.Is(err, expect_err) { t.Errorf("Wrong validation error: %v", err) }
}

func PopulateRestoreBadUuid(orig *pb.SubVolume, pairs []types.RestorePair) error {
  dst := pairs[len(pairs) - 1].Dst
  f_uuid, err := os.OpenFile(mocks.UuidFile(dst), os.O_APPEND|os.O_WRONLY, 0666)
  defer f_uuid.Close()
  _, err = f_uuid.WriteString("oops\n")
  return err
}
func TestRestoreChainAndValidate_NewChain_BadUuidFile(t *testing.T) {
  testRestoreFailValidation_Helper(t, 0, PopulateRestoreBadUuid, ErrValidateUuidFile)
}

func PopulateRestoreUuid_RemoveLine(orig *pb.SubVolume, pairs []types.RestorePair) error {
  if len(pairs) < 2 { return nil }
  dst := pairs[len(pairs) - 1].Dst
  content, err := os.ReadFile(mocks.UuidFile(dst))
  lines := strings.Split(string(content), "\n")
  err = os.WriteFile(mocks.UuidFile(dst),
                     []byte(fmt.Sprintf("%s\n", strings.Join(lines[:len(lines)-2], "\n"))),
                     0666)
  return err
}
func TestRestoreChainAndValidate_BadUuidFile_MissLine(t *testing.T) {
  testRestoreFailValidation_Helper(t, 2, PopulateRestoreUuid_RemoveLine, ErrValidateUuidFile)
}

func PopulateRestoreUuid_TweakLine(orig *pb.SubVolume, pairs []types.RestorePair) error {
  dst := pairs[len(pairs) - 1].Dst
  content, err := os.ReadFile(mocks.UuidFile(dst))
  lines := strings.Split(string(content), "\n")
  lines[len(lines)-1] = "baduuid"
  err = os.WriteFile(mocks.UuidFile(dst),
                     []byte(fmt.Sprintf("%s\n", strings.Join(lines, "\n"))),
                     0666)
  return err
}
func TestRestoreChainAndValidate_BadUuidFile_BadLine(t *testing.T) {
  testRestoreFailValidation_Helper(t, 2, PopulateRestoreUuid_TweakLine, ErrValidateUuidFile)
}

func PopulateRestoreDelDir_RemoveFile(orig *pb.SubVolume, pairs []types.RestorePair) error {
  dst := pairs[len(pairs) - 1].Dst
  entries, err := os.ReadDir(mocks.DelDir(dst))
  if err != nil { return err }
  for _,e := range entries {
    err := util.RemoveAll(fpmod.Join(mocks.DelDir(dst), e.Name()))
    if err != nil { return err }
  }
  return nil
}
func TestRestoreChainAndValidate_BadDelDir_MissFile(t *testing.T) {
  testRestoreFailValidation_Helper(t, 4, PopulateRestoreDelDir_RemoveFile, ErrValidateDelDir)
}

func PopulateRestoreDelDir_TweakFile(orig *pb.SubVolume, pairs []types.RestorePair) error {
  dst := pairs[len(pairs) - 1].Dst
  entries, err := os.ReadDir(mocks.DelDir(dst))
  if err != nil { return err }
  for _,e := range entries {
    err = os.WriteFile(fpmod.Join(mocks.DelDir(dst), e.Name()), []byte("oops"), 0666)
    if err != nil { return err }
  }
  return nil
}
func TestRestoreChainAndValidate_BadDelDir_BadContent(t *testing.T) {
  testRestoreFailValidation_Helper(t, 4, PopulateRestoreDelDir_TweakFile, ErrValidateDelDir)
}

func PopulateRestoreNewDir_RemoveFile(orig *pb.SubVolume, pairs []types.RestorePair) error {
  if len(pairs) < 3 { return nil }
  dst := pairs[len(pairs) - 1].Dst
  entries, err := os.ReadDir(mocks.NewDir(dst))
  if err != nil || len(entries) < 2 { return fmt.Errorf("bad entries: %w", err) }
  err = util.RemoveAll(fpmod.Join(mocks.NewDir(dst),
                                  entries[len(entries) - 2].Name()))
  return err
}
func TestRestoreChainAndValidate_BadNewDir_MissFile(t *testing.T) {
  testRestoreFailValidation_Helper(t, 3, PopulateRestoreNewDir_RemoveFile, ErrValidateNewDir)
}

func PopulateRestoreNewDir_TweakFile(orig *pb.SubVolume, pairs []types.RestorePair) error {
  if len(pairs) < 2 { return nil }
  dst := pairs[len(pairs) - 1].Dst
  entries, err := os.ReadDir(mocks.NewDir(dst))
  if err != nil || len(entries) < 1 { return fmt.Errorf("bad entries: %w", err) }
  err = os.WriteFile(fpmod.Join(mocks.NewDir(dst), entries[len(entries) - 1].Name()),
                     []byte("oops"), 0666)
  return err
}
func TestRestoreChainAndValidate_BadNewDir_BadContent(t *testing.T) {
  testRestoreFailValidation_Helper(t, 3, PopulateRestoreNewDir_TweakFile, ErrValidateNewDir)
}

func TestAppendSnapshotToValidationChain_NewChain(t *testing.T) {
  const hist_len = 0
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  canary, mock := buildBackupRestoreCanary(hist_len)
  defer mock.Lnxutil.CleanMountDirs()
  if err := canary.Setup(ctx); err != nil { t.Fatalf("Setup: %v", err) }
  btrfs_counts := mock.Btrfs.ObjCounts()

  _, err := canary.RestoreChainAndValidate(ctx)
  if err != nil { t.Fatalf("RestoreChainAndValidate: %v", err) }
  expect_restore_counts := mock.RestoreMgr.ObjCounts()
  pair, err := canary.AppendSnapshotToValidationChain(ctx)
  if err != nil { t.Fatalf("AppendSnapshotToValidationChain: %v", err) }

  util.EqualsOrFailTest(t, "Bad uuid", pair.Sv.Uuid, pair.Snap.ParentUuid)
  util.EqualsOrFailTest(t, "Should create a new snapshot",
                        len(mock.BackupMgr.SeqForUuid(pair.Sv.Uuid)), 2)
  // Most of the actions are intercepted by higher level mocks except cloning
  // and the first subvolume creation for a canary chain.
  util.EqualsOrFailTest(t, "No clone should be created", mock.Btrfs.ObjCounts(), btrfs_counts)
  util.EqualsOrFailTest(t, "Nothing should be restored by AppendSnapshotToValidationChain",
                        mock.RestoreMgr.ObjCounts(), expect_restore_counts)
}

func TestAppendSnapshotToValidationChain_ExistingChain(t *testing.T) {
  const hist_len = 3
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  canary, mock := buildBackupRestoreCanary(hist_len)
  defer mock.Lnxutil.CleanMountDirs()
  if err := canary.Setup(ctx); err != nil { t.Fatalf("Setup: %v", err) }
  btrfs_counts := mock.Btrfs.ObjCounts().Increment(1,0)

  pairs, err := canary.RestoreChainAndValidate(ctx)
  if err != nil { t.Fatalf("RestoreChainAndValidate: %v", err) }
  mock.SetCloneCallbackToCopyFrom(ctx, pairs[len(pairs)-1].Dst)
  expect_restore_counts := mock.RestoreMgr.ObjCounts()
  pair, err := canary.AppendSnapshotToValidationChain(ctx)
  if err != nil { t.Fatalf("AppendSnapshotToValidationChain: %v", err) }

  if pair.Sv.Uuid == pair.Snap.ParentUuid {
    t.Errorf("Clone should not share uuid with original sv %s/%s",
             pair.Sv.Uuid, pair.Snap.ParentUuid)
  }
  util.EqualsOrFailTest(t, "Should create a new snapshot",
                        len(mock.BackupMgr.SeqForCloneUuid(pair.Sv.Uuid)), 1)
  // Most of the actions are intercepted by higher level mocks except cloning
  // and the first subvolume creation for a canary chain.
  util.EqualsOrFailTest(t, "A single clone should be created", mock.Btrfs.ObjCounts(), btrfs_counts)
  util.EqualsOrFailTest(t, "Nothing should be restored by AppendSnapshotToValidationChain",
                        mock.RestoreMgr.ObjCounts(), expect_restore_counts)
}

func TestAppendSnapshotToValidationChain_NewChain_NonIdempotent(t *testing.T) {
  const chain_len = 3
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  canary, mock := buildBackupRestoreCanary(0)
  btrfs_counts := mock.Btrfs.ObjCounts().Increment(1,0)
  defer mock.Lnxutil.CleanMountDirs()

  if err := canary.Setup(ctx); err != nil { t.Fatalf("Setup: %v", err) }
  _, err := canary.RestoreChainAndValidate(ctx)
  if err != nil { t.Fatalf("RestoreChainAndValidate: %v", err) }

  vol_uuids := make(map[string]bool)
  for i:=0; i<chain_len; i+=1 {
    pair, err := canary.AppendSnapshotToValidationChain(ctx)
    if err != nil { t.Fatalf("AppendSnapshotToValidationChain: %v", err) }
    vol_uuids[pair.Sv.Uuid] = true
  }

  util.EqualsOrFailTest(t, "Only 1 subvol", len(vol_uuids), 1)
  for id,_ := range vol_uuids {
    util.EqualsOrFailTest(t, "Bad snap seq size",
                          len(mock.BackupMgr.SeqForUuid(id)), 1+chain_len)
  }
  util.EqualsOrFailTest(t, "Bad btrfs count",
                        mock.Btrfs.ObjCounts(), btrfs_counts)
}

func TestAppendSnapshotToValidationChain_ExistingChain_NonIdempotent(t *testing.T) {
  const hist_len = 2
  const chain_len = 3
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  canary, mock := buildBackupRestoreCanary(hist_len)
  btrfs_counts := mock.Btrfs.ObjCounts().Increment(1,0)
  defer mock.Lnxutil.CleanMountDirs()

  if err := canary.Setup(ctx); err != nil { t.Fatalf("Setup: %v", err) }
  pairs, err := canary.RestoreChainAndValidate(ctx)
  if err != nil { t.Fatalf("RestoreChainAndValidate: %v", err) }
  mock.SetCloneCallbackToCopyFrom(ctx, pairs[len(pairs)-1].Dst)

  vol_uuids := make(map[string]bool)
  for i:=0; i<chain_len; i+=1 {
    pair, err := canary.AppendSnapshotToValidationChain(ctx)
    if err != nil { t.Fatalf("AppendSnapshotToValidationChain: %v", err) }
    vol_uuids[pair.Sv.Uuid] = true
    mock.SetCloneCallbackToFail(t)
  }

  util.EqualsOrFailTest(t, "Bad clone count", len(vol_uuids), 1)
  for id,_ := range vol_uuids {
    util.EqualsOrFailTest(t, "Bad clone snap len",
                          len(mock.BackupMgr.SeqForCloneUuid(id)), chain_len)
  }
  util.EqualsOrFailTest(t, "Bad btrfs count",
                        mock.Btrfs.ObjCounts(), btrfs_counts)
}

func TestAppendSnapshotToValidationChain_CallBeforeRestore(t *testing.T) {
  const hist_len = 3
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  canary, mock := buildBackupRestoreCanary(hist_len)
  defer mock.Lnxutil.CleanMountDirs()
  if err := canary.Setup(ctx); err != nil { t.Fatalf("Setup: %v", err) }

  _, err := canary.AppendSnapshotToValidationChain(ctx)
  util.EqualsOrFailTest(t, "Bad error", err, ErrMustRestoreBefore)
}

func TestAppendSnapshotToValidationChain_InjectBackupErr(t *testing.T) {
  const hist_len = 3
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  expect_err := fmt.Errorf("TestAppendSnapshotToValidationChain_InjectBackupErr")
  canary, mock := buildBackupRestoreCanary(hist_len)
  defer mock.Lnxutil.CleanMountDirs()

  if err := canary.Setup(ctx); err != nil { t.Fatalf("Setup: %v", err) }
  pairs, err := canary.RestoreChainAndValidate(ctx)
  if err != nil { t.Fatalf("RestoreChainAndValidate: %v", err) }
  mock.SetCloneCallbackToCopyFrom(ctx, pairs[len(pairs)-1].Dst)

  mock.BackupMgr.ForMethodErr(mock.BackupMgr.BackupToCurrentSequenceUnrelatedVol, expect_err)
  _, err = canary.AppendSnapshotToValidationChain(ctx)
  util.EqualsOrFailTest(t, "Bad error", err, expect_err)
}

