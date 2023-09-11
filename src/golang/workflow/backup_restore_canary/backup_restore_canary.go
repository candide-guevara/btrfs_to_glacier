package backup_restore_canary

import (
  "context"
  "errors"
  "fmt"
  "os"
  fpmod "path/filepath"
  "strings"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"

  "github.com/google/uuid"
)

const (
  LoopDevSizeMb = 32
)

var ErrBadCanaryWfConfig = errors.New("workflow_config_incompatible_with_canary")
var ErrCannotCallTwice = errors.New("validate_cannot_be_called_twice")
var ErrMustRestoreBefore = errors.New("before_add_snap_need_restore")
var ErrCannotCallOnEmptyChain = errors.New("cannot_call_this_method_on_empty_restore_chain")
var ErrValidateUuidFile = errors.New("validate_error_uuid_file")
var ErrValidateNewDir = errors.New("validate_error_new_dir")
var ErrValidateDelDir = errors.New("validate_error_del_dir")

type DeferBuilder interface {
  BuildBackupAndRestoreMgr(context.Context, string) (types.BackupManagerAdmin, types.RestoreManagerAdmin, error)
}

type CanaryToken struct {
  New                 bool
  TopDstRestoredPath  string
  TopSrcRestoredSnap  *pb.SubVolume
  RestoredSrcSnaps    []*pb.SubVolume // does not contain TopSrcRestoredSnap
}

// Fields that are set during `Setup()`.
type State struct {
  Fs                  *types.Filesystem
  Uuid                string
  BackupMgr           types.BackupManagerAdmin
  RestoreMgr          types.RestoreManagerAdmin
}

// Note: this type cannot be abstracted away from btrfs.
// It needs to perform some operations that are not available in types.VolumeManager.
type BackupRestoreCanary struct {
  Conf       *pb.Config
  Btrfs      types.Btrfsutil
  Lnxutil    types.Linuxutil
  // We use a factory to defer creation of backup and restore objects
  // since we need to create the filesystem first.
  Factory    DeferBuilder
  ParsedWf   types.ParsedWorkflow
  State      *State
}

func NewBackupRestoreCanary(
    conf *pb.Config, wf_name string,
    btrfs types.Btrfsutil, lnxutil types.Linuxutil, factory DeferBuilder) (types.BackupRestoreCanary, error) {
  parsed_wf, err := util.WorkflowByName(conf, wf_name)
  if err != nil { return nil, err }
  if len(parsed_wf.Source.Paths) != 1 {
    return nil, fmt.Errorf("%w: only 1 source supported", ErrBadCanaryWfConfig)
  }

  canary := &BackupRestoreCanary{
    Conf: conf,
    Btrfs: btrfs,
    Lnxutil: lnxutil,
    Factory: factory,
    ParsedWf: parsed_wf,
    State: nil,
  }

  snap_root := fpmod.Dir(canary.SnapRoot())
  if canary.FsRoot() != snap_root {
    return nil, fmt.Errorf("%w: vol and snap do not share root", ErrBadCanaryWfConfig)
  }
  restore_root := fpmod.Dir(canary.RestoreRoot())
  if canary.FsRoot() != restore_root {
    return nil, fmt.Errorf("%w: vol and restore do not share root", ErrBadCanaryWfConfig)
  }
  return canary, nil
}

func CreateOrFailIfExists(path string) (*os.File, error) {
  return os.OpenFile(path, os.O_EXCL|os.O_CREATE|os.O_WRONLY, 0644)
}

// Creates empty btrfs filesystem on loop device.
// Prepares State to point to the newly created filesystem.
// Creates a new volume if this is the first time the canary is run.
func (self *BackupRestoreCanary) Setup(ctx context.Context) (types.CanaryToken, error) {
  token := &CanaryToken{}
  if self.State != nil {
    util.Infof("Setup twice is a noop: %s", self.State.Uuid)
    return nil, nil
  }
  drop_f := self.Lnxutil.GetRootOrDie()
  defer drop_f()
  dev, err := self.Lnxutil.CreateLoopDevice(ctx, LoopDevSizeMb)
  if err != nil { return nil, err }

  // Set the state to indicate there is something to tear down.
  self.State = &State{
    Fs: &types.Filesystem{ Devices: []*types.Device{dev,}, },
  }

  fs, err := self.Lnxutil.CreateBtrfsFilesystem(ctx, dev, uuid.NewString(), "--mixed")
  if err != nil { return nil, err }
  self.State.Fs = fs

  mnt, err := self.Lnxutil.Mount(ctx, fs.Uuid, self.FsRoot())
  if err != nil { return nil, err }
  fs.Mounts = append(fs.Mounts, mnt)

  err = self.SetupPathsInNewFs()
  if err != nil { return nil, err }

  self.State.BackupMgr, self.State.RestoreMgr, err = self.Factory.BuildBackupAndRestoreMgr(
                                                       ctx, self.ParsedWf.Wf.Name)
  if err != nil { return nil, err }
  err = self.State.BackupMgr.Setup(ctx)
  if err != nil { return nil, err }
  err = self.State.RestoreMgr.Setup(ctx)
  if err != nil { return nil, err }

  self.State.Uuid, err = self.DetermineVolUuid(ctx)
  if err != nil { return nil, err }

  if len(self.State.Uuid) < 1 {
    token.New = true
    err = self.Btrfs.CreateSubvolume(self.VolRoot())
    if err != nil { return nil, err }
    sv, err := self.Btrfs.SubVolumeInfo(self.VolRoot())
    if err != nil { return nil, err }
    err = self.CreateFirstValidationChainItem()
    if err != nil { return nil, err }
    _, err = self.State.BackupMgr.BackupAllToCurrentSequences(ctx, []*pb.SubVolume{sv,})
    if err != nil { return nil, err }
    self.State.Uuid, err = self.DetermineVolUuid(ctx)
    if err != nil { return nil, err }
  }
  if len(self.State.Uuid) < 1 { return nil, fmt.Errorf("self.State.Uuid == ''") }
  return token, err
}

func (self *BackupRestoreCanary) DetermineVolUuid(ctx context.Context) (string, error) {
  heads, err := self.State.RestoreMgr.ReadHeadAndSequenceMap(ctx)
  if err != nil { return "", err }
  if len(heads) > 1 {
    return "", fmt.Errorf("Metadata contains more than 1 volume: %v", len(heads))
  }
  for k,_ := range heads {
    return k, nil
  }
  return "", nil
}

// Structure of filesystem to validate:
// * restores/       # restored snapshots will go here
// * subvol/         # writable clone of most recent snapshot, used to continue the snap sequence to validate.
//                   # for first snapshot this will simply be a brand new subvolume
// * snapshots/      # new snapshots in the sequence go here
// * subvol/uuids    # contains all snapshot uuids in history, one per line
//                   # empty for the first snapshot
// * subvol/deleted/ # contains a single file named after the most recently deleted snapshot
//                   # content is hash(prev_hash, backup_sv.Uuid, backup_sv.Data.Chunks.Uuid)
//                   # no files for the first snapshot
// * subvol/new/     # contains one file per snapshot, named as its uuid
//                   # content is hash(backup_sv.Uuid, backup_sv.Data.Chunks.Uuid)
//                   # no files for the first snapshot
func (self *BackupRestoreCanary) SetupPathsInNewFs() error {
  if util.Exists(self.VolRoot()) { return fmt.Errorf("Filesystem is not new: %s", self.VolRoot()) }

  get_root, err := self.Lnxutil.DropRoot()
  if err != nil { return err }
  defer get_root()
  if err := os.Mkdir(self.RestoreRoot(), 0775); err != nil { return err }
  if err := os.Mkdir(self.SnapRoot(), 0775); err != nil { return err }
  return nil
}

func (self *BackupRestoreCanary) VolRoot() string {
  return self.ParsedWf.Source.Paths[0].VolPath
}
func (self *BackupRestoreCanary) FsRoot() string {
  return fpmod.Dir(self.VolRoot())
}
func (self *BackupRestoreCanary) SnapRoot() string {
  return self.ParsedWf.Source.Paths[0].SnapPath
}
func (self *BackupRestoreCanary) RestoreRoot() string {
  return self.ParsedWf.Restore.RootRestorePath
}
func (self *BackupRestoreCanary) DelDir() string {
  return fpmod.Join(self.VolRoot(), types.KCanaryDelDir)
}
func (self *BackupRestoreCanary) NewDir() string {
  return fpmod.Join(self.VolRoot(), types.KCanaryNewDir)
}
func (self *BackupRestoreCanary) UuidFile() string {
  return fpmod.Join(self.VolRoot(), types.KCanaryUuidFile)
}
func RestoredDelDir(token *CanaryToken) string {
  return fpmod.Join(token.TopDstRestoredPath, types.KCanaryDelDir)
}
func RestoredNewDir(token *CanaryToken) string {
  return fpmod.Join(token.TopDstRestoredPath, types.KCanaryNewDir)
}
func RestoredUuidFile(token *CanaryToken) string {
  return fpmod.Join(token.TopDstRestoredPath, types.KCanaryUuidFile)
}

func (self *BackupRestoreCanary) CreateFirstValidationChainItem() error {
  get_root, err := self.Lnxutil.DropRoot()
  if err != nil { return err }
  defer get_root()
  if err := os.Mkdir(self.DelDir(), 0775); err != nil { return err }
  if err := os.Mkdir(self.NewDir(), 0775); err != nil { return err }
  f, err := CreateOrFailIfExists(self.UuidFile())
  return util.Coalesce(err, f.Close())
}

// Destroys the loop device and backing file.
// In case of a partial `Setup()`, attempts to delete any dangling infrastructure.
func (self *BackupRestoreCanary) TearDown(ctx context.Context) error {
  if self.State == nil {
    util.Infof("Teardown before calling setup is a noop")
    return nil
  }
  var backup_err, umount_err, deldev_err error
  if self.State.BackupMgr != nil {
    backup_err = self.State.BackupMgr.TearDown(ctx)
  }
  drop_f := self.Lnxutil.GetRootOrDie()
  defer drop_f()
  if len(self.State.Fs.Mounts) > 0 {
    umount_err = self.Lnxutil.UMount(ctx, self.State.Fs.Uuid)
  }
  deldev_err = self.Lnxutil.DeleteLoopDevice(ctx, self.State.Fs.Devices[0])
  return util.Coalesce(backup_err, umount_err, deldev_err)
}

// btrfs subvolume snap restores/asubvol.snap.2 clones/asubvol.clone.2
// # ... add a couple new files ...
// btrfs subvolume snap -r clones/asubvol.clone.2 restores/asubvol.snap.3
// btrfs send -p restores/asubvol.snap.2 restores/asubvol.snap.3 | btrfs receive restore_dir2
// comm -3 <(find restore_dir2/asubvol.snap.3 -printf "./%P\n") <(find clones/asubvol.clone.2 -printf "./%P\n")
// # both subvolumes contain the same files
func (self *BackupRestoreCanary) AppendSnapshotToValidationChain(
    ctx context.Context, opaque_token types.CanaryToken) (types.BackupPair, error) {
  var err error
  token := opaque_token.(*CanaryToken)
  result := types.BackupPair{}
  if token.TopSrcRestoredSnap == nil { return result, ErrMustRestoreBefore }

  // Create the clone only if needed, if the original subvol is still present, use it instead.
  result.Sv, err = self.Btrfs.SubVolumeInfo(self.VolRoot())
  if err != nil {
    err := self.Btrfs.CreateClone(token.TopDstRestoredPath, self.VolRoot())
    if err != nil { return result, err }
    result.Sv, err = self.Btrfs.SubVolumeInfo(self.VolRoot())
    if err != nil { return result, err }
  }

  err = self.AppendDataToSubVolume(token.TopSrcRestoredSnap)
  if err != nil { return result, err }

  if result.Sv.Uuid == self.State.Uuid {
    bkp_pair, err := self.State.BackupMgr.BackupAllToCurrentSequences(
                       ctx, []*pb.SubVolume{result.Sv,})
    if err != nil { return result, err }
    if len(bkp_pair) != 1 {
      return bkp_pair[0], fmt.Errorf("canary should use just 1 subvolume")
    }
    result.Snap = bkp_pair[0].Snap
  } else {
    result.Snap, err = self.State.BackupMgr.BackupToCurrentSequenceUnrelatedVol(
                         ctx, result.Sv, self.State.Uuid)
    if err != nil { return result, err }
  }
  return result, err
}

func ReadFileIntoString(dir string, file string) (string, error) {
  path := fpmod.Join(dir, file)
  content, err := os.ReadFile(path)
  if err != nil { return "", err }
  return string(content), nil
}

// Prerequisite the subvolume must have been created before
// and should contain the file and directories listed in `SetupPathsInNewFs`.
func (self *BackupRestoreCanary) AppendDataToSubVolume(top_snap *pb.SubVolume) error {
  f, err := os.OpenFile(self.UuidFile(), os.O_WRONLY|os.O_APPEND, 0666)
  if err != nil { return err }
  _, err_w1 := f.WriteString(fmt.Sprintln(top_snap.Uuid))
  err_cl := f.Close()
  if err = util.Coalesce(err_w1, err_cl); err != nil { return err }

  newpath := fpmod.Join(self.NewDir(), top_snap.Uuid)
  f, err = CreateOrFailIfExists(newpath)
  if err != nil { return err }
  _, err_w1 = f.WriteString(util.HashFromSv(top_snap, ""))
  err_cl = f.Close()
  if err = util.Coalesce(err_w1, err_cl); err != nil { return err }

  var prev_content string
  entries, err := os.ReadDir(self.DelDir())
  if err != nil { return err }
  for _,e := range entries {
    if prev_content,err = ReadFileIntoString(self.DelDir(), e.Name()); err != nil { return nil }
    path := fpmod.Join(self.DelDir(), e.Name())
    if err = util.RemoveAll(path); err != nil { return err }
  }
  delpath := fpmod.Join(self.DelDir(), top_snap.Uuid)
  f, err = CreateOrFailIfExists(delpath)
  if err != nil { return err }
  _, err_w1 = f.WriteString(util.HashFromSv(top_snap, prev_content))
  err_cl = f.Close()
  return util.Coalesce(err_w1, err_cl)
}

func (self *BackupRestoreCanary) ValidateEmptyChain(token *CanaryToken) error {
  content, err := os.ReadFile(RestoredUuidFile(token))
  if err != nil { return err }
  if len(content) > 0 {
    return fmt.Errorf("%w: %s should be empty", ErrValidateUuidFile, RestoredUuidFile(token))
  }

  entries, err := os.ReadDir(RestoredDelDir(token))
  if err != nil { return err }
  if len(entries) > 0 {
    return fmt.Errorf("%w: %s should be empty", ErrValidateDelDir, RestoredDelDir(token))
  }

  entries, err = os.ReadDir(RestoredNewDir(token))
  if err != nil { return err }
  if len(entries) > 0 {
    return fmt.Errorf("%w: %s should be empty", ErrValidateNewDir, RestoredNewDir(token))
  }
  return nil
}

func (self *BackupRestoreCanary) ValidateUuidFile(token *CanaryToken) error {
  len_snaps_in_top := len(token.RestoredSrcSnaps)
  if len_snaps_in_top == 0 { return ErrCannotCallOnEmptyChain }

  content, err := os.ReadFile(RestoredUuidFile(token))
  lines := strings.Split(strings.TrimSpace(string(content)), "\n")
  if err != nil { return err }

  if len(lines) != len_snaps_in_top {
    return fmt.Errorf("%w: Volume does not contain a list of all of its ancestors: %d / %d",
                      ErrValidateUuidFile, len(lines), len_snaps_in_top)
  }
  for i,l := range lines {
    if l != token.RestoredSrcSnaps[i].Uuid {
      return fmt.Errorf("%w: Snapshot history mismatch: %s / %s",
                        ErrValidateUuidFile, l, token.RestoredSrcSnaps[i].Uuid)
    }
  }
  return nil
}

func (self *BackupRestoreCanary) ValidateDelDir(token *CanaryToken) error {
  if len(token.RestoredSrcSnaps) == 0 { return ErrCannotCallOnEmptyChain }

  entries, err := os.ReadDir(RestoredDelDir(token))
  if err != nil { return err }
  if len(entries) != 1 {
    return fmt.Errorf("%w: should contain only 1 file, got: %d",
                      ErrValidateDelDir, len(entries))
  }

  expect_delname := token.TopSrcRestoredSnap.Uuid
  if expect_delname != entries[0].Name() {
    return fmt.Errorf("%w: should contain a file named after State.RestoredSrcSnaps[-1]: '%s'",
                      ErrValidateDelDir, entries[0].Name())
  }

  got_hash, err := ReadFileIntoString(RestoredDelDir(token), entries[0].Name())
  if err != nil { return err }

  prev_hash, expect_hash := "", ""
  for _,sv := range token.RestoredSrcSnaps {
    expect_hash = util.HashFromSv(sv, prev_hash)
    prev_hash = expect_hash
  }
  if strings.Compare(got_hash, expect_hash) != 0 {
    return fmt.Errorf("%w: file, bad content: %x != %x", ErrValidateDelDir, got_hash, expect_hash)
  }
  return nil
}

func (self *BackupRestoreCanary) ValidateNewDir(token *CanaryToken) error {
  len_snaps_in_top := len(token.RestoredSrcSnaps)
  if len_snaps_in_top == 0 { return ErrCannotCallOnEmptyChain }

  sv_to_hash := make(map[string]string)
  for _,sv := range token.RestoredSrcSnaps { sv_to_hash[sv.Uuid] = util.HashFromSv(sv, "") }

  entries, err := os.ReadDir(RestoredNewDir(token))
  if err != nil { return err }
  if len(entries) != len_snaps_in_top {
    return fmt.Errorf("%w: should contain 1 file per snapshot in history: %d / %d",
                      ErrValidateNewDir, len(entries), len_snaps_in_top)
  }
  for _,entry := range entries {
    if entry.IsDir() {
      return fmt.Errorf("%w: should not contain directories, got: %s",
                        ErrValidateNewDir, entry.Name())
    }
    got_hash, err := ReadFileIntoString(RestoredNewDir(token), entry.Name())
    if err != nil { return err }
    expect_hash := sv_to_hash[entry.Name()]
    if strings.Compare(got_hash, expect_hash) != 0 {
      return fmt.Errorf("%w: file, bad content: %x != %x",
                        ErrValidateNewDir, got_hash, expect_hash)
    }
  }
  return nil
}

// Suppose `State.TopDstRestoredPath` contains the `n` snapshot in the sequence.
// Then we expected it contains all data from [0, n-1] as follows:
// `RestoredUuidFile` = [ snap_uuid(0) ... snap_uuid(n-1) ]
//    where snap_uuid is the id used in the backup metadata.
// `RestoredDelDir` = { Hash(snap(n-1), Hash(snap(n-2), ... Hash(snap(0))...)) }
//    where snap has the chunk ids in the backup metadata and the name of the file is snap_uuid(n).
// `RestoredNewDir` = [ {Hash(snap(0))} ... {Hash(snap(n-1)} ]
//    where snap has the chunk ids in the backup metadata and file are named after snap_uuid(i).
// Note that for the "zero" snapshot: Hash(snap(0))="", snap_uuid(0)=""
//
// `State.RestoredSrcSnaps` = [ snap(1) ... snap(n-1) ]
// `State.TopSrcRestoredSnap` = snap(n)
func (self *BackupRestoreCanary) RestoreChainAndValidate(
    ctx context.Context, opaque_token types.CanaryToken) ([]types.RestorePair, error) {
  token := opaque_token.(*CanaryToken)
  pairs, err := self.State.RestoreMgr.RestoreCurrentSequence(ctx, self.State.Uuid)
  if err != nil { return nil, err }
  if len(pairs) == 0 { return pairs, ErrCannotCallTwice }

  if token.New {
    if len(pairs) != 1 {
      return nil, fmt.Errorf("expected only the initial snapshot, got: %v", pairs)
    }
    token.New = false
    token.RestoredSrcSnaps = nil
    token.TopSrcRestoredSnap = pairs[0].Src
    token.TopDstRestoredPath = pairs[0].Dst.MountedPath
    return pairs, self.ValidateEmptyChain(token)
  }

  if token.TopSrcRestoredSnap != nil {
    token.RestoredSrcSnaps = append(token.RestoredSrcSnaps, token.TopSrcRestoredSnap)
  }
  for i,pair := range pairs {
    token.TopSrcRestoredSnap = pair.Src
    token.TopDstRestoredPath = pair.Dst.MountedPath
    if i != len(pairs) - 1 {
      token.RestoredSrcSnaps = append(token.RestoredSrcSnaps, pair.Src)
    }
  }

  err_uuid := self.ValidateUuidFile(token)
  err_newf := self.ValidateNewDir(token)
  err_deld := self.ValidateDelDir(token)

  util.Infof("Validated chain of %d items for vol '%s'",
             len(token.RestoredSrcSnaps), self.State.Uuid)
  return pairs, util.Coalesce(err_uuid, err_newf, err_deld)
}

