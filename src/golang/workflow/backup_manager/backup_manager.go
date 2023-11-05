package backup_manager

import (
  "context"
  "errors"
  "fmt"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"

  "github.com/google/uuid"
)

const (
  MinIntervalBetweenSnaps = 24 * time.Hour
)

var ErrSnapsMismatchWithSrc = errors.New("snapshot_mismatch_between_meta_and_source")
var ErrExpectCloneFromLastRec = errors.New("clone_should_be_issued_from_a_received_snap")
var ErrCannotFindParForClone = errors.New("unrelated_clone_cannot_find_suitable_restored_snap_par")

// Meta and Content must already been setup
type BackupManager struct {
  Conf     *pb.Config
  Meta     types.AdminMetadata
  Content  types.AdminBackupContent
  Source   types.VolumeSource
  MinInterval time.Duration
}

func NewBackupManagerAdmin(conf *pb.Config,
    meta types.AdminMetadata, content types.AdminBackupContent,
    vol_src types.VolumeSource) (types.BackupManagerAdmin, error) {
  mgr := &BackupManager{
    Conf: conf,
    Meta: meta,
    Content: content,
    Source: vol_src,
    MinInterval: MinIntervalBetweenSnaps,
  }
  return mgr, nil
}

func (self *BackupManager) Setup(ctx context.Context) error {
  if err := self.Meta.SetupMetadata(ctx); err != nil { return err }
  if err := self.Content.SetupBackupContent(ctx); err != nil { return err }
  return nil
}

func (self *BackupManager) TearDown(ctx context.Context) error {
  if err := self.Meta.TearDownMetadata(ctx); err != nil { return err }
  if err := self.Content.TearDownBackupContent(ctx); err != nil { return err }
  return nil
}

// Does NOT write anything to self.Meta: writes should be ordered chunk -> snap -> seq -> head
func (self *BackupManager) GetSequenceFor(
    ctx context.Context, sv *pb.SubVolume, new_seq bool) (*pb.SnapshotSequence, error) {
  seq := &pb.SnapshotSequence{
    Uuid: uuid.NewString(),
    Volume: sv,
  }
  if new_seq { return seq, nil }

  head, err := self.Meta.ReadSnapshotSeqHead(ctx, sv.Uuid)
  if errors.Is(err, types.ErrNotFound) { return seq, nil }
  if err != nil { return nil, err }

  return self.Meta.ReadSnapshotSeq(ctx, head.CurSeqUuid)
}

// Return value will contain the full sequence of snapshots including the new one created.
func (self *BackupManager) CreateNewSnapshotOrUseRecent(
    sv *pb.SubVolume, use_recent bool) ([]*pb.SubVolume, error) {
  src_snap_seq, err := self.Source.GetSnapshotSeqForVolume(sv)
  if err != nil { return nil, err }
  if use_recent && len(src_snap_seq) > 0 {
    top_snap := src_snap_seq[len(src_snap_seq)-1]
    age := time.Now().Sub(time.Unix(int64(top_snap.CreatedTs), 0))
    if age <= self.MinInterval { return src_snap_seq, nil }
  }
  create_f := self.Source.CreateSnapshot
  if !use_recent { create_f = self.Source.CreateSnapshotLongName }
  snap, err := create_f(sv)
  if err != nil { return nil, err }
  src_snap_seq = append(src_snap_seq, snap)
  util.Debugf("Backup snap %s for subvolume %s", snap.Uuid, sv.Uuid)
  return src_snap_seq, err
}

// IMPORTANT: this does not check the SnapshotSequence is up-to-date.
// The sequence should be written independently of this method result.
// Returns a non-nil snapshot if there is no need to write the snapshot data to storage.
func (self *BackupManager) IsBackupAlreadyInStorage(
    ctx context.Context, snap *pb.SubVolume) (*pb.SubVolume, error) {
  full_snap, err := self.Meta.ReadSnapshot(ctx, snap.Uuid)
  if errors.Is(err, types.ErrNotFound) { return nil, nil }
  if err != nil { return nil, err }
  util.Debugf("Found snapshot already in storage: %s", full_snap.Uuid)
  // We consider that all snapshots are written in a single call,
  // If the list of chunks is not empty then the full data is in storage.
  if full_snap.Data == nil || len(full_snap.Data.Chunks) == 0 { return nil, nil }
  return full_snap, nil
}

// Prerequisite: we know the new snapshot has not been persisted yet.
func (self *BackupManager) DetermineParentForIncremental(
    src_snap_seq []*pb.SubVolume, seq *pb.SnapshotSequence) (*pb.SubVolume, error) {
  if len(seq.SnapUuids) != 0 && len(src_snap_seq) == 1 {
    // This may happen if you delete past snapshots too aggresively in the source ?
    return nil, ErrSnapsMismatchWithSrc
  }
  if len(seq.SnapUuids) == 0 { return nil, nil }

  for i:=len(seq.SnapUuids)-1; i>=0; i-=1 {
    store_uuid := seq.SnapUuids[i]
    for j:=len(src_snap_seq)-1; j>=0; j-=1 {
      src_uuid := src_snap_seq[j].Uuid
      if src_uuid == store_uuid {
        util.Debugf("For incremental backup parent: %s", src_uuid)
        return src_snap_seq[j], nil
      }
    }
  }
  return nil, nil
}

func (self *BackupManager) BackupSingleSvToSequence(
    ctx context.Context, sv *pb.SubVolume, seq *pb.SnapshotSequence, reuse bool) (*pb.SubVolume, error) {
  src_snap_seq, err := self.CreateNewSnapshotOrUseRecent(sv, /*use_recent=*/reuse)
  if err != nil { return nil, err }
  snap := src_snap_seq[len(src_snap_seq)-1]
  full_snap, err := self.IsBackupAlreadyInStorage(ctx, snap)
  if err != nil { return nil, err }
  if full_snap != nil { return full_snap, nil }
  par_snap, err := self.DetermineParentForIncremental(src_snap_seq, seq)
  if err != nil { return nil, err }
  stream, err := self.Source.GetSnapshotStream(ctx, par_snap, snap)
  if err != nil { return nil, err }
  chunks, err := self.Content.WriteStream(ctx, /*offset=*/0, stream)
  if err != nil { return nil, err }
  full_snap, err = self.Meta.AppendChunkToSnapshot(ctx, snap, chunks)
  return full_snap, util.Coalesce(stream.GetErr(), err)
}

// Only if this method succeeds we can guarantee the incremental backup data is correctly stored.
func (self *BackupManager) PersistSequence(
    ctx context.Context, snap *pb.SubVolume, seq *pb.SnapshotSequence) (*pb.SnapshotSequence, error) {
  new_seq, err := self.Meta.AppendSnapshotToSeq(ctx, seq, snap)
  if err != nil { return nil, err }
  _, err = self.Meta.RecordSnapshotSeqHead(ctx, new_seq)
  if err != nil { return nil, err }
  version, err := self.Meta.PersistCurrentMetadataState(ctx)
  util.Infof("BackupManager.PersistSequence: %s -> %s", snap.ParentUuid, version)
  return new_seq, nil
}

func (self *BackupManager) BackupAllHelper(
    ctx context.Context, subvols []*pb.SubVolume, new_seq bool, reuse bool) ([]types.BackupPair, error) {
  if len(subvols) == 0 { return nil, fmt.Errorf("BackupAllHelper subvols empty") }
  backups := make([]types.BackupPair, 0, 10)

  for _,sv := range subvols {
    seq, err := self.GetSequenceFor(ctx, sv, new_seq)
    if err != nil { return backups, err }
    snap, err := self.BackupSingleSvToSequence(ctx, sv, seq, reuse)
    if err != nil { return backups, err }
    _, err = self.PersistSequence(ctx, snap, seq)
    if err != nil { return backups, err }
    backups = append(backups, types.BackupPair{ Sv: sv, Snap: snap, })
  }
  return backups, nil
}

func (self *BackupManager) BackupAllToCurrentSequences(
    ctx context.Context, subvols []*pb.SubVolume) ([]types.BackupPair, error) {
  return self.BackupAllHelper(ctx, subvols, /*new_seq=*/false, /*reuse=*/true)
}

func (self *BackupManager) BackupAllToCurrentSequences_NoReUse(
    ctx context.Context, subvols []*pb.SubVolume) ([]types.BackupPair, error) {
  return self.BackupAllHelper(ctx, subvols, /*new_seq=*/false, /*reuse=*/false)
}

func (self *BackupManager) BackupAllToNewSequences(
    ctx context.Context, subvols []*pb.SubVolume) ([]types.BackupPair, error) {
  return self.BackupAllHelper(ctx, subvols, /*new_seq=*/true, /*reuse=*/true)
}

// dd if=/dev/zero of=/tmp/loop.file bs=1M count=64
// sudo losetup /dev/loop11 /tmp/loop.file
// sudo mkfs.btrfs -f --mixed --label=btrfs_test /dev/loop11
// mkdir /tmp/btrfsmount
// sudo mount /dev/loop11 /tmp/btrfsmount
// sudo mkdir /tmp/btrfsmount/receives
// sudo btrfs subvol create /tmp/btrfsmount/subvol1
// echo subvol1 | sudo tee subvol1/data
// sudo btrfs subvol snap -r /tmp/btrfsmount/subvol1 /tmp/btrfsmount/snap1
// echo subvol2 | sudo tee subvol1/data
// sudo btrfs subvol snap -r /tmp/btrfsmount/subvol1 /tmp/btrfsmount/snap2
// echo subvol3 | sudo tee subvol1/data
// sudo btrfs subvol snap -r /tmp/btrfsmount/subvol1 /tmp/btrfsmount/snap3
// sudo btrfs subvol snap /tmp/btrfsmount/snap3 /tmp/btrfsmount/clone3
// echo subvol4 | sudo tee -a clone3/data
// sudo btrfs subvol snap -r /tmp/btrfsmount/clone3 /tmp/btrfsmount/clone_snap4
// sudo btrfs send /tmp/btrfsmount/snap1 | sudo btrfs receive /tmp/btrfsmount/receives
// sudo btrfs send -p /tmp/btrfsmount/snap1 /tmp/btrfsmount/snap2 | sudo btrfs receive /tmp/btrfsmount/receives
// sudo btrfs send -p /tmp/btrfsmount/snap2 /tmp/btrfsmount/snap3 | sudo btrfs receive /tmp/btrfsmount/receives
// sudo btrfs send -p /tmp/btrfsmount/snap3 /tmp/btrfsmount/clone_snap4 | sudo btrfs receive /tmp/btrfsmount/receives
// sudo btrfs subvol list -Ruq /tmp/btrfsmount
//
// ID 256 par_uuid -                                    rec_uuid -                                    uuid 824e2352-5e72-164e-9d44-b6713c3860d1 path subvol1
// ID 257 par_uuid 824e2352-5e72-164e-9d44-b6713c3860d1 rec_uuid -                                    uuid b1650f86-38b3-4d41-bd89-315c5ca87426 path snap1
// ID 258 par_uuid 824e2352-5e72-164e-9d44-b6713c3860d1 rec_uuid -                                    uuid e3067cad-5839-5147-a4a2-e8722e034cf7 path snap2
// ID 259 par_uuid 824e2352-5e72-164e-9d44-b6713c3860d1 rec_uuid -                                    uuid e3221197-9ba1-1747-b420-2d8f92039645 path snap3
// ID 260 par_uuid e3221197-9ba1-1747-b420-2d8f92039645 rec_uuid -                                    uuid 969ac62d-994f-bb43-a061-c974e384fbfe path clone3
// ID 261 par_uuid 969ac62d-994f-bb43-a061-c974e384fbfe rec_uuid -                                    uuid 72e5fba5-31a8-9c4e-baa3-ec1ceaeb4fa2 path clone_snap4
// ID 262 par_uuid -                                    rec_uuid b1650f86-38b3-4d41-bd89-315c5ca87426 uuid 376ad931-5542-1147-a91d-a05a693635a7 path receives/snap1
// ID 263 par_uuid 376ad931-5542-1147-a91d-a05a693635a7 rec_uuid e3067cad-5839-5147-a4a2-e8722e034cf7 uuid 8fa4203b-2630-6f43-87d7-f23b8b9ba26a path receives/snap2
// ID 264 par_uuid 8fa4203b-2630-6f43-87d7-f23b8b9ba26a rec_uuid e3221197-9ba1-1747-b420-2d8f92039645 uuid 5977462a-0d4b-674a-8ed0-1ede4f7da2b3 path receives/snap3
// ID 265 par_uuid 5977462a-0d4b-674a-8ed0-1ede4f7da2b3 rec_uuid 72e5fba5-31a8-9c4e-baa3-ec1ceaeb4fa2 uuid 22377240-c1a4-404c-8a8a-4d85f23cb1b6 path receives/clone_snap4
func (self *BackupManager) BackupToCurrentSequenceUnrelatedVol(
    ctx context.Context, src *pb.SubVolume, dst_uuid string) (*pb.SubVolume, error) {
  head, err := self.Meta.ReadSnapshotSeqHead(ctx, dst_uuid)
  if err != nil { return nil, err }
  seq, err := self.Meta.ReadSnapshotSeq(ctx, head.CurSeqUuid)
  if err != nil { return nil, err }

  clone_seq, err := self.CreateNewSnapshotOrUseRecent(src, /*use_recent=*/false)
  if err != nil { return nil, err }
  clone_snap := clone_seq[len(clone_seq) - 1]

  var last_rec_snap *pb.SubVolume
  // If this is the first snapshot we create from the clone
  // then the parent is the last restored snapshot.
  if len(clone_seq) == 1 {
    last_rec_snap, err = self.Source.FindVolume(src.MountedPath, types.ByUuid(src.ParentUuid))
    if err != nil || last_rec_snap == nil {
      return nil, fmt.Errorf("%w: last_rec_snap=%v err=%v", ErrCannotFindParForClone, last_rec_snap, err)
    }
    if len(last_rec_snap.ReceivedUuid) == 0 {
      return nil, fmt.Errorf("%w: %v", ErrExpectCloneFromLastRec, last_rec_snap)
    }
  }
  /*else */ if len(clone_seq) != 1 {
    last_rec_snap = clone_seq[len(clone_seq) - 2]
  }

  // Hack to make it look as if it all comes from the same subvolume
  clone_snap.ParentUuid = dst_uuid
  last_rec_snap.ParentUuid = dst_uuid

  stream, err := self.Source.GetSnapshotStream(ctx, last_rec_snap, clone_snap)
  if err != nil { return nil, err }
  chunks, err := self.Content.WriteStream(ctx, /*offset=*/0, stream)
  if err != nil { return nil, err }
  full_snap, err := self.Meta.AppendChunkToSnapshot(ctx, clone_snap, chunks)
  if err != nil { return nil, err }
  _, err = self.PersistSequence(ctx, full_snap, seq)
  if err != nil { return nil, err }
  return full_snap, util.Coalesce(stream.GetErr(), err)
}

