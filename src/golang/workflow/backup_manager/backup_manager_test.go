package backup_manager

import (
  "context"
  "errors"
  "fmt"
  "testing"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/types/mocks"
  "btrfs_to_glacier/util"

  "github.com/google/uuid"
  "google.golang.org/protobuf/proto"
)

type Mocks struct {
  ConfSrc *pb.Source
  Meta *mocks.Metadata
  Store *mocks.Storage
  Source *mocks.VolumeManager
}

type MockCountState struct {
  Meta mocks.MetaCounts
  Store mocks.StorageCounts
  Source mocks.VolMgrCounts
}

func (self *Mocks) AddSubVolumeInSrc(ppair *pb.Source_VolSnapPathPair, uuid_str string) *pb.SubVolume {
  sv := util.DummySubVolume(uuid_str)
  sv.MountedPath = ppair.VolPath
  sv.Data = nil
  self.Source.Vols[sv.MountedPath] = sv
  clone := proto.Clone(sv).(*pb.SubVolume)
  return clone
}

func (self *Mocks) AddSnapshotInSrc(sv *pb.SubVolume, uuid_str string, recent bool) *pb.SubVolume {
  var ppair *pb.Source_VolSnapPathPair
  for _,pp := range self.ConfSrc.Paths { if pp.VolPath == sv.MountedPath { ppair = pp } }
  snap := util.DummySnapshot(uuid_str, sv.Uuid)
  snap.MountedPath = ppair.SnapPath
  snap.Data = nil
  if recent { snap.CreatedTs = uint64(time.Now().Unix()) }
  self.Source.Snaps[sv.Uuid] = append(self.Source.Snaps[sv.Uuid], snap)
  clone := proto.Clone(snap).(*pb.SubVolume)
  return clone
}

func (self *Mocks) AddReceivedSnapFromMostRecentMetaSnap(head_uuid string) *pb.SubVolume {
  snaps_for_head := self.Meta.CurrentSnapsForHead(head_uuid)
  if len(snaps_for_head) == 0 { util.Fatalf("Cannot add received snap for unknown head") }
  last := snaps_for_head[len(snaps_for_head) - 1]
  rec_snap, err := self.Source.CreateReceivedFromSnap(last.Uuid)
  if err != nil { util.Fatalf("Source.CreateReceivedFromSnap: %v", err) }
  return rec_snap
}

func (self *Mocks) CountState() MockCountState {
  return MockCountState{
    Meta: self.Meta.ObjCounts(),
    Store: self.Store.ObjCounts(),
    Source: self.Source.ObjCounts(),
  }
}

func (self MockCountState) IncMeta(
    cnt_head int, cnt_seq int, cnt_snap int, cnt_version int) MockCountState {
  self.Meta = self.Meta.Increment(cnt_head, cnt_seq, cnt_snap, cnt_version)
  return self
}

func (self MockCountState) IncSource(
    cnt_vol int, cnt_seq int, cnt_snap int, cnt_rec int) MockCountState {
  self.Source = self.Source.Increment(cnt_vol, cnt_seq, cnt_snap, cnt_rec)
  return self
}

func (self MockCountState) IncStore(cnt_chunk int, cnt_restored int) MockCountState {
  self.Store = self.Store.Increment(cnt_chunk, cnt_restored)
  return self
}

func (self *Mocks) AddSvAndSnapsFromMetaInSrc() []*pb.SubVolume {
  heads := self.Meta.HeadKeys()
  expect_svs := []*pb.SubVolume{}
  for i,ppair := range self.ConfSrc.Paths {
    sv := self.AddSubVolumeInSrc(ppair, heads[i])
    expect_svs = append(expect_svs, sv)

    head := self.Meta.Heads[heads[i]]
    if len(head.CurSeqUuid) == 0 { continue }
    for _,uuid_str := range self.Meta.Seqs[head.CurSeqUuid].SnapUuids {
      self.AddSnapshotInSrc(sv, uuid_str, /*recent=*/false)
    }
  }
  return expect_svs
}

func buildConfSources(src_count int, path_count int) []*pb.Source {
  srcs := []*pb.Source{}
  for i:=0; i<src_count; i+=1 {
    source := &pb.Source{
      Type: pb.Source_BTRFS,
      Name: uuid.NewString(),
    }
    for j:=0; j<path_count; j+=1 {
      ppair := &pb.Source_VolSnapPathPair{
        VolPath:  fmt.Sprintf("/tmp/subvol_%d_%d", i, j),
        SnapPath: fmt.Sprintf("/tmp/snaps_%d_%d", i, j),
      }
      source.Paths = append(source.Paths, ppair)
    }
    srcs = append(srcs, source)
  }
  return srcs
}

func buildBackupManagerEmpty(path_count int) (*BackupManager, *Mocks) {
  conf := util.LoadTestConf()
  conf.Sources = buildConfSources(1, path_count)
  meta := mocks.NewMetadata()
  store := mocks.NewBackupContent()
  source := mocks.NewVolumeManager()
  mocks := &Mocks{
    ConfSrc: conf.Sources[0],
    Meta: meta,
    Store: store,
    Source: source,
  }
  mgr, err := NewBackupManagerAdmin(conf, meta, store, source)
  if err != nil { util.Fatalf("BuildBackupManager: %v", err) }
  return mgr.(*BackupManager), mocks
}

func buildBackupManager(
    meta *mocks.Metadata, store *mocks.Storage, source *mocks.VolumeManager) (*BackupManager, *Mocks) {
  conf := util.LoadTestConf()
  conf.Sources = buildConfSources(1, len(meta.HeadKeys()))
  mocks := &Mocks{
    ConfSrc: conf.Sources[0],
    Meta: meta,
    Store: store,
    Source: source,
  }
  mocks.AddSvAndSnapsFromMetaInSrc()
  mgr, err := NewBackupManagerAdmin(conf, meta, store, source)
  if err != nil { util.Fatalf("BuildBackupManager: %v", err) }
  return mgr.(*BackupManager), mocks
}

func ValidateBackupInVolumeSource(
    t *testing.T, mocks *Mocks, expect_sv *pb.SubVolume, pair types.BackupPair) {
  util.EqualsOrFailTest(t, "bad subvol", pair.Sv, expect_sv)
  src_snaps := mocks.Source.Snaps[expect_sv.Uuid]
  if len(src_snaps) < 1 { t.Fatalf("No snaps in source for '%s'", expect_sv.Uuid) }
  last_snap_src := src_snaps[len(src_snaps)-1]
  // Volume store should not contain chunk data, exclude from comparison
  res_without_data := proto.Clone(pair.Snap).(*pb.SubVolume)
  res_without_data.Data = nil
  util.EqualsOrFailTest(t, "bad snap [volume source]", res_without_data, last_snap_src)
}

func ValidateBackupInMetadata(
    t *testing.T, mocks *Mocks, expect_sv *pb.SubVolume, pair types.BackupPair) {
  if pair.Snap.Data == nil || len(pair.Snap.Data.Chunks) == 0 {
    t.Fatalf("Bad snap in pair, expect chunk data:\n%s", util.AsJson(pair.Snap))
  }
  head := mocks.Meta.Heads[expect_sv.Uuid]
  if head == nil {
    t.Fatalf("Bad head state:\n%s", util.AsJson(mocks.Meta))
  }
  cur_seq := mocks.Meta.Seqs[head.CurSeqUuid]
  if cur_seq == nil || len(cur_seq.SnapUuids) < 1 || cur_seq.Volume == nil {
    t.Fatalf("Bad snap seq state:\n%s", util.AsJson(mocks.Meta))
  }
  last_snap_meta,found := mocks.Meta.Snaps[cur_seq.SnapUuids[len(cur_seq.SnapUuids)-1]]
  if !found { t.Fatalf("Bad snap state:\n%s", util.AsJson(mocks.Meta)) }
  util.EqualsOrFailTest(t, "bad snap with meta", pair.Snap, last_snap_meta)
}

func ValidateMetadataAndStorageConsistency(
    t *testing.T, mocks *Mocks, expect_sv *pb.SubVolume) {
  head := mocks.Meta.Heads[expect_sv.Uuid]
  seq_uuids := head.PrevSeqUuid
  seq_uuids = append(seq_uuids, head.CurSeqUuid)
  for _,seq_uuid := range seq_uuids {
    seq,found := mocks.Meta.Seqs[seq_uuid]
    if !found { t.Fatalf("Bad sequence state:\n%s", util.AsJson(mocks.Meta)) }
    for _,snap_uuid := range seq.SnapUuids {
      snap, found := mocks.Meta.Snaps[snap_uuid]
      if !found { t.Fatalf("Bad snap state:\n%s", util.AsJson(mocks.Meta)) }
      if snap.ParentUuid != seq.Volume.Uuid || len(snap.Data.Chunks) < 1 {
        t.Fatalf("Bad snap:\n%s", util.AsJson(snap))
      }
      for _,chunk := range snap.Data.Chunks {
        _, found := mocks.Store.Chunks[chunk.Uuid]
        if !found { t.Fatalf("Bad store state:\n%s", util.AsJson(mocks.Store)) }
      }
    } // snaps in sequence
  }   // sequences in head
}

func ValidateBackupPairs(
    t *testing.T, mocks *Mocks, expect_svs []*pb.SubVolume, pairs []types.BackupPair) {
  vol_uuid_to_pair := make(map[string]types.BackupPair)
  for _,p := range pairs { vol_uuid_to_pair[p.Sv.Uuid] = p }

  for _,expect_sv := range expect_svs {
    pair, found := vol_uuid_to_pair[expect_sv.Uuid]
    if !found {
      t.Fatalf("expect_svs/pairs mismatch:\n%s\n%s", util.AsJson(expect_svs), util.AsJson(pairs))
    }
    ValidateBackupInVolumeSource(t, mocks, expect_sv, pair)
    ValidateBackupInMetadata(t, mocks, expect_sv, pair)
    ValidateMetadataAndStorageConsistency(t, mocks, expect_sv)
  }
}

func ValidateUnrelatedBackupSnap(
    t *testing.T, mocks *Mocks, expect_sv *pb.SubVolume, snap *pb.SubVolume, dst_uuid string) {
  if dst_uuid == expect_sv.Uuid { t.Fatalf("subvol uuid mismatch") }
  if dst_uuid != snap.ParentUuid { t.Fatalf("parent uuid mismatch") }

  // In the volume source, use the real IDs of the subvolumes
  real_pair := types.BackupPair{
    Sv: proto.Clone(expect_sv).(*pb.SubVolume),
    Snap: proto.Clone(snap).(*pb.SubVolume),
  }
  real_pair.Snap.ParentUuid = expect_sv.Uuid
  ValidateBackupInVolumeSource(t, mocks, expect_sv, real_pair)

  // In metadata, use the fake IDs corresponding to the unrelated subvolume
  fake_pair := types.BackupPair{
    Sv: proto.Clone(expect_sv).(*pb.SubVolume),
    Snap: proto.Clone(snap).(*pb.SubVolume),
  }
  fake_pair.Sv.Uuid = dst_uuid
  ValidateBackupInMetadata(t, mocks, fake_pair.Sv, fake_pair)
  ValidateMetadataAndStorageConsistency(t, mocks, fake_pair.Sv)
}

func ValidateObjectCounts(
    t *testing.T, mocks *Mocks, expect MockCountState) {
  util.EqualsOrFailTest(t, "bad obj count [volume source]",
                        mocks.Source.ObjCounts(), expect.Source)
  util.EqualsOrFailTest(t, "bad obj count [metadata]",
                        mocks.Meta.ObjCounts(), expect.Meta)
  util.EqualsOrFailTest(t, "bad obj count [storage]",
                        mocks.Store.ObjCounts(), expect.Store)
}

func HelperBackupAllToCurrentSequences_NoMetaNoSource(t *testing.T, vol_count int, new_seq bool) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  mgr, mocks := buildBackupManagerEmpty(vol_count)
  expect_svs := []*pb.SubVolume{}
  for i:=0; i<vol_count; i+=1 {
    expect_svs = append(expect_svs, mocks.AddSubVolumeInSrc(mocks.ConfSrc.Paths[i], uuid.NewString()))
  }
  new_state := mocks.CountState().IncMeta(vol_count, vol_count, vol_count, vol_count).
                                  IncStore(vol_count, 0).
                                  IncSource(0, vol_count, vol_count, 0)
  var pairs []types.BackupPair
  var err error
  if new_seq {
    pairs, err = mgr.BackupAllToNewSequences(ctx, mocks.Source.AllVols())
  }
  /*else*/ if !new_seq {
    pairs, err = mgr.BackupAllToCurrentSequences(ctx, mocks.Source.AllVols())
  }
  if err != nil { util.Fatalf("BackupAllToCurrentSequences: %v", err) }

  ValidateBackupPairs(t, mocks, expect_svs, pairs)
  ValidateObjectCounts(t, mocks, new_state)
  for _,args := range mocks.Source.GetSnapshotStreamCalls {
    if len(args[0]) != 0 { t.Errorf("GetSnapshotStream bad args: %v", args) }
  }

  // Idempotency
  _, err = mgr.BackupAllToCurrentSequences(ctx, mocks.Source.AllVols())
  if err != nil { util.Fatalf("BackupAllToCurrentSequences: %v", err) }
  ValidateObjectCounts(t, mocks, new_state.IncMeta(0,0,0,vol_count))
}

func TestBackupAllToCurrentSequences_NoMetaNoSource_SingleVol(t *testing.T) {
  const vol_count = 1
  HelperBackupAllToCurrentSequences_NoMetaNoSource(t, vol_count, /*new_seq=*/false)
}

func TestBackupAllToCurrentSequences_NoMetaNoSource_MultiVol(t *testing.T) {
  const vol_count = 3
  HelperBackupAllToCurrentSequences_NoMetaNoSource(t, vol_count, /*new_seq=*/false)
}

func TestBackupAllToCurrentSequences_SeqInMetaButNoSnapInSrc(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  meta, store := mocks.DummyMetaAndStorage(1,1,1,1)
  mgr, mocks := buildBackupManager(meta, store, mocks.NewVolumeManager())
  mocks.Source.ClearSnaps()
  _, err := mgr.BackupAllToCurrentSequences(ctx, mocks.Source.AllVols())
  if !errors.Is(err, ErrSnapsMismatchWithSrc) { util.Fatalf("BackupAllToCurrentSequences: %v", err) }
}

func HelperBackupAllToCurrentSequences_NewSeq_OldSnaps(t *testing.T, vol_count int) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  meta, store := mocks.DummyMetaAndStorage(vol_count,1,1,1)
  mgr, mocks := buildBackupManager(meta, store, mocks.NewVolumeManager())
  expect_svs := mocks.Source.AllVols()
  mocks.Meta.Clear()
  mocks.Store.Clear()
  expect_state := mocks.CountState().IncMeta(vol_count, vol_count, vol_count, vol_count).
                                     IncSource(0, 0, vol_count, 0).
                                     IncStore(vol_count, 0)
  pairs, err := mgr.BackupAllToCurrentSequences(ctx, mocks.Source.AllVols())
  if err != nil { util.Fatalf("BackupAllToCurrentSequences: %v", err) }

  ValidateBackupPairs(t, mocks, expect_svs, pairs)
  ValidateObjectCounts(t, mocks, expect_state)
}

func TestBackupAllToCurrentSequences_NewSeq_OldSnaps_SingleVol(t *testing.T) {
  const vol_count = 1
  HelperBackupAllToCurrentSequences_NewSeq_OldSnaps(t, vol_count)
}

func TestBackupAllToCurrentSequences_NewSeq_OldSnaps_MultiVol(t *testing.T) {
  const vol_count = 3
  HelperBackupAllToCurrentSequences_NewSeq_OldSnaps(t, vol_count)
}

func TestBackupAllToCurrentSequences_HeadButNoSeq(t *testing.T) {
  const vol_count = 1
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  meta, store := mocks.DummyMetaAndStorage(vol_count,1,1,1)
  mgr, mocks := buildBackupManager(meta, store, mocks.NewVolumeManager())
  mocks.Meta.Seqs = make(map[string]*pb.SnapshotSequence)
  _, err := mgr.BackupAllToCurrentSequences(ctx, mocks.Source.AllVols())
  if !errors.Is(err, types.ErrNotFound) { util.Fatalf("BackupAllToCurrentSequences: %v", err) }
}

func TestBackupAllToCurrentSequences_PrevSnapsAndMeta(t *testing.T) {
  const vol_count = 3
  const seq_len = 3
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  meta, store := mocks.DummyMetaAndStorage(vol_count,1,seq_len,1)
  mgr, mocks := buildBackupManager(meta, store, mocks.NewVolumeManager())
  expect_svs := mocks.Source.AllVols()
  new_state := mocks.CountState().IncMeta(0, 0, vol_count, vol_count).
                                  IncSource(0, 0, vol_count, 0).
                                  IncStore(vol_count, 0)
  pairs, err := mgr.BackupAllToCurrentSequences(ctx, mocks.Source.AllVols())
  if err != nil { util.Fatalf("BackupAllToCurrentSequences: %v", err) }

  ValidateBackupPairs(t, mocks, expect_svs, pairs)
  ValidateObjectCounts(t, mocks, new_state)
  expect_args := make(map[[2]string]bool)
  for _,seq := range mocks.Source.Snaps {
    if len(seq) != seq_len + 1 { t.Fatalf("Bad number of snaps per seq: %d", len(seq)) }
    expect_args[[2]string{ seq[seq_len-1].Uuid, seq[seq_len].Uuid, }] = true
  }
  for _,args := range mocks.Source.GetSnapshotStreamCalls {
    if !expect_args[args] {
      t.Errorf("GetSnapshotStream bad args: %v", args)
    }
  }

  // Idempotency
  _, err = mgr.BackupAllToCurrentSequences(ctx, mocks.Source.AllVols())
  if err != nil { util.Fatalf("BackupAllToCurrentSequences: %v", err) }
  ValidateObjectCounts(t, mocks, new_state.IncMeta(0,0,0,vol_count))
}

func TestBackupAllToCurrentSequences_ReuseRecentSnap(t *testing.T) {
  const vol_count = 3
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  meta, store := mocks.DummyMetaAndStorage(vol_count,1,1,1)
  mgr, mocks := buildBackupManager(meta, store, mocks.NewVolumeManager())
  expect_svs := mocks.Source.AllVols()
  for _,sv := range expect_svs {
    mocks.AddSnapshotInSrc(sv, uuid.NewString(), /*recent=*/true)
  }
  new_state := mocks.CountState().IncMeta(0, 0, vol_count, vol_count).
                                  IncSource(0, 0, 0, 0).
                                  IncStore(vol_count, 0)
  pairs, err := mgr.BackupAllToCurrentSequences(ctx, mocks.Source.AllVols())
  if err != nil { util.Fatalf("BackupAllToCurrentSequences: %v", err) }

  ValidateBackupPairs(t, mocks, expect_svs, pairs)
  ValidateObjectCounts(t, mocks, new_state)
}

func TestBackupAllToCurrentSequences_NoReuseRecentSnap(t *testing.T) {
  const vol_count = 3
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  meta, store := mocks.DummyMetaAndStorage(vol_count,1,1,1)
  mgr, mocks := buildBackupManager(meta, store, mocks.NewVolumeManager())
  expect_svs := mocks.Source.AllVols()
  for _,sv := range expect_svs {
    mocks.AddSnapshotInSrc(sv, uuid.NewString(), /*recent=*/true)
  }
  new_state := mocks.CountState().IncMeta(0, 0, vol_count, vol_count).
                                  IncSource(0, 0, vol_count, 0).
                                  IncStore(vol_count, 0)
  pairs, err := mgr.BackupAllToCurrentSequences_NoReUse(
                  ctx, mocks.Source.AllVols())
  if err != nil { util.Fatalf("BackupAllToCurrentSequences: %v", err) }

  ValidateBackupPairs(t, mocks, expect_svs, pairs)
  ValidateObjectCounts(t, mocks, new_state)
}

func TestBackupAllToNewSequences_NoMetaNoSource(t *testing.T) {
  const vol_count = 3
  HelperBackupAllToCurrentSequences_NoMetaNoSource(t, vol_count, /*new_seq=*/true)
}

func TestBackupAllToNewSequences_PrevSnapsAndMeta(t *testing.T) {
  const vol_count = 3
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  meta, store := mocks.DummyMetaAndStorage(vol_count,1,1,1)
  mgr, mocks := buildBackupManager(meta, store, mocks.NewVolumeManager())
  expect_svs := mocks.Source.AllVols()
  new_state := mocks.CountState().IncMeta(0, vol_count, vol_count, vol_count).
                                  IncSource(0, 0, vol_count, 0).
                                  IncStore(vol_count, 0)
  pairs, err := mgr.BackupAllToNewSequences(ctx, mocks.Source.AllVols())
  if err != nil { util.Fatalf("BackupAllToNewSequences: %v", err) }

  ValidateBackupPairs(t, mocks, expect_svs, pairs)
  ValidateObjectCounts(t, mocks, new_state)

  // NON Idempotency (but re-use recent snaps in source)
  _, err = mgr.BackupAllToNewSequences(ctx, mocks.Source.AllVols())
  if err != nil { util.Fatalf("BackupAllToNewSequences: %v", err) }
  new_state = new_state.IncMeta(0, vol_count, 0, vol_count)
  ValidateObjectCounts(t, mocks, new_state)

  // Never do incremental backups
  // Note that the same recent snapshot will be linked to several sequences.
  if len(mocks.Source.GetSnapshotStreamCalls) != vol_count {
    t.Errorf("Bad number of GetSnapshotStream calls: %d",
             len(mocks.Source.GetSnapshotStreamCalls))
  }
  for _,args := range mocks.Source.GetSnapshotStreamCalls {
    if len(args[0]) != 0 { t.Errorf("GetSnapshotStream bad args: %v", args) }
  }
  t.Logf("meta.Seqs:\n%s", util.AsJson(mocks.Meta.Seqs))
}

func TestBackupToCurrentSequenceUnrelatedVol_NoSeqInMetaFail(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  meta, store := mocks.DummyMetaAndStorage(1,1,1,1)
  mgr, mocks := buildBackupManager(meta, store, mocks.NewVolumeManager())
  prev_uuid := mocks.Meta.HeadKeys()[0]
  sv := mocks.AddSubVolumeInSrc(mocks.ConfSrc.Paths[0], uuid.NewString())
  mocks.Meta.Seqs = make(map[string]*pb.SnapshotSequence)
  _, err := mgr.BackupToCurrentSequenceUnrelatedVol(ctx, sv, prev_uuid)
  if !errors.Is(err, types.ErrNotFound) {
    util.Fatalf("BackupToCurrentSequenceUnrelatedVol: %v", err)
  }
}

func TestBackupToCurrentSequenceUnrelatedVol_NoParInSrcFail(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  meta, store := mocks.DummyMetaAndStorage(1,1,1,1)
  mgr, mocks := buildBackupManager(meta, store, mocks.NewVolumeManager())
  prev_uuid := mocks.Meta.HeadKeys()[0]
  sv := mocks.AddSubVolumeInSrc(mocks.ConfSrc.Paths[0], uuid.NewString())
  _, err := mgr.BackupToCurrentSequenceUnrelatedVol(ctx, sv, prev_uuid)
  if !errors.Is(err, ErrCannotFindParForClone) {
    util.Fatalf("BackupToCurrentSequenceUnrelatedVol: %v", err)
  }
}

func TestBackupToCurrentSequenceUnrelatedVol_CloneChildInSrc(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  meta, store := mocks.DummyMetaAndStorage(1,1,1,1)
  mgr, mocks := buildBackupManager(meta, store, mocks.NewVolumeManager())
  prev_uuid := mocks.Meta.HeadKeys()[0]
  sv := mocks.AddSubVolumeInSrc(mocks.ConfSrc.Paths[0], uuid.NewString())
  mocks.AddSnapshotInSrc(sv, uuid.NewString(), /*recent=*/true)
  snap, err := mgr.BackupToCurrentSequenceUnrelatedVol(ctx, sv, prev_uuid)
  if err != nil { util.Fatalf("BackupToCurrentSequenceUnrelatedVol: %v", err) }
  util.EqualsOrFailTest(t, "bad par_uuid", snap.ParentUuid, prev_uuid)
  util.EqualsOrFailTest(t, "bad rec_uuid", snap.ReceivedUuid, "")
  ValidateUnrelatedBackupSnap(t, mocks, sv, snap, prev_uuid)
}

func TestBackupToCurrentSequenceUnrelatedVol_Normal(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  meta, store := mocks.DummyMetaAndStorage(1,1,1,1)
  mgr, mocks := buildBackupManager(meta, store, mocks.NewVolumeManager())
  uuid_for_backup := mocks.Meta.HeadKeys()[0]

  last_rec_snap := mocks.AddReceivedSnapFromMostRecentMetaSnap(uuid_for_backup)
  sv := mocks.AddSubVolumeInSrc(mocks.ConfSrc.Paths[0], uuid.NewString())
  sv.ParentUuid = last_rec_snap.Uuid
  new_state := mocks.CountState().IncMeta(0, 0, 1, 1).
                                  IncSource(0, 1, 1, 0).
                                  IncStore(1, 0)

  clone_snap1, err := mgr.BackupToCurrentSequenceUnrelatedVol(ctx, sv, uuid_for_backup)
  if err != nil { util.Fatalf("BackupToCurrentSequenceUnrelatedVol: %v", err) }

  ValidateUnrelatedBackupSnap(t, mocks, sv, clone_snap1, uuid_for_backup)
  ValidateObjectCounts(t, mocks, new_state)
  if len(mocks.Source.GetSnapshotStreamCalls) != 1 {
    t.Errorf("Bad number of GetSnapshotStream calls: %d",
             len(mocks.Source.GetSnapshotStreamCalls))
  }
  args := mocks.Source.GetSnapshotStreamCalls[0]
  expect_args := [2]string{ last_rec_snap.Uuid, clone_snap1.Uuid, }
  util.EqualsOrFailTest(t, "bad GetSnapshotStream0 args", args, expect_args)

  // You can re-use last clone for appending more snapshots.
  new_state = mocks.CountState().IncMeta(0, 0, 1, 1).
                                 IncSource(0, 0, 1, 0).
                                 IncStore(1, 0)
  clone_snap2, err := mgr.BackupToCurrentSequenceUnrelatedVol(ctx, sv, uuid_for_backup)
  args = mocks.Source.GetSnapshotStreamCalls[1]
  expect_args = [2]string{ clone_snap1.Uuid, clone_snap2.Uuid, }
  util.EqualsOrFailTest(t, "bad GetSnapshotStream1 args", args, expect_args)
  ValidateObjectCounts(t, mocks, new_state)
}

