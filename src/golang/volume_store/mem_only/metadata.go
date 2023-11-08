package mem_only

import (
  "context"
  "fmt"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
  store "btrfs_to_glacier/volume_store"

  "google.golang.org/protobuf/proto"
)

type Metadata struct {
  Conf       *pb.Config
  innerState *pb.AllMetadata
}

func NewMetadataAdmin(conf *pb.Config) (types.AdminMetadata, error) {
  return &Metadata{
    Conf: conf,
    innerState: &pb.AllMetadata{},
  }, nil
}

func NewMetadata(conf *pb.Config) (types.Metadata, error) {
  return NewMetadataAdmin(conf)
}

func NewInMemMetadata(conf *pb.Config) (*Metadata, error) {
  meta, err := NewMetadataAdmin(conf)
  return meta.(*Metadata), err
}

func (self *Metadata) InMemState() *pb.AllMetadata { return self.innerState }
func (self *Metadata) SetInMemState(new_state *pb.AllMetadata) { self.innerState = new_state }

func (self *Metadata) FindHead(uuid string) (int,*pb.SnapshotSeqHead) {
  if self.innerState == nil { util.Fatalf("state not loaded") }
  for idx,head := range self.innerState.Heads {
    if head.Uuid == uuid { return idx,head }
  }
  return 0, nil
}
func (self *Metadata) FindOrAppendHead(uuid string) *pb.SnapshotSeqHead {
  if _,head := self.FindHead(uuid); head != nil { return head }
  head := &pb.SnapshotSeqHead{ Uuid: uuid, }
  self.innerState.Heads = append(self.innerState.Heads, head)
  return head
}

func (self *Metadata) FindSeq(uuid string) *pb.SnapshotSequence {
  if self.innerState == nil { util.Fatalf("state not loaded") }
  for _,meta_seq := range self.innerState.Sequences {
    if meta_seq.Uuid == uuid { return meta_seq }
  }
  return nil
}
func (self *Metadata) FindOrCloneSeq(seq *pb.SnapshotSequence) *pb.SnapshotSequence {
  if meta_seq := self.FindSeq(seq.Uuid); meta_seq != nil { return meta_seq }
  meta_seq := proto.Clone(seq).(*pb.SnapshotSequence)
  self.innerState.Sequences = append(self.innerState.Sequences, meta_seq)
  return meta_seq
}

func (self *Metadata) FindSnap(uuid string) *pb.SubVolume {
  if self.innerState == nil { util.Fatalf("state not loaded") }
  for _,meta_snap := range self.innerState.Snapshots {
    if meta_snap.Uuid == uuid { return meta_snap }
  }
  return nil
}

func (self *Metadata) RecordSnapshotSeqHead(
    ctx context.Context, new_seq *pb.SnapshotSequence) (*pb.SnapshotSeqHead, error) {
  err := store.ValidateSnapshotSequence(new_seq)
  if err != nil { return nil, err }

  uuid := new_seq.Volume.Uuid
  head := self.FindOrAppendHead(uuid)

  if head.CurSeqUuid == new_seq.Uuid {
    util.PbInfof("Noop already current seq in head: %v", head)
    return proto.Clone(head).(*pb.SnapshotSeqHead), nil
  }

  if len(head.CurSeqUuid) > 0 { head.PrevSeqUuid = append(head.PrevSeqUuid, head.CurSeqUuid) }
  head.CurSeqUuid = new_seq.Uuid

  err = store.ValidateSnapshotSeqHead(head)
  if err != nil { return nil, err }

  util.PbInfof("Wrote head: %v", head)
  return proto.Clone(head).(*pb.SnapshotSeqHead), nil
}

func (self *Metadata) AppendSnapshotToSeq(
    ctx context.Context, seq *pb.SnapshotSequence, snap *pb.SubVolume) (*pb.SnapshotSequence, error) {
  err := store.ValidateSubVolume(store.CheckSnapNoContent, snap)
  if err != nil { return nil, err }

  new_seq := self.FindOrCloneSeq(seq)
  if len(seq.SnapUuids) > 0 {
    last := seq.SnapUuids[len(seq.SnapUuids) - 1]
    if last == snap.Uuid {
      util.PbInfof("Noop already last snap in seq: %v", seq)
      return proto.Clone(new_seq).(*pb.SnapshotSequence), nil
    }
  }

  new_seq.SnapUuids = append(new_seq.SnapUuids, snap.Uuid)

  err = store.ValidateSnapshotSequence(new_seq)
  if err != nil { return nil, err }
  if new_seq.Volume.Uuid != snap.ParentUuid {
    return nil, util.PbErrorf("Sequence volume and snap parent do not match: %v, %v", new_seq, snap)
  }
  if new_seq.Volume.CreatedTs > snap.CreatedTs {
    return nil, util.PbErrorf("Sequence volume created after snap: %v, %v", new_seq, snap)
  }

  util.PbInfof("Wrote sequence: %v", new_seq)
  return proto.Clone(new_seq).(*pb.SnapshotSequence), nil
}

func (self *Metadata) AppendChunkToSnapshot(
    ctx context.Context, snap *pb.SubVolume, data *pb.SnapshotChunks) (*pb.SubVolume, error) {
  err := store.ValidateSnapshotChunks(store.CheckChunkNotFirst, data)
  if err != nil { return nil, err }

  new_snap := self.FindOrCloneSnap(snap)
  if new_snap.Data != nil && new_snap.Data.KeyFingerprint != data.KeyFingerprint {
    return nil, util.PbErrorf("Snapshot chunk key mismatch: %v, %v", new_snap, data)
  }
  if store.IsFullyContainedInSubvolume(new_snap, data) {
    util.PbInfof("Noop already last chunk in snap: %v", new_snap)
    return proto.Clone(new_snap).(*pb.SubVolume), nil
  }

  data_len := store.SubVolumeDataLen(snap)
  if data.Chunks[0].Start != data_len {
    return nil, util.PbErrorf("Snapshot chunk not contiguous: %v, %v", snap, data)
  }

  if new_snap.Data == nil {
    new_snap.Data = &pb.SnapshotChunks { KeyFingerprint: data.KeyFingerprint }
  }
  new_snap.Data.Chunks = append(new_snap.Data.Chunks, data.Chunks...)

  err = store.ValidateSubVolume(store.CheckSnapWithContent, new_snap)
  if err != nil { return nil, err }

  util.PbInfof("Wrote snapshot: %v", new_snap)
  return proto.Clone(new_snap).(*pb.SubVolume), nil
}

func (self *Metadata) ReadSnapshotSeqHead(
    ctx context.Context, uuid string) (*pb.SnapshotSeqHead, error) {
  if len(uuid) < 1 { return nil, fmt.Errorf("ReadSnapshotSeqHead: uuid is nil") }

  _,head := self.FindHead(uuid)
  if head == nil { return nil, types.ErrNotFound }

  err := store.ValidateSnapshotSeqHead(head)
  if err != nil { return nil, err }

  //util.PbInfof("Read head: %v", head)
  return proto.Clone(head).(*pb.SnapshotSeqHead), nil
}

func (self *Metadata) ReadSnapshotSeq(
    ctx context.Context, uuid string) (*pb.SnapshotSequence, error) {
  if len(uuid) < 1 { return nil, fmt.Errorf("ReadSnapshotSeq: uuid is nil") }

  seq := self.FindSeq(uuid)
  if seq == nil { return nil, types.ErrNotFound }

  err := store.ValidateSnapshotSequence(seq)
  if err != nil { return nil, err }

  //util.PbInfof("Read sequence: %v", seq)
  return proto.Clone(seq).(*pb.SnapshotSequence), nil
}

func (self *Metadata) ReadSnapshot(
    ctx context.Context, uuid string) (*pb.SubVolume, error) {
  if len(uuid) < 1 { return nil, fmt.Errorf("ReadSnapshot: uuid is nil") }

  snap := self.FindSnap(uuid)
  if snap == nil { return nil, types.ErrNotFound }

  err := store.ValidateSubVolume(store.CheckSnapWithContent, snap)
  if err != nil { return nil, err }

  //util.PbInfof("Read subvolume: %v", snap)
  return proto.Clone(snap).(*pb.SubVolume), nil
}

type SnapshotSeqHeadIterator struct { List []*pb.SnapshotSeqHead; Idx int }
func (self *SnapshotSeqHeadIterator) Next(ctx context.Context, o *pb.SnapshotSeqHead) bool {
  if self.Idx < len(self.List) {
    *o = *self.List[self.Idx]
    self.Idx += 1
    return true
  }
  return false
}
func (self *SnapshotSeqHeadIterator) Err() error { return nil }

type SnapshotSequenceIterator struct { List []*pb.SnapshotSequence; Idx int }
func (self *SnapshotSequenceIterator) Next(ctx context.Context, o *pb.SnapshotSequence) bool {
  if self.Idx < len(self.List) {
    *o = *self.List[self.Idx]
    self.Idx += 1
    return true
  }
  return false
}
func (self *SnapshotSequenceIterator) Err() error { return nil }

type SnapshotIterator struct { List []*pb.SubVolume; Idx int }
func (self *SnapshotIterator) Next(ctx context.Context, o *pb.SubVolume) bool {
  if self.Idx < len(self.List) {
    *o = *self.List[self.Idx]
    self.Idx += 1
    return true
  }
  return false
}
func (self *SnapshotIterator) Err() error { return nil }

func (self *Metadata) ListAllSnapshotSeqHeads(
    ctx context.Context) (types.SnapshotSeqHeadIterator, error) {
  return &SnapshotSeqHeadIterator{ List: self.innerState.Heads, }, nil
}

func (self *Metadata) ListAllSnapshotSeqs(
    ctx context.Context) (types.SnapshotSequenceIterator, error) {
  return &SnapshotSequenceIterator{ List: self.innerState.Sequences, }, nil
}

func (self *Metadata) ListAllSnapshots(
    ctx context.Context) (types.SnapshotIterator, error) {
  return &SnapshotIterator{ List: self.innerState.Snapshots, }, nil
}

func (self *Metadata) FindOrCloneSnap(snap *pb.SubVolume) *pb.SubVolume {
  if meta_snap := self.FindSnap(snap.Uuid); meta_snap != nil { return meta_snap }
  meta_snap := proto.Clone(snap).(*pb.SubVolume)
  self.innerState.Snapshots = append(self.innerState.Snapshots, meta_snap)
  return meta_snap
}

func (self *Metadata) DeleteMetadataUuids(
    ctx context.Context, seq_uuids []string, snap_uuids []string) error {
  seq_set := make(map[string]bool)
  for _,uuid := range seq_uuids { seq_set[uuid] = true }
  snap_set := make(map[string]bool)
  for _,uuid := range snap_uuids { snap_set[uuid] = true }

  new_seqs := make([]*pb.SnapshotSequence, 0, len(self.innerState.Sequences))
  new_snaps := make([]*pb.SubVolume, 0, len(self.innerState.Snapshots))

  for _,seq := range self.innerState.Sequences {
    if seq_set[seq.Uuid] { continue }
    new_seqs = append(new_seqs, seq)
  }
  for _,snap := range self.innerState.Snapshots {
    if snap_set[snap.Uuid] { continue }
    new_snaps = append(new_snaps, snap)
  }

  self.innerState.Sequences = new_seqs
  self.innerState.Snapshots = new_snaps
  return nil
}

func (self *Metadata) ReplaceSnapshotSeqHead(
    ctx context.Context, head *pb.SnapshotSeqHead) (*pb.SnapshotSeqHead, error) {
  err := store.ValidateSnapshotSeqHead(head)
  if err != nil { return nil, err }

  idx, prev_head := self.FindHead(head.Uuid)
  if prev_head == nil { return nil, fmt.Errorf("%w uuid=%v", types.ErrNotFound, head.Uuid) }

  self.innerState.Heads[idx] = proto.Clone(head).(*pb.SnapshotSeqHead)
  return prev_head, nil
}

func (self *Metadata) PersistCurrentMetadataState(ctx context.Context) (string, error) {
  return "mem_only_metadata_does_not_persist", nil
}
func (self *Metadata) SetupMetadata(ctx context.Context) error {
  return nil //noop
}
func (self *Metadata) TearDownMetadata(ctx context.Context) error {
  return nil //noop
}

