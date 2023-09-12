package mocks

import (
  "context"
  "fmt"
  "io"
  fpmod "path/filepath"
  "os"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"

  "github.com/google/uuid"
  "google.golang.org/protobuf/proto"
)

type BtrfsPathJuggler struct {
  Err error
  PathToFs map[string]*types.Filesystem
  PathToMnt map[string]*types.MountEntry
  UuidToFs map[string]*types.Filesystem
  UuidToMnt map[string]*types.MountEntry
  CheckResult []*types.Filesystem
}

func (self *BtrfsPathJuggler) FindFsAndTighterMountOwningPath(
    path string) (*types.Filesystem, *types.MountEntry, uint64, error) {
  fs, found := self.PathToFs[path]
  if !found { return nil, nil, 0, fmt.Errorf("FindFsAndTighterMountOwningPath not found") }
  mnt, found := self.PathToMnt[path]
  if !found { return nil, nil, 0, fmt.Errorf("FindFsAndTighterMountOwningPath not found") }
  return fs, mnt, mnt.BtrfsVolId, self.Err
}
func (self *BtrfsPathJuggler) FindTighterMountForSubVolume(
    fs_list []*types.Filesystem, sv *pb.SubVolume) (*types.Filesystem, *types.MountEntry, string, error) {
  mnt, found := self.UuidToMnt[sv.Uuid]
  if !found { return nil, nil, "", fmt.Errorf("FindTighterMountForSubVolume mnt not found") }
  fs, found := self.UuidToFs[sv.Uuid]
  if !found { return nil, nil, "", fmt.Errorf("FindTighterMountForSubVolume fs not found") }
  path := mnt.MountedPath
  if mnt.BtrfsVolId != sv.VolId { path = fpmod.Join(mnt.MountedPath, sv.TreePath) }
  return fs, mnt, path, self.Err
}
func (self *BtrfsPathJuggler) CheckSourcesAndReturnCorrespondingFs(
    sources []*pb.Source) ([]*types.Filesystem, error) {
  return self.CheckResult, self.Err
}
func (self *BtrfsPathJuggler) LoadFilesystem(fs *types.Filesystem) {
  if fs == nil { util.Fatalf("fs == nil") }
  if self.PathToFs == nil { self.PathToFs = make(map[string]*types.Filesystem) }
  if self.PathToMnt == nil { self.PathToMnt = make(map[string]*types.MountEntry) }
  for _,mnt := range fs.Mounts {
    self.PathToFs[mnt.MountedPath] = fs
    self.PathToMnt[mnt.MountedPath] = mnt
  }
  self.CheckResult = append(self.CheckResult, fs)
}

func (self *BtrfsPathJuggler) LoadSubVolume(
    fs *types.Filesystem, mnt *types.MountEntry, sv_list ...*pb.SubVolume) {
  if self.UuidToFs == nil { self.UuidToFs = make(map[string]*types.Filesystem) }
  if self.UuidToMnt == nil { self.UuidToMnt = make(map[string]*types.MountEntry) }
  for _,sv := range sv_list {
    if sv == nil || mnt == nil { util.Fatalf("sv == nil || mnt == nil") }
    self.UuidToFs[sv.Uuid] = fs
    self.UuidToMnt[sv.Uuid] = mnt
  }
}

type VolumeManager struct {
  SnapRoot  string
  Err       error
  Vols      map[string]*pb.SubVolume
  Snaps     map[string][]*pb.SubVolume
  Received  []*pb.SubVolume
  Changes   map[[2]string]*pb.SnapshotChanges
  GetSnapshotStreamCalls [][2]string
}

type VolMgrCounts struct {
  Vols, Seqs, Received, AllSnaps int
}

func NewVolumeManager() *VolumeManager {
  return &VolumeManager{
    SnapRoot: fpmod.Join(os.TempDir(), "snap_root"),
    Err: nil,
    Vols: make(map[string]*pb.SubVolume),
    Snaps: make(map[string][]*pb.SubVolume),
    Received: nil,
    Changes: make(map[[2]string]*pb.SnapshotChanges),
    GetSnapshotStreamCalls: [][2]string{},
  }
}

func CloneSnaps(snaps []*pb.SubVolume) []*pb.SubVolume {
  clone_snaps := []*pb.SubVolume{}
  for _,snap := range snaps {
    clone := proto.Clone(snap).(*pb.SubVolume)
    clone_snaps = append(clone_snaps, clone)
  }
  return clone_snaps
}

func (self *VolumeManager) ObjCounts() VolMgrCounts {
  all_snaps := len(self.Received)
  for _,seq := range self.Snaps { all_snaps += len(seq) }
  return VolMgrCounts{ Vols:len(self.Vols),
                       Seqs:len(self.Snaps),
                       Received:len(self.Received),
                       AllSnaps:all_snaps, }
}

func (self VolMgrCounts) IncReceived(count int) VolMgrCounts {
  self.Received += count
  self.AllSnaps += count
  return self
}

func (self VolMgrCounts) Increment(
    cnt_vol int, cnt_seq int, cnt_snap int, cnt_rec int) VolMgrCounts {
  self.Vols += cnt_vol
  self.Seqs += cnt_seq
  self.Received += cnt_rec
  self.AllSnaps += cnt_snap + cnt_rec
  return self
}

func (self *VolumeManager) ClearSnaps() {
  self.Snaps = make(map[string][]*pb.SubVolume)
  self.Received = nil
}

func (self *VolumeManager) AllVols() []*pb.SubVolume {
  all := []*pb.SubVolume{}
  for _,sv := range self.Vols { all = append(all, proto.Clone(sv).(*pb.SubVolume)) }
  return all
}

func (self *VolumeManager) CreateReceivedFrom(snap *pb.SubVolume, mnt_path string) *pb.SubVolume {
  rec_snap := util.DummySnapshot(uuid.NewString(), "")
  rec_snap.ReceivedUuid = snap.Uuid
  rec_snap.Data = nil
  rec_snap.MountedPath = mnt_path
  if len(self.Received) > 0 {
    rec_snap.ParentUuid = self.Received[len(self.Received)-1].Uuid
  }

  self.Received = append(self.Received, rec_snap)
  clone := proto.Clone(rec_snap).(*pb.SubVolume)
  return clone
}

func (self *VolumeManager) CreateReceivedFromSnap(snap_uuid string) (*pb.SubVolume, error) {
  snap, err := self.FindVolume("", types.ByUuid(snap_uuid))
  if snap == nil || err != nil { return nil, fmt.Errorf("No snap for '%s': %v", snap_uuid, err) }
  return self.CreateReceivedFrom(snap, ""), nil
}

func (self *VolumeManager) GetVolume(path string) (*pb.SubVolume, error) {
  sv, found := self.Vols[path]
  if !found { return nil, fmt.Errorf("No sv for '%s'", path) }
  return sv, self.Err
}
func (self *VolumeManager) ListVolumes(fs_path string) ([]*pb.SubVolume, error) {
  var vols []*pb.SubVolume
  for _,sv := range self.Vols {
    vols = append(vols, proto.Clone(sv).(*pb.SubVolume))
  }
  for _,seq := range self.Snaps {
    for _,snap := range seq { vols = append(vols, proto.Clone(snap).(*pb.SubVolume)) }
  }
  for _,snap := range self.Received { vols = append(vols, proto.Clone(snap).(*pb.SubVolume)) }
  return vols, self.Err
}
func (self *VolumeManager) FindVolume(
    fs_path string, matcher func(*pb.SubVolume) bool) (*pb.SubVolume, error) {
  vols, err := self.ListVolumes(fs_path)
  if err != nil { return nil, err }
  for _,sv := range vols {
    clone := proto.Clone(sv).(*pb.SubVolume)
    if matcher(sv) { return clone, self.Err }
  }
  return nil, self.Err
}
func (self *VolumeManager) GetSnapshotSeqForVolume(subvol *pb.SubVolume) ([]*pb.SubVolume, error) {
  for vol_uuid,snaps := range self.Snaps {
    if vol_uuid != subvol.Uuid { continue }
    return CloneSnaps(snaps), self.Err
  }
  return nil, self.Err
}
func (self *VolumeManager) GetChangesBetweenSnaps(
    ctx context.Context, from *pb.SubVolume, to *pb.SubVolume) (*pb.SnapshotChanges, error) {
  key := [2]string{ from.Uuid, to.Uuid }
  for k,changes := range self.Changes {
    if k != key { continue }
    clone := proto.Clone(changes).(*pb.SnapshotChanges)
    return clone, self.Err
  }
  return nil, fmt.Errorf("No changes for %v", key)
}
func (self *VolumeManager) CreateSnapshot(subvol *pb.SubVolume) (*pb.SubVolume, error) {
  snap := util.DummySnapshot(uuid.NewString(), subvol.Uuid)
  snap.MountedPath = fpmod.Join(self.SnapRoot, snap.Uuid)
  snap.CreatedTs = uint64(time.Now().Unix())
  snap.Data = nil
  snaps := self.Snaps[subvol.Uuid]
  snaps = append(snaps, snap)
  self.Snaps[subvol.Uuid] = snaps
  clone := proto.Clone(snap).(*pb.SubVolume)
  return clone, self.Err
}
func (self *VolumeManager) CreateSnapshotLongName(subvol *pb.SubVolume) (*pb.SubVolume, error) {
  return self.CreateSnapshot(subvol)
}
func (self *VolumeManager) GetSnapshotStream(
    ctx context.Context, from *pb.SubVolume, to *pb.SubVolume) (types.ReadEndIf, error) {
  found_to, err := self.FindVolume("", types.ByUuid(to.Uuid))
  if err != nil || found_to == nil {
    return nil, fmt.Errorf("`to` snap not found in source: %v, %v", found_to, err)
  }
  if from == nil {
    self.GetSnapshotStreamCalls = append(self.GetSnapshotStreamCalls, [2]string{ "", to.Uuid, })
  }
  /*else*/ if from != nil {
    found_from, err := self.FindVolume("", types.ByUuid(from.Uuid))
    if err != nil || found_from == nil {
      return nil, fmt.Errorf("`from` snap not found in source: %v, %v", found_from, err)
    }
    if from.ParentUuid != to.ParentUuid {
      return nil, fmt.Errorf("uuid: '%s' != '%s'", from.ParentUuid, to.ParentUuid)
    }
    self.GetSnapshotStreamCalls = append(self.GetSnapshotStreamCalls, [2]string{ from.Uuid, to.Uuid, })
  }
  pipe := NewPreloadedPipe(util.GenerateRandomTextData(32))
  return pipe.ReadEnd(), self.Err
}
func (self *VolumeManager) ReceiveSendStream(
    ctx context.Context, root_path string, src_snap *pb.SubVolume, read_pipe types.ReadEndIf) (*pb.SubVolume, error) {
  done := make(chan error)
  go func() {
    defer close(done)
    defer read_pipe.Close()
    _, err := io.Copy(io.Discard, read_pipe)
    done <- err
  }()
  util.WaitForNoErrorOrDie(ctx, done)
  snap := util.DummySnapshot(uuid.NewString(), "")
  snap.ReceivedUuid = src_snap.Uuid

  self.Received = append(self.Received, snap)
  clone := proto.Clone(snap).(*pb.SubVolume)
  return clone, util.Coalesce(read_pipe.GetErr(), self.Err)
}
func (self *VolumeManager) DeleteSnapshot(snap *pb.SubVolume) error {
  if _,found := self.Snaps[snap.ParentUuid]; found {
    delete(self.Snaps, snap.Uuid)
    return self.Err
  }
  var new_rec []*pb.SubVolume
  for _,s := range self.Received {
    if s.Uuid == snap.Uuid { continue }
    new_rec = append(new_rec, s)
  }
  if len(new_rec) < len(self.Received) {
    self.Received = new_rec
    return self.Err
  }
  return fmt.Errorf("delete unexisting snap: %s", util.AsJson(snap))
}
func (self *VolumeManager) TrimOldSnapshots(
    src_subvol *pb.SubVolume, dry_run bool) ([]*pb.SubVolume, error) {
  if _,found := self.Snaps[src_subvol.Uuid]; !found {
    return nil, self.Err
  }
  self.Snaps[src_subvol.Uuid] = []*pb.SubVolume{}
  return nil, self.Err
}

