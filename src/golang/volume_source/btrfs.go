package volume_source

import (
  "context"
  "fmt"
  fpmod "path/filepath"
  "sort"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/shim"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"

  "google.golang.org/protobuf/proto"
)

// Implementation must be thread safe.
type btrfsVolumeManager struct {
  btrfsutil     types.Btrfsutil
  juggler       types.BtrfsPathJuggler
  linuxutil     types.Linuxutil
  conf          *pb.Config
  k_sysinfo     *pb.SystemInfo
  lazy_src_fs_list []*types.Filesystem
}

func get_system_info(linuxutil types.Linuxutil) *pb.SystemInfo {
  kern_major, kern_minor := linuxutil.LinuxKernelVersion()
  btrfs_major, btrfs_minor := linuxutil.BtrfsProgsVersion()
  return &pb.SystemInfo{
    KernMajor: kern_major,
    KernMinor: kern_minor,
    BtrfsUsrMajor: btrfs_major,
    BtrfsUsrMinor: btrfs_minor,
    ToolGitCommit: linuxutil.ProjectVersion(),
  }
}

func newBtrfsVolumeManager(
    conf *pb.Config, btrfsutil types.Btrfsutil, linuxutil types.Linuxutil,
    juggler types.BtrfsPathJuggler) (*btrfsVolumeManager, error) {
  mgr := btrfsVolumeManager{
    btrfsutil: btrfsutil,
    juggler: juggler,
    linuxutil: linuxutil,
    conf: conf,
    k_sysinfo: get_system_info(linuxutil),
    lazy_src_fs_list: nil,
  }
  return &mgr, nil
}

func NewVolumeManager(
    conf *pb.Config, btrfsutil types.Btrfsutil, linuxutil types.Linuxutil,
    juggler types.BtrfsPathJuggler) (types.VolumeManager, error) {
  return newBtrfsVolumeManager(conf, btrfsutil, linuxutil, juggler)
}

func NewVolumeSource(
    conf *pb.Config, btrfsutil types.Btrfsutil, linuxutil types.Linuxutil,
    juggler types.BtrfsPathJuggler) (types.VolumeSource, error) {
  return newBtrfsVolumeManager(conf, btrfsutil, linuxutil, juggler)
}

func NewVolumeDestination(
    conf *pb.Config, btrfsutil types.Btrfsutil, linuxutil types.Linuxutil,
    juggler types.BtrfsPathJuggler) (types.VolumeDestination, error) {
  return newBtrfsVolumeManager(conf, btrfsutil, linuxutil, juggler)
}

func NewVolumeAdmin(
    conf *pb.Config, btrfsutil types.Btrfsutil, linuxutil types.Linuxutil,
    juggler types.BtrfsPathJuggler) (types.VolumeAdmin, error) {
  return newBtrfsVolumeManager(conf, btrfsutil, linuxutil, juggler)
}

// Defer finding errors with the filesystem after creation.
func (self *btrfsVolumeManager) LazySrcFsList() ([]*types.Filesystem, error) {
  if self.lazy_src_fs_list != nil { return self.lazy_src_fs_list, nil }
  fs_list, err := self.juggler.CheckSourcesAndReturnCorrespondingFs(self.conf.Sources)
  if err == nil { self.lazy_src_fs_list = fs_list }
  return self.lazy_src_fs_list, err
}

func (self *btrfsVolumeManager) TestOnlySwapSrcFsList(fs_list []*types.Filesystem) {
  self.lazy_src_fs_list = fs_list
}
func (self *btrfsVolumeManager) TestOnlySwapSysInfo(sysinfo *pb.SystemInfo) {
  self.k_sysinfo = sysinfo
}

func (self *btrfsVolumeManager) GetVolume(path string) (*pb.SubVolume, error) {
  drop_f := self.linuxutil.GetRootOrDie()
  defer drop_f()
  var subvol *pb.SubVolume
  var err error
  subvol, err = self.btrfsutil.SubVolumeInfo(path)
  if err != nil { return nil, err }
  if len(subvol.ParentUuid) > 0 && !subvol.ReadOnly {
    return nil, fmt.Errorf("'%s' is a writable snapshot, those are not supported", path)
  }
  clone := proto.Clone(self.k_sysinfo).(*pb.SystemInfo)
  subvol.OriginSys = clone
  return subvol, nil
}

// nil if no source found for `sv`
func (self *btrfsVolumeManager) FindConfForSubVolume(sv *pb.SubVolume) (*pb.Source, *pb.Source_VolSnapPathPair) {
  for _,src := range self.conf.Sources {
    if src.Type != pb.Source_BTRFS { continue }
    for _,p := range src.Paths {
      if p.VolPath == sv.MountedPath { return src, p }
    }
  }
  return nil, nil
}

func (self *btrfsVolumeManager) FindSnapPathForSubVolume(sv *pb.SubVolume) (string, error) {
  src, path_pair := self.FindConfForSubVolume(sv)
  if src == nil {
    return "", fmt.Errorf("no snap path for '%s'", sv.MountedPath)
  }
  return path_pair.SnapPath, nil
}

func (self *btrfsVolumeManager) FindSnapHistoryConf(sv *pb.SubVolume) (*pb.Source_SnapHistory, error) {
  src, _ := self.FindConfForSubVolume(sv)
  if src == nil {
    return nil, fmt.Errorf("no subvol history for '%s'", sv.MountedPath)
  }
  return src.History, nil
}

func (self *btrfsVolumeManager) FindMountedPath(sv *pb.SubVolume) (string, error) {
  if len(sv.MountedPath) > 0 { return sv.MountedPath, nil }
  fs_list, err := self.LazySrcFsList()
  if err != nil { return "", err }
  _, _, from_path, err := self.juggler.FindTighterMountForSubVolume(fs_list, sv)
  return from_path, err
}

func (self *btrfsVolumeManager) ListVolumes(fs_path string) ([]*pb.SubVolume, error) {
  drop_f := self.linuxutil.GetRootOrDie()
  defer drop_f()
  _,mnt,_,err := self.juggler.FindFsAndTighterMountOwningPath(fs_path)
  if err != nil { return nil, err }
  return self.btrfsutil.ListSubVolumesInFs(mnt.MountedPath,
                                           mnt.BtrfsVolId == shim.BTRFS_FS_TREE_OBJECTID)
}

func (self *btrfsVolumeManager) FindVolume(
    fs_path string, matcher func(*pb.SubVolume) bool) (*pb.SubVolume, error) {
  vols, err := self.ListVolumes(fs_path)
  if err != nil { return nil, err }
  for _,vol := range vols {
    if matcher(vol) { return vol, nil }
  }
  return nil, nil
}

// Implement interface for sorter
type ByCGen []*pb.SubVolume
func (a ByCGen) Len() int           { return len(a) }
func (a ByCGen) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByCGen) Less(i, j int) bool { return a[i].GenAtCreation < a[j].GenAtCreation }

type ByCreatedTsDesc []*pb.SubVolume
func (a ByCreatedTsDesc) Len() int           { return len(a) }
func (a ByCreatedTsDesc) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByCreatedTsDesc) Less(i, j int) bool { return a[i].CreatedTs > a[j].CreatedTs }

func (self *btrfsVolumeManager) GetSnapshotSeqForVolume(subvol *pb.SubVolume) ([]*pb.SubVolume, error) {
  var vols []*pb.SubVolume
  var err error
  var last_gen uint64

  if len(subvol.MountedPath) < 1 { return nil, fmt.Errorf("GetSnapshotSeqForVolume needs MountedPath") }
  drop_f := self.linuxutil.GetRootOrDie()
  defer drop_f()
  vols, err = self.btrfsutil.ListSubVolumesInFs(subvol.MountedPath,
                                                subvol.VolId == shim.BTRFS_FS_TREE_OBJECTID)
  if err != nil { return nil, err }

  seq := make([]*pb.SubVolume, 0, 32)
  sort.Sort(ByCGen(vols))
  for _,vol := range vols {
    if vol.ParentUuid == subvol.Uuid {
      if last_gen == vol.GenAtCreation {
        util.Fatalf("Found 2 snapshots with the same creation gen belonging to same parent")
      }
      seq = append(seq, vol)
      last_gen = vol.GenAtCreation
    }
  }
  return seq, nil
}

func (self *btrfsVolumeManager) GetChangesBetweenSnaps(
    ctx context.Context, from *pb.SubVolume, to *pb.SubVolume) (*pb.SnapshotChanges, error) {
  var read_end types.ReadEndIf
  var from_path, to_path string
  var err error
  if from.ParentUuid != to.ParentUuid {
    return nil, fmt.Errorf("Different parent uuid : '%s' != '%s'", from.ParentUuid, to.ParentUuid)
  }
  if from.GenAtCreation >= to.GenAtCreation {
    return nil, fmt.Errorf("From is not older than To : '%d' / '%d'", from.GenAtCreation, to.GenAtCreation)
  }
  if from_path,err = self.FindMountedPath(from); err != nil { return nil, err }
  if to_path,err   = self.FindMountedPath(to);   err != nil { return nil, err }

  drop_f := self.linuxutil.GetRootOrDie()
  defer drop_f()
  read_end, err = self.btrfsutil.StartSendStream(ctx, from_path, to_path, true)
  if err != nil { return nil, err }

  defer read_end.Close()
  dump_ops, err := self.btrfsutil.ReadAndProcessSendStream(read_end)
  if err != nil { return nil, err }
  changes := sendDumpOpsToSnapChanges(dump_ops)
  return changes, read_end.GetErr()
}

func (self *btrfsVolumeManager) GetSnapshotStream(
    ctx context.Context, from *pb.SubVolume, to *pb.SubVolume) (types.ReadEndIf, error) {
  var read_end types.ReadEndIf
  var from_path, to_path string
  var err error
  from_path = ""
  if from != nil {
    if from.ParentUuid != to.ParentUuid {
      return nil, fmt.Errorf("Different parent uuid : '%s' != '%s'", from.ParentUuid, to.ParentUuid)
    }
    if from.GenAtCreation >= to.GenAtCreation {
      return nil, fmt.Errorf("From is not older than To : '%d' / '%d'", from.GenAtCreation, to.GenAtCreation)
    }
    if from_path,err = self.FindMountedPath(from); err != nil { return nil, err }
  }
  if to_path,err = self.FindMountedPath(to); err != nil { return nil, err }

  drop_f := self.linuxutil.GetRootOrDie()
  defer drop_f()
  read_end, err = self.btrfsutil.StartSendStream(ctx, from_path, to_path, false)
  return read_end, err
}

func (self *btrfsVolumeManager) CreateSnapshot(subvol *pb.SubVolume) (*pb.SubVolume, error) {
  // If tree path == "" then it is not known or this is the root subvol
  if len(subvol.MountedPath) < 1 || len(subvol.TreePath) < 1 {
    return nil, fmt.Errorf("CreateSnapshot subvol needs MountedPath and TreePath: %v", subvol)
  }
  if len(subvol.ParentUuid) > 0 { return nil, fmt.Errorf("CreateSnapshot from a snapshot") }

  snap_root, err := self.FindSnapPathForSubVolume(subvol)
  if err != nil { return nil, err }

  ts_str    := time.Now().Format("20060201")
  snap_name := fmt.Sprintf("%s.%s.%d",
                           fpmod.Base(subvol.TreePath), ts_str, time.Now().Unix())
  snap_path := fpmod.Join(snap_root, snap_name)

  drop_f := self.linuxutil.GetRootOrDie()
  defer drop_f()
  err = self.btrfsutil.CreateSnapshot(subvol.MountedPath, snap_path)
  if err != nil { return nil, err }
  snap, err := self.GetVolume(snap_path)
  if err != nil { return nil, err }
  snap.MountedPath = snap_path
  return snap, nil
}

func IsReadOnlySnap(subvol *pb.SubVolume) bool {
  return len(subvol.ParentUuid) > 0 && subvol.ReadOnly
}

func (self *btrfsVolumeManager) DeleteSnapshot(subvol *pb.SubVolume) error {
  var err error
  var del_path string
  var re_read_sv *pb.SubVolume
  del_path, err = self.FindMountedPath(subvol)
  if err != nil { return err }

  re_read_sv, err = self.GetVolume(del_path)
  if err != nil { return err }
  if !IsReadOnlySnap(re_read_sv) {
    return fmt.Errorf("%v is not readonly", subvol)
  }
  drop_f := self.linuxutil.GetRootOrDie()
  defer drop_f()
  err = self.btrfsutil.DeleteSubVolume(del_path)
  if err != nil { return err }
  return nil
}

// It is an error is there is no parent subvolume in the restore filesystem for an incremental send stream.
// The first restored subvolume in the chain will be a readonly subvolume **without** ParentUuid.
func (self *btrfsVolumeManager) ReceiveSendStream(
    ctx context.Context, root_path string, src_snap *pb.SubVolume, read_pipe types.ReadEndIf) (*pb.SubVolume, error) {
  var err error
  var sv *pb.SubVolume
  defer read_pipe.Close()

  drop_f := self.linuxutil.GetRootOrDie()
  defer drop_f()
  err = util.Coalesce(read_pipe.GetErr(),
                      self.btrfsutil.ReceiveSendStream(ctx, root_path, read_pipe))
  if err != nil { return nil, err }

  sv, err = self.FindVolume(root_path, types.ByReceivedUuid(src_snap.Uuid))
  if err != nil { return nil, err }

  if sv == nil {
    return nil, fmt.Errorf("No subvolume with received uuid '%s' got created", src_snap.Uuid)
  }
  if len(sv.TreePath) < 1 {
    return nil, fmt.Errorf("Expected TreePath is restored subvol")
  }
  sv.MountedPath = fpmod.Join(root_path, fpmod.Base(sv.TreePath))
  return sv, read_pipe.GetErr()
}

// Returns the old snaps sorted by creation time descending.
func (self *btrfsVolumeManager) KeepOnlyOldSnapsSorted(
  snaps []*pb.SubVolume, history *pb.Source_SnapHistory) (time.Time, []*pb.SubVolume, error) {
  now := time.Now()
  keep_window := 24 * time.Duration(history.DaysKeepAll) * time.Hour
  keep_until := now.Add(-keep_window)
  var old_snaps []*pb.SubVolume

  for _,snap := range snaps {
    if int64(snap.CreatedTs) >= keep_until.Unix() { continue }
    old_snaps = append(old_snaps, snap)
  }
  sort.Sort(ByCreatedTsDesc(old_snaps))
  util.Infof("%d snapshots older than %s", len(old_snaps), keep_until.Format("2006/01/02 15:04"))
  return keep_until, old_snaps, nil
}

func (self *btrfsVolumeManager) SelectSnapsToDelPerPeriod(
    snaps []*pb.SubVolume, history *pb.Source_SnapHistory, least_old_date time.Time) ([]*pb.SubVolume, error) {
  if len(snaps) < 1 { return nil, nil }
  period_window := 24 * time.Duration(history.KeepOnePeriodDays) * time.Hour
  period_end := least_old_date
  period_start := period_end.Add(-period_window)
  var to_del []*pb.SubVolume

  for _,snap := range snaps {
    if int64(snap.CreatedTs) < period_start.Unix() {
      if len(to_del) > 0 {
        last := len(to_del) - 1
        to_del = to_del[:last]
      }
      interval := period_end.Sub(time.Unix(int64(snap.CreatedTs), 0))
      if interval == interval.Truncate(period_window) {
        interval -= period_window
      } else {
        interval = interval.Truncate(period_window)
      }
      period_end = period_end.Add(-interval)
      period_start = period_end.Add(-period_window)
      //util.Debugf("New period %s - %s", period_start.Format("2006/01/02 15:04"), period_end.Format("2006/01/02 15:04"))
    }
    to_del = append(to_del, snap)
    if int64(snap.CreatedTs) >= period_end.Unix() ||
       int64(snap.CreatedTs) < period_start.Unix() {
       util.Fatalf("Invariant broken: expect snap to always be inside period window")
    }
  }
  if len(to_del) > 0 {
    last := len(to_del) - 1
    if int64(to_del[last].CreatedTs) >= period_end.Unix() ||
       int64(to_del[last].CreatedTs) < period_start.Unix() {
      util.Fatalf("Invariant broken: expect last snap to always be inside period window")
    }
    to_del = to_del[:last]
  }
  //util.Debugf("Last period %s - %s", period_start.Format("2006/01/02 15:04"), period_end.Format("2006/01/02 15:04"))
  util.Infof("%d snapshots to delete from %d", len(to_del), len(snaps))
  return to_del, nil
}

func (self *btrfsVolumeManager) TrimOldSnapshots(
    src_subvol *pb.SubVolume, dry_run bool) ([]*pb.SubVolume, error) {
  history, err := self.FindSnapHistoryConf(src_subvol)
  if err != nil { return nil, err }
  snaps, err := self.GetSnapshotSeqForVolume(src_subvol)
  if err != nil { return nil, err }
  least_old_date, old_snaps, err := self.KeepOnlyOldSnapsSorted(snaps, history)
  if err != nil { return nil, err }
  to_del_snaps, err := self.SelectSnapsToDelPerPeriod(old_snaps, history, least_old_date)
  if err != nil { return nil, err }
  if len(to_del_snaps) >= len(snaps) {
    return nil, fmt.Errorf("TrimOldSnapshots should not delete ALL snapshots.")
  }

  var deleted []*pb.SubVolume
  for _,del_snap := range to_del_snaps {
    if !dry_run { err = self.DeleteSnapshot(del_snap) }
    if err != nil { break }
    deleted = append(deleted, del_snap)
  }
  return deleted, err
}

