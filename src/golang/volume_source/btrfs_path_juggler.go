package volume_source

import (
  "errors"
  "fmt"
  fpmod "path/filepath"
  "sort"
  "strings"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/shim"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
)

type IsDirFunc func(string) bool

// Should NOT require CAP_SYS_ADMIN in order to work.
type BtrfsPathJuggler struct {
  Btrfsutil    types.Btrfsutil
  Conf         *pb.Config
  KFilesystems []*types.Filesystem
  IsDir        IsDirFunc
}

// This implementation considers the filesystems and mounts are constant through
// this object lifetime.
func NewBtrfsPathJuggler(
    conf *pb.Config, btrfsutil types.Btrfsutil, linuxutil types.Linuxutil) (types.BtrfsPathJuggler, error) {
  filesys, err := linuxutil.ListBtrfsFilesystems()
  juggler := &BtrfsPathJuggler{
    Btrfsutil: btrfsutil,
    Conf: conf,
    KFilesystems: filesys,
    IsDir: util.IsDir,
  }
  return juggler, err
}

func (self *BtrfsPathJuggler) TestOnlySwapFilesystems(fs []*types.Filesystem) {
  self.KFilesystems = fs
}
func (self *BtrfsPathJuggler) TestOnlySwapIsDir(f IsDirFunc) {
  self.IsDir = f
}

func (self *BtrfsPathJuggler) FindFsAndTighterMountOwningPath(
    path string) (*types.Filesystem, *types.MountEntry, uint64, error) {
  if !fpmod.IsAbs(path) {
    return nil, nil, 0, fmt.Errorf("FindFsAndTighterMountForSubVolume expected absolute path")
  }
  longer_prefix := ""
  var candidate_fs *types.Filesystem
  var candidate_mnt *types.MountEntry

  for _,fs := range self.KFilesystems {
    for _,mnt := range fs.Mounts {
      if !strings.HasPrefix(path, mnt.MountedPath) { continue }
      if len(longer_prefix) > len(mnt.MountedPath) { continue }
      if len(longer_prefix) == len(mnt.MountedPath) {
        return nil, nil, 0, fmt.Errorf("2 distinct prefixes should not have the same len")
      }
      longer_prefix = mnt.MountedPath
      candidate_fs = fs
      candidate_mnt = mnt
    }
  }
  if candidate_mnt == nil {
    return nil, nil, 0, fmt.Errorf("'%s' does not belong to a btrfs filesystem", path)
  }
  if len(candidate_mnt.MountedPath) == len(path) {
    return candidate_fs, candidate_mnt, candidate_mnt.BtrfsVolId, nil
  }
  // Make sure there is not a nested non btrfs-filesystem that happens to own path
  id, err := self.Btrfsutil.SubVolumeIdForPath(path)
  return candidate_fs, candidate_mnt, id, err
}

type byLen struct { Mounts []*types.MountEntry }
func (s *byLen) Len() int { return len(s.Mounts) }
func (s *byLen) Swap(i, j int) { s.Mounts[i], s.Mounts[j] = s.Mounts[j], s.Mounts[i] }
func (s *byLen) Less(i, j int) bool { return len(s.Mounts[i].TreePath) > len(s.Mounts[j].TreePath) }

// In the very rare case there is another SubVolume with the same id and tree path on a nested mount.
func (self *BtrfsPathJuggler) doUuidsDiffer(path string, sv *pb.SubVolume) bool {
  // IMPORTANT
  // We assume path is the root of the subvolume.
  // This enables `BtrfsPathJuggler` to work without CAP_SYS_ADMIN.
  // `sv_in_path` should NOT be returned (because without CAP_SYS_ADMIN it lacks some info).
  sv_in_path,err := self.Btrfsutil.SubVolumeInfo(path)
  //util.Debugf("path: %s\nsv: %s", util.AsJson(sv_in_path), util.AsJson(sv))
  return err != nil || sv_in_path.Uuid != sv.Uuid
}

func (self *BtrfsPathJuggler) FindTighterMountForSubVolumeSingle(
    fs *types.Filesystem, sv *pb.SubVolume) (*types.MountEntry, string, error) {
  var candidates []*types.MountEntry
  for _,mnt := range fs.Mounts {
    // Easy case: there is an exclusive mount entry for the subvolume.
    if mnt.BtrfsVolId == sv.VolId && mnt.TreePath == sv.TreePath {
      if self.doUuidsDiffer(mnt.MountedPath, sv) { continue }
      return mnt, mnt.MountedPath, nil
    }
    if strings.HasPrefix(sv.TreePath, mnt.TreePath) { candidates = append(candidates, mnt) }
  }
  // Hard case: determine the closer mount entry that may contain the subvolume based on its TreePath.
  sort.Sort(&byLen{candidates})
  for _,mnt := range candidates {
    path := fpmod.Join(mnt.MountedPath, sv.TreePath[len(mnt.TreePath):])
    if !self.IsDir(path) { continue }
    if self.doUuidsDiffer(path, sv) { continue }
    return mnt, path, nil
  }
  return nil, "", types.ErrNotMounted
}

func (self *BtrfsPathJuggler) FindTighterMountForSubVolume(
    fs_list []*types.Filesystem, sv *pb.SubVolume) (*types.Filesystem, *types.MountEntry, string, error) {
  if len(sv.TreePath) < 1 && sv.VolId != shim.BTRFS_FS_TREE_OBJECTID {
    return nil, nil, "", fmt.Errorf("Expect valid TreePath for sv")
  }
  for _,fs := range fs_list {
    mnt, path, err := self.FindTighterMountForSubVolumeSingle(fs, sv)
    if err != nil {
      if errors.Is(err, types.ErrNotMounted) { continue }
      return nil, nil, "", err
    }
    return fs, mnt, path, err
  }
  return nil, nil, "", types.ErrNotMounted
}

func (self *BtrfsPathJuggler) sourceContainedInSingleFs(src *pb.Source) (*types.Filesystem, error) {
  var fs *types.Filesystem
  for _,p_pair := range src.Paths {
    other_fs, _, _, err := self.FindFsAndTighterMountOwningPath(p_pair.VolPath)
    if err != nil { return nil, err }
    if fs == nil { fs = other_fs }
    if fs.Uuid != other_fs.Uuid { return nil, fmt.Errorf("source contains different filesystems") }
  }
  return fs, nil
}

func (self *BtrfsPathJuggler) sourcePointToSubVolumeRoot(src *pb.Source) error {
  for _,p_pair := range src.Paths {
    err := self.Btrfsutil.IsSubVolumeMountPath(p_pair.VolPath)
    if err != nil { return err }
  }
  return nil
}

func (self *BtrfsPathJuggler) sourceAllSubVolumeDistinct(src *pb.Source) error {
  ids := make(map[uint64]bool)
  for _,p_pair := range src.Paths {
    id, err := self.Btrfsutil.SubVolumeIdForPath(p_pair.VolPath)
    if err != nil { return err }
    if _,found := ids[id]; found { return fmt.Errorf("duplicate volume in source: %d", id) }
    ids[id] = true
  }
  return nil
}

func (self *BtrfsPathJuggler) sourceSnapPathInCorrectFs(src *pb.Source, fs *types.Filesystem) error {
  for _,p_pair := range src.Paths {
    other_fs, _, _, err := self.FindFsAndTighterMountOwningPath(p_pair.SnapPath)
    if err != nil { return nil }
    if fs.Uuid != other_fs.Uuid { return fmt.Errorf("snap paths in different filesystems") }
  }
  return nil
}

func (self *BtrfsPathJuggler) CheckSourcesAndReturnCorrespondingFs(
    sources []*pb.Source) ([]*types.Filesystem, error) {
  var fs_list []*types.Filesystem
  for idx,src := range sources {
    fs_list = append(fs_list, nil)
    if src.Type != pb.Source_BTRFS { continue }

    fs, err := self.sourceContainedInSingleFs(src)
    if err != nil { return nil, err }
    if err := self.sourcePointToSubVolumeRoot(src); err != nil { return nil, err }
    if err := self.sourceAllSubVolumeDistinct(src); err != nil { return nil, err }
    if err := self.sourceSnapPathInCorrectFs(src, fs); err != nil { return nil, err }

    fs_list[idx] = fs
  }
  util.Infof("Filesystems matched to sources: %v", fs_list)
  return fs_list, nil
}

