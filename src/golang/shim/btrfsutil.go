package shim

/*
#include <stdlib.h>
#include <stdio.h>
#include <btrfsutil.h>
#include <btrfs/ctree.h>
*/
import "C"
import (
  "context"
  "io"
  "fmt"
  fpmod "path/filepath"
  "strings"
  "unsafe"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/util"
  "btrfs_to_glacier/types"
)

const NULL_UUID = "00000000000000000000000000000000"
const BTRFS_FS_TREE_OBJECTID = C.BTRFS_FS_TREE_OBJECTID

// Must be thread-safe.
// But does nto prevent concurrent write operations on the same subvolumes.
// It is up to btrfs not to end up in inconsistent state.
type btrfsUtilImpl struct {
  linuxutil types.Linuxutil
}

func NewBtrfsutil(conf *pb.Config, linuxutil types.Linuxutil) (types.Btrfsutil, error) {
  impl := &btrfsUtilImpl{ linuxutil:linuxutil, }
  return impl, nil
}

func (self *btrfsUtilImpl) GetSubVolumeTreePath(subvol *pb.SubVolume) (string, error) {
  if !self.linuxutil.IsCapSysAdmin() {
    return "", fmt.Errorf("GetSubvolumeTreePath requires CAP_SYS_ADMIN")
  }
  var c_tree_path *C.char = nil
  c_path := C.CString(subvol.MountedPath)
  defer C.free(unsafe.Pointer(c_path))
  defer C.free(unsafe.Pointer(c_tree_path))

  stx := C.btrfs_util_subvolume_path(c_path, (C.uint64_t)(subvol.VolId), &c_tree_path)
  if stx != C.BTRFS_UTIL_OK {
    return "", fmt.Errorf("btrfs_util_subvolume_path: %s = %d",
                           C.GoString(C.btrfs_util_strerror(stx)), stx)
  }
  tree_path := C.GoString(c_tree_path)
  return tree_path, nil
}

func (self *btrfsUtilImpl) SubVolumeIdForPath(path string) (uint64, error) {
  c_path := C.CString(path)
  defer C.free(unsafe.Pointer(c_path))
  var vol_id C.uint64_t = 0

  stx := C.btrfs_util_subvolume_id(c_path, &vol_id)
  if stx != C.BTRFS_UTIL_OK {
    return 0, fmt.Errorf("btrfs_util_subvolume_id: %s = %d",
                           C.GoString(C.btrfs_util_strerror(stx)), stx)
  }
  return (uint64)(vol_id), nil
}

func (self *btrfsUtilImpl) IsSubVolumeMountPath(path string) error {
  c_path := C.CString(path)
  defer C.free(unsafe.Pointer(c_path))

  stx := C.btrfs_util_is_subvolume(c_path)
  if stx != C.BTRFS_UTIL_OK {
    return fmt.Errorf("btrfs_util_subvolume_path: %s = %d",
                      C.GoString(C.btrfs_util_strerror(stx)), stx)
  }
  return nil
}

func (self *btrfsUtilImpl) SubVolumeInfo(path string) (*pb.SubVolume, error) {
  var subvol C.struct_btrfs_util_subvolume_info
  c_path := C.CString(path)
  defer C.free(unsafe.Pointer(c_path))

  if !fpmod.IsAbs(path) {
    return nil, fmt.Errorf("needs an absolute path, got: %s", path)
  }

  util.Infof("btrfs_util_subvolume_info('%s')", path)
  // We pass 0 so that the subvolume ID of @path is used.
  stx := C.btrfs_util_subvolume_info(c_path, 0, &subvol)
  if stx != C.BTRFS_UTIL_OK {
    return nil, fmt.Errorf("btrfs_util_subvolume_info: %s = %d",
                           C.GoString(C.btrfs_util_strerror(stx)), stx)
  }
  sv_pb,err := self.toProtoSnapOrSubvol(&subvol, "", path)
  if err == nil && self.linuxutil.IsCapSysAdmin() {
    sv_pb.TreePath, err = self.GetSubVolumeTreePath(sv_pb)
  }
  return sv_pb, err
}

func (*btrfsUtilImpl) toProtoSubVolume(
    subvol *C.struct_btrfs_util_subvolume_info, tree_path string, mnt_path string) *pb.SubVolume {
  sv := &pb.SubVolume {
    Uuid: bytesToUuid(subvol.uuid),
    VolId: uint64(subvol.id),
    TreePath: strings.Trim(tree_path, "/"),
    MountedPath: strings.TrimSuffix(mnt_path, "/"),
    GenAtCreation: uint64(subvol.otransid),
    CreatedTs: uint64(subvol.otime.tv_sec),
  }
  sv.ReceivedUuid = bytesToUuid(subvol.received_uuid)
  return sv
}

// BE CAREFUL IT IS A TRAP!
// `subvol.parent_id` has nothing to do with the parent subvol of the snapshot.
// `subvol.parent_id` is only an indication of its location relative to the filesystem root.
// aka BTRFS_FS_TREE_OBJECTID means it is at the root.
func (self *btrfsUtilImpl) toProtoSnapOrSubvol(
    subvol *C.struct_btrfs_util_subvolume_info, tree_path string, mnt_path string) (*pb.SubVolume, error) {
  //util.Debugf("tree_path=%s mnt_path=%s\nsubvol=%#v\n\n", tree_path, mnt_path, subvol)
  snap := self.toProtoSubVolume(subvol, tree_path, mnt_path)
  snap.ParentUuid = bytesToUuid(subvol.parent_uuid)
  snap.ReadOnly = (subvol.flags & C.BTRFS_ROOT_SUBVOL_RDONLY) > 0
  return snap, nil
}

// If we get NULL_UUID then just return an empty string.
func bytesToUuid(uuid [16]C.uchar) string {
  var b strings.Builder
  is_null := true
  for _, chr := range uuid {
    is_null = is_null && (chr == '\000')
    fmt.Fprintf(&b, "%.2x", chr)
  }
  if is_null { return "" }
  return b.String()
}

func (self *btrfsUtilImpl) CreateSubVolumeIterator(
    path string, is_root_fs bool) (*C.struct_btrfs_util_subvolume_iterator, error) {
  //util.Infof("btrfs_util_create_subvolume_iterator('%s')", path)
  var subvol_it *C.struct_btrfs_util_subvolume_iterator
  c_path := C.CString(path)
  defer C.free(unsafe.Pointer(c_path))

  if !fpmod.IsAbs(path) {
    return nil, fmt.Errorf("needs an absolute path, got: %s", path)
  }

  // top=C.BTRFS_FS_TREE_OBJECTID list all vols but needs CAP_SYS_ADMIN
  // top=0 lists all vols if the path is the root of the btrfs filesystem
  // top=0 does not do sh*t if `path` is not the root of the fs
  var top C.ulong = 0
  if !is_root_fs {
    top = C.BTRFS_FS_TREE_OBJECTID
    if !self.linuxutil.IsCapSysAdmin() {
      return nil, fmt.Errorf("CreateSubVolumeIterator requires CAP_SYS_ADMIN for non root paths")
    }
  }
  stx := C.btrfs_util_create_subvolume_iterator(c_path, top, 0, &subvol_it)
  if stx != C.BTRFS_UTIL_OK {
    return nil, fmt.Errorf("btrfs_util_create_subvolume_iterator: %s = %d",
                           C.GoString(C.btrfs_util_strerror(stx)), stx)
  }
  return subvol_it, nil
}

func (self *btrfsUtilImpl) SubVolumeIteratorNextInfo(
    subvol_it *C.struct_btrfs_util_subvolume_iterator) (*pb.SubVolume, error) {
  var c_rel_path *C.char = nil
  var subvol C.struct_btrfs_util_subvolume_info
  defer C.free(unsafe.Pointer(c_rel_path))

  stx := C.btrfs_util_subvolume_iterator_next_info(subvol_it, &c_rel_path, &subvol)
  //util.Debugf("btrfs_util_subvolume_iterator_next_info('%p') = %v", subvol_it, stx)
  if stx == C.BTRFS_UTIL_ERROR_STOP_ITERATION {
    return nil, nil
  }
  if stx != C.BTRFS_UTIL_OK {
    return nil, fmt.Errorf("btrfs_util_subvolume_iterator_next_info: %s = %d",
                           C.GoString(C.btrfs_util_strerror(stx)), stx)
  }
  if c_rel_path == nil {
    return nil, fmt.Errorf("btrfs_util_subvolume_iterator_next_info: no tree path")
  }
  // Note: `c_rel_path` will should be relative to the root of the btrfs filesystem.
  // We could assert this by calling `btrfs_util_subvolume_path`
  tree_path := C.GoString(c_rel_path)
  return self.toProtoSnapOrSubvol(&subvol, tree_path, "")
}

// By using `is_root_fs` we guarantee the tree paths returned by `Btrfsutil.ListSubVolumesInFs`
// are relative to the filesystem root.
// * `is_root_fs == false` implies listing relative to `BTRFS_FS_TREE_OBJECTID`
// * `is_root_fs == true` implies listing relative to the id of the root volume.
func (self *btrfsUtilImpl) ListSubVolumesInFs(path string, is_root_fs bool) ([]*pb.SubVolume, error) {
  vols := make([]*pb.SubVolume, 0, 32)
  var err error
  var subvol *pb.SubVolume
  var subvol_it *C.struct_btrfs_util_subvolume_iterator

  subvol_it, err = self.CreateSubVolumeIterator(path, is_root_fs)
  if err != nil { return nil, err }
  defer C.btrfs_util_destroy_subvolume_iterator(subvol_it)
  for subvol, err = self.SubVolumeIteratorNextInfo(subvol_it);
      err == nil && subvol != nil;
      subvol, err = self.SubVolumeIteratorNextInfo(subvol_it) {
      vols = append(vols, subvol)
  }
  return vols, err
}

func (self *btrfsUtilImpl) ReadAndProcessSendStream(dump types.ReadEndIf) (*types.SendDumpOperations, error) {
  defer dump.Close()
  if file_pipe,ok := dump.(types.HasFileDescriptorIf); ok {
    ops, err := readAndProcessSendStreamHelper(file_pipe.Fd())
    return ops, util.Coalesce(dump.GetErr(), err)
  }
  // We connect `pipe` to `dump` so if dump is cancelled then `pipe` will be closed.
  pipe := util.NewFileBasedPipe(context.TODO())
  defer pipe.ReadEnd().Close()
  go func() {
    defer pipe.WriteEnd().Close()
    io.Copy(pipe.WriteEnd(), dump)
  }()
  fd := pipe.ReadEnd().(types.HasFileDescriptorIf).Fd()
  ops, err := readAndProcessSendStreamHelper(fd)
  return ops, util.Coalesce(dump.GetErr(), err)
}

func (self *btrfsUtilImpl) StartSendStream(
    ctx context.Context, from string, to string, no_data bool) (types.ReadEndIf, error) {
  if !self.linuxutil.IsCapSysAdmin() {
    return nil, fmt.Errorf("StartSendStream requires CAP_SYS_ADMIN")
  }
  if len(from) > 0 && !fpmod.IsAbs(from) {
    return nil, fmt.Errorf("'from' needs an absolute path, got: %s", from)
  }
  if !fpmod.IsAbs(to) {
    return nil, fmt.Errorf("'to' needs an absolute path, got: %s", to)
  }

  args := make([]string, 0, 16)
  args = append(args, "btrfs")
  // `--proto=0` uses the latest version protocol (depends on running linux and btrfs-progs versions).
  // Note: option `--compressed-data` is useless since it applies only if the btrfs filesystem
  // uses transparent compression of files. It does not influence whether btrfs-send will compress the stream.
  args = append(args, "send", "--proto=0")
  if no_data {
    args = append(args, "--no-data")
  }
  if len(from) > 0 {
    args = append(args, "-p")
    args = append(args, from)
  }
  args = append(args, to)

  return util.StartCmdWithPipedOutput(ctx, args)
}

func (self *btrfsUtilImpl) CreateSubvolume(sv_path string) error {
  if !fpmod.IsAbs(sv_path) {
    return fmt.Errorf("`sv_path` needs an absolute path, got: %s", sv_path)
  }
  c_subvol := C.CString(sv_path)
  stx := C.btrfs_util_create_subvolume(c_subvol, 0, nil, nil)
  if stx != C.BTRFS_UTIL_OK {
    return fmt.Errorf("btrfs_util_create_subvolume(%s): %s = %d",
                      sv_path, C.GoString(C.btrfs_util_strerror(stx)), stx)
  }
  return self.linuxutil.ChownAsRealUser(sv_path)
}

func (self *btrfsUtilImpl) HelperCreateSnapshot(
    sv_path string, snap_path string, flags C.int) error {
  if !fpmod.IsAbs(sv_path) {
    return fmt.Errorf("`sv_path` needs an absolute path, got: %s", sv_path)
  }
  if !fpmod.IsAbs(snap_path) {
    return fmt.Errorf("`snap_path` needs an absolute path, got: %s", snap_path)
  }
  c_subvol := C.CString(sv_path)
  c_snap := C.CString(snap_path)
  // Async creation has been deprecated in btrfs 5.7, using `async_transid` arg will f*ck things up.
  // https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=15c981d16d70e8a5be297fa4af07a64ab7e080ed
  stx := C.btrfs_util_create_snapshot(c_subvol, c_snap, flags, nil, nil)
  if stx != C.BTRFS_UTIL_OK {
    return fmt.Errorf("btrfs_util_create_snapshot(%s, %s, %d): %s = %d",
                      sv_path, snap_path, flags, C.GoString(C.btrfs_util_strerror(stx)), stx)
  }
  if (flags | C.BTRFS_UTIL_CREATE_SNAPSHOT_READ_ONLY) == 0 {
    return self.linuxutil.ChownAsRealUser(snap_path)
  }
  return nil
}

func (self *btrfsUtilImpl) CreateClone(sv_path string, clone_path string) error {
  var flags C.int = 0
  return self.HelperCreateSnapshot(sv_path, clone_path, flags)
}

func (self *btrfsUtilImpl) CreateSnapshot(sv_path string, snap_path string) error {
  var flags C.int = C.BTRFS_UTIL_CREATE_SNAPSHOT_READ_ONLY
  return self.HelperCreateSnapshot(sv_path, snap_path, flags)
}

func (self *btrfsUtilImpl) DeleteSubVolume(subvol string) error {
  if !self.linuxutil.IsCapSysAdmin() {
    return fmt.Errorf("DeleteSubvolume requires CAP_SYS_ADMIN (only for snapshots though)")
  }
  if !fpmod.IsAbs(subvol) {
    return fmt.Errorf("'subvol' needs an absolute path, got: %s", subvol)
  }
  c_subvol := C.CString(subvol)
  stx := C.btrfs_util_delete_subvolume(c_subvol, 0)
  if stx != C.BTRFS_UTIL_OK {
    return fmt.Errorf("btrfs_util_delete_subvolume: %s = %d",
                           C.GoString(C.btrfs_util_strerror(stx)), stx)
  }
  return nil
}

func (self *btrfsUtilImpl) ReceiveSendStream(ctx context.Context, to_dir string, read_pipe types.ReadEndIf) error {
  if !self.linuxutil.IsCapSysAdmin() {
    return fmt.Errorf("ReceiveSendStream requires CAP_SYS_ADMIN")
  }
  defer read_pipe.Close()
  if !fpmod.IsAbs(to_dir) {
    return fmt.Errorf("'to_dir' needs an absolute path, got: %s", to_dir)
  }

  args := make([]string, 0, 16)
  args = append(args, "btrfs")
  args = append(args, "receive")
  args = append(args, "-e")
  args = append(args, "--quiet")
  args = append(args, to_dir)

  return util.StartCmdWithPipedInput(ctx, read_pipe, args)
}

