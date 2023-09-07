package main

import (
  "context"
  "fmt"
  "flag"
  fpmod "path/filepath"
  "os"
  "strings"
  "time"
  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/shim"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
)

var root_flag string
var dest_flag string
var snap1_flag string
var snap2_flag string
var subvol_flag string
var subvol_alt_flag string
var subvol_dir string
var not_btrfs_path string

func init() {
  flag.StringVar(&root_flag, "rootvol", "", "the fullpath to the source btrfs filesystem")
  flag.StringVar(&dest_flag, "destvol", "", "the fullpath to the destination btrfs filesystem")
  flag.StringVar(&snap1_flag, "snap1",  "", "the fullpath to the oldest snapshot")
  flag.StringVar(&snap2_flag, "snap2",  "", "the fullpath to the latest snapshot")
  flag.StringVar(&subvol_flag, "subvol",  "", "the fullpath to the btrfs subvolume")
  flag.StringVar(&subvol_alt_flag, "subvol-alt",  "", "another mount point only for the subvolume")
  flag.Parse()
  subvol_dir = fpmod.Join(subvol_flag, "adir")
  not_btrfs_path = os.TempDir()
}

type TestBtrfsUtil struct {
  conf *pb.Config
  btrfsutil types.Btrfsutil
  linuxutil types.Linuxutil
}

func GetConf() *pb.Config {
  conf := &pb.Config{}
  flags := []string{subvol_flag, subvol_alt_flag, root_flag, dest_flag, snap1_flag, snap2_flag,}
  for _,f := range flags {
    if f == "" { util.Fatalf("Bad flag value: '%s'", f) }
  }
  return conf
}

func GetBtrfsUtil(conf *pb.Config, linuxutil types.Linuxutil) types.Btrfsutil {
  var err error
  var btrfsutil types.Btrfsutil
  btrfsutil, err = shim.NewBtrfsutil(conf, linuxutil)
  if err != nil { util.Fatalf("integration failed = %v", err) }
  return btrfsutil
}

func GetLinuxUtil() types.Linuxutil {
  var conf *pb.Config
  linuxutil, err := shim.NewLinuxutil(conf)
  if err != nil {
    util.Fatalf("integration failed = %v", err)
  }
  return linuxutil
}

func (self *TestBtrfsUtil) GetNewSnapName(leaf_name string) string {
  return fpmod.Join(fpmod.Dir(snap1_flag),
                    fmt.Sprintf("%s.%d", leaf_name, time.Now().Unix()))
}

func (self *TestBtrfsUtil) GetRestoreDir() string {
  restore_dir := fpmod.Join(root_flag,
                            fmt.Sprintf("restore.%d", time.Now().Unix()))
  err := os.Mkdir(restore_dir, os.ModePerm)
  if err != nil {
    if !os.IsExist(err) { util.Fatalf("failed to create '%s': %v", restore_dir, err) }
  }
  return restore_dir
}

func validateSubVolOrDie(subvol *pb.SubVolume, check_mnt bool, check_tree bool) {
  bad_tree_path := check_tree &&
                   ((subvol.VolId == shim.BTRFS_FS_TREE_OBJECTID && len(subvol.TreePath) == 0) ||
                   len(subvol.TreePath) < 1)
  bad_vol := (check_mnt && len(subvol.MountedPath) < 1) ||
             subvol.VolId < shim.BTRFS_FS_TREE_OBJECTID ||
             len(subvol.Uuid) < 1 || subvol.CreatedTs < 1 ||
             subvol.CreatedTs < 1 || subvol.GenAtCreation < 1
  if bad_vol || bad_tree_path { util.Fatalf("bad subvol = %s\n", util.AsJson(subvol)) }
}

func validateSnapOrDie(subvol *pb.SubVolume, check_mnt bool, check_tree bool) {
  validateSubVolOrDie(subvol, check_mnt, check_tree)
  bad_snap := len(subvol.ParentUuid) < 1 || !subvol.ReadOnly
  if bad_snap { util.Fatalf("bad snap = %s\n", util.AsJson(subvol)) }
}

func (self *TestBtrfsUtil) TestSubVolumeIdForPath(path string, expect_ok bool) {
  id, err := self.btrfsutil.SubVolumeIdForPath(path)
  if expect_ok && err != nil {
    util.Fatalf("SubVolumeIdForPath(%s) failed = %v", path, err)
  }
  if !expect_ok && err == nil {
    util.Fatalf("SubVolumeIdForPath(%s) should have failed", path)
  }
  if expect_ok && id < shim.BTRFS_FS_TREE_OBJECTID {
    util.Fatalf("SubVolumeIdForPath(%s) invalid id", path)
  }
  if err != nil {
    util.Debugf("TestSubVolumeIdForPath(%s): %v", path, err)
  }
}

func (self *TestBtrfsUtil) TestIsSubVolumeMountPath(path string, expect_ok bool) {
  err := self.btrfsutil.IsSubVolumeMountPath(path)
  if expect_ok && err != nil {
    util.Fatalf("IsSubVolumeMountPath(%s) failed = %v", path, err)
  }
  if !expect_ok && err == nil {
    util.Fatalf("IsSubVolumeMountPath(%s) should have failed", path)
  }
}

func (self *TestBtrfsUtil) TestSubVolumeInfo(path string) {
  subvol, err := self.btrfsutil.SubVolumeInfo(path)
  if err != nil { util.Fatalf("SubvolumeInfo failed = %v", err) }
  validateSubVolOrDie(subvol, true, self.linuxutil.IsCapSysAdmin())
  util.Infof("subvol = %s\n", util.AsJson(subvol))
}
func (self *TestBtrfsUtil) TestSubVolumeInfoFail(path string) {
  _, err := self.btrfsutil.SubVolumeInfo(path)
  if err == nil { util.Fatalf("btrfsutil.SubvolumeInfo should have failed for '%s'", path) }
  util.Debugf("TestSubVolumeInfoFail(%s): %v", path, err)
}

func (self *TestBtrfsUtil) TestGetSubVolumeTreePath(root string, path string) {
  if !self.linuxutil.IsCapSysAdmin() {
    util.Warnf("TestGetSubvolumeTreePath needs CAP_SYS_ADMIN")
    return
  }
  subvol, err := self.btrfsutil.SubVolumeInfo(root)
  if err != nil { util.Fatalf("SubvolumeInfo failed = %v", err) }
  subvol.MountedPath = path

  tree_path, err := self.btrfsutil.GetSubVolumeTreePath(subvol)
  if err != nil { util.Fatalf("GetSubVolumeTreePath failed = %v", err) }
  util.Debugf("tree_path: '%s'", tree_path)
  if len(tree_path) < 1 { util.Fatalf("bad tree path") }
  if strings.HasPrefix(tree_path, "/") { util.Fatalf("bad tree path") }
}

func (self *TestBtrfsUtil) TestListSubVolumesAt(path string, is_root_fs bool) {
  if !self.linuxutil.IsCapSysAdmin() && !is_root_fs {
    util.Warnf("TestBtrfsUtil_ListSubVolumesAt needs CAP_SYS_ADMIN for non root paths")
    return
  }
  var err error
  var vols []*pb.SubVolume
  vols, err = self.btrfsutil.ListSubVolumesInFs(path, is_root_fs)
  if err != nil { util.Fatalf("integration failed = %v", err) }
  if len(vols) < 1 { util.Fatalf("returned 0 vols: '%s'", path) }
  for _,subvol := range(vols) {
    validateSubVolOrDie(subvol, false, true)
    util.Debugf("%s\n", util.AsJson(subvol))
  }
  util.Infof("len(vols) = %d\n", len(vols))
}

func (self *TestBtrfsUtil) TestCreateSnapshot() {
  snap_path := self.GetNewSnapName("TestBtrfsUtil_CreateSnapshotAndWait")
  err := self.btrfsutil.CreateSnapshot(subvol_flag, snap_path);
  if err != nil { util.Fatalf("btrfsutil.CreateSnapshot(%s, %s) failed = %v", subvol_flag, snap_path, err) }

  subvol, err := self.btrfsutil.SubVolumeInfo(snap_path);
  if err != nil { util.Fatalf("btrfsutil.SubvolumeInfo failed = %v", err) }
  validateSnapOrDie(subvol, true, self.linuxutil.IsCapSysAdmin())
  util.Infof("snap = %s\n", subvol)
}

func (self *TestBtrfsUtil) TestCreateSubvolume() {
  sv_path := fpmod.Join(root_flag,
                        fmt.Sprintf("%s.%d", "TestCreateSubvolume", time.Now().Unix()))
  err := self.btrfsutil.CreateSubvolume(sv_path);
  if err != nil { util.Fatalf("btrfsutil.CreateSubvolume(%s) failed = %v", sv_path, err) }
  err = DoesNotBelongToRoot(sv_path)
  if err != nil { util.Fatalf("DoesNotBelongToRoot %v", err) }

  subvol, err := self.btrfsutil.SubVolumeInfo(sv_path);
  if err != nil { util.Fatalf("btrfsutil.SubvolumeInfo failed = %v", err) }
  validateSubVolOrDie(subvol, true, self.linuxutil.IsCapSysAdmin())
  util.Infof("subvol = %s\n", subvol)
}

func (self *TestBtrfsUtil) TestCreateClone() {
  sv_path := fpmod.Join(root_flag,
                        fmt.Sprintf("%s.%d", "TestCreateClone", time.Now().Unix()))
  err := self.btrfsutil.CreateClone(subvol_flag, sv_path);
  if err != nil { util.Fatalf("btrfsutil.CreateClone(%s, %s) failed = %v", subvol_flag, sv_path, err) }
  err = DoesNotBelongToRoot(sv_path)
  if err != nil { util.Fatalf("DoesNotBelongToRoot %v", err) }

  subvol, err := self.btrfsutil.SubVolumeInfo(sv_path);
  if err != nil { util.Fatalf("btrfsutil.SubvolumeInfo failed = %v", err) }
  validateSubVolOrDie(subvol, true, self.linuxutil.IsCapSysAdmin())
  util.Infof("clone = %s\n", subvol)
}

// Requires CAP_SYS_ADMIN
func (self *TestBtrfsUtil) TestDeleteSubVolume() {
  if !self.linuxutil.IsCapSysAdmin() {
    util.Warnf("TestBtrfsUtil_DeleteSubvolume needs CAP_SYS_ADMIN")
    return
  }
  snap_path := self.GetNewSnapName("TestBtrfsUtil_DeleteSubvolume")
  err := self.btrfsutil.CreateSnapshot(subvol_flag, snap_path);
  if err != nil { util.Fatalf("btrfsutil.CreateSnapshot(%s, %s) failed = %v", subvol_flag, snap_path, err) }

  err = self.btrfsutil.DeleteSubVolume(snap_path);
  if err != nil { util.Fatalf("btrfsutil.DeleteSubVolume(%s) failed = %v", snap_path, err) }

  var subvol *pb.SubVolume
  subvol, err = self.btrfsutil.SubVolumeInfo(snap_path);
  if err == nil { util.Fatalf("btrfsutil.DeleteSubvolume was not deleted: %v", subvol) }
  util.Debugf("TestDeleteSubVolume(): %v", err)

  err = self.btrfsutil.DeleteSubVolume(snap_path);
  if err == nil { util.Fatalf("btrfsutil.DeleteSubVolume(%s) twice should have failed") }
}

const send_stream = `
YnRyZnMtc3RyZWFtAAEAAAAyAAAAAQBpJfHHDwAOAGFzdWJ2b2wuc25hcC4xAQAQABZlGMCFNHhA
ibMz9Eo0TMsCAAgABwAAAAAAAAAcAAAAEwDZwsOqDwAAAAYACADoAwAAAAAAAAcACADpAwAAAAAA
ABAAAAASAFlVdTUPAAAABQAIAO0BAAAAAAAANAAAABQAN8fP7Q8AAAALAAwAUV5nYAAAAAB5dbYD
CgAMAFFeZ2AAAAAAOqpLBgkADABRXmdgAAAAADqqSwYYAAAAAwBsbtsDDwAIAG8yNTctNy0wAwAI
AAEBAAAAAAAAGwAAAAkAGi4Hzg8ACABvMjU3LTctMBAACwBmaWxlLkwzQkFyajQAAAAUADfHz+0P
AAAACwAMAFFeZ2AAAAAAeXW2AwoADABRXmdgAAAAADqqSwYJAAwAUV5nYAAAAAA6qksGlAIAAA8A
FeqoZg8ACwBmaWxlLkwzQkFyahIACAAAAAAAAAAAABMAdQJnNywzCiInZmwrIgpRMWtYSwpqSVhl
ClFASWNERQo3cmI7JworOE5DPidceApvZGQ5Ci5cQkR8Ci4iWHYKV1lRewogIEkwCiR6N1MKd2Bz
eQpQPCV3CkxZYEkKUk8tWHQKUXpMXQogd2g+ZQo7YjpqCmBRY2sKLQlBQQppbHtWCitxID0KSyIk
Wwo7dEZ7Cm5dZjNEcwooRyZ3CmV4PzkKVlM0RApjfUtQCkJMOkYKPU91Swp0IG8pCj88cX0KaXUv
XQonVy1zCkA3NH1wRgotCSx6CnctNnYKaXVGSQp9ZzxqCktfd2wKall1SQpTXGh8Jwo0dWhOIQpo
bVM6JQptcEZACjtZV00KYCl5eVgKMXInSwo0P2RPCkFlejAKRSxeZFBPCioJYzkKV1hIQQp9bDRy
Cmx1J0AKfltWTAouUHR7CnouWDQKYEA9ICFSLQpMV25uCk5Bb0MKa2RUegpKfV8jCiojcjsiCkV2
CXJqSwpFT2ZfClJGeHQKTVBCOgprbXx5Cno/YU0KOmcwWQogUCRNVgpPSl09CiFeTTVeClA6Pj5V
Ck1nTmwKQGU/MApqclNeCm07OiUKKVp5LwolYn4yCiViUV8jQgo9O04lCnJxM00KUixjCQp9MnZx
CikjZDgKc3dqbwpqP3ksPGoKdUM4JGIKTikuJzIKIEZuSzMKOD4scgpQVjtfCnxfakkKW2h8SQop
OyVWCnlda0IKRkQpaAo/YSJ1CQphcl8wCj0mMiIKX35uPwpiLVhUCmRQWCZjcQouTiJyCnx3JFQK
b2g9UApoKDFpClktfScKOUVFYQpHTwl+ZT0KOGpxXgojOVVnCicAAAATALfmH3YPAAsAZmlsZS5M
M0JBcmoGAAgA6AMAAAAAAAAHAAgA6QMAAAAAAAAbAAAAEgB+Pj7mDwALAGZpbGUuTDNCQXJqBQAI
AKQBAAAAAAAAPwAAABQAg7nC8g8ACwBmaWxlLkwzQkFyagsADABRXmdgAAAAADqqSwYKAAwAUV5n
YAAAAAA6qksGCQAMAFFeZ2AAAAAAOqpLBgAAAAAVAFBsyZ0=
`
const received_name = "asubvol.snap.1"
const received_uuid = "166518c08534784089b333f44a344ccb"

// Requires CAP_SYS_ADMIN
func (self *TestBtrfsUtil) TestReceiveSendStream() {
  if !self.linuxutil.IsCapSysAdmin() {
    util.Warnf("TestBtrfsUtil_ReceiveSendStream needs CAP_SYS_ADMIN")
    return
  }
  restore_dir := self.GetRestoreDir()
  preload_pipe := LoadPipeFromBase64SendData(send_stream)
  defer preload_pipe.WriteEnd().Close()
  ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
  defer cancel()

  err := self.btrfsutil.ReceiveSendStream(ctx, restore_dir, preload_pipe.ReadEnd())
  if err != nil { util.Fatalf("btrfsutil.ReceiveSendStream failed = %v", err) }

  var vols []*pb.SubVolume
  vols, err = self.btrfsutil.ListSubVolumesInFs(root_flag, true)
  if err != nil { util.Fatalf("integration failed = %v", err) }
  for _,sv := range(vols) {
    util.Debugf("subvol = %s", util.AsJson(sv))
    if strings.HasSuffix(sv.TreePath, received_name) && sv.ReceivedUuid == received_uuid {
      util.Infof("Received subvol: %v", sv)
      return
    }
  }
  util.Fatalf("Could not find any volume in '%s'", restore_dir)
}


func TestBtrfsUtil_AllFuncs(conf *pb.Config, linuxutil types.Linuxutil, btrfsutil types.Btrfsutil) {
  suite := &TestBtrfsUtil{
    conf: conf, btrfsutil: btrfsutil, linuxutil: linuxutil,
  }
  suite.TestSubVolumeIdForPath(subvol_flag, true)
  suite.TestSubVolumeIdForPath(root_flag, true)
  suite.TestSubVolumeIdForPath(subvol_dir, true)
  // Error: Could not lookup inode = 13
  suite.TestSubVolumeIdForPath(not_btrfs_path, false)
  // Error: Could not open = 7
  suite.TestSubVolumeIdForPath(fpmod.Join(subvol_flag, "/not/exist"), false)
  suite.TestIsSubVolumeMountPath(subvol_flag, true)
  suite.TestIsSubVolumeMountPath(root_flag, true)
  suite.TestIsSubVolumeMountPath(subvol_dir, false)
  suite.TestSubVolumeInfo(subvol_flag)
  suite.TestSubVolumeInfo(subvol_alt_flag)
  // Error: Not a Btrfs subvolume = 5
  suite.TestSubVolumeInfoFail(subvol_dir)
  // Error: Could not open = 7
  suite.TestSubVolumeInfoFail(fpmod.Join(subvol_flag, "/not/exist"))
  // Error: Not a Btrfs filesystem = 4
  suite.TestSubVolumeInfoFail(not_btrfs_path)
  suite.TestGetSubVolumeTreePath(subvol_flag, subvol_flag)
  suite.TestGetSubVolumeTreePath(subvol_flag, subvol_dir)
  suite.TestListSubVolumesAt(root_flag, true)
  suite.TestListSubVolumesAt(subvol_flag, false)
  suite.TestListSubVolumesAt(subvol_alt_flag, false)
  suite.TestListSubVolumesAt(snap1_flag, false)
  suite.TestCreateSnapshot()
  suite.TestCreateSubvolume()
  suite.TestCreateClone()
  suite.TestDeleteSubVolume()
  suite.TestReceiveSendStream()
}

// Cannot use a test since Testing does not support cgo
func main() {
  util.Infof("shim_integration run")
  conf := GetConf()
  linuxutil := GetLinuxUtil()
  btrfsutil := GetBtrfsUtil(conf, linuxutil)

  TestLinuxUtils_AllFuncs(linuxutil, root_flag, dest_flag)
  TestBtrfsUtil_AllFuncs(conf, linuxutil, btrfsutil)
  TestSendDumpAll(btrfsutil)
  TestBtrfsSendStreamAll(linuxutil, btrfsutil)

  if !linuxutil.IsCapSysAdmin() {
    util.Warnf("Some tests will only be run with CAP_SYS_ADMIN")
  }
  util.Infof("ALL DONE")
}

