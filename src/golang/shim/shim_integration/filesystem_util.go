package main

import (
  "context"
  "fmt"
  fpmod "path/filepath"
  "os"
  "syscall"
  "time"

  "btrfs_to_glacier/shim"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"

  "github.com/google/uuid"
)

type TestFilesystemUtil struct {
  linuxutil *shim.Linuxutil
  mnt_path_1 string
  mnt_path_2 string
  mnt_path_3 string
}

func (self *TestFilesystemUtil) CheckBtrfsFs(fs *types.Filesystem, mnt_path string) bool {
   var found_path bool
   if fs.Label != fpmod.Base(mnt_path) { return false }
   for _,mnt := range fs.Mounts { found_path = found_path || mnt.MountedPath == mnt_path }
   if !found_path { util.Fatalf("Did not find expected mount: '%s'", mnt_path) }
   return true
}

func (self *TestFilesystemUtil) TestListBtrfsFilesystems() {
  var found_fs_1, found_fs_2 bool
  fs_list, err := self.linuxutil.ListBtrfsFilesystems()
  if err != nil { util.Fatalf("cannot get filesystems: %v", err) }
  if len(fs_list) < 1 { util.Fatalf("failed to find any btrfs fs") }

  for _,fs := range fs_list {
    if len(fs.Uuid) < 1 { util.Fatalf("bad uuid") }
    if len(fs.Label) < 1 { util.Fatalf("bad label") }
    if len(fs.Devices) < 1 { util.Fatalf("no devices found") }
    if len(fs.Mounts) < 1 { util.Fatalf("no mounts found") }
    for _,mnt := range fs.Mounts {
      if mnt.BtrfsVolId < 1 { util.Fatalf("bad btrfs subvol id") }
      if len(mnt.MountedPath) < 1 { util.Fatalf("bad btrfs mounted path") }
    }

    found_fs_1 = found_fs_1 || self.CheckBtrfsFs(fs, self.mnt_path_1)
    found_fs_2 = found_fs_2 || self.CheckBtrfsFs(fs, self.mnt_path_2)
  }

  util.Debugf("fs_list: %s", util.AsJson(fs_list))
  if !found_fs_1 || !found_fs_2 { util.Fatalf("Did not find all expected filesystems") }
}

func (self *TestFilesystemUtil) TestListBlockDevMounts() {
  var found_mnt_1, found_mnt_2 bool
  mnt_list, err := self.linuxutil.ListBlockDevMounts()
  if err != nil { util.Fatalf("ListBlockDevMounts: %v", err) }

  for _,mnt := range mnt_list {
    dev := mnt.Device
    if dev == nil || len(mnt.MountedPath) < 1 {
      util.Fatalf("malformed mount: %#v", mnt)
    }
    if len(dev.Name) < 1 || len(dev.FsUuid) < 1 {
      util.Fatalf("malformed block device: %#v", dev)
    }

    found_mnt_1 = found_mnt_1 || mnt.MountedPath == self.mnt_path_1
    found_mnt_2 = found_mnt_2 || mnt.MountedPath == self.mnt_path_2
  }
  util.Debugf("mnt_list: %s", util.AsJson(mnt_list))
  if !found_mnt_1 || !found_mnt_2 { util.Fatalf("Did not find all expected mounts") }
}

func (self *TestFilesystemUtil) TestListMount_Noop() {
  var noop_mnt *types.MountEntry
  mnt_list, err := self.linuxutil.ListBlockDevMounts()
  if err != nil { util.Fatalf("ListBlockDevMounts: %v", err) }

  for _,mnt := range mnt_list {
    if mnt.MountedPath != self.mnt_path_1 { continue }
    noop_mnt = mnt
  }
  if noop_mnt == nil { util.Fatalf("Did not find %s", self.mnt_path_1) }

  got_mnt, err := self.linuxutil.Mount(context.TODO(), noop_mnt.Device.FsUuid, self.mnt_path_1)
  if err != nil { util.Fatalf("linuxutil.Mount: %v", err) }
  util.Debugf("entry: %s", util.AsJson(got_mnt))
  util.EqualsOrDie("Bad mount entry", got_mnt, noop_mnt)
}

func (self *TestFilesystemUtil) TestListMount_NoSuchDev() {
  _, err := self.linuxutil.Mount(context.TODO(), "bad_uuid", "/some/path")
  util.Debugf("no such dev err: %v", err)
  if err == nil { util.Fatalf("linuxutil.Mount: expected error for unexisting device") }
}

func (self *TestFilesystemUtil) TestListUMount_NoSuchDev() {
  err := self.linuxutil.UMount(context.TODO(), "bad_uuid")
  if err != nil { util.Fatalf("linuxutil.UMount: %v", err) }
}

func (self *TestFilesystemUtil) TestListUMount_Mount_Cycle() {
  var expect_mnt *types.MountEntry
  mnt_list, err := self.linuxutil.ListBlockDevMounts()
  if err != nil { util.Fatalf("ListBlockDevMounts: %v", err) }

  for _,mnt := range mnt_list {
    if mnt.MountedPath != self.mnt_path_3 { continue }
    expect_mnt = mnt
  }
  if expect_mnt == nil { util.Fatalf("Did not find %s", self.mnt_path_3) }

  err = self.linuxutil.UMount(context.TODO(), expect_mnt.Device.FsUuid)
  if err != nil { util.Fatalf("linuxutil.UMount: %v", err) }

  got_mnt, err := self.linuxutil.Mount(context.TODO(), expect_mnt.Device.FsUuid, self.mnt_path_3)
  if err != nil { util.Fatalf("linuxutil.Mount: %v", err) }
  util.Debugf("entry: %s", util.AsJson(got_mnt))
  util.EqualsOrDie("Bad mount entry", got_mnt, expect_mnt)
}

func DoesNotBelongToRoot(path string) error {
  var stat syscall.Stat_t
  err := syscall.Stat(path, &stat)
  if err != nil {
    return fmt.Errorf("syscall.stat: %w", err)
  }
  if stat.Uid == shim.ROOT_UID {
    return fmt.Errorf("owner is root: %s", path)
  }
  return nil
}

func (self *TestFilesystemUtil) TestCreateLoopDevice() (*types.Device, error) {
  if !self.linuxutil.IsCapSysAdmin() {
    util.Warnf("TestFilesystemUtil_TestCreateLoopDevice needs CAP_SYS_ADMIN")
    return nil, nil
  }

  dev, err := self.linuxutil.CreateLoopDevice(context.TODO(), 32)
  if err != nil { return nil, fmt.Errorf("linuxutil.CreateLoopDevice: %w", err) }
  util.Debugf("New loop device: %s", util.AsJson(dev))

  if !util.Exists(dev.LoopFile) {
    return dev, fmt.Errorf("Backing file not created: '%s'", dev.LoopFile)
  }
  return dev, DoesNotBelongToRoot(dev.LoopFile)
}

func WaitForItem(path string, wait_for_creation bool) error {
  condition := func() bool {
    existance := util.Exists(path)
    return (existance || wait_for_creation) && !(existance && wait_for_creation) // xor
  }
  for i := 0; condition(); i += 1 {
    if i > 100 { return fmt.Errorf("Timeout wait_for_creation:%v path:%s'", wait_for_creation, path) }
    time.Sleep(util.LargeTimeout)
  }
  return nil
}

func (self *TestFilesystemUtil) TestCreateBtrfsFilesystem(dev *types.Device) (string, error) {
  if !self.linuxutil.IsCapSysAdmin() {
    util.Warnf("TestFilesystemUtil_TestCreateBtrfsFilesystem needs CAP_SYS_ADMIN")
    return "", nil
  }
  if dev == nil { return "", nil }

  label := uuid.NewString()
  fs, err := self.linuxutil.CreateBtrfsFilesystem(context.TODO(), dev, label, "--mixed")
  if err != nil { return "", fmt.Errorf("linuxutil.CreateBtrfsFilesystem: %w", err) }
  util.Debugf("New filesystem: %s", util.AsJson(fs))

  if len(fs.Uuid) < 1 { return "", fmt.Errorf("Empty uuid") }
  util.EqualsOrDie("Bad fs label", fs.Label, label)
  util.EqualsOrDie("There should not be any mount", len(fs.Mounts), 0)
  util.EqualsOrDie("There should only be 1 device", len(fs.Devices), 1)
  util.EqualsOrDie("Bad device", fs.Devices[0].Name, dev.Name)

  _, err = self.linuxutil.CreateBtrfsFilesystem(context.TODO(), dev, label, "--mixed")
  if err == nil { return "", fmt.Errorf("Cannot overwrite filesystem in device") }
  return fs.Uuid, nil
}

func (self *TestFilesystemUtil) TestLoopdevMountUmount(fs_uuid string) error {
  if !self.linuxutil.IsCapSysAdmin() {
    util.Warnf("TestFilesystemUtil_TestLoopdevMountUmount needs CAP_SYS_ADMIN")
    return nil
  }
  target_mnt, err := os.MkdirTemp("", "TestLoopdevMountUmount")
	if err != nil { return fmt.Errorf("os.MkdirTemp: %w", err) }

  got_mnt, err := self.linuxutil.Mount(context.TODO(), fs_uuid, target_mnt)
  if err != nil { return fmt.Errorf("linuxutil.Mount: %w", err) }
  fs_sys_path := fpmod.Join(types.SYS_FS_BTRFS, fs_uuid)

  mnt_list, err := self.linuxutil.ListBlockDevMounts()
  if err != nil { return fmt.Errorf("linuxutil.ListBlockDevMounts: %w", err) }
  found := false
  for _,mnt := range mnt_list {
    if mnt.MountedPath == target_mnt {
      found = true
      util.EqualsOrDie("Bad mount entry", got_mnt, mnt)
      break 
    }
  }
  if !found { return fmt.Errorf("Nothing mounted at '%s'", target_mnt) }
  root_err := DoesNotBelongToRoot(target_mnt)

  err = self.linuxutil.UMount(context.TODO(), fs_uuid)
  if err != nil { return fmt.Errorf("linuxutil.UMount: %v", err) }

  err = WaitForItem(fs_sys_path, false)
  util.RemoveAll(target_mnt)
  return util.Coalesce(root_err, err)
}

func (self *TestFilesystemUtil) TestDeleteLoopDevice(dev *types.Device) error {
  if !self.linuxutil.IsCapSysAdmin() {
    util.Warnf("TestFilesystemUtil_TestDeleteLoopDevice needs CAP_SYS_ADMIN")
    return nil
  }
  err := self.linuxutil.DeleteLoopDevice(context.TODO(), dev)
  if err != nil { return fmt.Errorf("linuxutil.DeleteLoopDevice: %w", err) }
  if util.Exists(dev.LoopFile) { return fmt.Errorf("Backing file should have been deleted") }
  backing_file_path := fpmod.Join(shim.SYS_BLOCK, dev.Name, "loop", "backing_file")
  // Loop device persist for a while in /sys
  return WaitForItem(backing_file_path, false)
}

func TestFilesystemUtil_AllFuncs(
    linuxutil types.Linuxutil, src_fs string, dest_fs string) {
  suite := &TestFilesystemUtil{
    linuxutil: linuxutil.(*shim.Linuxutil),
    mnt_path_1: src_fs,
    mnt_path_2: dest_fs,
    mnt_path_3: "/tmp/ext4_test_partition_1",
  }
  suite.TestListBtrfsFilesystems()
  suite.TestListBlockDevMounts()
  suite.TestListMount_Noop()
  suite.TestListMount_NoSuchDev()
  suite.TestListUMount_NoSuchDev()

  dev, create_err := suite.TestCreateLoopDevice()
  fs_uuid, fs_err := suite.TestCreateBtrfsFilesystem(dev)
  mount_err := suite.TestLoopdevMountUmount(fs_uuid)
  del_err := suite.TestDeleteLoopDevice(dev)
  util.Debugf("\ncreate_err:%v\nfs_err:%v\nmount_err:%v\ndel_err:%v",
              create_err, fs_err, mount_err, del_err)
  final_err := util.Coalesce(create_err, fs_err, mount_err, del_err)
  if final_err != nil { util.Fatalf("%v", final_err) }
  // Special snowflake test, do not run automatically
  //suite.TestListUMount_Mount_Cycle()
}

