package main

import (
  "fmt"
  "os"
  "os/exec"
  fpmod "path/filepath"
  "syscall"

  "btrfs_to_glacier/shim"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
)

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

type TestLinuxUtils struct {
  linuxutil *shim.Linuxutil
}

func (self *TestLinuxUtils) TestIsCapSysAdmin() {
  util.Infof("IsCapSysAdmin = %v", self.linuxutil.IsCapSysAdmin())
}

func (self *TestLinuxUtils) TestLinuxKernelVersion() {
  kmaj, kmin := self.linuxutil.LinuxKernelVersion()
  util.Infof("LinuxKernelVersion = %d.%d", kmaj, kmin)
  if kmaj < 1 { util.Fatalf("wrong version") }
}

func (self *TestLinuxUtils) TestBtrfsProgsVersion() {
  bmaj, bmin := self.linuxutil.BtrfsProgsVersion()
  util.Infof("BtrfsProgsVersion = %d.%d", bmaj, bmin)
  if bmaj < 1 { util.Fatalf("wrong version") }
}

func (self *TestLinuxUtils) TestProjectVersion() {
  version := self.linuxutil.ProjectVersion()
  util.Infof("ProjectVersion = %s", version)
  if len(version) < 1 { util.Fatalf("wrong version") }
}

func (self *TestLinuxUtils) TestDropRoot() {
  if !self.linuxutil.IsCapSysAdmin() {
    util.Warnf("TestLinuxUtils_TestDropRoot needs CAP_SYS_ADMIN")
    return
  }

  restore_f, err := self.linuxutil.DropRoot()
  if err != nil { util.Fatalf("cannot drop root: %v", err) }
  util.Debugf("getuid=%v", os.Geteuid())
  if os.Geteuid() == shim.ROOT_UID { util.Fatalf("did not change euid") }
  if self.linuxutil.IsCapSysAdmin() { util.Fatalf("still have cap sys admin") }

  cmd := exec.Command("ls", "/sys/kernel/debug")
  _, err = cmd.CombinedOutput()
  if err == nil { util.Fatalf("should not be able to list /sys/kernel/debug") }

  restore_f()
  if os.Geteuid() != shim.ROOT_UID { util.Fatalf("did not change euid") }
  if !self.linuxutil.IsCapSysAdmin() { util.Fatalf("could not obtain cap sys admin") }

  cmd = exec.Command("ls", "/sys/kernel/debug")
  _, err = cmd.CombinedOutput()
  if err != nil { util.Fatalf("should be able to list /sys/kernel/debug: %v", err) }
}

func (self *TestLinuxUtils) TestGetRoot() {
  if !self.linuxutil.IsCapSysAdmin() {
    util.Warnf("TestLinuxUtils_TestDropRoot needs CAP_SYS_ADMIN")
    return
  }

  restore_root, err := self.linuxutil.DropRoot()
  defer restore_root()
  restore_user, err := self.linuxutil.GetRoot()
  if err != nil { util.Fatalf("cannot get root: %v", err) }
  if os.Geteuid() != shim.ROOT_UID { util.Fatalf("did not change euid") }
  if !self.linuxutil.IsCapSysAdmin() { util.Fatalf("could not obtain cap sys admin") }
  util.Debugf("getuid=%v", os.Geteuid())

  restore_user()
  if os.Geteuid() == shim.ROOT_UID { util.Fatalf("did not change euid") }
  if self.linuxutil.IsCapSysAdmin() { util.Fatalf("still have cap sys admin") }
}

func (self *TestLinuxUtils) TestChownAsRealUser() {
  target_dir, err := os.MkdirTemp("", "TestChownAsRealUser")
  target_file := fpmod.Join(target_dir, "file")
  if err != nil { util.Fatalf("os.MkdirTemp: %v", err) }

  err = os.WriteFile(target_file, []byte("TestChownAsRealUser"), 0666)
  if err != nil { util.Fatalf("os.WriteFile: %v", err) }
  err = self.linuxutil.ChownAsRealUser(target_file)
  if err != nil { util.Fatalf("ChownAsRealUser_File: %v", err) }
  err = DoesNotBelongToRoot(target_file)
  if err != nil { util.Fatalf("TestChownAsRealUser_File: %v", err) }

  err = self.linuxutil.ChownAsRealUser(target_dir)
  if err != nil { util.Fatalf("ChownAsRealUser_Dir: %v", err) }
  err = DoesNotBelongToRoot(target_dir)
  if err != nil { util.Fatalf("TestChownAsRealUser_Dir: %v", err) }

  util.RemoveAll(target_dir)
}

func TestLinuxUtils_AllFuncs(
    linuxutil types.Linuxutil, src_fs string, dest_fs string) {
  suite := &TestLinuxUtils{linuxutil.(*shim.Linuxutil)}
  suite.TestIsCapSysAdmin()
  suite.TestLinuxKernelVersion()
  suite.TestBtrfsProgsVersion()
  suite.TestProjectVersion()
  suite.TestChownAsRealUser()
  suite.TestDropRoot()
  suite.TestGetRoot()
  TestFilesystemUtil_AllFuncs(linuxutil, src_fs, dest_fs)
}

