package shim

/*
#include <btrfs/version.h>
#include <stdlib.h>
#include <stdio.h>
#include <linux_utils.h>

// This macro is normally defined by the preprocessor flags introduced by `go env`
#ifndef BTRFS_TO_GLACIER_VERSION
#define BTRFS_TO_GLACIER_VERSION "NO_VERSION"
#endif
*/
import "C"
import (
  "fmt"
  fpmod "path/filepath"
  "os"
  "os/exec"
  "os/user"
  "strconv"
  "strings"
  "sync"

  "btrfs_to_glacier/util"
)

// user.User type is not convenient because it uses strings instead of ints
type User struct {
  Name     string
  Uid, Gid int
}

var (
  cap_sys_admin_mutex sync.Mutex
  cap_sys_admin_nesting uint32
  is_cap_sys_admin bool

  linux_version_mutex sync.Mutex
  has_linux_version bool
  linux_maj, linux_min uint32

  real_user_mutex sync.Mutex
  has_real_user bool
  real_user User
  NULL_USR  User
)

func init() {
  is_cap_sys_admin = C.is_cap_sys_admin() != 0
  NULL_USR = User{ Name:"", Uid:-1, Gid:-1 }
}

const ROOT_UID = 0

// This type is thread-safe.
type SysUtilImpl struct {}

func (self *SysUtilImpl) CombinedOutput(cmd *exec.Cmd) ([]byte, error) {
  // util.Debugf("%s found at %s", cmd.Args[0], cmd.Path)
  util.Debugf("%s", strings.Join(cmd.Args, " "))
  return cmd.CombinedOutput()
}

func (self *SysUtilImpl) ReadDir(dir string) ([]os.DirEntry, error) {
  return os.ReadDir(dir)
}

func (self *SysUtilImpl) EvalSymlinks(path string) (string, error) {
  return fpmod.EvalSymlinks(path)
}

func (self *SysUtilImpl) ReadAsciiFile(
    dir string, name string, allow_ctrl bool) (string, error) {
  fpath := fpmod.Join(dir, name)
  //util.Debugf("Reading: '%s'", fpath)
  bytes, err := os.ReadFile(fpath)
  if err != nil { return "", err }
  str := strings.TrimRight(string(bytes), "\n")
  err = util.IsOnlyAsciiString([]byte(str), allow_ctrl)
  if err != nil { err = fmt.Errorf("file:'%s', err:%v", fpath, err) }
  return str, err
}

func (self *SysUtilImpl) IsDir(p string) bool {
  return util.IsDir(p)
}

func (self *SysUtilImpl) Remove(p string) error {
  return os.Remove(p)
}

func (*SysUtilImpl) IsCapSysAdmin() bool {
  cap_sys_admin_mutex.Lock()
  defer cap_sys_admin_mutex.Unlock()
  return is_cap_sys_admin
}

func (self *SysUtilImpl) LinuxKernelVersion() (uint32, uint32) {
  linux_version_mutex.Lock()
  defer linux_version_mutex.Unlock()
  if !has_linux_version {
    var result C.struct_MajorMinor
    C.linux_kernel_version(&result)
    linux_maj = uint32(result.major)
    linux_min = uint32(result.minor)
    has_linux_version = true
  }
  return linux_maj, linux_min
}

func (*SysUtilImpl) BtrfsProgsVersion() (uint32, uint32) {
  var maj, min int
  tok_cnt, err := fmt.Sscanf(C.BTRFS_BUILD_VERSION, "Btrfs v%d.%d", &maj, &min)
  if tok_cnt != 2 || err != nil {
    panic("Failed to get btrfs progrs version from header.")
  }
  return uint32(maj), uint32(min)
}

func (*SysUtilImpl) ProjectVersion() string {
  return C.BTRFS_TO_GLACIER_VERSION
}

func UserToUser(go_user *user.User) (User, error) {
  uid, err := strconv.Atoi(go_user.Uid)
  if err != nil { return NULL_USR, err }
  gid, err := strconv.Atoi(go_user.Gid)
  if err != nil { return NULL_USR, err }
  return User{ Name:go_user.Username, Uid:uid, Gid:gid, }, nil
}

func (self *SysUtilImpl) GetRealUser() (User, error) {
  real_user_mutex.Lock()
  defer real_user_mutex.Unlock()
  if !has_real_user {
    env_var := os.Getenv("SUDO_UID")
    var ru *user.User
    var err error
    if len(env_var) == 0 {
      ru, err = user.Current()
      if err != nil { return NULL_USR, err }
    } else {
      sudo_uid, err := strconv.Atoi(env_var)
      if err != nil { return NULL_USR, err }
      if sudo_uid < 1 { return NULL_USR, fmt.Errorf("invalid sudo uid") }
      ru, err = user.LookupId(env_var)
    }
    real_user, err = UserToUser(ru)
    if err != nil { return NULL_USR, err }
    //util.Debugf("real_user=%v", real_user)
    has_real_user = true
  }
  return real_user, nil
}

func (self *SysUtilImpl) DropRoot() (func(), error) {
  ru, err := self.GetRealUser()
  if err != nil { return nil, err }

  cap_sys_admin_mutex.Lock()
  defer cap_sys_admin_mutex.Unlock()
  if !is_cap_sys_admin { return func() {}, nil }

  C.set_euid_or_die((C.int)(ru.Uid))
  cap_sys_admin_nesting += 1
  expect_nest := cap_sys_admin_nesting
  is_cap_sys_admin = false

  restore_f := func() {
    cap_sys_admin_mutex.Lock()
    defer cap_sys_admin_mutex.Unlock()
    if cap_sys_admin_nesting != expect_nest { util.Fatalf("DropRoot bad nesting") }
    C.set_euid_or_die(ROOT_UID)
    cap_sys_admin_nesting -= 1
    is_cap_sys_admin = true
  }
  return restore_f, nil
}

func (self *SysUtilImpl) GetRoot() (func(), error) {
  ru, err := self.GetRealUser()
  if err != nil { return nil, err }

  cap_sys_admin_mutex.Lock()
  defer cap_sys_admin_mutex.Unlock()
  if is_cap_sys_admin { return func() {}, nil }

  C.set_euid_or_die(ROOT_UID)
  cap_sys_admin_nesting += 1
  expect_nest := cap_sys_admin_nesting
  is_cap_sys_admin = true

  restore_f := func() {
    cap_sys_admin_mutex.Lock()
    defer cap_sys_admin_mutex.Unlock()
    if cap_sys_admin_nesting != expect_nest { util.Fatalf("GetRoot bad nesting") }
    C.set_euid_or_die((C.int)(ru.Uid))
    cap_sys_admin_nesting -= 1
    is_cap_sys_admin = false
  }
  return restore_f, nil
}

func (self *SysUtilImpl) GetRootOrDie() func() {
  drop_f, err := self.GetRoot()
  if err != nil { util.Fatalf("GetRootOrDie: %v", err) }
  return drop_f
}

func (self *SysUtilImpl) Chown(path string, owner User) error {
  return os.Chown(path, owner.Uid, owner.Gid)
}

