package shim

import (
  "fmt"
  fpmod "path/filepath"
  "os"
  "os/exec"
  "strings"

  "btrfs_to_glacier/util"
)

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

