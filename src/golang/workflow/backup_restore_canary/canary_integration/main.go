package main

import (
  "btrfs_to_glacier/shim"
  "btrfs_to_glacier/util"
)

func main() {
  linuxutil, err := shim.NewLinuxutil(nil)
  if err != nil || !linuxutil.IsCapSysAdmin() {
    util.Warnf("Canary integration test needs CAP_SYS_ADMIN: %v", err)
    return
  }
  linuxutil.DropRootOrDie()

  //InMemMain()
  //LocalFsMain(linuxutil)
  AwsMain()
  util.Infof("ALL DONE")
}

