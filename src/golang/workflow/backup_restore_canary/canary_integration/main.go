package main

import (
  "btrfs_to_glacier/shim"
  "btrfs_to_glacier/util"
)

func main() {
  linuxutil, err := shim.NewLinuxutil(nil)
  if err != nil || !linuxutil.IsCapSysAdmin() {
    util.Fatalf("Canary integration test needs CAP_SYS_ADMIN: %v", err)
  }
  _, err = linuxutil.DropRoot()
  if err != nil { util.Fatalf("DropRoot: %v", err) }

  InMemMain()
  util.Infof("ALL DONE")
}

