package shim

import (
  "fmt"
  "io/fs"
  fpmod "path/filepath"
  "os"
  "strings"
  "testing"

  "btrfs_to_glacier/util"
)

type FsReaderMock struct {}
type DirEntry struct {
  Leaf string
  IsLink bool
}

func (self *DirEntry) Name() string { return self.Leaf }
func (self *DirEntry) IsDir() bool { return !self.IsLink }
func (self *DirEntry) Type() fs.FileMode { var m fs.FileMode; return m }
func (self *DirEntry) Info() (fs.FileInfo, error) { return nil, nil }

func (self *FsReaderMock) ReadAsciiFile(
    dir string, name string, allow_ctrl bool) (string, error) {
  switch name {
    case fpmod.Base(MOUNT_INFO):
    return `
29  1   8:18 /                    /                     rw shared:1   - ext4  /dev/sdb2 rw
142 29  8:19 /                    /home                 rw shared:63  - ext4  /dev/sdb3 rw
169 29  0:38 /Lucian_PrioA        /media/Lucian_PrioA   rw shared:92  - btrfs /dev/sdc1 some_opt,subvolid=260,subvol=/Lucian_PrioA
172 29  0:38 /Lucian_PrioB        /media/Lucian_PrioB   rw shared:89  - btrfs /dev/sdc1 subvolid=258,subvol=/Lucian_PrioB
170 29  0:38 /Lucian_PrioC        /media/Lucian_PrioC   rw shared:95  - btrfs /dev/sdc1 subvolid=259,subvol=/Lucian_PrioC
189 142 0:38 /Lucian_PrioA/Images /home/cguevara/Images rw shared:92  - btrfs /dev/sdc1 subvolid=260,subvol=/Lucian_PrioA
194 142 0:38 /Lucian_PrioA/MyProj /home/cguevara/Progr  rw shared:92  - btrfs /dev/sdc1 subvolid=260,blabla,subvol=/Lucian_PrioA
199 142 0:38 /Lucian_PrioC/Music  /home/cguevara/Music  rw shared:95  - btrfs /dev/sdc1 subvolid=259,subvol=/Lucian_PrioC
204 142 0:38 /Lucian_PrioC/Video  /home/cguevara/Videos rw shared:95  - btrfs /dev/sdc1 subvolid=259,subvol=/Lucian_PrioC
436 29  0:38 /BifrostSnap         /media/BifrostSnap    rw shared:219 - btrfs /dev/sdc1 subvolid=629,subvol=/BifrostSnap,silly_opt

527 1   0:43 /                    /tmp/other_fs_src     rw shared:279 - btrfs /dev/loop111p1 user_subvol_rm_allowed,subvolid=5,subvol=/
544 1   0:46 /                    /tmp/other_fs_dst     rw            - btrfs /dev/loop111p2 user_subvol_rm_allowed,subvolid=5,subvol=/
561 1   0:43 /asubvol             /tmp/asubvol_mnt      rw shared:298 - btrfs /dev/loop111p1 subvolid=257,subvol=/asubvol
578 1   0:43 /snaps/asubvol.snap  /tmp/with\040spaces   rw shared:341 - btrfs /dev/loop111p1 subvolid=258,subvol=/snaps/asubvol.snap
`, nil
  case fpmod.Base(SYS_FS_UUID):
    return fpmod.Base(dir), nil
  case fpmod.Base(SYS_FS_LABEL):
    return fmt.Sprintf("%s_label", dir), nil
  case fpmod.Base(SYS_FS_DEVICE_FILE):
    return fmt.Sprintf("%d:%d", len(dir),len(dir)), nil
  }
  return "", fmt.Errorf("'%s/%s' not found in mock", dir, name)
}

func (self *FsReaderMock) ReadDir(dir string) ([]os.DirEntry, error) {
  switch dir {
    case SYS_FS:
      return []fs.DirEntry{
        &DirEntry{ Leaf:"fs1_uuid" },
        &DirEntry{ Leaf:"fs2_uuid" },
        &DirEntry{ Leaf:"fs3_uuid" },
      }, nil
    case fpmod.Join(SYS_FS, "fs1_uuid"): fallthrough
    case fpmod.Join(SYS_FS, "fs2_uuid"): fallthrough
    case fpmod.Join(SYS_FS, "fs3_uuid"):
      return []fs.DirEntry{
        &DirEntry{ Leaf:SYS_FS_UUID },
        &DirEntry{ Leaf:SYS_FS_LABEL },
        &DirEntry{ Leaf:SYS_FS_DEVICE_DIR },
      }, nil
    case fpmod.Join(SYS_FS, "fs1_uuid", SYS_FS_DEVICE_DIR):
      return []fs.DirEntry{
        &DirEntry{ Leaf:"sda1", IsLink:true },
        &DirEntry{ Leaf:"sdc1", IsLink:true },
      }, nil
    case fpmod.Join(SYS_FS, "fs2_uuid", SYS_FS_DEVICE_DIR):
      return []fs.DirEntry{ &DirEntry{ Leaf:"loop111p1", IsLink:true }, }, nil
    case fpmod.Join(SYS_FS, "fs3_uuid", SYS_FS_DEVICE_DIR):
      return []fs.DirEntry{ &DirEntry{ Leaf:"loop111p2", IsLink:true }, }, nil
  }
  return nil, fmt.Errorf("'%s' not found in mock", dir)
}

func (self *FsReaderMock) EvalSymlinks(path string) (string, error) {
  return path, nil
}

func BuildLinuxutils(t *testing.T) *Linuxutil {
  lu := &Linuxutil{
    FsReader: &FsReaderMock{},
  }
  return lu
}

func TestListBtrfsFilesystems(t *testing.T) {
  linuxutils := BuildLinuxutils(t)
  fs_list,err := linuxutils.ListBtrfsFilesystems()
  if err != nil { t.Errorf("ListBtrfsFilesystems: %v", err) }
  if len(fs_list) != 3 { t.Errorf("found wrong number of filesystems") }
  expect_fs_list := `[
  {
    "Uuid": "fs1_uuid",
    "Label": "/sys/fs/btrfs/fs1_uuid_label",
    "Devices": [
      {
        "Name": "sda1",
        "Minor": 35,
        "Major": 35
      },
      {
        "Name": "sdc1",
        "Minor": 35,
        "Major": 35
      }
    ],
    "Mounts": [
      {
        "Id": 169,
        "Minor": 38,
        "Major": 0,
        "TreePath": "Lucian_PrioA",
        "MountedPath": "/media/Lucian_PrioA",
        "FsType": "btrfs",
        "DevPath": "/dev/sdc1",
        "Options": {
          "some_opt": "",
          "subvol": "/Lucian_PrioA",
          "subvolid": "260"
        },
        "BtrfsVolId": 260,
        "Binds": [
          {
            "Id": 189,
            "Minor": 38,
            "Major": 0,
            "TreePath": "Lucian_PrioA/Images",
            "MountedPath": "/home/cguevara/Images",
            "FsType": "btrfs",
            "DevPath": "/dev/sdc1",
            "Options": {
              "subvol": "/Lucian_PrioA",
              "subvolid": "260"
            },
            "BtrfsVolId": 260,
            "Binds": null
          },
          {
            "Id": 194,
            "Minor": 38,
            "Major": 0,
            "TreePath": "Lucian_PrioA/MyProj",
            "MountedPath": "/home/cguevara/Progr",
            "FsType": "btrfs",
            "DevPath": "/dev/sdc1",
            "Options": {
              "blabla": "",
              "subvol": "/Lucian_PrioA",
              "subvolid": "260"
            },
            "BtrfsVolId": 260,
            "Binds": null
          }
        ]
      },
      {
        "Id": 172,
        "Minor": 38,
        "Major": 0,
        "TreePath": "Lucian_PrioB",
        "MountedPath": "/media/Lucian_PrioB",
        "FsType": "btrfs",
        "DevPath": "/dev/sdc1",
        "Options": {
          "subvol": "/Lucian_PrioB",
          "subvolid": "258"
        },
        "BtrfsVolId": 258,
        "Binds": null
      },
      {
        "Id": 170,
        "Minor": 38,
        "Major": 0,
        "TreePath": "Lucian_PrioC",
        "MountedPath": "/media/Lucian_PrioC",
        "FsType": "btrfs",
        "DevPath": "/dev/sdc1",
        "Options": {
          "subvol": "/Lucian_PrioC",
          "subvolid": "259"
        },
        "BtrfsVolId": 259,
        "Binds": [
          {
            "Id": 199,
            "Minor": 38,
            "Major": 0,
            "TreePath": "Lucian_PrioC/Music",
            "MountedPath": "/home/cguevara/Music",
            "FsType": "btrfs",
            "DevPath": "/dev/sdc1",
            "Options": {
              "subvol": "/Lucian_PrioC",
              "subvolid": "259"
            },
            "BtrfsVolId": 259,
            "Binds": null
          },
          {
            "Id": 204,
            "Minor": 38,
            "Major": 0,
            "TreePath": "Lucian_PrioC/Video",
            "MountedPath": "/home/cguevara/Videos",
            "FsType": "btrfs",
            "DevPath": "/dev/sdc1",
            "Options": {
              "subvol": "/Lucian_PrioC",
              "subvolid": "259"
            },
            "BtrfsVolId": 259,
            "Binds": null
          }
        ]
      },
      {
        "Id": 436,
        "Minor": 38,
        "Major": 0,
        "TreePath": "BifrostSnap",
        "MountedPath": "/media/BifrostSnap",
        "FsType": "btrfs",
        "DevPath": "/dev/sdc1",
        "Options": {
          "silly_opt": "",
          "subvol": "/BifrostSnap",
          "subvolid": "629"
        },
        "BtrfsVolId": 629,
        "Binds": null
      }
    ]
  },
  {
    "Uuid": "fs2_uuid",
    "Label": "/sys/fs/btrfs/fs2_uuid_label",
    "Devices": [
      {
        "Name": "loop111p1",
        "Minor": 40,
        "Major": 40
      }
    ],
    "Mounts": [
      {
        "Id": 527,
        "Minor": 43,
        "Major": 0,
        "TreePath": "",
        "MountedPath": "/tmp/other_fs_src",
        "FsType": "btrfs",
        "DevPath": "/dev/loop111p1",
        "Options": {
          "subvol": "/",
          "subvolid": "5",
          "user_subvol_rm_allowed": ""
        },
        "BtrfsVolId": 5,
        "Binds": null
      },
      {
        "Id": 561,
        "Minor": 43,
        "Major": 0,
        "TreePath": "asubvol",
        "MountedPath": "/tmp/asubvol_mnt",
        "FsType": "btrfs",
        "DevPath": "/dev/loop111p1",
        "Options": {
          "subvol": "/asubvol",
          "subvolid": "257"
        },
        "BtrfsVolId": 257,
        "Binds": null
      },
      {
        "Id": 578,
        "Minor": 43,
        "Major": 0,
        "TreePath": "snaps/asubvol.snap",
        "MountedPath": "/tmp/with spaces",
        "FsType": "btrfs",
        "DevPath": "/dev/loop111p1",
        "Options": {
          "subvol": "/snaps/asubvol.snap",
          "subvolid": "258"
        },
        "BtrfsVolId": 258,
        "Binds": null
      }
    ]
  },
  {
    "Uuid": "fs3_uuid",
    "Label": "/sys/fs/btrfs/fs3_uuid_label",
    "Devices": [
      {
        "Name": "loop111p2",
        "Minor": 40,
        "Major": 40
      }
    ],
    "Mounts": [
      {
        "Id": 544,
        "Minor": 46,
        "Major": 0,
        "TreePath": "",
        "MountedPath": "/tmp/other_fs_dst",
        "FsType": "btrfs",
        "DevPath": "/dev/loop111p2",
        "Options": {
          "subvol": "/",
          "subvolid": "5",
          "user_subvol_rm_allowed": ""
        },
        "BtrfsVolId": 5,
        "Binds": null
      }
    ]
  }
]`
  if strings.Compare(util.AsJson(fs_list), expect_fs_list) != 0 {
    //util.Debugf("Got: %s", util.AsJson(fs_list))
    t.Errorf("Bad result: %v", fs_list)
  }
}
