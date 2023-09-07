package shim

import (
  "fmt"
  "io/fs"
  fpmod "path/filepath"
  "os"
  "strings"
  "testing"

  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
)

type SysUtilMock_ForBtrfs struct { *SysUtilForTest }

func (self *SysUtilMock_ForBtrfs) ReadAsciiFile(
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
  case fpmod.Base(types.SYS_FS_UUID):
    return fpmod.Base(dir), nil
  case fpmod.Base(types.SYS_FS_LABEL):
    return fmt.Sprintf("%s_label", dir), nil
  case fpmod.Base(types.SYS_FS_DEVICE_FILE):
    return fmt.Sprintf("%d:%d", len(dir),len(dir)), nil
  }
  return "", fmt.Errorf("'%s/%s' not found in mock", dir, name)
}

func (self *SysUtilMock_ForBtrfs) ReadDir(dir string) ([]os.DirEntry, error) {
  switch dir {
    case DEV_BLOCK:
      return []fs.DirEntry{
        &DirEntry{ Leaf:"259:0", Mode:fs.ModeSymlink, },
        &DirEntry{ Leaf:"259:1", Mode:fs.ModeSymlink, },
        &DirEntry{ Leaf:"259:2", Mode:fs.ModeSymlink, },
        &DirEntry{ Leaf:"260:0", Mode:fs.ModeSymlink, },
        &DirEntry{ Leaf:"260:1", Mode:fs.ModeSymlink, },
      }, nil
    case DEV_BY_PART:
      return []fs.DirEntry{
        &DirEntry{ Leaf:"gpt-uuid-sdb2", Mode:fs.ModeSymlink, },
        &DirEntry{ Leaf:"gpt-uuid-sdb3", Mode:fs.ModeSymlink, },
        &DirEntry{ Leaf:"gpt-uuid-sdc1", Mode:fs.ModeSymlink, },
        &DirEntry{ Leaf:"gpt-uuid-loop111p1", Mode:fs.ModeSymlink, },
        &DirEntry{ Leaf:"gpt-uuid-loop111p2", Mode:fs.ModeSymlink, },
      }, nil
    case DEV_BY_UUID:
      return []fs.DirEntry{
        &DirEntry{ Leaf:"fs-uuid-sdb2", Mode:fs.ModeSymlink, },
        &DirEntry{ Leaf:"fs-uuid-sdb3", Mode:fs.ModeSymlink, },
        &DirEntry{ Leaf:"fs-uuid-sdc1", Mode:fs.ModeSymlink, },
        &DirEntry{ Leaf:"fs-uuid-loop111p1", Mode:fs.ModeSymlink, },
        &DirEntry{ Leaf:"fs-uuid-loop111p2", Mode:fs.ModeSymlink, },
      }, nil
    case DEV_MAPPER:
      return []fs.DirEntry{}, nil
    case types.SYS_FS_BTRFS:
      return []fs.DirEntry{
        &DirEntry{ Leaf:"fs1_uuid", Mode:fs.ModeDir, },
        &DirEntry{ Leaf:"fs2_uuid", Mode:fs.ModeDir, },
        &DirEntry{ Leaf:"fs3_uuid", Mode:fs.ModeDir, },
      }, nil
    case fpmod.Join(types.SYS_FS_BTRFS, "fs1_uuid"): fallthrough
    case fpmod.Join(types.SYS_FS_BTRFS, "fs2_uuid"): fallthrough
    case fpmod.Join(types.SYS_FS_BTRFS, "fs3_uuid"):
      return []fs.DirEntry{
        &DirEntry{ Leaf:types.SYS_FS_UUID },
        &DirEntry{ Leaf:types.SYS_FS_LABEL },
        &DirEntry{ Leaf:types.SYS_FS_DEVICE_DIR, Mode:fs.ModeDir, },
      }, nil
    case SYS_BLOCK:
      return []fs.DirEntry{}, nil
    case fpmod.Join(types.SYS_FS_BTRFS, "fs1_uuid", types.SYS_FS_DEVICE_DIR):
      return []fs.DirEntry{
        &DirEntry{ Leaf:"sdb2", Mode:fs.ModeSymlink },
        &DirEntry{ Leaf:"sdc1", Mode:fs.ModeSymlink },
      }, nil
    case fpmod.Join(types.SYS_FS_BTRFS, "fs2_uuid", types.SYS_FS_DEVICE_DIR):
      return []fs.DirEntry{ &DirEntry{ Leaf:"loop111p1", Mode:fs.ModeSymlink }, }, nil
    case fpmod.Join(types.SYS_FS_BTRFS, "fs3_uuid", types.SYS_FS_DEVICE_DIR):
      return []fs.DirEntry{ &DirEntry{ Leaf:"loop111p2", Mode:fs.ModeSymlink }, }, nil
  }
  return nil, fmt.Errorf("ReadDir '%s' not found in mock", dir)
}

func (self *SysUtilMock_ForBtrfs) EvalSymlinks(path string) (string, error) {
  switch path {
    case "/dev/disk/by-partuuid/gpt-uuid-sdb2": return "/dev/sdb2", nil
    case "/dev/disk/by-partuuid/gpt-uuid-sdb3": return "/dev/sdb3", nil
    case "/dev/disk/by-partuuid/gpt-uuid-sdc1": return "/dev/sdc1", nil
    case "/dev/disk/by-partuuid/gpt-uuid-loop111p1": return "/dev/loop111p1", nil
    case "/dev/disk/by-partuuid/gpt-uuid-loop111p2": return "/dev/loop111p2", nil

    case "/dev/disk/by-uuid/fs-uuid-sdb2": return "/dev/sdb2", nil
    case "/dev/disk/by-uuid/fs-uuid-sdb3": return "/dev/sdb3", nil
    case "/dev/disk/by-uuid/fs-uuid-sdc1": return "/dev/sdc1", nil
    case "/dev/disk/by-uuid/fs-uuid-loop111p1": return "/dev/loop111p1", nil
    case "/dev/disk/by-uuid/fs-uuid-loop111p2": return "/dev/loop111p2", nil

    case "/dev/block/259:0": return "/dev/sdb2", nil
    case "/dev/block/259:1": return "/dev/sdb3", nil
    case "/dev/block/259:2": return "/dev/sdc1", nil
    case "/dev/block/260:0": return "/dev/loop111p1", nil
    case "/dev/block/260:1": return "/dev/loop111p2", nil
    default:
      if strings.HasPrefix(path, types.SYS_FS_BTRFS) { return fpmod.Join("/dev", fpmod.Base(path)), nil }
  }
  return "", fmt.Errorf("EvalSymlinks '%s' not found in mock", path)
}

func TestListBtrfsFilesystems(t *testing.T) {
  linuxutils := &Linuxutil{ SysUtilIf: &SysUtilMock_ForBtrfs{}, }
  fs_list,err := linuxutils.ListBtrfsFilesystems()
  if err != nil { t.Errorf("ListBtrfsFilesystems: %v", err) }
  if len(fs_list) != 3 { t.Errorf("found wrong number of filesystems") }
  expect_fs_list := `[
  {
    "Uuid": "fs1_uuid",
    "Label": "/sys/fs/btrfs/fs1_uuid_label",
    "Devices": [
      {
        "Name": "sdb2",
        "MapperGroup": "",
        "Minor": 0,
        "Major": 259,
        "FsUuid": "fs-uuid-sdb2",
        "GptUuid": "gpt-uuid-sdb2",
        "LoopFile": ""
      },
      {
        "Name": "sdc1",
        "MapperGroup": "",
        "Minor": 2,
        "Major": 259,
        "FsUuid": "fs-uuid-sdc1",
        "GptUuid": "gpt-uuid-sdc1",
        "LoopFile": ""
      }
    ],
    "Mounts": [
      {
        "Id": 169,
        "Device": {
          "Name": "sdc1",
          "MapperGroup": "",
          "Minor": 2,
          "Major": 259,
          "FsUuid": "fs-uuid-sdc1",
          "GptUuid": "gpt-uuid-sdc1",
          "LoopFile": ""
        },
        "TreePath": "Lucian_PrioA",
        "MountedPath": "/media/Lucian_PrioA",
        "FsType": "btrfs",
        "Options": {
          "some_opt": "",
          "subvol": "/Lucian_PrioA",
          "subvolid": "260"
        },
        "BtrfsVolId": 260,
        "Binds": [
          {
            "Id": 189,
            "Device": {
              "Name": "sdc1",
              "MapperGroup": "",
              "Minor": 2,
              "Major": 259,
              "FsUuid": "fs-uuid-sdc1",
              "GptUuid": "gpt-uuid-sdc1",
              "LoopFile": ""
            },
            "TreePath": "Lucian_PrioA/Images",
            "MountedPath": "/home/cguevara/Images",
            "FsType": "btrfs",
            "Options": {
              "subvol": "/Lucian_PrioA",
              "subvolid": "260"
            },
            "BtrfsVolId": 260,
            "Binds": null
          },
          {
            "Id": 194,
            "Device": {
              "Name": "sdc1",
              "MapperGroup": "",
              "Minor": 2,
              "Major": 259,
              "FsUuid": "fs-uuid-sdc1",
              "GptUuid": "gpt-uuid-sdc1",
              "LoopFile": ""
            },
            "TreePath": "Lucian_PrioA/MyProj",
            "MountedPath": "/home/cguevara/Progr",
            "FsType": "btrfs",
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
        "Device": {
          "Name": "sdc1",
          "MapperGroup": "",
          "Minor": 2,
          "Major": 259,
          "FsUuid": "fs-uuid-sdc1",
          "GptUuid": "gpt-uuid-sdc1",
          "LoopFile": ""
        },
        "TreePath": "Lucian_PrioB",
        "MountedPath": "/media/Lucian_PrioB",
        "FsType": "btrfs",
        "Options": {
          "subvol": "/Lucian_PrioB",
          "subvolid": "258"
        },
        "BtrfsVolId": 258,
        "Binds": null
      },
      {
        "Id": 170,
        "Device": {
          "Name": "sdc1",
          "MapperGroup": "",
          "Minor": 2,
          "Major": 259,
          "FsUuid": "fs-uuid-sdc1",
          "GptUuid": "gpt-uuid-sdc1",
          "LoopFile": ""
        },
        "TreePath": "Lucian_PrioC",
        "MountedPath": "/media/Lucian_PrioC",
        "FsType": "btrfs",
        "Options": {
          "subvol": "/Lucian_PrioC",
          "subvolid": "259"
        },
        "BtrfsVolId": 259,
        "Binds": [
          {
            "Id": 199,
            "Device": {
              "Name": "sdc1",
              "MapperGroup": "",
              "Minor": 2,
              "Major": 259,
              "FsUuid": "fs-uuid-sdc1",
              "GptUuid": "gpt-uuid-sdc1",
              "LoopFile": ""
            },
            "TreePath": "Lucian_PrioC/Music",
            "MountedPath": "/home/cguevara/Music",
            "FsType": "btrfs",
            "Options": {
              "subvol": "/Lucian_PrioC",
              "subvolid": "259"
            },
            "BtrfsVolId": 259,
            "Binds": null
          },
          {
            "Id": 204,
            "Device": {
              "Name": "sdc1",
              "MapperGroup": "",
              "Minor": 2,
              "Major": 259,
              "FsUuid": "fs-uuid-sdc1",
              "GptUuid": "gpt-uuid-sdc1",
              "LoopFile": ""
            },
            "TreePath": "Lucian_PrioC/Video",
            "MountedPath": "/home/cguevara/Videos",
            "FsType": "btrfs",
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
        "Device": {
          "Name": "sdc1",
          "MapperGroup": "",
          "Minor": 2,
          "Major": 259,
          "FsUuid": "fs-uuid-sdc1",
          "GptUuid": "gpt-uuid-sdc1",
          "LoopFile": ""
        },
        "TreePath": "BifrostSnap",
        "MountedPath": "/media/BifrostSnap",
        "FsType": "btrfs",
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
        "MapperGroup": "",
        "Minor": 0,
        "Major": 260,
        "FsUuid": "fs-uuid-loop111p1",
        "GptUuid": "gpt-uuid-loop111p1",
        "LoopFile": ""
      }
    ],
    "Mounts": [
      {
        "Id": 527,
        "Device": {
          "Name": "loop111p1",
          "MapperGroup": "",
          "Minor": 0,
          "Major": 260,
          "FsUuid": "fs-uuid-loop111p1",
          "GptUuid": "gpt-uuid-loop111p1",
          "LoopFile": ""
        },
        "TreePath": "",
        "MountedPath": "/tmp/other_fs_src",
        "FsType": "btrfs",
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
        "Device": {
          "Name": "loop111p1",
          "MapperGroup": "",
          "Minor": 0,
          "Major": 260,
          "FsUuid": "fs-uuid-loop111p1",
          "GptUuid": "gpt-uuid-loop111p1",
          "LoopFile": ""
        },
        "TreePath": "asubvol",
        "MountedPath": "/tmp/asubvol_mnt",
        "FsType": "btrfs",
        "Options": {
          "subvol": "/asubvol",
          "subvolid": "257"
        },
        "BtrfsVolId": 257,
        "Binds": null
      },
      {
        "Id": 578,
        "Device": {
          "Name": "loop111p1",
          "MapperGroup": "",
          "Minor": 0,
          "Major": 260,
          "FsUuid": "fs-uuid-loop111p1",
          "GptUuid": "gpt-uuid-loop111p1",
          "LoopFile": ""
        },
        "TreePath": "snaps/asubvol.snap",
        "MountedPath": "/tmp/with spaces",
        "FsType": "btrfs",
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
        "MapperGroup": "",
        "Minor": 1,
        "Major": 260,
        "FsUuid": "fs-uuid-loop111p2",
        "GptUuid": "gpt-uuid-loop111p2",
        "LoopFile": ""
      }
    ],
    "Mounts": [
      {
        "Id": 544,
        "Device": {
          "Name": "loop111p2",
          "MapperGroup": "",
          "Minor": 1,
          "Major": 260,
          "FsUuid": "fs-uuid-loop111p2",
          "GptUuid": "gpt-uuid-loop111p2",
          "LoopFile": ""
        },
        "TreePath": "",
        "MountedPath": "/tmp/other_fs_dst",
        "FsType": "btrfs",
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
    t.Errorf(util.DiffLines(fs_list, expect_fs_list))
  }
}

