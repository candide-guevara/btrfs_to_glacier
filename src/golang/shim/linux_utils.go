package shim

import (
  "context"
  "errors"
  "fmt"
  "io/fs"
  fpmod "path/filepath"
  "os"
  "os/exec"
  "regexp"
  "strconv"
  "strings"
  "sync"
  "time"

  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
  pb "btrfs_to_glacier/messages"

  "github.com/google/uuid"
)

const DEV_BLOCK = "/dev/block" //ex: 8:1 -> ../sda1
const DEV_BY_PART = "/dev/disk/by-partuuid" //ex: YYYYYYYY-bc17-4e6f-9c1d-XXXXXXXXXXXX -> ../../sda3
const DEV_BY_UUID = "/dev/disk/by-uuid" //ex: ZZZZ-WWWW -> ../../sda1
const DEV_MAPPER = "/dev/mapper" //ex: mapper-group -> ../dm-0
const SYS_BLOCK = "/sys/block" // Block devices are presented like a tree. ex sda -> (sda1, sda2)
const MOUNT_INFO = "/proc/self/mountinfo"

type SysUtilIf interface {
  GetRealUser() (User, error)
  ReadAsciiFile(string, string, bool) (string, error)
  ReadDir(string) ([]os.DirEntry, error)
  IsDir(string) bool
  Remove(string) error
  EvalSymlinks(string) (string, error)
  CombinedOutput(*exec.Cmd) ([]byte, error)
  Chown(string, User) error

  // Part of public interface
  IsCapSysAdmin() bool
  LinuxKernelVersion() (uint32, uint32)
  BtrfsProgsVersion() (uint32, uint32)
  ProjectVersion() string
  DropRoot() (func(), error)
  GetRoot() (func(), error)
  GetRootOrDie() func()
}

// This type is thread-safe.
type Linuxutil struct {
  SysUtilIf
  mutex    sync.Mutex
}

func NewLinuxutil(conf *pb.Config) (types.Linuxutil, error) {
  return &Linuxutil{ 
    SysUtilIf: new(SysUtilImpl),
  }, nil
}

func majminFromString(in string) (int,int,error) {
  sep_idx := strings.Index(in, ":")
  if sep_idx < 1 { return 0,0, fmt.Errorf("bad format for device/dev file, expectin maj:min") }
  maj, err := strconv.Atoi(in[:sep_idx])
  if err != nil { return 0,0, err }
  min, err := strconv.Atoi(in[sep_idx+1:])
  if err != nil { return 0,0, err }
  return maj, min, nil
}

func (self *Linuxutil) parseMountOptions(line string) (map[string]string, error) {
  opts := make(map[string]string)
  for _,kv := range strings.Split(line, ",") {
    var err error
    var key, val string
    eq_idx := strings.Index(kv, "=")
    if eq_idx > -1 {
      key, err = strconv.Unquote(fmt.Sprintf(`"%s"`, kv[:eq_idx]))
      if err != nil { return nil, err }
      val, err = strconv.Unquote(fmt.Sprintf(`"%s"`, kv[eq_idx+1:]))
      if err != nil { return nil, err }
    } else {
      key, err = strconv.Unquote(fmt.Sprintf(`"%s"`, kv))
      if err != nil { return nil, err }
      val = ""
    }
    opts[key] = val
  }
  return opts, nil
}

// Note : there is a c library to do this, but re-implementing is easier.
// https://git.kernel.org/pub/scm/utils/util-linux/util-linux.git/tree/libmount
//
// be careful it is a trap ! the major/minor numbers in this file do not correspond to the device major/minor
//
//29  1   8:18 /                    /                     rw,... shared:1   - ext4  /dev/sdb2 rw
//142 29  8:19 /                    /home                 rw,... shared:63  - ext4  /dev/sdb3 rw
//169 29  0:38 /Lucian_PrioA        /media/Lucian_PrioA   rw,... shared:92  - btrfs /dev/sdc1 subvolid=260,subvol=/Lucian_PrioA
//172 29  0:38 /Lucian_PrioB        /media/Lucian_PrioB   rw,... shared:89  - btrfs /dev/sdc1 subvolid=258,subvol=/Lucian_PrioB
//170 29  0:38 /Lucian_PrioC        /media/Lucian_PrioC   rw,... shared:95  - btrfs /dev/sdc1 subvolid=259,subvol=/Lucian_PrioC
//189 142 0:38 /Lucian_PrioA/Images /home/cguevara/Images rw,... shared:92  - btrfs /dev/sdc1 subvolid=260,subvol=/Lucian_PrioA
//194 142 0:38 /Lucian_PrioA/MyProj /home/cguevara/Progr  rw,... shared:92  - btrfs /dev/sdc1 subvolid=260,subvol=/Lucian_PrioA
//199 142 0:38 /Lucian_PrioC/Music  /home/cguevara/Music  rw,... shared:95  - btrfs /dev/sdc1 subvolid=259,subvol=/Lucian_PrioC
//204 142 0:38 /Lucian_PrioC/Video  /home/cguevara/Videos rw,... shared:95  - btrfs /dev/sdc1 subvolid=259,subvol=/Lucian_PrioC
//436 29  0:38 /BifrostSnap         /media/BifrostSnap    rw,... shared:219 - btrfs /dev/sdc1 subvolid=629,subvol=/BifrostSnap
//451 29  0:38 /                    /media/Bifrost        rw,... shared:252 - btrfs /dev/sdc1 subvolid=5,subvol=/
//
//578 37  0:43 /snaps/asubvol.snap  /tmp/with\040spaces   rw,... shared:341 - btrfs /dev/loop111p1 subvolid=258,subvol=/snaps/asubvol.snap
func (self *Linuxutil) parseProcMountInfoFile() ([]*types.MountEntry, error) {
  const ID_IDX = 0
  const MAJMIN_IDX = 2
  const TREE_IDX = 3
  const MOUNT_IDX = 4
  const FS_IDX = 1
  const DEV_IDX = 2
  const OPT_IDX = 3
  const OPT_FLD_END = "-"

  var mnt_list []*types.MountEntry
  rx := regexp.MustCompile(" +")
  file_content, err := self.SysUtilIf.ReadAsciiFile(fpmod.Dir(MOUNT_INFO),
                                                  fpmod.Base(MOUNT_INFO), true)
  if err != nil { return nil, err }

  for _,line := range strings.Split(file_content, "\n") {
    mnt := &types.MountEntry{ Device: &types.Device{}, }
    toks := rx.Split(line, /*all_matches=*/-1)
    if len(line) < 1 || len(toks) < 1 { continue }

    mnt.Device.Major, mnt.Device.Minor, err = majminFromString(toks[MAJMIN_IDX])
    if err != nil { return nil, err }

    mnt.Id, err = strconv.Atoi(toks[ID_IDX])
    if err != nil { return nil, err }

    mnt.TreePath = strings.TrimLeft(toks[TREE_IDX], "/")
    if len(mnt.TreePath) == len(toks[TREE_IDX]) {
      return nil, fmt.Errorf("mountinfo line malformed, expected path: '%s'", line)
    }
    mnt.TreePath, err = strconv.Unquote(fmt.Sprintf(`"%s"`, mnt.TreePath))
    if err != nil { return nil, err }

    mnt.MountedPath, err = strconv.Unquote(fmt.Sprintf(`"%s"`, toks[MOUNT_IDX]))
    if err != nil { return nil, err }

    var tok string
    sep_idx := 0
    for sep_idx,tok = range toks { if tok == OPT_FLD_END { break } }
    if sep_idx >= len(toks)-1 {
      return nil, fmt.Errorf("mountinfo line malformed, no separator: '%s'", line)
    }

    mnt.FsType, err = strconv.Unquote(fmt.Sprintf(`"%s"`, toks[sep_idx+FS_IDX]))
    if err != nil { return nil, err }
    mnt.Device.Name, err = strconv.Unquote(fmt.Sprintf(`"%s"`, toks[sep_idx+DEV_IDX]))
    if err != nil { return nil, err }
    mnt.Device.Name = fpmod.Base(mnt.Device.Name)
    mnt.Options, err = self.parseMountOptions(toks[sep_idx+OPT_IDX])
    if err != nil { return nil, err }

    mnt_list = append(mnt_list, mnt)
  }
  // util.Debugf("Found %d mount entries", len(mnt_list))
  return mnt_list, nil
}

// Example:
// nameOfTarget("/dev/disk/by-uuid", "<uuid>") -> sda3, nil
func (self *Linuxutil) nameOfTarget(path string, link string) (string, error) {
  real_path, err := self.SysUtilIf.EvalSymlinks(fpmod.Join(path, link))
  if err != nil { return "", err }
  return fpmod.Base(real_path), err
}

func (self *Linuxutil) ListBlockDevicesOnHost() (map[string]*types.Device, error) {
  return self.listBlockDevicesMatching(nil)
}

func (self *Linuxutil) listBlockDevicesMatching(
    include_rx *regexp.Regexp) (map[string]*types.Device, error) {
  dev_list := make(map[string]*types.Device)

  items, err := self.SysUtilIf.ReadDir(DEV_BLOCK)
  if err != nil { return nil, err }
  for _,item := range items {
    if item.Type() & fs.ModeSymlink == 0 { continue }
    name, err := self.nameOfTarget(DEV_BLOCK, item.Name())
    if include_rx != nil && !include_rx.MatchString(name) { continue }
    if err != nil { return nil, err }
    maj, min, err := majminFromString(item.Name())
    if err != nil { return nil, err }
    dev_list[name] = &types.Device{ Name:name, Major:maj, Minor:min, }
  }

  items, err = self.SysUtilIf.ReadDir(DEV_MAPPER)
  if err != nil { return nil, err }
  for _,item := range items {
    if item.Type() & fs.ModeSymlink == 0 { continue }
    name, err := self.nameOfTarget(DEV_MAPPER, item.Name())
    if err != nil { return nil, err }
    dev, found := dev_list[name]
    if !found { continue }
    dev.MapperGroup = item.Name()
  }

  items, err = self.SysUtilIf.ReadDir(DEV_BY_PART)
  if err != nil { return nil, err }
  for _,item := range items {
    if item.Type() & fs.ModeSymlink == 0 { continue }
    name, err := self.nameOfTarget(DEV_BY_PART, item.Name())
    if err != nil { return nil, err }
    dev, found := dev_list[name]
    if !found { continue }
    dev.GptUuid = item.Name()
  }

  items, err = self.SysUtilIf.ReadDir(DEV_BY_UUID)
  if err != nil { return nil, err }
  for _,item := range items {
    //util.Debugf("%s/%s", DEV_BY_UUID, item.Name())
    if item.Type() & fs.ModeSymlink == 0 { continue }
    name, err := self.nameOfTarget(DEV_BY_UUID, item.Name())
    if err != nil { return nil, err }
    //util.Debugf("link: %s", name)
    dev, found := dev_list[name]
    if !found { continue }
    dev.FsUuid = item.Name()
  }

  items, err = self.SysUtilIf.ReadDir(SYS_BLOCK)
  if err != nil { return nil, err }
  for _,item := range items {
    prop_dir := fpmod.Join(SYS_BLOCK, item.Name(), "loop")
    if !self.SysUtilIf.IsDir(prop_dir) { continue }
    backing_file, err := self.SysUtilIf.ReadAsciiFile(prop_dir, "backing_file", false)
    if errors.Is(err, fs.ErrNotExist) { continue }
    if err != nil { return nil, err }
    dev, found := dev_list[item.Name()]
    if found { dev.LoopFile = backing_file }

    parts, err := self.SysUtilIf.ReadDir(fpmod.Join(SYS_BLOCK, item.Name()))
    if err != nil { return nil, err }
    for _,part := range parts {
      dev, found := dev_list[part.Name()]
      if found { dev.LoopFile = backing_file }
    }
  }
  return dev_list, nil
}

func (self *Linuxutil) mergeDevicesToMounts(mnt_list []*types.MountEntry, dev_map map[string]*types.Device) []*types.MountEntry {
  filter_mnts := make([]*types.MountEntry, 0, len(mnt_list))
  for _, mnt := range mnt_list {
    dev, found := dev_map[mnt.Device.Name]
    if !found {
      //util.Debugf("Mapper for '%s' %s", mnt.MountedPath, mnt.Device.Name)
      for _,d := range dev_map {
        if d.MapperGroup == mnt.Device.Name { dev = d; found = true; break }
      }
    }
    if !found { continue }
    mnt.Device = dev
    filter_mnts = append(filter_mnts, mnt)
  }
  return filter_mnts
}

func (self *Linuxutil) ListBlockDevMounts() ([]*types.MountEntry, error) {
  mnt_list, err := self.parseProcMountInfoFile()
  if err != nil { return nil, err }
  dev_map, err := self.ListBlockDevicesOnHost()
  if err != nil { return nil, err }
  filter_mnts := self.mergeDevicesToMounts(mnt_list, dev_map)
  return filter_mnts, nil
}

func (self *Linuxutil) ChownAsRealUser(path string) error {
  ru, err := self.SysUtilIf.GetRealUser()
  if err != nil { return err }
  err = self.SysUtilIf.Chown(path, ru)
  return err
}

func (self *Linuxutil) IsMounted(
    ctx context.Context, fs_uuid string, target string) (*types.MountEntry, error) {
  mnt_list, err := self.ListBlockDevMounts()
  if err != nil { return nil, err }
  for _,mnt := range mnt_list {
    if mnt.Device.FsUuid != fs_uuid || mnt.MountedPath != target { continue }
    return mnt, nil
  }
  return nil, nil
}

func (self *Linuxutil) Mount(
    ctx context.Context, fs_uuid string, target string) (*types.MountEntry, error) {
  if mnt, err := self.IsMounted(ctx, fs_uuid, target); err != nil || mnt != nil {
    return mnt, err
  }
  self.mutex.Lock()
  defer self.mutex.Unlock()

  cmd := exec.CommandContext(ctx, "mount", "-o", "user", fmt.Sprintf("UUID=%s", fs_uuid))
  _, err_mnt := self.SysUtilIf.CombinedOutput(cmd)
  // In case the filesystem is not in /etc/fstab add the target explicitely
  if err_mnt != nil {
    cmd := exec.CommandContext(ctx, "mount", "-o", "user", fmt.Sprintf("UUID=%s", fs_uuid), target)
    _, err_mnt = self.SysUtilIf.CombinedOutput(cmd)
  }
  if err_mnt != nil {
    fstab_msg := fmt.Sprintf("You may need to configure /etc/fstab, example:\nUUID=%s %s auto noauto,user,noatime,nodiratime,noexec 0 2",
                             fs_uuid, target)
    return nil, fmt.Errorf("failed to mount: %w\n%s", err_mnt, fstab_msg)
  }

  for range make([]int, 50) {
    mnt, err := self.IsMounted(ctx, fs_uuid, target)
    if err != nil { return mnt, err }
    if mnt != nil {
      err = self.ChownAsRealUser(mnt.MountedPath)
      return mnt, err
    }
    time.Sleep(util.MedTimeout)
  }
  return nil, fmt.Errorf("timeout while waiting for mount to be visible '%s'", fs_uuid)
}

func (self *Linuxutil) UMount(ctx context.Context, fs_uuid string) error {
  self.mutex.Lock()
  defer self.mutex.Unlock()

  cmd := exec.CommandContext(ctx, "umount", fmt.Sprintf("UUID=%s", fs_uuid))
  util.Debugf("Running: %s", cmd.String())
  _, err_mnt := self.SysUtilIf.CombinedOutput(cmd)

  mnt_list, err := self.ListBlockDevMounts()
  if err != nil { return err }

  for _,mnt := range mnt_list {
    if mnt.Device.FsUuid != fs_uuid { continue }
    return fmt.Errorf("%s is still mounted at %s: %w", fs_uuid, mnt.MountedPath, err_mnt)
  }
  return nil
}

func (self *Linuxutil) CreateLoopDevice(
    ctx context.Context, size_mb uint64) (*types.Device, error) {
  self.mutex.Lock()
  defer self.mutex.Unlock()

  backing_file := fpmod.Join(os.TempDir(), uuid.NewString())
  cmd := exec.CommandContext(ctx, "dd", "if=/dev/zero", "count=1",
                             fmt.Sprintf("of=%s", backing_file), fmt.Sprintf("bs=%dM", size_mb))
  if _, err := self.SysUtilIf.CombinedOutput(cmd); err != nil { return nil, err }
  bail_out := func(err error) (*types.Device, error) { self.SysUtilIf.Remove(backing_file); return nil, err }
  err := self.ChownAsRealUser(backing_file)
  if err != nil { return bail_out(err) }

  cmd = exec.CommandContext(ctx, "losetup", "-f")
  stdout, err := self.SysUtilIf.CombinedOutput(cmd)
  if err != nil { return bail_out(err) }
  devpath := strings.TrimSpace(util.SanitizeShellInput(stdout))
  devname := fpmod.Base(devpath)

  cmd = exec.CommandContext(ctx, "losetup", devpath, backing_file)
  if _, err := self.SysUtilIf.CombinedOutput(cmd); err != nil { return bail_out(err) }

  dev_filter := regexp.MustCompile(fmt.Sprintf("^%s$", devname))
  for range make([]int, 50) {
    dev_map, err := self.listBlockDevicesMatching(dev_filter)
    if err != nil { return bail_out(err) }
    dev, found := dev_map[devname]
    if found {
      util.Infof("New loop device: %v", dev.Name)
      return dev, nil
    }
    time.Sleep(util.MedTimeout)
  }
  return bail_out(fmt.Errorf("could not find loopdev: %s", devname))
}

func (self *Linuxutil) DeleteLoopDevice(ctx context.Context, dev *types.Device) error {
  self.mutex.Lock()
  defer self.mutex.Unlock()

  util.Infof("Deleting device: %v", dev.Name)
  devpath := fpmod.Join("/dev", dev.Name)
  cmd := exec.CommandContext(ctx, "losetup", "-d", devpath)
  if _, err := self.SysUtilIf.CombinedOutput(cmd); err != nil { return err }
  err := self.SysUtilIf.Remove(dev.LoopFile)
  return err
}

///////////////// BTRFS ///////////////////////////////////////////////////////

func treePathFromOpts(mnt *types.MountEntry) string {
  return strings.TrimLeft(mnt.Options["subvol"], "/")
}

// Make sure we can rely on the device name as a unique id for the filesystem.
func (self *Linuxutil) validateAndKeepOnlyBtrfsEntries(
    mnt_list []*types.MountEntry) ([]*types.MountEntry, error) {
  var new_list []*types.MountEntry
  devname_to_majmin := make(map[string]string)
  for _,mnt := range mnt_list {
    var err error
    if mnt.FsType != "btrfs" { continue }

    mnt.BtrfsVolId, err = strconv.ParseUint(mnt.Options["subvolid"], 10, 64)
    if err != nil { return nil, err }

    opt_tree_path := treePathFromOpts(mnt)
    if mnt.BtrfsVolId != BTRFS_FS_TREE_OBJECTID {
      if len(opt_tree_path) < 1 { return nil, fmt.Errorf("expected subvol path to be in options") }
      if !strings.HasPrefix(mnt.TreePath, opt_tree_path) {
        return nil, fmt.Errorf("mismatch between tree paths")
      }
    }

    majmin := fmt.Sprintf("%d%d", mnt.Device.Major, mnt.Device.Minor)
    devname := mnt.Device.Name
    expect,found := devname_to_majmin[devname]
    if found && expect != majmin { return nil, fmt.Errorf("devname is not unique") }
    if !found { devname_to_majmin[devname] = majmin }

    new_list = append(new_list, mnt)
  }
  util.Infof("Found %d/%d relevant mount entries", len(new_list), len(mnt_list))
  return new_list, nil
}

func (self *Linuxutil) collapseBtrfsBindMounts(
    mnt_list []*types.MountEntry) ([]*types.MountEntry, error) {
  masters := make(map[string]*types.MountEntry)
  // To avoid name collisions between different btrfs filesystems
  key_f := func(mnt *types.MountEntry) string {
    return fmt.Sprintf("%s%d", mnt.Device.Name, mnt.BtrfsVolId)
  }
  var new_list []*types.MountEntry

  for _,mnt := range mnt_list {
    if mnt.TreePath != treePathFromOpts(mnt) { continue }
    key := key_f(mnt)
    if _,found := masters[key]; found { return nil, fmt.Errorf("duplicate master mount") }
    masters[key] = mnt
  }
  for _,mnt := range mnt_list {
    key := key_f(mnt)
    master,found := masters[key]
    if !found { return nil, fmt.Errorf("no master mount found") }
    if master.Id == mnt.Id { new_list = append(new_list, mnt); continue }

    if !strings.HasPrefix(mnt.TreePath, master.TreePath) &&
      mnt.BtrfsVolId != master.BtrfsVolId {
      return nil, fmt.Errorf("mismatch between tree paths")
    }
    master.Binds = append(master.Binds, mnt)
  }
  util.Infof("Found %d/%d after collapsing bind mounts", len(new_list), len(mnt_list))
  return new_list, nil
}

func (self *Linuxutil) matchMountEntriesToFilesystem(
    mnt_list []*types.MountEntry, fs_list []*types.Filesystem) error {
  grp_by_devname := make(map[string][]*types.MountEntry)
  for _,mnt := range mnt_list {
    devname := mnt.Device.Name
    grp_by_devname[devname] = append(grp_by_devname[devname], mnt)
  }
  for _,fs := range fs_list {
    found_mnts := false
    for _,dev := range fs.Devices {
      mnts,found := grp_by_devname[dev.Name]
      if !found { continue }
      if found_mnts { return fmt.Errorf("fs has mount entries on several devices") }
      fs.Mounts = mnts
      found_mnts = true
    }
    if !found_mnts { return fmt.Errorf("fs '%s' has no mount entries", fs.Uuid) }
  }
  return nil
}

// Looks at relevant info in /sys/fs/btrfs/<uuid>/devices
func (self *Linuxutil) readSysFsBtrfsDir(dev_map map[string]*types.Device, path string) ([]*types.Device, error) {
  var dev_list []*types.Device
  items, err := self.SysUtilIf.ReadDir(path)
  if err != nil { return nil, err }

  for _,item := range items {
    dev, found := dev_map[item.Name()]
    if !found { util.Fatalf("Device '%s' referenced by '%s' not found", item.Name(), path) }
    dev_list = append(dev_list, dev)
  }
  return dev_list, nil
}

func (self *Linuxutil) btrfsFilesystemsFromSysFs(dev_map map[string]*types.Device) ([]*types.Filesystem, error) {
  return self.btrfsFilesystemsMatching(nil, dev_map)
}

// types.SYS_FS_BTRFS will only show filesystems that have been mounted.
func (self *Linuxutil) btrfsFilesystemsMatching(
    include_rx *regexp.Regexp, dev_map map[string]*types.Device) ([]*types.Filesystem, error) {
  var fs_list []*types.Filesystem
  items, err := self.SysUtilIf.ReadDir(types.SYS_FS_BTRFS)
  if err != nil { return nil, err }

  for _,item := range items {
    if !item.IsDir() { continue }
    if include_rx != nil && !include_rx.MatchString(item.Name()) { continue }
    if item.Name() == types.SYS_FS_FEATURE_DIR { continue }
    fs_item := &types.Filesystem{ Uuid: item.Name(), }
    dir_path := fpmod.Join(types.SYS_FS_BTRFS, fs_item.Uuid)
    items, err := self.SysUtilIf.ReadDir(dir_path)
    if err != nil { return nil, err }

    for _,item := range items {
      switch name := item.Name(); name {
        case types.SYS_FS_UUID:
          uuid, err := self.SysUtilIf.ReadAsciiFile(dir_path, name, false)
          if err != nil { return nil, err }
          if uuid != fs_item.Uuid { return nil, fmt.Errorf("fs uuid mismatch: %s != %s", uuid, fs_item.Uuid) }
        case types.SYS_FS_LABEL:
          label, err := self.SysUtilIf.ReadAsciiFile(dir_path, name, false)
          if err != nil { return nil, err }
          if len(label) < 1 { return nil, fmt.Errorf("expect fs to have a non empty label") }
          fs_item.Label = label
        case types.SYS_FS_DEVICE_DIR:
          devs, err := self.readSysFsBtrfsDir(dev_map, fpmod.Join(dir_path, name))
          if err != nil { return nil, err }
          fs_item.Devices = devs
      }
    }

    if len(fs_item.Label) > 0 && len(fs_item.Devices) > 0 {
      fs_list = append(fs_list, fs_item)
    }
  }
  util.Infof("Found %d btrfs filesystems", len(fs_list))
  return fs_list, nil
}

func (self *Linuxutil) CreateBtrfsFilesystem(
    ctx context.Context, dev *types.Device, label string, opts ...string) (*types.Filesystem, error) {
  self.mutex.Lock()
  defer self.mutex.Unlock()

  fs_uuid := uuid.NewString()
  all_opts := []string{ "--uuid", fs_uuid, "--label", label, }
  all_opts = append(all_opts, opts...)
  all_opts = append(all_opts, fpmod.Join("/dev", dev.Name))
  cmd := exec.CommandContext(ctx, "mkfs.btrfs", all_opts...)
  if _, err := self.SysUtilIf.CombinedOutput(cmd); err != nil { return nil, err }

  dev_rx := regexp.MustCompile(fmt.Sprintf("^%s$", dev.Name))
  for range make([]int, 50) {
    devs, err := self.listBlockDevicesMatching(dev_rx)
    if err != nil { return nil, err }
    for _,d := range devs {
      if d.FsUuid != fs_uuid { continue }
      util.Infof("New btrfs filesystem: %v", fs_uuid)
      fs := &types.Filesystem{
        Uuid: fs_uuid,
        Label: label,
        Devices: []*types.Device{ d, },
      }
      return fs, nil
    }
    time.Sleep(util.MedTimeout)
  }
  return nil, fmt.Errorf("Timedout waiting for '%s'", fs_uuid)
}

func (self *Linuxutil) ListBtrfsFilesystems() ([]*types.Filesystem, error) {
  mnt_list, err := self.parseProcMountInfoFile()
  if err != nil { return nil, err }
  mnt_list, err = self.validateAndKeepOnlyBtrfsEntries(mnt_list)
  if err != nil { return nil, err }

  dev_map, err := self.ListBlockDevicesOnHost()
  if err != nil { return nil, err }
  mnt_list = self.mergeDevicesToMounts(mnt_list, dev_map)

  mnt_list, err = self.collapseBtrfsBindMounts(mnt_list)
  if err != nil { return nil, err }

  fs_list, err := self.btrfsFilesystemsFromSysFs(dev_map)
  if err != nil { return nil, err }
  err = self.matchMountEntriesToFilesystem(mnt_list, fs_list)
  if err != nil { return nil, err }
  return fs_list, nil
}

