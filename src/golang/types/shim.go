package types

import (
  "context"
  pb "btrfs_to_glacier/messages"
)

// Constants for the sysps pseudo filesystem linux interface.
const SYS_FS_BTRFS = "/sys/fs/btrfs"
const SYS_FS_FEATURE_DIR = "features"
const SYS_FS_UUID = "metadata_uuid"
const SYS_FS_LABEL = "label"
const SYS_FS_DEVICE_DIR = "devices"
const SYS_FS_DEVICE_FILE = "dev"

// Represents a line in /proc/self/mountinfo
// Many be enriched from info from other places ...
type MountEntry struct {
  Id int // NOT stable across reads of mountinfo
  Device *Device
  TreePath string
  MountedPath string
  FsType string
  Options map[string]string // correspond to the per-superblock options
  BtrfsVolId uint64
  // Bind mounts to the same filesystem/subvolume
  Binds []*MountEntry
}
type Device struct {
  Name string
  MapperGroup string // if device belongs to a virtual block device
  Minor, Major int // Unreliable when taken from /proc/self/mountinfo
  FsUuid string   // Optional
  GptUuid string  // Optional
  LoopFile string // Optional
}
type Filesystem struct {
  Uuid string
  Label string
  Devices []*Device
  Mounts []*MountEntry
}

// Implementations must be thread-safe.
type Linuxutil interface {
  // Returns true if this process is running with CAP_SYS_ADMIN privileges.
  // Many btrfs operations require this.
  IsCapSysAdmin() bool
  // The same as what you would get with `uname -a`.
  LinuxKernelVersion() (uint32, uint32)
  // The build version in the btrfs-progs header we are linking against.
  BtrfsProgsVersion() (uint32, uint32)
  // The git commit hash from which the current binary was built.
  ProjectVersion() string
  // Drops root privileges or dies if `seteuid` clib call fails.
  // Only works if go binary invoked via `sudo`.
  // Returns a function that can be called to restore back privileges.
  DropRoot() (func(), error)
  // Obtains root privileges back or dies if `seteuid` clib call fails.
  // Only works if go binary invoked via `sudo`.
  // Returns a function that can be called to restore user permissions.
  GetRoot() (func(), error)
  GetRootOrDie() func()

  // Mounts the device and checks it got mounted at desired path.
  // Mounted tree will belong to the executing user.
  // If device is already mounted at target, this is a noop.
  // This method should only return once the mount is fully visible.
  // Requires CAP_SYS_ADMIN (but will not be acquired)
  // or device needs to be mountable by the user in /etc/fstab.
  Mount(context.Context, string, string) (*MountEntry, error)
  UMount(context.Context, string) error
  // Returns all mounts found on the host that are backed by a block device.
  // Caveats:
  // * Bind mounts are NOT deduplicated.
  // * Mounts assotiated to multiple devices (ex: btrfs raid) will only have device assotiated
  // * Retrieves each mount `FsUUID` and `GptUUID` (if available: /dev/mapper does not have a GptUuid)
  ListBlockDevMounts() ([]*MountEntry, error)
  // Returns all btrfs filesystems found on the host.
  // Bind mounts to the same subvolume are deduplicated.
  // For each filesystem list all the mounts it owns.
  ListBtrfsFilesystems() ([]*Filesystem, error)
  // Creates a file of the size specified in Mb and a loop device backed by it.
  // This method should only return once the device is visible.
  // Requires CAP_SYS_ADMIN.
  CreateLoopDevice(context.Context, uint64) (*Device, error)
  // Deletes loop device and backing file.
  // Requires CAP_SYS_ADMIN.
  DeleteLoopDevice(context.Context, *Device) error
  // Creates a btrfs filesystem on the device.
  // This method should only return once the filesystem is visible.
  // Requires CAP_SYS_ADMIN.
  CreateBtrfsFilesystem(context.Context, *Device, string, ...string) (*Filesystem, error)
}

// Implementations must be thread-safe.
type Btrfsutil interface {
  // Get the `struct btrfs_util_subvolume_info` for a btrfs subvolume.
  // If `path` does not point to a snapshot the corresponding fields will be empty.
  // Requires CAP_SYS_ADMIN unless `path` is the root of the subvolume (even so some fields may be empty).
  SubVolumeInfo(path string) (*pb.SubVolume, error)
  // Returns the btrfs filesystem ID for the subvolume that owns `path`.
  // Works for any path under the volume.
  // Does NOT require CAP_SYS_ADMIN (even for non-root subvolume paths).
  SubVolumeIdForPath(path string) (uint64, error)
  // Returns an error unless `path` is the root of a btrfs subvolume.
  // It works even on the root subvolume.
  // Does NOT require CAP_SYS_ADMIN.
  IsSubVolumeMountPath(path string) error
  // Returns the TreePath of a volume in its btrfs filesystem.
  // Requires the argument to have a valid MountedPath (it can work with a path inside the volume).
  // Requires CAP_SYS_ADMIN.
  GetSubVolumeTreePath(*pb.SubVolume) (string, error)
  // Returns a list with all subvolumes in the filesystem that owns `path`.
  // If the subvolume is not a snapshot then the corresponding fields will be empty.
  // Requires CAP_SYS_ADMIN unless `is_root_fs=true` and `path` is the filesystem root.
  ListSubVolumesInFs(path string, is_root_fs bool) ([]*pb.SubVolume, error)
  // Reads a stream generated from `btrfs send --no-data` and returns a record of the operations.
  // Takes ownership of `read_pipe` and will close it once done.
  // Does NOT require CAP_SYS_ADMIN.
  ReadAndProcessSendStream(dump ReadEndIf) (*SendDumpOperations, error)
  // Starts a separate `btrfs send` and returns the read end of the pipe.
  // `no_data` is the same option as for `btrfs send`.
  // `from` can be null to get the full contents of the subvolume.
  // When `ctx` is done/cancelled the write end of the pipe should be closed and the forked process killed.
  // Requires CAP_SYS_ADMIN.
  StartSendStream(ctx context.Context, from string, to string, no_data bool) (ReadEndIf, error)
  // Wrapper around `btrfs receive`. `to_dir` must exist and be a directory.
  // The mounted path of the received subvol will be `to_dir/<basename_src_subvol>`.
  // Takes ownership of `read_pipe` and will close it once done.
  // Requires CAP_SYS_ADMIN.
  ReceiveSendStream(ctx context.Context, to_dir string, read_pipe ReadEndIf) error
  // Calls `btrfs_util_create_subvolume()` to new subvolume in `sv_path`.
  // Requires CAP_SYS_ADMIN.
  CreateSubvolume(sv_path string) error
  // Calls `btrfs_util_create_snapshot()` to create a clone of subvol at `sv_path` in `clone_path`.
  // Requires CAP_SYS_ADMIN.
  CreateClone(sv_path string, clone_path string) error
  // Calls `btrfs_util_create_snapshot()` to create a snapshot of `subvol` in `snap` path.
  // Sets the read-only flag.
  // Note async subvolume is no longer possible.
  // Requires CAP_SYS_ADMIN.
  CreateSnapshot(subvol string, snap string) error
  // Calls `btrfs_util_delete_subvolume` with empty `flags` argument.
  // Requires CAP_SYS_ADMIN.
  DeleteSubVolume(subvol string) error
}

