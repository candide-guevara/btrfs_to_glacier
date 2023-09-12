package types

import (
  "context"
  "errors"
  pb "btrfs_to_glacier/messages"
)

var ErrNotMounted = errors.New("subvolume_not_mounted")

// The raw operations from a btrfs-send dump
type SendDumpOperations struct {
  Written map[string]bool
  New map[string]bool
  NewDir map[string]bool
  Deleted map[string]bool
  DelDir map[string]bool
  FromTo map[string]string
  ToUuid string
  FromUuid string
}

func ByUuid(uuid string) func(*pb.SubVolume) bool {
  return func(sv *pb.SubVolume) bool { return sv.Uuid == uuid }
}
func ByReceivedUuid(uuid string) func(*pb.SubVolume) bool {
  return func(sv *pb.SubVolume) bool { return sv.ReceivedUuid == uuid }
}

// Implementations must be thread safe.
// Implementations may request CAP_SYS_ADMIN before calling any method from the interface.
type VolumeManager interface {
  // `path` must be the root of the volume.
  // If `path` does not point to a snapshot the corresponding fields will be empty.
  // Returns an error if `path` is not the root of a subvolume. The error may vary depending on `path`.
  GetVolume(path string) (*pb.SubVolume, error)
  // Returns the first subvolume in filesystem owning `fs_path` that matches.
  // Will return nil if nothing was found.
  FindVolume(fs_path string, matcher func(*pb.SubVolume) bool) (*pb.SubVolume, error)
  // Returns the list of subvolumes in filesystem owning `fs_path`.
  ListVolumes(fs_path string) ([]*pb.SubVolume, error)
  // Returns all snapshots whose parent is `subvol` (or an empty slice if there are snapshots for `subvol`).
  // Returned snaps are sorted by creation generation (oldest first).
  // `received_uuid` will only be set if the snapshot was effectibely received.
  GetSnapshotSeqForVolume(subvol *pb.SubVolume) ([]*pb.SubVolume, error)
  // Returns the changes between 2 snapshots of the same subvolume.
  // Both snaps must come from the same parent and `from` must be from a previous gen than `to`.
  GetChangesBetweenSnaps(ctx context.Context, from *pb.SubVolume, to *pb.SubVolume) (*pb.SnapshotChanges, error)
}

// Implementations must be thread safe.
// Implementations may request CAP_SYS_ADMIN before calling any method from the interface.
type VolumeSource interface {
  VolumeManager
  // Creates a read-only snapshot of `subvol`.
  // The path for the new snapshot will be determined by configuration.
  CreateSnapshot(subvol *pb.SubVolume) (*pb.SubVolume, error)
  // Same as `CreateSnapshot` but tries harder to avoid naming conflicts.
  // Advanced operation prefer `CreateSnapshot`.
  CreateSnapshotLongName(subvol *pb.SubVolume) (*pb.SubVolume, error)
  // Create a pipe with the data from the delta between `from` and `to` snapshots.
  // `from` can be nil to get the full snapshot content.
  GetSnapshotStream(ctx context.Context, from *pb.SubVolume, to *pb.SubVolume) (ReadEndIf, error)
}

// Implementations must be thread safe.
// Implementations may request CAP_SYS_ADMIN before calling any method from the interface.
type VolumeDestination interface {
  VolumeManager
  // Reads subvolume data from the pipe and creates a subvolume using `btrfs receive`.
  // Received subvolume will be mounted at `root_path/<basename_src_subvol>`.
  // As a safety check this method asserts that received snapshot is coherent with `src_snap`.
  // Takes ownership of `read_pipe` and will close it once done.
  ReceiveSendStream(ctx context.Context, root_path string, src_snap *pb.SubVolume, read_pipe ReadEndIf) (*pb.SubVolume, error)
}

// Implementations must be thread safe.
// Implementations may request CAP_SYS_ADMIN before calling any method from the interface.
type VolumeAdmin interface {
  // Diamond dependency
  VolumeSource
  VolumeDestination
  // Deletes a snapshot.
  // Deleting the same snapshot a second time is an error.
  // Returns an error if attempting to delete a write snapshot or subvolume.
  DeleteSnapshot(snap *pb.SubVolume) error
  // Goes through all snapshots fathered by `src_subvol` and deletes the oldest ones according to the parameters in the config.
  // Returns the list of snapshots deleted.
  // If there are no old snapshots this is a noop.
  TrimOldSnapshots(src_subvol *pb.SubVolume, dry_run bool) ([]*pb.SubVolume, error)
}

// Implementations must be thread safe.
// Should NOT require CAP_SYS_ADMIN in order to work.
// Btrfs API is just bad.
// * Some operations only take as input paths.
// * VolumeId are unique only within a filesystem.
// * We cannot use UUIDs to uniquely identify snapshots.
//   * Instead we need a pair (fs_path, vol_id)
//
// The following look ups are guaranteed to never return incorrect results.
// (They may however fail to find a correct result even if one exists)
// * MountedPath -> Filesystem
// * Filesystem, TreePath, VolId -> MountedPath (if mounted)
type BtrfsPathJuggler interface {
  // Returns the Filesystem, MountEntry and SubVolume Id that own `path`.
  // "Tighter" means the MountEntry returned has the longer prefix of `path` found.
  // Fails if `path` is not owned by a btrfs filesystem.
  // `path` must be an absolute path and must exist.
  // Bind mounts are ignored when searching.
  FindFsAndTighterMountOwningPath(path string) (*Filesystem, *MountEntry, uint64, error)
  // Returns the filesystem, mount entry and path to the root of `sv`.
  // "Tighter" means the MountEntry returned has the longer prefix of `path` found.
  // Requires the subvolume argument to have a TreePath.
  // Bind mounts are ignored when searching.
  // Only the filesystems in `fs_list` will be scanned looking for `sv`.
  // If no mount in `fs_list` is found for `sv` then returns ErrNotMounted.
  FindTighterMountForSubVolume(fs_list []*Filesystem, sv *pb.SubVolume) (*Filesystem, *MountEntry, string, error)
  // For each source returns its corresponding filesystem if the following are OK:
  // * Checks that all volumes for a given source belong to the same filesystem.
  // * Checks all subvolume paths actually point to the root of a subvolume.
  // * Checks each subvolume listed is different.
  // * Checks the snapshot path is within the correct filesystem.
  // Apply only to sources of type BTRFS, other sources will have a nil Filesystem in
  // their corresponding return value.
  CheckSourcesAndReturnCorrespondingFs([]*pb.Source) ([]*Filesystem, error)
}

