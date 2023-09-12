package types

import (
  "context"
  pb "btrfs_to_glacier/messages"
)

type HeadAndSequence struct {
  Head *pb.SnapshotSeqHead
  Cur  *pb.SnapshotSequence
}
type BackupPair struct {
  Sv   *pb.SubVolume
  // `Snap` should contain information about the chunks stored.
  Snap *pb.SubVolume
}
type RestorePair struct {
  // `Src` should contain information about the chunks stored.
  Src *pb.SubVolume
  Dst *pb.SubVolume
}
// Maps the subvolue uuid to the current snapshot sequence.
type HeadAndSequenceMap = map[string]HeadAndSequence
// Used internally by the BackupRestoreCanary to keep track of its state.
type CanaryToken = interface{}
const KCanaryDelDir = "deleted"
const KCanaryNewDir = "new"
const KCanaryUuidFile = "uuids"

// Convenient way to access the configuration objects referenced in a configuration.
type ParsedWorkflow struct {
  Wf      *pb.Workflow
  Source  *pb.Source
  Backup  *pb.Backup
  Restore *pb.Restore
}

// Maintains a small filesystem that can be restored from scratch and validated.
// Ensures that all stored volumes are still compatible and can be restored.
// Implementations may request CAP_SYS_ADMIN for some operations.
type BackupRestoreCanary interface {
  // Creates the canary filesystem.
  // Creates dummy subvolume if there is no data in the Metadata under test.
  // Calling this method twice is a noop.
  Setup(ctx context.Context) (CanaryToken, error)
  // Destroys the canary filesystem.
  // Calling this method twice or before `Setup()` is a noop.
  TearDown(ctx context.Context) error
  // Restores the whole snapshot sequence into the canary filesystem.
  // Validates the most recent snapshot according to its predecessors.
  // Calling this method multiple times without calling `AppendSnapshotToValidationChain` in between is an error.
  // Returns the restored pairs from storage that were validated.
  RestoreChainAndValidate(context.Context, CanaryToken) ([]RestorePair, error)
  // Modifies the restored subvolume (by making a clone) and adds another snapshot to the sequence.
  // Backups the new snapshot into the current sequence.
  // Calling this method multiple times without calling `RestoreChainAndValidate` in between is an error.
  // Returns the snapshot that was backed up and its corresponding entry in metadata.
  AppendSnapshotToValidationChain(context.Context, CanaryToken) (BackupPair, error)
}

// Handles volume backup from a particular source.
type BackupManager interface {
  // For all subvolumes in a source performs an **incremental** backup.
  // For each source subvolume `vol_uuid` checks:
  // * If `vol_uuid` has a recent enough snapshot then an incremental backup of it will be stored.
  // * If `vol_uuid` has no recent snapshots, a new one will be created on the fly.
  // If metadata does not contain any data for a given subvolume it will be created on the fly.
  // This operation is a noop for a given subvolume if a recent snapshot has already been backep-up.
  // Returns the pairs of (subvolume, incremental snapshot) in unspecified order.
  // An error indicates at least 1 subvolume could not be backep-up but other may have been.
  // (Given the idempotency of this operation, you can simply try again)
  BackupAllToCurrentSequences(context.Context, []*pb.SubVolume) ([]BackupPair, error)
  // Like `BackupToCurrentSequence` except that recent snapshots will not be re-used.
  // This is an advanced operation, behviour is undefined if no data has changed in the subvolumes.
  BackupAllToCurrentSequences_NoReUse(context.Context, []*pb.SubVolume) ([]BackupPair, error)
  // Like `BackupToCurrentSequence` except that:
  // * A **full** backup of the source subvolumes will be stored.
  // * Every call will always create a new `SnapshotSequence`.
  // Note that several calls to this method may NOT create each a snapshot in metadata or storage.
  // Rather the created sequences may point to an already stored recent snapshot.
  BackupAllToNewSequences(context.Context, []*pb.SubVolume) ([]BackupPair, error)
}

// TODO Who is responsible for this ?
// After a successful backup, old volumes will be removed from the source according to the config.

type BackupManagerAdmin interface {
  BackupManager
  // Creates the infrastructure (depend on implementation) that will contain the backup.
  // Calling this method twice is a noop.
  Setup(ctx context.Context) error

  // Performs the cleanups (depend on implementation) after the backups.
  // Calling this method twice is a noop.
  // Calling this method before setup is an error.
  TearDown(ctx context.Context) error

  // Used to append to a sequence a snapshot which is not related to the original subvolume.
  // Takes a snapshot from `sv` and appends it to the current sequence for SnapshotSeqHead `dst_uuid`.
  // This method expects a SnapshotSequence for `dst_uuid` in the metadata, otherwise it will return an error.
  // Returns the snapshot created for `sv`, however it will look like it is a snaphost of `dst_uuid`.
  // NON idempotent, the unrelated volume cannot have any pre-existing child snapshots.
  //
  // This is an advanced operation, the caller is responsible for `sv` to be compatible with the sequence.
  // For example `sv` is a clone from a restore of the original subvolume in `dst_uuid`.
  BackupToCurrentSequenceUnrelatedVol(
    ctx context.Context, sv *pb.SubVolume, dst_uuid string) (*pb.SubVolume, error)
}

// Handles volume restores to a particular destination.
// Implementations do not create the restore location if it does not exist.
type RestoreManager interface {
  // Reads all snapshot heads and their current sequence from Metadata.
  ReadHeadAndSequenceMap(ctx context.Context) (HeadAndSequenceMap, error)
  // Restores all of the snapshots for the most recent sequence corresponding to `vol_uuid`.
  // If some snapshots are already present at the destination, then only the new ones are restored.
  // If all snapshots have been restored this is a noop.
  // Returns both the snapshot from Metadata with its corresponding snapshot in the restored filesystem.
  // The return list follows the order in which each snapshot got restored.
  RestoreCurrentSequence(ctx context.Context, vol_uuid string) ([]RestorePair, error)
}

type RestoreManagerAdmin interface {
  RestoreManager
  // Creates the infrastructure (depend on implementation) that will contain the restore.
  // Calling this method twice is a noop.
  Setup(ctx context.Context) error

  // Performs the cleanups (depend on implementation) after the restores.
  // Calling this method twice is a noop.
  // Calling this method before setup is an error.
  TearDown(ctx context.Context) error
}
