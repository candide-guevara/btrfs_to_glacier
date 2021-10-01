package types

import "context"
import "errors"
import "io"
import pb "btrfs_to_glacier/messages"

var ErrNotFound = errors.New("key_not_found_in_metadata")
var ErrMissingChunks = errors.New("not_all_chunks_uploaded")

type ChunksOrError struct {
  Val *pb.SnapshotChunks
  Err error
}

type RestoreStatus int
const (
  Unknown  RestoreStatus = iota
  Pending  RestoreStatus = iota
  Restored RestoreStatus = iota
)

type ObjRestoreOrErr struct {
  Stx RestoreStatus
  Err error
}
type RestoreResult = map[string]ObjRestoreOrErr

// Usage example:
// for it.Next(ctx, val) { ... }
// if it.Err() != nil { ... }
type SnapshotSeqHeadIterator interface {
  Next(context.Context, *pb.SnapshotSeqHead) bool
  Err() error
}
type SnapshotSequenceIterator interface {
  Next(context.Context, *pb.SnapshotSequence) bool
  Err() error
}
type SnapshotIterator interface {
  Next(context.Context, *pb.SubVolume) bool
  Err() error
}
type SnapshotChunksIterator interface {
  Next(context.Context, *pb.SnapshotChunks_Chunk) bool
  Err() error
}

type Metadata interface {
  // Sets `new_seq` as the snaps sequence that will be appended when backing up the corresponding volume.
  // If there is not already a sequence head, a new one will be created.
  // Otherwise updates the current head and archives the previously current.
  // If `new_seq` is already the current sequence, this is a noop.
  // This should be called **after** the snapshot sequence has been persisted.
  // Returns the new SnapshotSeqHead just persisted.
  RecordSnapshotSeqHead(ctx context.Context, new_seq *pb.SnapshotSequence) (*pb.SnapshotSeqHead, error)

  // Adds `snap` to `seq` and persists `seq`.
  // Returns the new state of the snapshot sequence.
  // This should be called **after** the snapshot has been persisted.
  // If `snap` is already the last snapshot in the sequence this is a noop.
  AppendSnapshotToSeq(ctx context.Context, seq *pb.SnapshotSequence, snap *pb.SubVolume) (*pb.SnapshotSequence, error)

  // Adds `chunk` and records it into the subvolume `snap`.
  // If `chunk` is not the first, it must match the previous fingerprint.
  // Returns the new state of the subvolume metadata.
  // If `chunk` is already the last recorded in `snap` this is a noop.
  AppendChunkToSnapshot(ctx context.Context, snap *pb.SubVolume, chunk *pb.SnapshotChunks) (*pb.SubVolume, error)

  // Reads sequence head for subvolume with `uuid`.
  // If there is no head, returns `ErrNotFound`.
  ReadSnapshotSeqHead(ctx context.Context, uuid string) (*pb.SnapshotSeqHead, error)

  // Reads snapshot sequence with key `uuid`.
  // If there is no sequence, returns `ErrNotFound`.
  ReadSnapshotSeq(ctx context.Context, uuid string) (*pb.SnapshotSequence, error)

  // Reads subvolume with `uuid`.
  // If there is no subvolume, returns `ErrNotFound`.
  ReadSnapshot(ctx context.Context, uuid string) (*pb.SubVolume, error)

  // Returns all heads in no particular order.
  ListAllSnapshotSeqHeads(ctx context.Context) (SnapshotSeqHeadIterator, error)

  // Returns all sequences in no particular order.
  ListAllSnapshotSeqs(ctx context.Context) (SnapshotSequenceIterator, error)

  // Returns all snapshots in no particular order.
  ListAllSnapshots(ctx context.Context) (SnapshotIterator, error)
}

// Separate from `Metadata` since it contains dangerous operations that should only be invoked by admins.
type AdminMetadata interface {
  Metadata

  // Creates the infrastructure (depend on implementation) that will contain the metadata.
  // Creation can take some time so it is done asynchronously.
  // If the channel contains a null error then the infrastructure has been created ok and is ready to use.
  // It is a noop if they are already created.
  SetupMetadata(ctx context.Context) (<-chan error)

  // Deletes sequence head for subvolume with `uuid`.
  // If there is no head, returns `ErrNotFound`.
  // This should be called **before** the snapshot sequences referenced by the head have been deleted.
  DeleteSnapshotSeqHead(ctx context.Context, uuid string) error

  // Deletes snapshot sequence with key `uuid`.
  // If there is no sequence, returns `ErrNotFound`.
  // This should be called **before** the snapshots referenced by the sequence have been deleted.
  DeleteSnapshotSeq(ctx context.Context, uuid string) error

  // Deletes subvolume with `uuid`.
  // If there is no subvolume, returns `ErrNotFound`.
  DeleteSnapshot(ctx context.Context, uuid string) error

  // Deletes all items corresponding to the uuids.
  // Uuids not existing will be ignored.
  // Even if an error is returned, some items may have been deleted.
  DeleteMetadataUuids(ctx context.Context, seq_uuids []string, snap_uuids []string) (<-chan error)

  // Replaces a head with a different one.
  // Returns the old head that got replaced.
  // If there was no old head, returns `ErrNotFound` and no item will be written.
  ReplaceSnapshotSeqHead(ctx context.Context, head *pb.SnapshotSeqHead) (*pb.SnapshotSeqHead, error)
}

type Storage interface {
  // Reads `read_pipe` and uploads its content in equally sized chunks.
  // If `offset` > 0 then the first part of the stream is dropped and the rest will be uploaded.
  // Data may be filtered by a codec depending on the implementation.
  // Chunk length is determined by configuration.
  // Returns the ids of all chunks uploaded. If some error prevented all pipe content from being uploaded,
  // then ChunksOrError.Err will contain ErrMissingChunks as well as the chunks that got uploaded.
  // Takes ownership of `read_pipe` and will close it once done.
  WriteStream(ctx context.Context, offset uint64, read_pipe io.ReadCloser) (<-chan ChunksOrError, error)

  // Request all objects identified by `uuids` to be restored so they can be downloaded.
  // Restoration can take several hours, this method will return sooner, after all object restore requests
  // have been sent.
  // Restoring an already restored object is a noop (or it can extend the restored lifetime).
  // Restoring an object which is not archived is a noop.
  // Clients can use this method to poll and get the status of their pending restores.
  // Returns a result per object, for some the restore may have failed.
  QueueRestoreObjects(ctx context.Context, uuids []string) (<-chan RestoreResult, error)

  // Reads all `chunks` in order and outputs them to a stream.
  // Data may be filtered by a codec depending on the implementation.
  // A permanent error while reading a chunk will close the stream.
  ReadChunksIntoStream(ctx context.Context, chunks *pb.SnapshotChunks) (io.ReadCloser, error)

  // Returns all chunks in no particular order.
  // Not all chunk fields may be filled.
  ListAllChunks(ctx context.Context) (SnapshotChunksIterator, error)
}

// Separate from `Storage` since it contains dangerous operations that should only be invoked by admins.
type AdminStorage interface {
  Storage

  // Creates the infrastructure (depend on implementation) that will contain the storage.
  // Creation can take some time so it is done asynchronously.
  // If the channel contains a null error then the infrastructure has been created ok and is ready to use.
  // It is a noop if they are already created.
  SetupStorage(ctx context.Context) (<-chan error)

  // Deletes all objects in `chunks`.
  // If the channel contains a null error then all objects got deleted.
  // Objects not found (already deleted?) should be a noop.
  DeleteChunks(ctx context.Context, chunks []*pb.SnapshotChunks_Chunk) (<-chan error)
}

