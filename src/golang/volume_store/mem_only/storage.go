package mem_only

import (
  "bytes"
  "context"
  "fmt"
  "io"
  "strings"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
  store "btrfs_to_glacier/volume_store"

  "github.com/google/uuid"
)

const (
  ChunkLen = 4 * 1024 * 1024
)

type ChunkIoIf interface {
  // Reading an object which does not exist should return `ErrChunkFound`.
  ReadOneChunk(
    ctx context.Context, key_fp types.PersistableString, chunk *pb.SnapshotChunks_Chunk, output io.Writer) error
  WriteOneChunk(
    ctx context.Context, start_offset uint64, clear_input io.Reader) (*pb.SnapshotChunks_Chunk, bool, error)
  RestoreSingleObject(ctx context.Context, key string) types.ObjRestoreOrErr
  ListChunks(ctx context.Context, continuation *string) ([]*pb.SnapshotChunks_Chunk, *string, error)
}

type ChunkIoImpl struct {
  Chunks    map[string][]byte
  ParCodec  types.Codec
  ChunkLen  uint64
}

type BaseStorage struct {
  ChunkIo   ChunkIoIf
  Conf      *pb.Config
  Codec     types.Codec
}
type Storage struct { *BaseStorage }

type ObjectIterator struct {
  Parent   *BaseStorage
  Buffer   []*pb.SnapshotChunks_Chunk
  Token    *string
  BufNext  int
  Started  bool
  InnerErr error
}

func NewStorageAdmin(conf *pb.Config, codec types.Codec) (types.AdminStorage, error) {
  base := &BaseStorage{
    ChunkIo: &ChunkIoImpl{
      Chunks: make(map[string][]byte),
      ParCodec: codec,
      ChunkLen: ChunkLen,
    },
    Conf: conf,
    Codec: codec,
  }
  return &Storage{base}, nil
}

func NewStorage(conf *pb.Config, codec types.Codec) (types.Storage, error) {
  return NewStorageAdmin(conf, codec)
}

func (self *ChunkIoImpl) ReadOneChunk(
    ctx context.Context, key_fp types.PersistableString, chunk *pb.SnapshotChunks_Chunk, output io.Writer) error {
  data, found := self.Chunks[chunk.Uuid]
  if !found { return types.ErrChunkFound }
  if len(data) != int(chunk.Size) {
    return fmt.Errorf("mismatched length with metadata: %d != %d", len(data), chunk.Size)
  }
  input := io.NopCloser(bytes.NewReader(data))
  done := self.ParCodec.DecryptStreamInto(ctx, key_fp, input, output)
  select {
    case err := <-done: return err
    case <-ctx.Done():
  }
  return nil
}

// Race detector does not recognize the ordering event (close pipe write end, EOF on read end)
func HasMoreData(chunk_len uint64, codec_hdr int, data_len uint64, source *io.LimitedReader) bool {
  if !util.RaceDetectorOn { return source.N == 0 }
  return data_len == chunk_len + uint64(codec_hdr)
}
func IsChunkEmpty(chunk_len uint64, codec_hdr int, data_len uint64, source *io.LimitedReader) bool {
  if !util.RaceDetectorOn { return source.N == int64(chunk_len) }
  return data_len == uint64(codec_hdr)
}

func (self *ChunkIoImpl) WriteOneChunk(
    ctx context.Context, start_offset uint64, clear_input io.Reader) (*pb.SnapshotChunks_Chunk, bool, error) {
  key_str := uuid.NewString()
  limit_reader := &io.LimitedReader{ R:clear_input, N:int64(self.ChunkLen) }

  encrypted_reader, err := self.ParCodec.EncryptStream(ctx, io.NopCloser(limit_reader))
  if err != nil { return nil, false, err }
  defer encrypted_reader.Close()

  data, err := io.ReadAll(encrypted_reader)
  if err != nil { return nil, false, err }

  chunk := &pb.SnapshotChunks_Chunk{
    Uuid: key_str,
    Start: start_offset,
    Size: uint64(len(data)),
  }

  codec_hdr := self.ParCodec.EncryptionHeaderLen()
  if IsChunkEmpty(self.ChunkLen, codec_hdr, chunk.Size, limit_reader) { return nil, false, nil }
  self.Chunks[key_str] = data
  return chunk, HasMoreData(self.ChunkLen, codec_hdr, chunk.Size, limit_reader), nil
}

func (self *ChunkIoImpl) RestoreSingleObject(ctx context.Context, key string) types.ObjRestoreOrErr {
  _, found := self.Chunks[key]
  if !found { return types.ObjRestoreOrErr{ Err:types.ErrChunkFound } }
  return types.ObjRestoreOrErr{ Stx:types.Restored, }
}

func (self *ChunkIoImpl) ListChunks(
    ctx context.Context, continuation *string) ([]*pb.SnapshotChunks_Chunk, *string, error) {
  if continuation != nil { return nil, nil, fmt.Errorf("implementation does not support continuation tokens") }
  chunks := make([]*pb.SnapshotChunks_Chunk, 0, len(self.Chunks))
  for k,v := range self.Chunks {
    c := &pb.SnapshotChunks_Chunk{
      Uuid: k,
      Start: 0, //unknown
      Size: uint64(len(v)),
    }
    chunks = append(chunks, c)
  }
  return chunks, nil, nil
}

func (self *BaseStorage) WriteStream(
    ctx context.Context, offset uint64, read_pipe io.ReadCloser) (<-chan types.ChunksOrError, error) {
  done := make(chan types.ChunksOrError, 1)

  go func() {
    defer close(done)
    defer read_pipe.Close()
    if offset > 0 {
      cnt, err := io.CopyN(io.Discard, read_pipe, int64(offset))
      if err != nil { done <- types.ChunksOrError{Err:err,}; return }
      if cnt != int64(offset) {
        err := fmt.Errorf("Discarded less bytes than expected.")
        done <- types.ChunksOrError{Err:err,}
        return
      }
    }

    more_data := true
    start_offset := uint64(offset)
    result := types.ChunksOrError{
      Val: &pb.SnapshotChunks{ KeyFingerprint: self.Codec.CurrentKeyFingerprint().S, },
    }

    for more_data {
      var err error
      var chunk *pb.SnapshotChunks_Chunk
      chunk, more_data, err = self.ChunkIo.WriteOneChunk(ctx, start_offset, read_pipe)
      if err != nil { result.Err = err; break }
      if chunk != nil {
        result.Val.Chunks = append(result.Val.Chunks, chunk)
        start_offset += chunk.Size
      }
    }

    if len(result.Val.Chunks) < 1 { result.Err = fmt.Errorf("stream contained no data") }
    util.Infof(self.UploadSummary(result))
    done <- result
  }()
  return done, nil
}

func (self *BaseStorage) UploadSummary(result types.ChunksOrError) string {
  var total_size uint64 = 0
  var uuids strings.Builder
  for _,c := range result.Val.Chunks {
    total_size += c.Size
    uuids.WriteString(c.Uuid)
    uuids.WriteString(", ")
  }
  if result.Err == nil {
    return fmt.Sprintf("Wrote OK %d bytes in %d chunks: %s",
                       total_size, len(result.Val.Chunks), uuids.String())
  }
  return fmt.Sprintf("Wrote %d bytes in %d chunks: %s\nError: %v",
                     total_size, len(result.Val.Chunks), uuids.String(), result.Err)
}

func (self *BaseStorage) QueueRestoreObjects(
    ctx context.Context, uuids []string) (<-chan types.RestoreResult, error) {
  done := make(chan types.RestoreResult, 1)
  result := make(types.RestoreResult)
  defer close(done)

  for _,uuid := range uuids {
    result[uuid] = self.ChunkIo.RestoreSingleObject(ctx, uuid)
  }
  done <- result
  return done, nil
}

func (self *BaseStorage) ReadChunksIntoStream(
    ctx context.Context, chunks *pb.SnapshotChunks) (io.ReadCloser, error) {
  err := store.ValidateSnapshotChunks(store.CheckChunkFromStart, chunks)
  if err != nil { return nil, err }
  pipe := util.NewFileBasedPipe(ctx)
  key_fp := types.PersistableString{chunks.KeyFingerprint}

  go func() {
    var err error
    defer func() { util.ClosePipeWithError(pipe, err) }()
    for _,chunk := range chunks.Chunks {
      err = self.ChunkIo.ReadOneChunk(ctx, key_fp, chunk, pipe.WriteEnd())
      if err != nil { return }
    }
    util.Infof("Read chunks: %v", chunks.Chunks)
  }()
  return pipe.ReadEnd(), nil
}

func (self *Storage) SetupStorage(ctx context.Context) (<-chan error) {
  return util.WrapInChan(nil)
}

func (self *Storage) DeleteChunks(
    ctx context.Context, chunks []*pb.SnapshotChunks_Chunk) (<-chan error) {
  if len(chunks) < 1 { return util.WrapInChan(fmt.Errorf("cannot delete 0 keys")) }
  if ctx.Err() != nil { return util.WrapInChan(ctx.Err()) }
  switch impl := self.ChunkIo.(type) {
    case *ChunkIoImpl:
      for _,c := range chunks { delete(impl.Chunks, c.Uuid) }
    default: util.Fatalf("You should have never called into the base class")
  }
  return util.WrapInChan(nil)
}

func (self *BaseStorage) ListAllChunks(
    ctx context.Context) (types.SnapshotChunksIterator, error) {
  it := &ObjectIterator{ Parent:self, }
  return it, nil
}

func (self *ObjectIterator) Err() error { return self.InnerErr }

func (self *ObjectIterator) Next(ctx context.Context, chunk *pb.SnapshotChunks_Chunk) bool {
  if self.InnerErr != nil { return false }
  if self.BufNext < len(self.Buffer) {
    *chunk = *self.Buffer[self.BufNext]
    self.BufNext += 1
    return true
  }
  if self.Started && self.Token == nil { return false }
  self.Started = true
  self.Buffer, self.Token, self.InnerErr = self.Parent.ChunkIo.ListChunks(ctx, self.Token)
  self.BufNext = 0
  return self.Next(ctx, chunk)
}

