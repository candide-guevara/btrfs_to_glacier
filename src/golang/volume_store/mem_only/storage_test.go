package mem_only

import (
  "context"
  "fmt"
  "io"
  "testing"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/encryption"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/types/mocks"
  "btrfs_to_glacier/util"
)

type ChunkIoForTestImpl struct { *ChunkIoImpl }

func (self *ChunkIoForTestImpl) Get(uuid string) ([]byte, bool) { v,ok := self.Chunks[uuid]; return v,ok }
func (self *ChunkIoForTestImpl) Set(uuid string, data []byte)  { self.Chunks[uuid] = data }
func (self *ChunkIoForTestImpl) Len() int { return len(self.Chunks) }
func (self *ChunkIoForTestImpl) SetCodecFp(fp string) {
  self.ParCodec.(*mocks.Codec).Fingerprint = types.PersistableString{fp}
}
func (self *ChunkIoForTestImpl) GetCodecFp() types.PersistableString {
  return self.ParCodec.(*mocks.Codec).CurrentKeyFingerprint()
}
func (self *ChunkIoForTestImpl) AlwaysReturnErr(storage types.BackupContent, err error) {
  base_storage := storage.(*Storage).BaseStorage
  base_storage.ChunkIo = mocks.AlwaysErrChunkIo(storage, err)
}

func buildTestStorage(
    t *testing.T, chunk_len uint64, codec types.Codec) (*Storage, *ChunkIoForTestImpl) {
  conf := util.LoadTestConf()
  gen_store,err := NewBackupContent(conf, codec)
  if err != nil { util.Fatalf("NewBackupContent: %v", err) }
  storage := gen_store.(*Storage)
  chunkio := &ChunkIoForTestImpl{ ChunkIoImpl: storage.ChunkIo.(*ChunkIoImpl) }
  chunkio.ChunkLen = chunk_len
  return storage, chunkio
}

func buildTestStorageWithChunkLen(t *testing.T, chunk_len uint64) (*Storage, *ChunkIoForTestImpl) {
  codec := new(mocks.Codec)
  codec.Fingerprint = types.PersistableString{"mock_fp"}
  return buildTestStorage(t, chunk_len, codec)
}

func buildTestCodec(t *testing.T) types.Codec {
  // see encryption/aes_gzip_codec_test.go
  const dummy_pw = "chocolat"
  const persisted_key_1 = "OC0aSSg2woV0bUfw0Ew1+ej5fYCzzIPcTnqbtuKXzk8="

  conf := util.LoadTestConf()
  conf.Encryption.Keys = []string {persisted_key_1,}

  codec, err := encryption.NewCodecHelper(conf, encryption.TestOnlyFixedPw)
  if err != nil { t.Fatalf("Could not create codec: %v", err) }
  return codec
}

func buildTestStorageRealCodec(t *testing.T, chunk_len uint64) (*Storage, *ChunkIoForTestImpl) {
  codec := buildTestCodec(t)
  return buildTestStorage(t, chunk_len, codec)
}

func TestSetupBackupContent(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  storage,_ := buildTestStorageWithChunkLen(t, 16)
  err := storage.SetupBackupContent(ctx)
  if err != nil { t.Errorf("Returned error: %v", err) }
}

func TestAllMemOnlyStorage(t *testing.T) {
  storage_ctor := func(t *testing.T, chunk_len uint64) (types.BackupContent, ChunkIoForTest) {
    return buildTestStorageWithChunkLen(t, chunk_len)
  }
  admin_ctor := func(t *testing.T, chunk_len uint64) (types.AdminBackupContent, ChunkIoForTest) {
    return buildTestStorageWithChunkLen(t, chunk_len)
  }
  fixture := &Fixture{
    StorageCtor: storage_ctor,
    AdminCtor:   admin_ctor,
  }
  RunAllTestStorage(t, fixture)
}

func HelperWriteRead(
    t *testing.T, storage *Storage, total_len uint64) *pb.SnapshotChunks {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  data := util.GenerateRandomTextData(int(total_len))
  expect_data := make([]byte, total_len)
  copy(expect_data, data)
  pipe := mocks.NewBigPreloadedPipe(ctx, data)

  var chunks_written *pb.SnapshotChunks
  chunks_written,err := storage.WriteStream(ctx, /*offest*/0, pipe.ReadEnd())
  if err != nil { t.Fatalf("storage.WriteStream: %v", err) }
  t.Logf("chunks_written: %v", chunks_written)

  var got_data []byte
  read_end,err := storage.ReadChunksIntoStream(ctx, chunks_written)
  if err != nil { t.Fatalf("failed: %v", err) }

  done := make(chan error)
  go func() {
    defer close(done)
    defer read_end.Close()
    got_data, err = io.ReadAll(read_end)
    done <- err
  }()
  t.Logf("ReadAll: %v", util.WaitForClosure(t, ctx, done))

  if len(got_data) < 1 { t.Fatalf("no data read") }
  util.EqualsOrFailTest(t, "Mismatched data", got_data, expect_data)
  return chunks_written
}

func TestWriteReadWithRealCodec_OneChunk(t *testing.T) {
  const chunk_len = 128
  const total_len = 64
  storage,_ := buildTestStorageRealCodec(t, chunk_len)
  written := HelperWriteRead(t, storage, total_len)
  util.EqualsOrFailTest(t, "Bad chunk count", len(written.Chunks), 1)
}

func TestWriteReadWithRealCodec_NoData(t *testing.T) {
  const chunk_len = 128
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  storage,_ := buildTestStorageRealCodec(t, chunk_len)
  pipe := mocks.NewPreloadedPipe([]byte{})

  _,err := storage.WriteStream(ctx, /*offest*/0, pipe.ReadEnd())
  if err == nil { t.Errorf("Expected error") }
}

func TestWriteRead_2ChunksWithIv(t *testing.T) {
  const chunk_len = 64
  const total_len = chunk_len + 1
  storage,_ := buildTestStorageRealCodec(t, chunk_len)
  written := HelperWriteRead(t, storage, total_len)
  util.EqualsOrFailTest(t, "Bad chunk count", len(written.Chunks), 2)

  expect_size := 1 + new(mocks.Codec).EncryptionHeaderLen()
  storage,_ = buildTestStorageWithChunkLen(t, chunk_len)
  written = HelperWriteRead(t, storage, total_len)
  util.EqualsOrFailTest(t, "Bad chunk count", len(written.Chunks), 2)
  util.EqualsOrFailTest(t, "Bad 2nd chunk", written.Chunks[1].Size, expect_size)
}

func TestWriteRead_IVandDataExactChunk(t *testing.T) {
  const chunk_len = 64
  const total_len = chunk_len
  storage,_ := buildTestStorageRealCodec(t, chunk_len)
  written := HelperWriteRead(t, storage, total_len)
  util.EqualsOrFailTest(t, "Bad chunk count", len(written.Chunks), 1)

  expect_size := chunk_len + new(mocks.Codec).EncryptionHeaderLen()
  storage,_ = buildTestStorageWithChunkLen(t, chunk_len)
  written = HelperWriteRead(t, storage, total_len)
  util.EqualsOrFailTest(t, "Bad chunk count", len(written.Chunks), 1)
  util.EqualsOrFailTest(t, "Bad 1st chunk", written.Chunks[0].Size, expect_size)
}

func TestWriteReadWithRealCodec_ManyChunks(t *testing.T) {
  const chunk_len = 64
  const total_len = chunk_len * 3
  storage,_ := buildTestStorageRealCodec(t, chunk_len)
  written := HelperWriteRead(t, storage, total_len)
  util.EqualsOrFailTest(t, "Bad chunk count", len(written.Chunks), 3)
}

func TestWriteStream_PrematureClosure(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  storage,_ := buildTestStorageRealCodec(t, 64)
  pipe := mocks.NewPreloadedPipe(util.GenerateRandomTextData(32))
  pipe.ReadEnd().Close()

  _,err := storage.WriteStream(ctx, /*offest*/0, pipe.ReadEnd())
  if err == nil { t.Errorf("Expected error for premature closure") }
}

func TestWriteStream_ErrPropagation(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  expect_err := fmt.Errorf("some_fake_error")
  storage,_ := buildTestStorageRealCodec(t, 64)
  pipe := util.NewInMemPipe(ctx)
  pipe.WriteEnd().SetErr(expect_err)

  _,err := storage.WriteStream(ctx, /*offest*/0, pipe.ReadEnd())
  if err != expect_err {
    t.Errorf("Expected error for premature closure: %v", err)
  }
}

func TestReadChunksIntoStream_ErrPropagation(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  chunks := &pb.SnapshotChunks{
    KeyFingerprint: "for_giggles",
    Chunks: []*pb.SnapshotChunks_Chunk{
      &pb.SnapshotChunks_Chunk{ Uuid:"uuid0", Start:0, Size:24, },
    },
  }

  storage,chunkio := buildTestStorageWithChunkLen(t, 64)
  mock_codec := chunkio.ParCodec.(*mocks.Codec)
  mock_codec.Err = fmt.Errorf("premature_closure")
  chunkio.Set(chunks.Chunks[0].Uuid, util.GenerateRandomTextData(24))

  read_end,err := storage.ReadChunksIntoStream(ctx, chunks)
  if err != nil { t.Fatalf("failed: %v", err) }

  done := make(chan error)
  go func() {
    defer close(done)
    defer read_end.Close()
    got_data,err := io.ReadAll(read_end)
    if err == nil { t.Logf("io.ReadAll returned no error") }
    if read_end.GetErr() == nil { t.Errorf("Expected error for premature closure") }
    if len(got_data) > 0 { t.Logf("Garbage data was written") }
  }()
  util.WaitForClosure(t, ctx, done)
}

