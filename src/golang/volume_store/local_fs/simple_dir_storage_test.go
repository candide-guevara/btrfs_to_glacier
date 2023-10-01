package local_fs


import (
  "context"
  "io/fs"
  "os"
  "testing"

  "btrfs_to_glacier/types"
  "btrfs_to_glacier/types/mocks"
  "btrfs_to_glacier/util"
  "btrfs_to_glacier/volume_store/mem_only"

  "github.com/google/uuid"
)

type ChunkIoForTestImpl struct { *ChunkIoImpl }

type Fixture struct {
  *mem_only.Fixture
  CleanF func()
}

func (self *ChunkIoForTestImpl) Get(key string) ([]byte, bool) {
  data, err := os.ReadFile(ChunkFile(self.ChunkDir, key))
  if util.IsNotExist(err) { return nil, false }
  if err != nil { util.Fatalf("ChunkIoForTestImpl.Get: %v", err) }
  return data, true
}
func (self *ChunkIoForTestImpl) Set(key string, data []byte) {
  err := os.WriteFile(ChunkFile(self.ChunkDir, key), data, fs.ModePerm)
  if err != nil { util.Fatalf("ChunkIoForTestImpl.Set: %v", err) }
  self.ChunkIndex[key] = true
}
func (self *ChunkIoForTestImpl) Len() int {
  chunks,_,err := self.ListChunks(context.TODO(), nil)
  if err != nil { util.Fatalf("ChunkIoForTestImpl.Len: %v", err) }
  real_len := len(chunks)
  idx_len := len(self.ChunkIndex)
  util.Infof("idx_len=%d / real_len=%d", idx_len, real_len)
  return real_len
}
func (self *ChunkIoForTestImpl) SetCodecFp(fp string) {
  self.ParCodec.(*mocks.Codec).Fingerprint = types.PersistableString{fp}
}
func (self *ChunkIoForTestImpl) GetCodecFp() types.PersistableString {
  return self.ParCodec.(*mocks.Codec).CurrentKeyFingerprint()
}
func (self *ChunkIoForTestImpl) AlwaysReturnErr(storage types.BackupContent, err error) {
  base_storage := storage.(*SimpleDirStorage).BaseStorage
  base_storage.ChunkIo = mocks.AlwaysErrChunkIo(storage, err)
}

func buildTestSimpleDirStorage(
    t *testing.T, chunk_len uint64, codec types.Codec) (*SimpleDirStorage, *ChunkIoForTestImpl, func()) {
  local_fs, clean_f := util.LoadTestSimpleDirBackupConf()
  conf := util.LoadTestConfWithLocalFs(local_fs)
  gen_store,err := NewSimpleDirStorageAdmin(conf, codec, local_fs.Sinks[0].FsUuid)
  if err != nil { util.Fatalf("NewBackupContent: %v", err) }
  storage := gen_store.(*SimpleDirStorage)
  chunkio := &ChunkIoForTestImpl{ ChunkIoImpl: storage.ChunkIo.(*ChunkIoImpl) }
  chunkio.ChunkLen = chunk_len
  return storage, chunkio, clean_f
}

func buildTestSimpleDirStorageWithChunkLen(
    t *testing.T, chunk_len uint64) (*SimpleDirStorage, *ChunkIoForTestImpl, func()) {
  codec := new(mocks.Codec)
  return buildTestSimpleDirStorage(t, chunk_len, codec)
}

func GetChunkIoForTest(storage types.BackupContent) *ChunkIoForTestImpl {
  if impl, ok := storage.(*SimpleDirStorage); ok {
    return &ChunkIoForTestImpl{ ChunkIoImpl: impl.ChunkIo.(*ChunkIoImpl) }
  }
  if impl, ok := storage.(*RoundRobinContent); ok {
    return &ChunkIoForTestImpl{ ChunkIoImpl: impl.ChunkIo.(*ChunkIoImpl) }
  }
  util.Fatalf("Unknown types.BackupContent implementation")
  return nil
}

func HelperSetupBackupContent(t *testing.T, chunk_cnt int) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  storage,chunkio,clean_f := buildTestSimpleDirStorageWithChunkLen(t, 16)
  defer clean_f()
  for i:=0; i<chunk_cnt; i+=1 {
    data := util.GenerateRandomTextData(i*32)
    key := uuid.NewString()
    chunkio.Set(key, data)
  }
  chunkio.ChunkIndex = make(map[string]bool)
  err := storage.SetupBackupContent(ctx)
  if err != nil { t.Errorf("Returned error: %v", err) }
  util.EqualsOrFailTest(t, "Bad loaded state", len(chunkio.ChunkIndex), chunk_cnt)
}

func TestSetupBackupContent_Empty(t *testing.T) {
  HelperSetupBackupContent(t, 0)
}

func TestSetupBackupContent_Simple(t *testing.T) {
  HelperSetupBackupContent(t, 3)
}

func TestSetupBackupContent_Idempotent(t *testing.T) {
  HelperSetupBackupContent(t, 3)
  HelperSetupBackupContent(t, 3)
}

func TestAllSimpleDirStorage(t *testing.T) {
  fixture := &Fixture{
    Fixture: &mem_only.Fixture{},
    CleanF: func() {},
  }
  fixture.StorageCtor = func(t *testing.T, chunk_len uint64) (types.BackupContent, mem_only.ChunkIoForTest) {
    return fixture.AdminCtor(t, chunk_len)
  }
  fixture.AdminCtor = func(t *testing.T, chunk_len uint64) (types.AdminBackupContent, mem_only.ChunkIoForTest) {
    storage, chunkio, clean_f := buildTestSimpleDirStorageWithChunkLen(t, chunk_len)
    fixture.CleanF = clean_f
    return storage, chunkio
  }
  fixture.TearDown = func(t *testing.T) { fixture.CleanF() }
  mem_only.RunAllTestStorage(t, fixture.Fixture)
}

