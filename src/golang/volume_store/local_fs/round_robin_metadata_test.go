package local_fs

import (
  "context"
  "io"
  "strings"
  "testing"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/types/mocks"
  "btrfs_to_glacier/util"
  "btrfs_to_glacier/volume_store/mem_only"

  "github.com/google/uuid"
)

func buildTestRoundRobinMetadataWithState(
    t *testing.T, state *pb.AllMetadata) (*RoundRobinMetadata, func()) {
  local_fs, clean_f := util.LoadTestMultiSinkBackupConf(3, state != nil)
  conf := util.LoadTestConfWithLocalFs(local_fs)
  PutStateInAllParts(local_fs, state)
  meta, err := NewRoundRobinMetadataAdmin(conf, mocks.NewLinuxutil(), conf.Backups[0].Name)
  if err != nil { t.Fatalf("NewRoundRobinMetadataAdmin %v", err) }
  return meta.(*RoundRobinMetadata), clean_f
}

func FirstFs(meta *RoundRobinMetadata) *pb.Backup_Fs {
  return meta.Conf.Backups[0].Fs
}

func callSetupMetadataSync(t *testing.T, meta *RoundRobinMetadata) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  err := meta.SetupMetadata(ctx)
  if err != nil { t.Fatalf("SetupMetadata err: %v", err) }
}

func getPairStorageAndSetup(t *testing.T, meta *RoundRobinMetadata) (types.AdminBackupContent, *ChunkIoForTestImpl) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  codec := new(mocks.Codec)
  codec.Fingerprint = types.PersistableString{"some_fp"}
  storage, err := NewRoundRobinContentAdmin(meta.Conf, meta.Linuxutil, codec, meta.Conf.Backups[0].Name)
  if err != nil { t.Fatalf("meta.GetPairStorage: %v", err) }
  err = storage.SetupBackupContent(ctx)
  if err != nil { t.Fatalf("SetupBackupContent err: %v", err) }
  chunkio := GetChunkIoForTest(storage)
  if !strings.HasPrefix(chunkio.ChunkDir, meta.DirInfo.MountRoot) {
    t.Fatalf("Different fs between metadata and storage: '%s', '%s'", chunkio.ChunkDir, meta.DirInfo.MountRoot)
  }
  return storage, chunkio
}

func checkStateAfterSetup(t *testing.T, meta *RoundRobinMetadata, expect_state *pb.AllMetadata) {
  lu := meta.Linuxutil.(*mocks.Linuxutil)
  found_part := false
  if meta.SimpleDirMetadata == nil { t.Fatalf("meta.SimpleDirMetadata == nil") }

  mount_map := make(map[string]bool)
  for _,m := range lu.Mounts { mount_map[m.Device.FsUuid] = true }

  for _,p := range FirstFs(meta).Sinks {
    if !util.IsDir(MetaDir(p)) { t.Errorf("!IsDir '%s'", MetaDir(p)) }
    if !mount_map[p.FsUuid] { t.Errorf("%s was not mounted", p.String()) }
    if p.FsUuid == meta.DirInfo.FsUuid {
      found_part = true
      client := SimpleDirRw{ p }
      persisted_state := client.GetState()
      if persisted_state == nil { persisted_state = &pb.AllMetadata{} }
      mem_only.CompareStates(t, "Bad persisted state", persisted_state, expect_state)
    }
  }
  if !found_part { t.Errorf("!found_part") }
  mem_only.CompareStates(t, "Bad state", meta.InMemState(), expect_state)
}

func TestSetupRoundRobinMetadata_AllPartitionsNew(t *testing.T) {
  meta,clean_f := buildTestRoundRobinMetadataWithState(t, nil)
  defer clean_f()
  for _,p := range FirstFs(meta).Sinks {
    if util.IsDir(MetaDir(p)) { t.Errorf("IsDir '%s'", MetaDir(p)) }
  }

  callSetupMetadataSync(t, meta)
  checkStateAfterSetup(t, meta, &pb.AllMetadata{})
}

func TestGetPairStorage_AllPartitionsNew(t *testing.T) {
  meta,clean_f := buildTestRoundRobinMetadataWithState(t, nil)
  defer clean_f()

  callSetupMetadataSync(t, meta)
  storage,_ := getPairStorageAndSetup(t, meta)
  it, err := storage.ListAllChunks(context.TODO())
  if err != nil { t.Errorf("storage.ListChunks: %v", err) }
  var chunk pb.SnapshotChunks_Chunk
  if it.Next(context.TODO(), &chunk) { t.Errorf("Expected no chunks") }
}

func TestSetupRoundRobinMetadata_OneNewPartition(t *testing.T) {
  const part_idx = 1
  _, state := util.DummyAllMetadata()
  meta,clean_f := buildTestRoundRobinMetadataWithState(t, state)
  defer clean_f()
  fs := FirstFs(meta)
  client := SimpleDirRw{ fs.Sinks[part_idx] }
  client.DeleteState(/*del_dir*/true)

  callSetupMetadataSync(t, meta)
  checkStateAfterSetup(t, meta, &pb.AllMetadata{})
  util.EqualsOrFailTest(t, "Bad partition index", meta.DirInfo.FsUuid, fs.Sinks[part_idx].FsUuid)
}

func TestSetupRoundRobinMetadata_ExistingPartitions(t *testing.T) {
  _, expect_state := util.DummyAllMetadata()
  meta,clean_f := buildTestRoundRobinMetadataWithState(t, expect_state)
  defer clean_f()

  callSetupMetadataSync(t, meta)
  checkStateAfterSetup(t, meta, expect_state)
}

func TestGetPairStorage_ExistingPartitions(t *testing.T) {
  _, expect_state := util.DummyAllMetadata()
  meta,clean_f := buildTestRoundRobinMetadataWithState(t, expect_state)
  defer clean_f()

  callSetupMetadataSync(t, meta)
  chunkio := &ChunkIoForTestImpl{ ChunkIoImpl: NewChunkIoImpl(meta.DirInfo, new(mocks.Codec)) }
  expect_key := uuid.NewString()
  chunkio.Set(expect_key, util.GenerateRandomTextData(39))
  storage,_ := getPairStorageAndSetup(t, meta)

  it, err := storage.ListAllChunks(context.TODO())
  if err != nil { t.Errorf("storage.ListChunks: %v", err) }
  var chunk pb.SnapshotChunks_Chunk
  if !it.Next(context.TODO(), &chunk) { t.Errorf("Expected at least 1 chunk") }
  util.EqualsOrFailTest(t, "Bad listed key", chunk.Uuid, expect_key)
  if it.Next(context.TODO(), &chunk) { t.Errorf("Expected only 1 chunk") }
}

func TestSetupRoundRobinMetadata_ExistingPartitionsWithoutState(t *testing.T) {
  _, state := util.DummyAllMetadata()
  meta,clean_f := buildTestRoundRobinMetadataWithState(t, state)
  defer clean_f()
  for _,p := range FirstFs(meta).Sinks {
    client := SimpleDirRw{ p }
    client.DeleteState(/*del_dir*/false)
  }

  callSetupMetadataSync(t, meta)
  checkStateAfterSetup(t, meta, &pb.AllMetadata{})
}

func TestSetupRoundRobinMetadata_MountFail(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  meta,clean_f := buildTestRoundRobinMetadataWithState(t, nil)
  defer clean_f()
  lu := meta.Linuxutil.(*mocks.Linuxutil)
  lu.ForAllErrMsg("mount_err")

  err := meta.SetupMetadata(ctx)
  if err == nil { t.Errorf("expected error") }
}

func TestSetupRoundRobinMetadata_Idempotent(t *testing.T) {
  _, expect_state := util.DummyAllMetadata()
  meta,clean_f := buildTestRoundRobinMetadataWithState(t, expect_state)
  defer clean_f()

  callSetupMetadataSync(t, meta)
  expect_fs := meta.DirInfo.FsUuid
  lu := meta.Linuxutil.(*mocks.Linuxutil)
  expect_counts := lu.ObjCounts()
  callSetupMetadataSync(t, meta)
  util.EqualsOrFailTest(t, "Should to same fs", meta.DirInfo.FsUuid, expect_fs)
  util.EqualsOrFailTest(t, "Bad counts", lu.ObjCounts(), expect_counts)
}

func TestUMountAllSinkPartitions(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  meta,clean_f := buildTestRoundRobinMetadataWithState(t, &pb.AllMetadata{})
  defer clean_f()

  callSetupMetadataSync(t, meta)
  err := meta.UMountAllSinkPartitions(ctx)
  if err != nil { t.Errorf("TestUMountAllSinkPartitions: %v", err) }

  lu := meta.Linuxutil.(*mocks.Linuxutil)
  util.EqualsOrFailTest(t, "Still mounted partitions", len(lu.Mounts), 0)
}

func TestReadWriteSaveCycle(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  vol_uuid, expect_state := util.DummyAllMetadata()
  meta,clean_f := buildTestRoundRobinMetadataWithState(t, expect_state)
  defer clean_f()

  callSetupMetadataSync(t, meta)
  head, err := meta.RecordSnapshotSeqHead(ctx, util.DummySnapshotSequence(vol_uuid, "seq2"))
  if err != nil { t.Errorf("RecordSnapshotSeqHead: %v", err) }
  expect_state.Heads[0] = head
  _, err = meta.PersistCurrentMetadataState(ctx)
  if err != nil { t.Errorf("PersistCurrentMetadataState: %v", err) }

  mem_only.CompareStates(t, "Bad state", meta.InMemState(), expect_state)
  client := SimpleDirRw{ meta.DirInfo }
  persisted_state := client.GetState()
  mem_only.CompareStates(t, "Bad persisted state", persisted_state, expect_state)
}

func TestStorageReadWriteCycle(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  meta,clean_f := buildTestRoundRobinMetadataWithState(t, &pb.AllMetadata{})
  defer clean_f()

  callSetupMetadataSync(t, meta)
  storage,chunkio := getPairStorageAndSetup(t, meta)

  expect_data := util.GenerateRandomTextData(32)
  pipe := mocks.NewPreloadedPipe(expect_data)
  val, err := storage.WriteStream(ctx, 0, pipe.ReadEnd())
  if err != nil { t.Fatalf("ChunksOrError: %v", err) }
  util.EqualsOrFailTest(t, "Bad len", len(val.Chunks), 1)

  reader, err := storage.ReadChunksIntoStream(ctx, val)
  if err != nil { t.Fatalf("storage.ReadChunksIntoStream: %v", err) }
  var got_data []byte
  done_r := make(chan error)
  go func() {
    defer close(done_r)
    defer reader.Close()
    got_data, err = io.ReadAll(reader)
    if err != nil { t.Fatalf("io.ReadAll: %v", err) }
  }()
  util.WaitForClosure(t, ctx, done_r)

  util.EqualsOrFailTest(t, "Bad chunk", got_data, expect_data)
  persisted_data, _ := chunkio.Get(val.Chunks[0].Uuid)
  util.EqualsOrFailTest(t, "Bad persisted chunk", persisted_data, expect_data)
}

func TestReadWriteSaveCycle_ChangePartition(t *testing.T) {
  const part_cnt = 3
  vol_uuid, state := util.DummyAllMetadata()
  local_fs, clean_f := util.LoadTestMultiSinkBackupConf(part_cnt, true)
  conf := util.LoadTestConfWithLocalFs(local_fs)
  PutStateInAllParts(local_fs, state)
  touched_fs := make(map[string]bool)
  defer clean_f()

  for i:=0; i<part_cnt; i+=1 {
    meta_if, err := NewRoundRobinMetadataAdmin(conf, mocks.NewLinuxutil(), conf.Backups[0].Name)
    if err != nil { t.Fatalf("NewRoundRobinMetadataAdmin %v", err) }
    meta := meta_if.(*RoundRobinMetadata)
    callSetupMetadataSync(t, meta)

    time.Sleep(100 * time.Millisecond) // wait so that fs mod time moves
    ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
    defer cancel()

    _, err = meta.RecordSnapshotSeqHead(ctx, util.DummySnapshotSequence(vol_uuid, "seq2"))
    if err != nil { t.Errorf("RecordSnapshotSeqHead: %v", err) }
    _, err = meta.PersistCurrentMetadataState(ctx)
    if err != nil { t.Errorf("PersistCurrentMetadataState: %v", err) }
    touched_fs[meta.DirInfo.FsUuid] = true
  }
  util.EqualsOrFailTest(t, "Should have changed all parts", len(touched_fs), part_cnt)
}

