package main

import (
  "bytes"
  "context"
  "errors"
  "io"
  "math/rand"

  store "btrfs_to_glacier/volume_store/aws_s3_storage"
  s3_common "btrfs_to_glacier/volume_store/aws_s3_common"
  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/types/mocks"
  "btrfs_to_glacier/util"

  "github.com/aws/aws-sdk-go-v2/aws"
  "github.com/aws/aws-sdk-go-v2/service/s3"
  s3_types "github.com/aws/aws-sdk-go-v2/service/s3/types"

  "google.golang.org/protobuf/proto"
  "github.com/google/uuid"
)

type s3StoreReadWriteTester struct {
  Conf *pb.Config
  Client *s3.Client
  Storage types.AdminBackupContent
}

func (self *s3StoreReadWriteTester) getObject(ctx context.Context, key string) ([]byte, error) {
  bucket := Backup(self.Conf).Aws.S3.StorageBucketName
  return s3_common.GetObject(ctx, self.Client, bucket, key)
}

func (self *s3StoreReadWriteTester) putRandomObject(ctx context.Context, size int) (string, []byte, error) {
  bucket := Backup(self.Conf).Aws.S3.StorageBucketName
  data := util.GenerateRandomTextData(size)
  key := uuid.NewString()
  err := s3_common.PutObject(ctx, self.Client, bucket, key, data)
  return key, data, err
}

func (self *s3StoreReadWriteTester) getObjectOrDie(ctx context.Context, key string) []byte {
  bucket := Backup(self.Conf).Aws.S3.StorageBucketName
  return s3_common.GetObjectOrDie(ctx, self.Client, bucket, key)
}

func (self *s3StoreReadWriteTester) putRandomObjectOrDie(ctx context.Context, size int) (string, []byte) {
  key, data, err := self.putRandomObject(ctx, size)
  if err != nil { util.Fatalf("Failed to put object '%s': %v", key, err) }
  return key, data
}

func (self *s3StoreReadWriteTester) helperWrite(
    ctx context.Context, offset uint64, total_len uint64) *pb.SnapshotChunks {
  chunk_len := Backup(self.Conf).Aws.S3.ChunkLen
  data := util.GenerateRandomTextData(int(total_len))
  expect_obj := make([]byte, total_len - offset)
  copy(expect_obj, data[offset:])
  pipe := mocks.NewBigPreloadedPipe(ctx, data)

  done := make(chan *pb.SnapshotChunks)
  go func() {
    defer close(done)
    result, err := self.Storage.WriteStream(ctx, offset, pipe.ReadEnd())
    if err != nil { util.Fatalf("Storage.WriteStream: %v", err) }
    chunks := result.Chunks
    if len(result.KeyFingerprint) < 1 || len(chunks) < 1 || len(chunks[0].Uuid) < 1 {
      util.Fatalf("Malformed chunks: %v", chunks)
    }
    for idx,chunk := range chunks {
      if len(chunk.Uuid) < 1 { util.Fatalf("Malformed chunk: %v", chunk) }
      object := self.getObjectOrDie(ctx, chunk.Uuid)
      start := int(chunk_len) * idx
      end := start + int(chunk_len)
      if end > len(expect_obj) { end = len(expect_obj) }
      util.EqualsOrDie("Bad object data", object, expect_obj[start:end])
    }
    done <- result
  }()
  select {
    case result := <-done: return result
    case <-ctx.Done(): util.Fatalf("timedout")
  }
  return nil
}

func (self *s3StoreReadWriteTester) TestWriteObjectLessChunkLen(ctx context.Context) {
  const offset = 0
  var total_len = Backup(self.Conf).Aws.S3.ChunkLen/3
  expect_chunk := &pb.SnapshotChunks_Chunk{
    Uuid: "some_uuid",
    Start: offset,
    Size: total_len-offset,
  }

  snap_chunks := self.helperWrite(ctx, offset, total_len)
  first_chunk := snap_chunks.Chunks[0]
  expect_chunk.Uuid = first_chunk.Uuid //intended since uuid is random
  util.EqualsOrDie("Bad SnapshotChunk[0]", first_chunk, expect_chunk)
}

func (self *s3StoreReadWriteTester) TestWriteObjectMoreChunkLen(ctx context.Context) {
  const offset = 0
  var total_len = Backup(self.Conf).Aws.S3.ChunkLen*3 + 1
  snap_chunks := self.helperWrite(ctx, offset, total_len)
  util.EqualsOrDie("Bad number of chunks", len(snap_chunks.Chunks), 4)
}

func (self *s3StoreReadWriteTester) TestWriteObjectMultipleChunkLen(ctx context.Context) {
  const offset = 0
  var total_len = Backup(self.Conf).Aws.S3.ChunkLen * 2
  snap_chunks := self.helperWrite(ctx, offset, total_len)
  util.EqualsOrDie("Bad number of chunks", len(snap_chunks.Chunks), 2)
}

func (self *s3StoreReadWriteTester) TestWriteEmptyObject(ctx context.Context) {
  const offset = 0
  read_end := util.ReadEndFromBytes(nil)
  result, err := self.Storage.WriteStream(ctx, offset, read_end)
  if err == nil { util.Fatalf("empty object should return error") }
  if result != nil {
    if len(result.Chunks) > 0 { util.Fatalf("no chunks should have been returned") }
  }
}

func (self *s3StoreReadWriteTester) testReadObject_Helper(ctx context.Context, chunk_sizes []uint64) {
  var expect_data bytes.Buffer
  var offset uint64
  chunks := &pb.SnapshotChunks{ KeyFingerprint: "for_giggles", }
  for _,size := range chunk_sizes {
    key, data := self.putRandomObjectOrDie(ctx, int(size))
    expect_data.Write(data)
    chunk := &pb.SnapshotChunks_Chunk{ Uuid:key, Start:offset, Size:size, }
    chunks.Chunks = append(chunks.Chunks, chunk)
    offset += size
  }

  read_end,err := self.Storage.ReadChunksIntoStream(ctx, chunks)
  if err != nil { util.Fatalf("failed: %v", err) }

  var got_data []byte
  done := make(chan error)
  go func() {
    defer close(done)
    defer read_end.Close()
    got_data, err = io.ReadAll(read_end)
    if err != nil { util.Fatalf("failed: %v", err) }
  }()
  util.WaitForClosureOrDie(ctx, done)

  util.EqualsOrDie( "Mismatched concat data", got_data, expect_data.Bytes())
}

func (self *s3StoreReadWriteTester) TestReadSingleChunkObject(ctx context.Context) {
  sizes := []uint64{4096}
  self.testReadObject_Helper(ctx, sizes)
}

func (self *s3StoreReadWriteTester) TestReadUnexistingKey(ctx context.Context) {
  chunk := &pb.SnapshotChunks_Chunk{ Uuid:uuid.NewString(), Start:0, Size:32, }
  chunks := &pb.SnapshotChunks{
    KeyFingerprint: "for_giggles",
    Chunks: []*pb.SnapshotChunks_Chunk{ chunk, },
  }

  read_end,err := self.Storage.ReadChunksIntoStream(ctx, chunks)
  if err != nil { util.Fatalf("Error should be sent via the channel: %v", err) }
  done := make(chan error)
  go func() {
    defer close(done)
    defer read_end.Close()
    written,_ := io.Copy(io.Discard, read_end)
    if written > 0 { util.Fatalf("expecting no data, got %d bytes", written) }
  }()
  util.WaitForClosureOrDie(ctx, done)
}

func (self *s3StoreReadWriteTester) TestReadMultiChunkObject(ctx context.Context) {
  sizes := []uint64{4096, 1024, 666,}
  self.testReadObject_Helper(ctx, sizes)
}

func (self *s3StoreReadWriteTester) testQueueRestoreObjects_Helper(ctx context.Context, keys []string, expect_obj types.ObjRestoreOrErr) {
  done := make(chan bool)
  go func() {
    defer close(done)
    result := self.Storage.QueueRestoreObjects(ctx, keys)
    if len(result) < 1 { util.Fatalf("Storage.QueueRestoreObjects empty result") }

    expect := make(map[string]types.ObjRestoreOrErr)
    for _,k := range keys { expect[k] = expect_obj }
    util.Debugf("result: %v", result)
    util.EqualsOrDie("Bad obj status", result, expect)
  }()
  select {
    case <-done:
    case <-ctx.Done(): util.Fatalf("timedout")
  }
}

func (self *s3StoreReadWriteTester) TestQueueRestoreObjects_StandardClass(ctx context.Context) {
  key1,_ := self.putRandomObjectOrDie(ctx, 4096)
  key2,_ := self.putRandomObjectOrDie(ctx, 1111)
  keys := []string{key1, key2}
  expect_obj := types.ObjRestoreOrErr{ Stx:types.Restored, }
  self.testQueueRestoreObjects_Helper(ctx, keys, expect_obj)
}

func (self *s3StoreReadWriteTester) TestQueueRestoreObjects_NoSuchObject(ctx context.Context) {
  keys := []string{uuid.NewString()}
  result := self.Storage.QueueRestoreObjects(ctx, keys)
  if len(result) < 1 { util.Fatalf("Storage.QueueRestoreObjects empty result") }
  got_err := result[keys[0]].Err
  if !errors.Is(got_err, types.ErrChunkFound) {
    util.Fatalf("Expected error status: %v", result)
  }
}

func (self *s3StoreReadWriteTester) TestQueueRestoreObjects_Idempotent(ctx context.Context, snowflake_bucket string, snowflake_key string) {
  tmp_conf := proto.Clone(self.Conf).(*pb.Config)
  Backup(tmp_conf).Aws.S3.StorageBucketName = snowflake_bucket
  restore_func := store.TestOnlySwapConf(self.Storage, tmp_conf)
  defer restore_func()

  keys := []string{snowflake_key}
  expect_obj := types.ObjRestoreOrErr{ Stx:types.Pending, }
  self.testQueueRestoreObjects_Helper(ctx, keys, expect_obj)
  self.testQueueRestoreObjects_Helper(ctx, keys, expect_obj)
}

func (self *s3StoreReadWriteTester) TestQueueRestoreObjects_AlreadyRestored(ctx context.Context, snowflake_bucket string, snowflake_key string) {
  tmp_conf := proto.Clone(self.Conf).(*pb.Config)
  Backup(tmp_conf).Aws.S3.StorageBucketName = snowflake_bucket
  restore_func := store.TestOnlySwapConf(self.Storage, tmp_conf)
  defer restore_func()

  keys := []string{snowflake_key}
  expect_obj := types.ObjRestoreOrErr{ Stx:types.Restored, }
  self.testQueueRestoreObjects_Helper(ctx, keys, expect_obj)
}

func (self *s3StoreReadWriteTester) testListAllChunks_Helper(ctx context.Context, total int, fill_size int32) {
  bucket := Backup(self.Conf).Aws.S3.StorageBucketName
  s3_common.EmptyBucketOrDie(ctx, self.Client, bucket)
  restore_f := store.TestOnlyChangeIterationSize(self.Storage, fill_size)
  defer restore_f()
  expect_objs := make(map[string]*pb.SnapshotChunks_Chunk)
  got_objs := make(map[string]*pb.SnapshotChunks_Chunk)

  for i:=0; i<total; i+=1 {
    key,data := self.putRandomObjectOrDie(ctx, rand.Intn(1024)+16)
    expect_objs[key] = &pb.SnapshotChunks_Chunk{ Uuid:key, Size:uint64(len(data)), }
  }

  it, err := self.Storage.ListAllChunks(ctx)
  if err != nil { util.Fatalf("failed while iterating: %v", err) }
  obj := &pb.SnapshotChunks_Chunk{}
  for it.Next(ctx, obj) {
    got_objs[obj.Uuid] = proto.Clone(obj).(*pb.SnapshotChunks_Chunk)
  }
  if it.Err() != nil { util.Fatalf("failed while iterating: %v", it.Err()) }

  util.EqualsOrDie("Bad len", len(got_objs), len(expect_objs))
  for key,expect := range expect_objs {
    util.EqualsOrDie("Bad obj", got_objs[key], expect)
  }
}

func (self *s3StoreReadWriteTester) TestListAllChunksSingleFill(ctx context.Context) {
  const fill_size = 10
  const total = 3
  self.testListAllChunks_Helper(ctx, total, fill_size)
}

func (self *s3StoreReadWriteTester) TestListAllChunksMultiFill(ctx context.Context) {
  const fill_size = 4
  const total = fill_size * 3
  self.testListAllChunks_Helper(ctx, total, fill_size)
}

func TestS3GenericRead_UnknownKey(ctx context.Context, conf *pb.Config, client *s3.Client) {
  bucket := Backup(conf).Aws.S3.StorageBucketName
  unk_key := uuid.NewString()

  get_in := &s3.GetObjectInput{
    Bucket: &bucket,
    Key:    &unk_key,
  }
  get_out, err := client.GetObject(ctx, get_in)
  util.Debugf("GetObjectInput (unknown key): %s", util.AsJson(get_out))
  if !s3_common.IsS3Error(new(s3_types.NoSuchKey), err) {
    util.Fatalf("failed while reading unknown key: %v", err)
  }
}

// we do not test with offsets, that should be covered by the unittests
func TestAllS3StoreReadWrite(ctx context.Context, conf *pb.Config, client *s3.Client, storage types.AdminBackupContent) {
  suite := s3StoreReadWriteTester{
    Conf: conf, Client: client, Storage: storage,
  }

  suite.TestWriteObjectLessChunkLen(ctx)
  suite.TestWriteObjectMoreChunkLen(ctx)
  suite.TestWriteObjectMultipleChunkLen(ctx)
  suite.TestWriteEmptyObject(ctx)
  suite.TestReadSingleChunkObject(ctx)
  suite.TestReadUnexistingKey(ctx)
  suite.TestListAllChunksSingleFill(ctx)
  suite.TestListAllChunksMultiFill(ctx)
  suite.TestReadMultiChunkObject(ctx)
  suite.TestQueueRestoreObjects_StandardClass(ctx)
  suite.TestQueueRestoreObjects_NoSuchObject(ctx)
  // adhoc manual testing given the nature of restores :-(
  //snowflake_bucket := "candide.test.bucket.1"
  //snowflake_key := "s3_obj_983680415d7ec9ccf80c88df8e3d4d7e"
  //suite.TestQueueRestoreObjects_Idempotent(ctx, snowflake_bucket, snowflake_key)
  //suite.TestQueueRestoreObjects_AlreadyRestored(ctx, snowflake_bucket, snowflake_key)
}

func TestAllS3Storage(ctx context.Context, conf *pb.Config, aws_conf *aws.Config) {
  new_conf := proto.Clone(conf).(*pb.Config)
  // A bigger chunk, will make tests slow+expensive
  Backup(new_conf).Aws.S3.ChunkLen = 128*1024

  codec := new(mocks.Codec)
  codec.Fingerprint = types.PersistableString{"some_fp"}
  storage, err := store.NewBackupContentAdmin(new_conf, aws_conf, Backup(new_conf).Name, codec)
  //client := s3.NewFromConfig(*aws_conf)
  client := store.TestOnlyGetInnerClientToAvoidConsistencyFails(storage)
  if err != nil { util.Fatalf("%v", err) }

  TestS3StorageSetup(ctx, new_conf, client, storage)
  TestS3GenericRead_UnknownKey(ctx, new_conf, client)
  TestAllS3StoreReadWrite(ctx, new_conf, client, storage)
  TestAllS3StoreDelete(ctx, new_conf, client, storage)
  s3_common.DeleteBucketOrDie(ctx, client, Backup(new_conf).Aws.S3.StorageBucketName)
}

