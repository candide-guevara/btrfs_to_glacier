package aws_dynamodb_metadata

import (
  "bytes"
  "context"
  "errors"
  "fmt"
  "sort"
  "testing"

  "btrfs_to_glacier/encryption"
  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
  store "btrfs_to_glacier/volume_store"

  "github.com/aws/aws-sdk-go-v2/service/dynamodb"
  dyn_types "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

  "github.com/google/uuid"
  "google.golang.org/protobuf/proto"
)

type keyAndtype struct {
  Key string
  Type string
}

type mockDynamoDbClient struct {
  Err error
  Data map[keyAndtype][]byte
  CreateTableOutput   dyn_types.TableDescription
  DescribeTableOutput dyn_types.TableDescription
  FirstScanEmpty bool
}

func stringOrDie(vals map[string]dyn_types.AttributeValue, col string) string {
  switch v := vals[col].(type) {
    case *dyn_types.AttributeValueMemberS:
      return v.Value
   default:
     util.Fatalf("Malformed value for col '%v'", col)
     return ""
  }
}
func blobOrDie(vals map[string]dyn_types.AttributeValue, col string) []byte {
  switch v := vals[col].(type) {
    case *dyn_types.AttributeValueMemberB:
      return v.Value
   default:
     util.Fatalf("Malformed value for col '%v'", col)
     return nil
  }
}
func typeFromExprValues(vals map[string]dyn_types.AttributeValue) string {
  t_snap := string((&pb.SubVolume{}).ProtoReflect().Descriptor().FullName())
  t_seq := string((&pb.SnapshotSequence{}).ProtoReflect().Descriptor().FullName())
  t_head := string((&pb.SnapshotSeqHead{}).ProtoReflect().Descriptor().FullName())
  for _,v := range vals {
    switch s := v.(type) {
      case *dyn_types.AttributeValueMemberS:
        if s.Value == t_snap || s.Value == t_seq || s.Value == t_head { return s.Value }
    }
  }
  util.Fatalf("could not find type in filter")
  return ""
}

func (self *mockDynamoDbClient) CreateTable(
    ctx context.Context, params *dynamodb.CreateTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.CreateTableOutput, error) {
  result := &dynamodb.CreateTableOutput {
    TableDescription: &self.CreateTableOutput,
  }
  return result, self.Err
}
func (self *mockDynamoDbClient) DescribeTable(
    ctx context.Context, params *dynamodb.DescribeTableInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error) {
  result := &dynamodb.DescribeTableOutput {
    Table: &self.DescribeTableOutput,
  }
  return result, self.Err
}
func (self *mockDynamoDbClient) GetItem(
    ctx context.Context, params *dynamodb.GetItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error) {
  key := keyAndtype{
    Key: stringOrDie(params.Key, Uuid_col),
    Type: stringOrDie(params.Key, Type_col),
  }
  data, found := self.Data[key]
  if !found {
    return &dynamodb.GetItemOutput{ Item: nil }, self.Err
  }
  item := map[string]dyn_types.AttributeValue{
    Blob_col: &dyn_types.AttributeValueMemberB{Value: data,},
  }
  result := &dynamodb.GetItemOutput{ Item: item, }
  return result, self.Err
}
func (self *mockDynamoDbClient) Scan(
    ctx context.Context, in *dynamodb.ScanInput, opts...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error) {
  if in.Segment != nil { util.Fatalf("not_implemented") }
  if in.TableName == nil { return nil, fmt.Errorf("invald request.") }
  var page_count int32
  type_str := typeFromExprValues(in.ExpressionAttributeValues)
  out := &dynamodb.ScanOutput{ Items:make([]map[string]dyn_types.AttributeValue, 0, len(self.Data)), }
  //util.Debugf("type:%s request:\n%v", type_str, util.AsJson(in))

  // iteration order is not stable: https://go.dev/blog/maps
  keys := make([]string, 0, len(self.Data))
  for k,_ := range self.Data {
    if k.Type == type_str { keys = append(keys, k.Key) }
  }
  sort.Strings(keys)

  if self.FirstScanEmpty {
    self.FirstScanEmpty = false
    out.LastEvaluatedKey = make(map[string]dyn_types.AttributeValue)
    out.LastEvaluatedKey[""] = &dyn_types.AttributeValueMemberS{ Value:"", }
    //util.Debugf("response:\n%v", util.AsJson(out))
    return out, self.Err
  }
  for _,key:= range keys {
    if len(in.ExclusiveStartKey) > 0 {
      token := stringOrDie(in.ExclusiveStartKey, "")
      if key <= token { continue }
    }
    data := self.Data[keyAndtype{ Key:key, Type:type_str, }]
    item := make(map[string]dyn_types.AttributeValue)
    item[Blob_col] = &dyn_types.AttributeValueMemberB{ Value:data, }
    out.Items = append(out.Items, item)
    page_count += 1
    if page_count >= *in.Limit {
      out.LastEvaluatedKey = make(map[string]dyn_types.AttributeValue)
      out.LastEvaluatedKey[""] = &dyn_types.AttributeValueMemberS{ Value:key, }
      break
    }
  }
  out.Count = page_count
  //util.Debugf("response:\n%v", util.AsJson(out))
  return out, self.Err
}
func (self *mockDynamoDbClient) PutItem(
    ctx context.Context, params *dynamodb.PutItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error) {
  key := keyAndtype{
    Key: stringOrDie(params.Item, Uuid_col),
    Type: stringOrDie(params.Item, Type_col),
  }
  old_data, found := self.Data[key]
  if !found && params.ConditionExpression != nil {
    err := new(dyn_types.ConditionalCheckFailedException)
    return &dynamodb.PutItemOutput{}, err
  }
  self.Data[key] = blobOrDie(params.Item, Blob_col)
  put_out := &dynamodb.PutItemOutput{
    Attributes: map[string]dyn_types.AttributeValue{
      Blob_col: &dyn_types.AttributeValueMemberB{Value: old_data,},
    },
  }
  return put_out, nil
}
func (self *mockDynamoDbClient) DeleteItem(
    ctx context.Context, params *dynamodb.DeleteItemInput, optFns ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error) {
  key := keyAndtype{
    Key: stringOrDie(params.Key, Uuid_col),
    Type: stringOrDie(params.Key, Type_col),
  }
  _, found := self.Data[key]
  if !found {
    err := new(dyn_types.ConditionalCheckFailedException)
    return &dynamodb.DeleteItemOutput{}, err
  }
  delete(self.Data, key)
  return &dynamodb.DeleteItemOutput{}, nil
}
func (self *mockDynamoDbClient) BatchWriteItem(
    ctx context.Context, del_in *dynamodb.BatchWriteItemInput, opts ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error) {
  for tabname,rq_list := range del_in.RequestItems {
    if len(rq_list) < 1 { return nil, fmt.Errorf("Bad request: %v", del_in) }
    if rq_list[0].DeleteRequest == nil { return nil, fmt.Errorf("Bad request: %v", del_in) }
    del_key := rq_list[0].DeleteRequest.Key
    if len(del_key) != 2 { return nil, fmt.Errorf("Bad request: %v", del_in) }
    mock_key := keyAndtype{
      Key: stringOrDie (del_key, Uuid_col),
      Type: stringOrDie(del_key, Type_col),
    }
    delete(self.Data, mock_key)

    del_out := &dynamodb.BatchWriteItemOutput{
      UnprocessedItems: map[string][]dyn_types.WriteRequest{
        tabname: rq_list[1:],
      },
    }
    return del_out, self.Err
  }
  return nil, fmt.Errorf("Bad request: %v", del_in)
}
func (self *mockDynamoDbClient) putForTest(k string, p proto.Message) {
  key := keyAndtype{
    Key: k,
    Type: string(p.ProtoReflect().Descriptor().FullName()),
  }
  b := new(bytes.Buffer)
  if err := util.MarshalCompressedPb(b, p); err == nil { self.Data[key] = b.Bytes() }
}
func (self *mockDynamoDbClient) getForTest(k string, p proto.Message) bool {
  key := keyAndtype{
    Key: k,
    Type: string(p.ProtoReflect().Descriptor().FullName()),
  }
  if data, found := self.Data[key]; found {
    b := bytes.NewReader(data)
    if err := util.UnmarshalCompressedPb(b, p); err != nil { return false }
    return true
  }
  return false
}
func (self *mockDynamoDbClient) delForTest(k string, p proto.Message) bool {
  key := keyAndtype{
    Key: k,
    Type: string(p.ProtoReflect().Descriptor().FullName()),
  }
  _, found := self.Data[key]
  if found { delete(self.Data, key) }
  return found
}

func buildTestMetadata(t *testing.T) (*dynamoMetadata, *mockDynamoDbClient) {
  conf := util.LoadTestConf()
  client := new(mockDynamoDbClient)
  client.Data = make(map[keyAndtype][]byte)
  aws_conf, err := encryption.TestOnlyAwsConfFromPlainKey(conf, "", "", "")
  if err != nil { t.Fatalf("Failed aws config: %v", err) }

  meta := &dynamoMetadata{
    conf: conf,
    aws_conf: aws_conf,
    client: client,
    uuid_col: Uuid_col,
    type_col: Type_col,
    blob_col: Blob_col,
    describe_retry: util.SmallTimeout,
  }
  return meta, client
}

func TestRecordSnapshotSeqHead_New(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  metadata, _ := buildTestMetadata(t)
  new_seq := util.DummySnapshotSequence("vol", "seq")
  expect_head := util.DummySnapshotSeqHead(new_seq)
  head, err := metadata.RecordSnapshotSeqHead(ctx, new_seq)
  if err != nil { t.Errorf("Returned error: %v", err) }
  util.EqualsOrFailTest(t, "SnapshotSeqHead", head, expect_head)
}

func TestRecordSnapshotSeqHead_Add(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  metadata, client := buildTestMetadata(t)
  old_seq := util.DummySnapshotSequence("vol", "seq1")
  new_seq := util.DummySnapshotSequence("vol", "seq2")
  expect_head := util.DummySnapshotSeqHead(old_seq)
  client.putForTest(expect_head.Uuid, expect_head)
  expect_head.CurSeqUuid = new_seq.Uuid
  expect_head.PrevSeqUuid = []string{old_seq.Uuid}

  head, err := metadata.RecordSnapshotSeqHead(ctx, new_seq)
  if err != nil { t.Errorf("Returned error: %v", err) }
  util.EqualsOrFailTest(t, "SnapshotSeqHead", head, expect_head)
}

func TestRecordSnapshotSeqHead_Noop(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  metadata, client := buildTestMetadata(t)
  new_seq := util.DummySnapshotSequence("vol", "seq")
  expect_head := util.DummySnapshotSeqHead(new_seq)
  client.putForTest(expect_head.Uuid, expect_head)

  head, err := metadata.RecordSnapshotSeqHead(ctx, new_seq)
  if err != nil { t.Errorf("Returned error: %v", err) }
  util.EqualsOrFailTest(t, "SnapshotSeqHead", head, expect_head)
}

func TestAppendSnapshotToSeq_New(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  metadata, client := buildTestMetadata(t)
  seq := util.DummySnapshotSequence("vol", "seq")
  seq.SnapUuids = nil
  expect_seq := util.DummySnapshotSequence("vol", "seq")
  snap_to_add := util.DummySnapshot(expect_seq.SnapUuids[0], "vol")
  new_seq, err := metadata.AppendSnapshotToSeq(ctx, seq, snap_to_add)

  if err != nil { t.Errorf("Returned error: %v", err) }
  util.EqualsOrFailTest(t, "SnapshotSequence", new_seq, expect_seq)
  if !client.getForTest("seq", &pb.SnapshotSequence{}) { t.Errorf("No sequence persisted") }
}

func TestAppendSnapshotToSeq_Noop(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  metadata, client := buildTestMetadata(t)
  client.Err = fmt.Errorf("No methods on the client should have been called")
  seq := util.DummySnapshotSequence("vol", "seq")
  snap_to_add := util.DummySnapshot(seq.SnapUuids[0], "vol")
  _, err := metadata.AppendSnapshotToSeq(ctx, seq, snap_to_add)
  if err != nil { t.Errorf("Returned error: %v", err) }
}

func TestAppendSnapshotToChunk_New(t *testing.T) {
  snap := util.DummySnapshot("snap_uuid", "par_uuid")
  chunk := util.DummyChunks("chunk_uuid")
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  metadata, client := buildTestMetadata(t)
  new_snap, err := metadata.AppendChunkToSnapshot(ctx, snap, chunk)
  if err != nil { t.Errorf("Returned error: %v", err) }

  persisted_snap := &pb.SubVolume{}
  if !client.getForTest("snap_uuid", persisted_snap) { t.Errorf("No snapshot persisted") }
  util.EqualsOrFailTest(t, "Snapshot", persisted_snap, new_snap)
  util.EqualsOrFailTest(t, "SnapshotChunk", new_snap.Data, chunk)
}

func TestAppendSnapshotToChunk_Append(t *testing.T) {
  snap := util.DummySnapshot("snap_uuid", "par_uuid")
  snap.Data = util.DummyChunks("chunk_uuid1")
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  chunk := util.DummyChunks("chunk_uuid2")
  chunk.Chunks[0].Start = store.SubVolumeDataLen(snap)

  util.PbInfof("snap: %v", snap)
  util.PbInfof("chunk: %v", chunk)
  metadata, client := buildTestMetadata(t)
  new_snap, err := metadata.AppendChunkToSnapshot(ctx, snap, chunk)
  if err != nil { t.Errorf("Returned error: %v", err) }

  if !client.getForTest("snap_uuid", &pb.SubVolume{}) { t.Errorf("No snapshot persisted") }
  expect_chunks := util.DummyChunks("chunk_uuid1")
  expect_chunks.Chunks = append(expect_chunks.Chunks, chunk.Chunks[0])
  util.EqualsOrFailTest(t, "SnapshotChunk", new_snap.Data, expect_chunks)
}

func TestAppendSnapshotToChunk_Noop(t *testing.T) {
  snap := util.DummySnapshot("snap_uuid", "par_uuid")
  chunk := util.DummyChunks("chunk_uuid")
  snap.Data = chunk
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  metadata, client := buildTestMetadata(t)
  client.Err = fmt.Errorf("No methods on the client should have been called")
  new_snap, err := metadata.AppendChunkToSnapshot(ctx, snap, chunk)
  if err != nil { t.Errorf("Returned error: %v", err) }
  util.EqualsOrFailTest(t, "Snapshot", snap, new_snap)
}

func TestAppendSnapshotToChunk_Errors(t *testing.T) {
  var err error
  snap := util.DummySnapshot("snap_uuid", "par_uuid")
  snap.Data = util.DummyChunks("chunk_uuid")
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()

  metadata, _ := buildTestMetadata(t)

  chunk_1 := util.DummyChunks("chunk_uuid1")
  chunk_1.Chunks[0].Start += 1
  _, err = metadata.AppendChunkToSnapshot(ctx, snap, chunk_1)
  if err == nil { t.Errorf("Expected error: %v", err) }

  chunk_2 := util.DummyChunks("chunk_uuid2")
  chunk_2.Chunks[0].Size += 1
  _, err = metadata.AppendChunkToSnapshot(ctx, snap, chunk_2)
  if err == nil { t.Errorf("Expected error: %v", err) }

  chunk_3 := util.DummyChunks("chunk_uuid3")
  chunk_3.Chunks[0].Start = store.SubVolumeDataLen(snap) + 1
  _, err = metadata.AppendChunkToSnapshot(ctx, snap, chunk_3)
  if err == nil { t.Errorf("Expected error: %v", err) }

  chunk_4 := util.DummyChunks("chunk_uuid4")
  chunk_4.KeyFingerprint = snap.Data.KeyFingerprint + "_wrong_keyfp"
  _, err = metadata.AppendChunkToSnapshot(ctx, snap, chunk_4)
  if err == nil { t.Errorf("Expected error: %v", err) }
}

func TestReadSnapshotSeqHead(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  metadata, client := buildTestMetadata(t)
  seq := util.DummySnapshotSequence("vol", "seq1")
  expect_head := util.DummySnapshotSeqHead(seq)
  client.putForTest(expect_head.Uuid, expect_head)

  head, err := metadata.ReadSnapshotSeqHead(ctx, expect_head.Uuid)
  if err != nil { t.Errorf("Returned error: %v", err) }
  util.EqualsOrFailTest(t, "SnapshotSeqHead", head, expect_head)
}

func TestReadSnapshotSeqHead_NoHead(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  metadata, _ := buildTestMetadata(t)

  _, err := metadata.ReadSnapshotSeqHead(ctx, "does_not_exist")
  if errors.Is(err, types.ErrNotFound) { return }
  if err != nil { t.Errorf("Returned error: %v", err) }
}

func TestReadSnapshotSeq(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  metadata, client := buildTestMetadata(t)
  expect_seq := util.DummySnapshotSequence("vol", "seq1")
  client.putForTest(expect_seq.Uuid, expect_seq)

  seq, err := metadata.ReadSnapshotSeq(ctx, expect_seq.Uuid)
  if err != nil { t.Errorf("Returned error: %v", err) }
  util.EqualsOrFailTest(t, "SnapshotSequence", seq, expect_seq)
}

func TestReadSnapshotSeq_NoSequence(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  metadata, _ := buildTestMetadata(t)

  _, err := metadata.ReadSnapshotSeq(ctx, "does_not_exist")
  if errors.Is(err, types.ErrNotFound) { return }
  if err != nil { t.Errorf("Returned error: %v", err) }
}

func TestReadSnapshot(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  metadata, client := buildTestMetadata(t)
  expect_snap := util.DummySnapshot("snap_uuid", "vol_uuid")
  expect_snap.Data = util.DummyChunks("chunk_uuid1")
  client.putForTest(expect_snap.Uuid, expect_snap)

  snap, err := metadata.ReadSnapshot(ctx, expect_snap.Uuid)
  if err != nil { t.Errorf("Returned error: %v", err) }
  util.EqualsOrFailTest(t, "Snapshot", snap, expect_snap)
}

func TestReadSnapshotSeq_NoSnap(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  metadata, _ := buildTestMetadata(t)

  _, err := metadata.ReadSnapshot(ctx, "does_not_exist")
  if errors.Is(err, types.ErrNotFound) { return }
  if err != nil { t.Errorf("Returned error: %v", err) }
}

type create_pb_f = func() (string, proto.Message)
type iterate_f = func(context.Context, types.Metadata) (map[string]proto.Message, error)
func testMetadataListAll_Helper(t *testing.T, total int, fill_size int32, pb_f create_pb_f, iter_f iterate_f) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  metadata, client := buildTestMetadata(t)
  metadata.iter_buf_len = fill_size
  expect_objs := make(map[string]proto.Message)

  for i:=0; i<total; i+=1 {
    key,obj := pb_f()
    expect_objs[key] = proto.Clone(obj)
    client.putForTest(key, obj)
  }

  got_objs, err := iter_f(ctx, metadata)
  if err != nil { t.Fatalf("failed while iterating: %v", err) }
  util.EqualsOrFailTest(t, "Bad len", len(got_objs), len(expect_objs))
  for key,expect := range expect_objs {
    util.EqualsOrFailTest(t, "Bad obj", got_objs[key], expect)
  }
}

func head_pb_f() (string, proto.Message) {
  new_seq := util.DummySnapshotSequence(uuid.NewString(), uuid.NewString())
  new_head := util.DummySnapshotSeqHead(new_seq)
  return new_head.Uuid, new_head
}
func head_iter_f(ctx context.Context, metadata types.Metadata) (map[string]proto.Message, error) {
  got_objs := make(map[string]proto.Message)
  it, err := metadata.ListAllSnapshotSeqHeads(ctx)
  if err != nil { return nil, err }
  obj := &pb.SnapshotSeqHead{}
  for it.Next(ctx, obj) { got_objs[obj.Uuid] = proto.Clone(obj) }
  return got_objs, it.Err()
}

func TestListAllSnapshotSeqHeads_SingleFill(t *testing.T) {
  const total = 3
  const fill_size = 10
  testMetadataListAll_Helper(t, total, fill_size, head_pb_f, head_iter_f)
}
func TestListAllSnapshotSeqHeads_MultipleFill(t *testing.T) {
  const total = 10
  const fill_size = 3
  testMetadataListAll_Helper(t, total, fill_size, head_pb_f, head_iter_f)
}
func TestListAllSnapshotSeqHeads_NoObjects(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  metadata,_ := buildTestMetadata(t)
  got_objs, err := head_iter_f(ctx, metadata)
  if err != nil { t.Errorf("failed while iterating: %v", err) }
  if len(got_objs) > 0 { t.Errorf("should not return any object") }
}
func TestListAllSnapshotSeqHeads_EmptyNonFinalFill(t *testing.T) {
  const fill_size = 3
  const total = fill_size * 2
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  metadata, client := buildTestMetadata(t)
  metadata.iter_buf_len = fill_size

  for i:=0; i<total; i+=1 {
    key,obj := head_pb_f()
    client.putForTest(key, obj)
  }

  client.FirstScanEmpty = true
  got_objs, err := head_iter_f(ctx, metadata)
  if err != nil { t.Fatalf("failed while iterating: %v", err) }
  util.EqualsOrFailTest(t, "Bad len", len(got_objs), total)
}
func TestListAllSnapshotSeqHeads_ErrDuringIteration(t *testing.T) {
  ctx, cancel := context.WithTimeout(context.Background(), util.TestTimeout)
  defer cancel()
  metadata,client := buildTestMetadata(t)
  key,obj := head_pb_f()
  client.putForTest(key, obj)
  client.Err = fmt.Errorf("fail iteration")
  got_objs, err := head_iter_f(ctx, metadata)
  if err == nil { t.Errorf("expected iteration failure") }
  if len(got_objs) > 0 { t.Errorf("should not return any object") }
}

func seq_pb_f() (string, proto.Message) {
  new_seq := util.DummySnapshotSequence(uuid.NewString(), uuid.NewString())
  return new_seq.Uuid, new_seq
}
func seq_iter_f(ctx context.Context, metadata types.Metadata) (map[string]proto.Message, error) {
  got_objs := make(map[string]proto.Message)
  it, err := metadata.ListAllSnapshotSeqs(ctx)
  if err != nil { return nil, err }
  obj := &pb.SnapshotSequence{}
  for it.Next(ctx, obj) { got_objs[obj.Uuid] = proto.Clone(obj) }
  return got_objs, it.Err()
}

func TestListAllSnapshotSeqs_SingleFill(t *testing.T) {
  const total = 3
  const fill_size = 10
  testMetadataListAll_Helper(t, total, fill_size, seq_pb_f, seq_iter_f)
}
func TestListAllSnapshotSeqs_MultipleFill(t *testing.T) {
  const fill_size = 3
  const total = fill_size * 3
  testMetadataListAll_Helper(t, total, fill_size, seq_pb_f, seq_iter_f)
}

func snap_pb_f() (string, proto.Message) {
  new_sv := util.DummySubVolume(uuid.NewString())
  return new_sv.Uuid, new_sv
}
func snap_iter_f(ctx context.Context, metadata types.Metadata) (map[string]proto.Message, error) {
  got_objs := make(map[string]proto.Message)
  it, err := metadata.ListAllSnapshots(ctx)
  if err != nil { return nil, err }
  obj := &pb.SubVolume{}
  for it.Next(ctx, obj) { got_objs[obj.Uuid] = proto.Clone(obj) }
  return got_objs, it.Err()
}

func TestListAllSnapshots_SingleFill(t *testing.T) {
  const total = 3
  const fill_size = 10
  testMetadataListAll_Helper(t, total, fill_size, snap_pb_f, snap_iter_f)
}
func TestListAllSnapshots_MultipleFill(t *testing.T) {
  const fill_size = 3
  const total = fill_size * 2
  testMetadataListAll_Helper(t, total, fill_size, snap_pb_f, snap_iter_f)
}
