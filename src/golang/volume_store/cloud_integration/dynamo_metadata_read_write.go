package main

import (
  "bytes"
  "context"
  "fmt"
  "errors"

  meta "btrfs_to_glacier/volume_store/aws_dynamodb_metadata"
  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"

  "github.com/aws/aws-sdk-go-v2/aws"
  dyn_expr "github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
  "github.com/aws/aws-sdk-go-v2/service/dynamodb"
  dyn_types "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

  "github.com/google/uuid"
  "google.golang.org/protobuf/proto"
)

type dynReadWriteTester struct {
  Conf *pb.Config
  Client *dynamodb.Client
  Metadata types.AdminMetadata
}

type genIterator interface {
  Next(context.Context) (string, proto.Message, bool)
  Err() error
}

func toItem(key string, msg proto.Message) (map[string]dyn_types.AttributeValue, error) {
  typename := msg.ProtoReflect().Descriptor().FullName()
  blob := new(bytes.Buffer)
  err := util.MarshalCompressedPb(blob, msg)
  if err != nil { return nil, err }
  item := map[string]dyn_types.AttributeValue{
    meta.Uuid_col: &dyn_types.AttributeValueMemberS{Value:key, },
    meta.Type_col: &dyn_types.AttributeValueMemberS{Value:string(typename), },
    meta.Blob_col: &dyn_types.AttributeValueMemberB{Value:blob.Bytes(), },
  }
  return item, nil
}

func getBlobFromItem(item map[string]dyn_types.AttributeValue) ([]byte, error) {
  abstract_val, found := item[meta.Blob_col]
  if !found { return nil, types.ErrNotFound }

  switch v := abstract_val.(type) {
    case *dyn_types.AttributeValueMemberB:
      return v.Value, nil
   default:
     return nil, fmt.Errorf("Malformed value for: %v", v)
  }
}

func (self *dynReadWriteTester) getItem(ctx context.Context, key string, msg proto.Message) error {
  var data []byte
  var get_out *dynamodb.GetItemOutput
  tab_name := DynTableName(self.Conf)
  key_map, err := toItem(key, msg)
  if err != nil { return err }
  delete(key_map, meta.Blob_col)
  get_in := &dynamodb.GetItemInput{
    TableName: &tab_name,
    Key: key_map,
    AttributesToGet: []string{ meta.Blob_col },
    ConsistentRead: aws.Bool(true),
  }
  get_out, err = self.Client.GetItem(ctx, get_in)
  //util.Debugf("Get request:\n%s\n%s\nerr: %v", util.AsJson(get_in), util.AsJson(get_out), err)
  if err != nil { return err }
  data, err = getBlobFromItem(get_out.Item)
  if err != nil { return err }
  err = util.UnmarshalCompressedPb(bytes.NewReader(data), msg)
  return err
}

func (self *dynReadWriteTester) getItemOrDie(ctx context.Context, key string, msg proto.Message) {
  err := self.getItem(ctx, key, msg)
  if err != nil { util.Fatalf("Failed get item: %v", err) }
}

func (self *dynReadWriteTester) putItemOrDie(ctx context.Context, key string, msg proto.Message) {
  err := self.putItem(ctx, key, msg)
  if err != nil { util.Fatalf("Failed put item: %v", err) }
}

func (self *dynReadWriteTester) putItem(ctx context.Context, key string, msg proto.Message) error {
  item, err := toItem(key, msg)
  if err != nil { return err }
  tab_name := DynTableName(self.Conf)
  params := &dynamodb.PutItemInput{
    TableName: &tab_name,
    Item: item,
  }
  //util.Debugf("Put request:\n%s", util.AsJson(params))
  _, err = self.Client.PutItem(ctx, params)
  return err
}

func (self *dynReadWriteTester) deleteTable(ctx context.Context) {
  tab_name := DynTableName(self.Conf)
  _, err := self.Client.DeleteTable(ctx, &dynamodb.DeleteTableInput{
    TableName: &tab_name,
  })
  if err != nil { util.Fatalf("Failed table delete: %v", err) }
}

func (self *dynReadWriteTester) emptyTableOrDie(ctx context.Context) {
  err := self.emptyTable(ctx)
  if err != nil { util.Fatalf("Failed to empty table: %v", err) }
}

func (self *dynReadWriteTester) emptyTable(ctx context.Context) error {
  tab_name := DynTableName(self.Conf)
  projection := dyn_expr.NamesList(dyn_expr.Name(meta.Uuid_col), dyn_expr.Name(meta.Type_col))
  expr, err := dyn_expr.NewBuilder().WithProjection(projection).Build()
  if err != nil { return err }
  scan_in := &dynamodb.ScanInput{
    TableName:              &tab_name,
    ExpressionAttributeNames: expr.Names(),
    ProjectionExpression:   expr.Projection(),
    ConsistentRead:         aws.Bool(true),
    ReturnConsumedCapacity: dyn_types.ReturnConsumedCapacityNone,
  }
  scan_out, err := self.Client.Scan(ctx, scan_in)
  if err != nil { return err }
  if len(scan_out.LastEvaluatedKey) > 0 { return fmt.Errorf("need more iterations") }
  for _,item := range scan_out.Items {
    del_in := &dynamodb.DeleteItemInput{
      TableName: &tab_name,
      Key: item,
    }
    _, err := self.Client.DeleteItem(ctx, del_in)
    if err != nil { return err }
  }
  //util.Debugf("Scan response:\n%s", util.AsJson(scan_out))
  return nil
}

func (self *dynReadWriteTester) TestRecordSnapshotSeqHead(ctx context.Context) {
  var err error
  var head1, head2, head3 *pb.SnapshotSeqHead
  vol_uuid := timedUuid("vol")
  new_seq := util.DummySnapshotSequence(vol_uuid, timedUuid("seq1"))
  new_seq_2 := util.DummySnapshotSequence(vol_uuid, timedUuid("seq2"))

  head1, err = self.Metadata.RecordSnapshotSeqHead(ctx, new_seq)
  if err != nil { util.Fatalf("%v", err) }
  util.EqualsOrDie("Bad subvol uuid", head1.Uuid, new_seq.Volume.Uuid)
  util.EqualsOrDie("Bad sequence uuid", head1.CurSeqUuid, new_seq.Uuid)

  head2, err = self.Metadata.RecordSnapshotSeqHead(ctx, new_seq)
  if err != nil { util.Fatalf("%v", err) }
  util.EqualsOrDie("Bad SnapshotSeqHead", head2, head1)

  head3, err = self.Metadata.RecordSnapshotSeqHead(ctx, new_seq_2)
  if err != nil { util.Fatalf("%v", err) }
  util.EqualsOrDie("Bad sequence uuid2", head3.CurSeqUuid, new_seq_2.Uuid)

  _, err = self.Metadata.RecordSnapshotSeqHead(ctx, new_seq)
  if err == nil { util.Fatalf("Adding an old sequence should be an error") }
}

func (self *dynReadWriteTester) TestAppendSnapshotToSeq(ctx context.Context) {
  var err error
  var seq_1, seq_noop, seq_2 *pb.SnapshotSequence
  vol_uuid := timedUuid("vol")
  seq_uuid := timedUuid("seq")
  snap1_uuid := timedUuid("snap1")
  snap2_uuid := timedUuid("snap2")
  snap_1 := util.DummySnapshot(snap1_uuid, vol_uuid)
  snap_2 := util.DummySnapshot(snap2_uuid, vol_uuid)
  expect_seq_0 := util.DummySnapshotSequence(vol_uuid, seq_uuid)
  expect_seq_0.SnapUuids = nil
  expect_seq_1 := util.DummySnapshotSequence(vol_uuid, seq_uuid)
  expect_seq_1.SnapUuids = []string{snap1_uuid}
  expect_seq_2 := util.DummySnapshotSequence(vol_uuid, seq_uuid)
  expect_seq_2.SnapUuids = []string{snap1_uuid, snap2_uuid}

  seq_1, err = self.Metadata.AppendSnapshotToSeq(ctx, expect_seq_0, snap_1)
  if err != nil { util.Fatalf("%v", err) }
  util.EqualsOrDie("Bad SnapshotSequence", seq_1, expect_seq_1)

  seq_noop, err = self.Metadata.AppendSnapshotToSeq(ctx, seq_1, snap_1)
  if err != nil { util.Fatalf("%v", err) }
  util.EqualsOrDie("Bad SnapshotSequence2", seq_noop, expect_seq_1)

  seq_2, err = self.Metadata.AppendSnapshotToSeq(ctx, expect_seq_1, snap_2)
  if err != nil { util.Fatalf("%v", err) }
  util.EqualsOrDie("Bad SnapshotSequence3", seq_2, expect_seq_2)
}

func (self *dynReadWriteTester) TestAppendChunkToSnapshot(ctx context.Context) {
  snap := util.DummySnapshot(timedUuid("snap"), timedUuid("par"))
  chunk_1 := util.DummyChunks(timedUuid("chunk_1"))
  chunk_2 := util.DummyChunks(timedUuid("chunk_2"))
  chunk_2.Chunks[0].Start = chunk_1.Chunks[0].Size

  expect_first := proto.Clone(snap).(*pb.SubVolume)
  expect_first.Data = proto.Clone(chunk_1).(*pb.SnapshotChunks)
  expect_second := proto.Clone(expect_first).(*pb.SubVolume)
  expect_second.Data.Chunks = append(expect_second.Data.Chunks,
                                     proto.Clone(chunk_2.Chunks[0]).(*pb.SnapshotChunks_Chunk))

  var err error
  var written_snap_1, written_snap_2, written_snap_3, written_snap_4 *pb.SubVolume
  written_snap_1, err = self.Metadata.AppendChunkToSnapshot(ctx, snap, chunk_1)
  if err != nil { util.Fatalf("%v", err) }
  util.EqualsOrDie("Bad Snapshot", written_snap_1, expect_first)

  written_snap_2, err = self.Metadata.AppendChunkToSnapshot(ctx, written_snap_1, chunk_1)
  if err != nil { util.Fatalf("%v", err) }
  util.EqualsOrDie("Bad Snapshot2", written_snap_2, written_snap_1)

  written_snap_3, err = self.Metadata.AppendChunkToSnapshot(ctx, written_snap_1, chunk_2)
  if err != nil { util.Fatalf("%v", err) }
  util.EqualsOrDie("Bad Snapshot3", written_snap_3, expect_second)

  written_snap_4, err = self.Metadata.AppendChunkToSnapshot(ctx, written_snap_3, chunk_2)
  if err != nil { util.Fatalf("%v", err) }
  util.EqualsOrDie("Bad Snapshot4", written_snap_4, written_snap_3)
}

func (self *dynReadWriteTester) TestReadSnapshotSeqHead(ctx context.Context) {
  var err error
  var expect_head, head *pb.SnapshotSeqHead
  vol_uuid := timedUuid("vol")
  seq := util.DummySnapshotSequence(vol_uuid, timedUuid("seq1"))

  _, err = self.Metadata.ReadSnapshotSeqHead(ctx, vol_uuid)
  if !errors.Is(err, types.ErrNotFound) { util.Fatalf("%v", err) }

  expect_head, err = self.Metadata.RecordSnapshotSeqHead(ctx, seq)
  if err != nil { util.Fatalf("%v", err) }

  head, err = self.Metadata.ReadSnapshotSeqHead(ctx, vol_uuid)
  if err != nil { util.Fatalf("%v", err) }
  util.EqualsOrDie("Bad SnapshotSeqHead", expect_head, head)
}

func (self *dynReadWriteTester) TestReadSnapshotSeq(ctx context.Context) {
  var err error
  var empty_seq, expect_seq, seq *pb.SnapshotSequence
  vol_uuid := timedUuid("vol")
  seq_uuid := timedUuid("seq")
  snap_uuid := timedUuid("snap")
  snap := util.DummySnapshot(snap_uuid, vol_uuid)
  empty_seq = util.DummySnapshotSequence(vol_uuid, seq_uuid)

  _, err = self.Metadata.ReadSnapshotSeq(ctx, empty_seq.Uuid)
  if !errors.Is(err, types.ErrNotFound) { util.Fatalf("%v", err) }

  expect_seq, err = self.Metadata.AppendSnapshotToSeq(ctx, empty_seq, snap)
  if err != nil { util.Fatalf("%v", err) }

  seq, err = self.Metadata.ReadSnapshotSeq(ctx, empty_seq.Uuid)
  if err != nil { util.Fatalf("%v", err) }
  util.EqualsOrDie("Bad SnapshotSequence", expect_seq, seq)
}

func (self *dynReadWriteTester) TestReadSnapshot(ctx context.Context) {
  var err error
  var snap *pb.SubVolume
  vol_uuid := timedUuid("vol")
  snap_uuid := timedUuid("snap")
  chunk_uuid := timedUuid("seq")
  empty_snap := util.DummySnapshot(snap_uuid, vol_uuid)
  expect_snap := util.DummySnapshot(snap_uuid, vol_uuid)
  expect_snap.Data = util.DummyChunks(chunk_uuid)

  _, err = self.Metadata.ReadSnapshot(ctx, expect_snap.Uuid)
  if !errors.Is(err, types.ErrNotFound) { util.Fatalf("%v", err) }

  expect_snap, err = self.Metadata.AppendChunkToSnapshot(ctx, empty_snap, util.DummyChunks(chunk_uuid))
  if err != nil { util.Fatalf("%v", err) }

  snap, err = self.Metadata.ReadSnapshot(ctx, expect_snap.Uuid)
  if err != nil { util.Fatalf("%v", err) }
  util.EqualsOrDie("Bad Snapshot", expect_snap, snap)
}

type pb_create_f = func() (string, proto.Message)
type iter_create_f = func(context.Context, types.Metadata) (genIterator, error)
func (self *dynReadWriteTester) testDynamotListAll_Helper(
    ctx context.Context, total int, fill_size int32, pb_f pb_create_f, iter_f iter_create_f) {
  self.emptyTableOrDie(ctx)
  meta.TestOnlyDynMetaChangeIterationSize(self.Metadata, fill_size)
  expect_objs := make(map[string]proto.Message)
  got_objs := make(map[string]proto.Message)

  for i:=0; i<total; i+=1 {
    key,msg := pb_f()
    expect_objs[key] = msg
    self.putItemOrDie(ctx, key, msg)
  }

  it, err := iter_f(ctx, self.Metadata)
  if err != nil { util.Fatalf("failed creating iterator: %v", err) }
  for {
    key,msg,more := it.Next(ctx)
    if !more { break }
    if len(key) < 1 { util.Fatalf("returned bad object: %v", msg) }
    got_objs[key] = msg
  }
  if it.Err() != nil { util.Fatalf("failed while iterating: %v", it.Err()) }
  util.EqualsOrDie("Bad len", len(got_objs), len(expect_objs))
  for key,expect := range expect_objs {
    util.EqualsOrDie("Bad obj", got_objs[key], expect)
  }
}

type headIterator struct { inner types.SnapshotSeqHeadIterator }
func (self * headIterator) Next(ctx context.Context) (string, proto.Message, bool) {
  obj := &pb.SnapshotSeqHead{}
  more := self.inner.Next(ctx, obj)
  return obj.Uuid, obj, more
}
func (self * headIterator) Err() error { return self.inner.Err() }
func head_pb_f() (string, proto.Message) {
  new_seq := util.DummySnapshotSequence(uuid.NewString(), uuid.NewString())
  new_head := util.DummySnapshotSeqHead(new_seq)
  return new_head.Uuid, new_head
}
func head_iter_f(ctx context.Context, metadata types.Metadata) (genIterator, error) {
  it,err := metadata.ListAllSnapshotSeqHeads(ctx)
  return &headIterator{it}, err
}
func (self *dynReadWriteTester) TestListAllSnapshotSeqHeads_Single(ctx context.Context) {
  const fill_size = 10
  const total = 3
  self.testDynamotListAll_Helper(ctx, total, fill_size, head_pb_f, head_iter_f)
}
func (self *dynReadWriteTester) TestListAllSnapshotSeqHeads_Multi(ctx context.Context) {
  const fill_size = 3
  const total = fill_size * 3
  self.testDynamotListAll_Helper(ctx, total, fill_size, head_pb_f, head_iter_f)
}

type seqIterator struct { inner types.SnapshotSequenceIterator }
func (self * seqIterator) Next(ctx context.Context) (string, proto.Message, bool) {
  obj := &pb.SnapshotSequence{}
  more := self.inner.Next(ctx, obj)
  return obj.Uuid, obj, more
}
func (self * seqIterator) Err() error { return self.inner.Err() }
func seq_pb_f() (string, proto.Message) {
  new_seq := util.DummySnapshotSequence(uuid.NewString(), uuid.NewString())
  return new_seq.Uuid, new_seq
}
func seq_iter_f(ctx context.Context, metadata types.Metadata) (genIterator, error) {
  it,err := metadata.ListAllSnapshotSeqs(ctx)
  return &seqIterator{it}, err
}
func (self *dynReadWriteTester) TestListAllSnapshotSeqs_Single(ctx context.Context) {
  const fill_size = 10
  const total = 3
  self.testDynamotListAll_Helper(ctx, total, fill_size, seq_pb_f, seq_iter_f)
}
func (self *dynReadWriteTester) TestListAllSnapshotSeqs_Multi(ctx context.Context) {
  const fill_size = 2
  const total = fill_size * 2
  self.testDynamotListAll_Helper(ctx, total, fill_size, seq_pb_f, seq_iter_f)
}

type snapIterator struct { inner types.SnapshotIterator }
func (self * snapIterator) Next(ctx context.Context) (string, proto.Message, bool) {
  obj := &pb.SubVolume{}
  more := self.inner.Next(ctx, obj)
  return obj.Uuid, obj, more
}
func (self * snapIterator) Err() error { return self.inner.Err() }
func snap_pb_f() (string, proto.Message) {
  new_snap := util.DummySnapshot(uuid.NewString(), uuid.NewString())
  return new_snap.Uuid, new_snap
}
func snap_iter_f(ctx context.Context, metadata types.Metadata) (genIterator, error) {
  it,err := metadata.ListAllSnapshots(ctx)
  return &snapIterator{it}, err
}
func (self *dynReadWriteTester) TestListAllSnapshots_Single(ctx context.Context) {
  const fill_size = 10
  const total = 3
  self.testDynamotListAll_Helper(ctx, total, fill_size, snap_pb_f, snap_iter_f)
}
func (self *dynReadWriteTester) TestListAllSnapshots_Multi(ctx context.Context) {
  const fill_size = 2
  const total = fill_size * 2
  self.testDynamotListAll_Helper(ctx, total, fill_size, snap_pb_f, snap_iter_f)
}

func (self *dynReadWriteTester) TestAllDynamoDbReadWrite(ctx context.Context) {
  self.TestRecordSnapshotSeqHead(ctx)
  self.TestAppendSnapshotToSeq(ctx)
  self.TestAppendChunkToSnapshot(ctx)
  self.TestReadSnapshotSeqHead(ctx)
  self.TestReadSnapshotSeq(ctx)
  self.TestReadSnapshot(ctx)
  self.TestListAllSnapshotSeqHeads_Single(ctx)
  self.TestListAllSnapshotSeqHeads_Multi(ctx)
  self.TestListAllSnapshotSeqs_Single(ctx)
  self.TestListAllSnapshotSeqs_Multi(ctx)
  self.TestListAllSnapshots_Single(ctx)
  self.TestListAllSnapshots_Multi(ctx)
}

func TestAllDynamoDbMetadata(ctx context.Context, conf *pb.Config, aws_conf *aws.Config) {
  client := dynamodb.NewFromConfig(*aws_conf)
  metadata, err := meta.NewAdminMetadata(conf, aws_conf, Backup(conf).Name)
  if err != nil { util.Fatalf("%v", err) }
  suite := &dynReadWriteTester{ Conf:conf, Client:client, Metadata:metadata, }

  TestDynamoDbMetadataSetup(ctx, conf, client, metadata)
  suite.TestAllDynamoDbReadWrite(ctx)
  TestAllDynamoDbDelete(ctx, conf, client, metadata)
  suite.deleteTable(ctx)
}

