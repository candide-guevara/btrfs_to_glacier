package aws_dynamodb_metadata
// * Can be used as KV store but blobs limited to 400KB
// * Eternal free tier should cover all storage needs
// * Which replication settings to get 99.999 durability ? (already replicated in the aws region)

import (
  "bytes"
  "context"
  "errors"
  "fmt"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"
  store "btrfs_to_glacier/volume_store"

  "github.com/aws/aws-sdk-go-v2/aws"
  dyn_expr "github.com/aws/aws-sdk-go-v2/feature/dynamodb/expression"
  "github.com/aws/aws-sdk-go-v2/service/dynamodb"
  dyn_types "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

  "google.golang.org/protobuf/proto"
)

const (
  Uuid_col = "uuid"
  Type_col = "blobType"
  Blob_col = "blobProto"
  describe_retry_millis = 2000
  dyn_iter_buf_len = 100
)

// The subset of the dynamodb client used.
// Convenient for unittesting purposes.
type usedDynamoDbIf interface {
  BatchWriteItem(context.Context, *dynamodb.BatchWriteItemInput, ...func(*dynamodb.Options)) (*dynamodb.BatchWriteItemOutput, error)
  CreateTable   (context.Context, *dynamodb.CreateTableInput,    ...func(*dynamodb.Options)) (*dynamodb.CreateTableOutput, error)
  DeleteItem    (context.Context, *dynamodb.DeleteItemInput,     ...func(*dynamodb.Options)) (*dynamodb.DeleteItemOutput, error)
  DescribeTable (context.Context, *dynamodb.DescribeTableInput,  ...func(*dynamodb.Options)) (*dynamodb.DescribeTableOutput, error)
  GetItem       (context.Context, *dynamodb.GetItemInput,        ...func(*dynamodb.Options)) (*dynamodb.GetItemOutput, error)
  PutItem       (context.Context, *dynamodb.PutItemInput,        ...func(*dynamodb.Options)) (*dynamodb.PutItemOutput, error)
  Scan          (context.Context, *dynamodb.ScanInput,           ...func(*dynamodb.Options)) (*dynamodb.ScanOutput, error)
}

type dynamoMetadata struct {
  conf     *pb.Config
  aws_conf *aws.Config
  tab_name string
  client   usedDynamoDbIf
  uuid_col string
  type_col string
  blob_col string
  iter_buf_len int32
  describe_retry time.Duration
}

type blobIterator struct {
  msg_type proto.Message
  parent   *dynamoMetadata
  buffer   []map[string]dyn_types.AttributeValue
  token    map[string]dyn_types.AttributeValue
  buf_next int
  started  bool
  err      error
}

func NewMetadata(conf *pb.Config, aws_conf *aws.Config, backup_name string) (types.Metadata, error) {
  meta := &dynamoMetadata{
    conf: conf,
    aws_conf: aws_conf,
    client: dynamodb.NewFromConfig(*aws_conf),
    uuid_col: Uuid_col,
    type_col: Type_col,
    blob_col: Blob_col,
    iter_buf_len: dyn_iter_buf_len,
    describe_retry: describe_retry_millis * time.Millisecond,
  }
  if b,err := util.BackupAwsByName(conf, backup_name); err == nil {
    meta.tab_name = b.DynamoDb.MetadataTableName
  } else {
    return nil, err
  }
  return meta, nil
}

// aws dynamodb scan --table-name Metadata_Test_coucou2 \
//   --projection-expression '#B' \
//   --filter-expression '#T = :t' \
//   --expression-attribute-names '{"#B":"Blob", "#T":"BlobType"}' \
//   --expression-attribute-values '{":t":{"S":"messages.SubVolume"}}'
func (self *dynamoMetadata) getScanExpression(msg proto.Message) dyn_expr.Expression {
  typename := msg.ProtoReflect().Descriptor().FullName()
  filter := dyn_expr.Name(self.type_col).Equal(dyn_expr.Value(string(typename)))
  projection := dyn_expr.NamesList(dyn_expr.Name(self.blob_col))
  expr, err := dyn_expr.NewBuilder().WithFilter(filter).WithProjection(projection).Build()
  if err != nil { util.Fatalf("failed building filter predicate: %v", err) }
  return expr
}

func typeColValue(msg proto.Message) string {
  typename := msg.ProtoReflect().Descriptor().FullName()
  return string(typename)
}

func (self *dynamoMetadata) uuidTypeToKey(uuid string, typename string) map[string]dyn_types.AttributeValue {
  composite_k := map[string]dyn_types.AttributeValue{
    self.uuid_col: &dyn_types.AttributeValueMemberS{Value: uuid,},
    self.type_col: &dyn_types.AttributeValueMemberS{Value: typename,},
  }
  return composite_k
}

func (self *dynamoMetadata) getItemKey(uuid string, msg proto.Message) map[string]dyn_types.AttributeValue {
  typename := typeColValue(msg)
  return self.uuidTypeToKey(uuid, typename)
}

func (self *dynamoMetadata) getBlobFromItem(item map[string]dyn_types.AttributeValue) ([]byte, error) {
  abstract_val, found := item[self.blob_col]
  if !found { return nil, types.ErrNotFound }

  switch v := abstract_val.(type) {
    case *dyn_types.AttributeValueMemberB:
      return v.Value, nil
   default:
     return nil, fmt.Errorf("Malformed value for '%v': %v", self.blob_col, v)
  }
}

// Returns ErrNotFound if the item does not exist in the database.
func (self *dynamoMetadata) ReadObject(ctx context.Context, key string, msg proto.Message) error {
  params := &dynamodb.GetItemInput{
    TableName: &self.tab_name,
    Key: self.getItemKey(key, msg),
    ProjectionExpression: &self.blob_col,
    ConsistentRead: aws.Bool(false),
    ReturnConsumedCapacity: dyn_types.ReturnConsumedCapacityNone,
  }
  result, err := self.client.GetItem(ctx, params)
  if err != nil { return err }
  data, err := self.getBlobFromItem(result.Item)
  if err != nil { return err }
  err = util.UnmarshalCompressedPb(bytes.NewReader(data), msg)
  return err
}

// Create or updates
func (self *dynamoMetadata) WriteObject(ctx context.Context, key string, msg proto.Message) error {
  item := self.getItemKey(key, msg)
  blob := new(bytes.Buffer)
  err := util.MarshalCompressedPb(blob, msg)
  if err != nil { return err }
  item[self.blob_col] = &dyn_types.AttributeValueMemberB{Value: blob.Bytes(),}
  params := &dynamodb.PutItemInput{
    TableName: &self.tab_name,
    Item: item,
  }
  _, err = self.client.PutItem(ctx, params)
  return err
}

func (self *dynamoMetadata) RecordSnapshotSeqHead(ctx context.Context, new_seq *pb.SnapshotSequence) (*pb.SnapshotSeqHead, error) {
  err := store.ValidateSnapshotSequence(new_seq)
  if err != nil { return nil, err }

  head := &pb.SnapshotSeqHead{}
  err = self.ReadObject(ctx, new_seq.Volume.Uuid, head)
  is_new_head := errors.Is(err, types.ErrNotFound)
  if err != nil && !is_new_head { return nil, err }

  if head.CurSeqUuid == new_seq.Uuid {
    util.PbInfof("Noop already current seq in head: %v", head)
    return head, nil
  }
  if is_new_head { head.Uuid = new_seq.Volume.Uuid }
  if !is_new_head { head.PrevSeqUuid = append(head.PrevSeqUuid, head.CurSeqUuid) }
  head.CurSeqUuid = new_seq.Uuid

  err = store.ValidateSnapshotSeqHead(head)
  if err != nil { return nil, err }
  err = self.WriteObject(ctx, new_seq.Volume.Uuid, head)
  if err != nil { return nil, err }

  util.PbInfof("Wrote head: %v", head)
  return head, nil
}

func (self *dynamoMetadata) AppendSnapshotToSeq(
    ctx context.Context, seq *pb.SnapshotSequence, snap *pb.SubVolume) (*pb.SnapshotSequence, error) {
  err := store.ValidateSubVolume(store.CheckSnapNoContent, snap)
  if err != nil { return nil, err }

  new_seq := proto.Clone(seq).(*pb.SnapshotSequence)
  if len(seq.SnapUuids) > 0 {
    last := seq.SnapUuids[len(seq.SnapUuids) - 1]
    if last == snap.Uuid {
      util.PbInfof("Noop already last snap in seq: %v", seq)
      return new_seq, nil
    }
  }

  new_seq.SnapUuids = append(new_seq.SnapUuids, snap.Uuid)

  err = store.ValidateSnapshotSequence(new_seq)
  if err != nil { return nil, err }
  if new_seq.Volume.Uuid != snap.ParentUuid {
    return nil, util.PbErrorf("Sequence volume and snap parent do not match: %v, %v", new_seq, snap)
  }
  if new_seq.Volume.CreatedTs >= snap.CreatedTs {
    return nil, util.PbErrorf("Sequence volume created after snap: %v, %v", new_seq, snap)
  }
  self.WriteObject(ctx, new_seq.Uuid, new_seq)
  if err != nil { return nil, err }

  util.PbInfof("Wrote sequence: %v", new_seq)
  return new_seq, nil
}

func (self *dynamoMetadata) AppendChunkToSnapshot(
    ctx context.Context, snap *pb.SubVolume, data *pb.SnapshotChunks) (*pb.SubVolume, error) {
  err := store.ValidateSnapshotChunks(store.CheckChunkNotFirst, data)
  if err != nil { return nil, err }

  if snap.Data != nil && snap.Data.KeyFingerprint != data.KeyFingerprint {
    return nil, util.PbErrorf("Snapshot chunk key mismatch: %v, %v", snap, data)
  }

  new_snap := proto.Clone(snap).(*pb.SubVolume)
  if store.IsFullyContainedInSubvolume(snap, data) {
    util.PbInfof("Noop already last chunk in snap: %v", snap)
    return new_snap, nil
  }

  data_len := store.SubVolumeDataLen(snap)
  if data.Chunks[0].Start != data_len {
    return nil, util.PbErrorf("Snapshot chunk not contiguous: %v, %v", snap, data)
  }

  if new_snap.Data == nil {
    new_snap.Data = &pb.SnapshotChunks { KeyFingerprint: data.KeyFingerprint }
  }
  new_snap.Data.Chunks = append(new_snap.Data.Chunks, data.Chunks...)

  err = store.ValidateSubVolume(store.CheckSnapWithContent, new_snap)
  if err != nil { return nil, err }
  err = self.WriteObject(ctx, new_snap.Uuid, new_snap)
  if err != nil { return nil, err }

  util.PbInfof("Wrote snapshot: %v", new_snap)
  return new_snap, nil
}

func (self *dynamoMetadata) ReadSnapshotSeqHead(
    ctx context.Context, uuid string) (*pb.SnapshotSeqHead, error) {
  if len(uuid) < 1 { return nil, fmt.Errorf("ReadSnapshotSeqHead: uuid is nil") }
  head := &pb.SnapshotSeqHead{}
  err := self.ReadObject(ctx, uuid, head)
  if err != nil { return nil, err }
  err = store.ValidateSnapshotSeqHead(head)
  if err != nil { return nil, err }

  util.PbInfof("Read head: %v", head)
  return head, nil
}

func (self *dynamoMetadata) ReadSnapshotSeq(
    ctx context.Context, uuid string) (*pb.SnapshotSequence, error) {
  if len(uuid) < 1 { return nil, fmt.Errorf("ReadSnapshotSeq: uuid is nil") }
  seq := &pb.SnapshotSequence{}
  err := self.ReadObject(ctx, uuid, seq)
  if err != nil { return nil, err }
  err = store.ValidateSnapshotSequence(seq)
  if err != nil { return nil, err }

  util.PbInfof("Read sequence: %v", seq)
  return seq, nil
}

func (self *dynamoMetadata) ReadSnapshot(
    ctx context.Context, uuid string) (*pb.SubVolume, error) {
  if len(uuid) < 1 { return nil, fmt.Errorf("ReadSnapshot: uuid is nil") }
  snap := &pb.SubVolume{}
  err := self.ReadObject(ctx, uuid, snap)
  if err != nil { return nil, err }
  err = store.ValidateSubVolume(store.CheckSnapWithContent, snap)
  if err != nil { return nil, err }

  util.PbInfof("Read subvolume: %v", snap)
  return snap, nil
}

func (self *dynamoMetadata) NewIterator(msg proto.Message) *blobIterator {
  return &blobIterator{ msg_type: msg, parent: self, }
}

func (self *blobIterator) popBuffer(msg proto.Message) error {
  item := self.buffer[self.buf_next]
  self.buf_next += 1
  data, err := self.parent.getBlobFromItem(item)
  if err != nil { return err }
  err = util.UnmarshalCompressedPb(bytes.NewReader(data), msg)
  return err
}

func (self *blobIterator) fillBuffer(ctx context.Context) error {
  if self.buf_next < len(self.buffer) { util.Fatalf("filling before exhausting buffer") }
  filter_proj := self.parent.getScanExpression(self.msg_type)
  scan_in := &dynamodb.ScanInput{
    TableName: &self.parent.tab_name,
    ExpressionAttributeNames:  filter_proj.Names(),
    ExpressionAttributeValues: filter_proj.Values(),
    FilterExpression:          filter_proj.Filter(),
    ProjectionExpression:      filter_proj.Projection(),
    ConsistentRead:            aws.Bool(false),
    ReturnConsumedCapacity:    dyn_types.ReturnConsumedCapacityNone,
    ExclusiveStartKey:         self.token,
    Limit:                     aws.Int32(self.parent.iter_buf_len),
    TotalSegments:             nil, // sequential scan
  }
  scan_out, err := self.parent.client.Scan(ctx, scan_in)
  //util.Debugf("request:%v\nresponse:\n%v\nerror:%v", util.AsJson(scan_in), util.AsJson(scan_out), err)
  if err != nil { return err }
  self.token = nil
  if len(scan_out.LastEvaluatedKey) > 0 { self.token = scan_out.LastEvaluatedKey }
  self.buffer = scan_out.Items
  self.buf_next = 0
  if len(self.buffer) != int(scan_out.Count) { util.Fatalf("Scan yielded less than %d", scan_out.Count) }
  return nil
}

func (self *blobIterator) Next(ctx context.Context, msg proto.Message) bool {
  if self.err != nil { return false }
  if self.buf_next < len(self.buffer) {
    self.err = self.popBuffer(msg)
    return self.err == nil
  }
  if self.started && self.token == nil { return false }
  self.started = true
  self.err = self.fillBuffer(ctx)
  return self.Next(ctx, msg)
}

type snapshotSeqHeadIterator struct { generic_it *blobIterator }
func (self *snapshotSeqHeadIterator) Next(ctx context.Context, msg *pb.SnapshotSeqHead) bool {
  return self.generic_it.Next(ctx, msg)
}
func (self *snapshotSeqHeadIterator) Err() error { return self.generic_it.err }
func (self *dynamoMetadata) ListAllSnapshotSeqHeads(ctx context.Context) (types.SnapshotSeqHeadIterator, error) {
  msg := &pb.SnapshotSeqHead{}
  it := &snapshotSeqHeadIterator{ generic_it:self.NewIterator(msg), }
  return it, nil
}

type snapshotSequenceIterator struct { generic_it *blobIterator }
func (self *snapshotSequenceIterator) Next(ctx context.Context, msg *pb.SnapshotSequence) bool {
  return self.generic_it.Next(ctx, msg)
}
func (self *snapshotSequenceIterator) Err() error { return self.generic_it.err }
func (self *dynamoMetadata) ListAllSnapshotSeqs(ctx context.Context) (types.SnapshotSequenceIterator, error) {
  msg := &pb.SnapshotSequence{}
  it := &snapshotSequenceIterator{ generic_it:self.NewIterator(msg), }
  return it, nil
}

type snapshotIterator struct { generic_it *blobIterator }
func (self *snapshotIterator) Next(ctx context.Context, msg *pb.SubVolume) bool {
  return self.generic_it.Next(ctx, msg)
}
func (self *snapshotIterator) Err() error { return self.generic_it.err }
func (self *dynamoMetadata) ListAllSnapshots(ctx context.Context) (types.SnapshotIterator, error) {
  msg := &pb.SubVolume{}
  it := &snapshotIterator{ generic_it:self.NewIterator(msg), }
  return it, nil
}

func (self *dynamoMetadata) PersistCurrentMetadataState(ctx context.Context) (string, error) {
  return "", fmt.Errorf("dynamoMetadata.PersistCurrentMetadataState not_implemented")
}

