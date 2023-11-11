package aws_dynamodb_metadata

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
  "github.com/aws/aws-sdk-go-v2/service/dynamodb"
  dyn_types "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
  delete_batch = 100
)

type dynamoAdminMetadata struct {
  *dynamoMetadata
  delete_batch int
}

func NewAdminMetadata(
    conf *pb.Config, aws_conf types.AwsConf, backup_name string) (types.AdminMetadata, error) {
  meta, err := NewMetadata(conf, aws_conf, backup_name)
  if err != nil { return nil, err }
  admin := &dynamoAdminMetadata{
    dynamoMetadata: meta.(*dynamoMetadata),
    delete_batch: delete_batch,
  }
  return admin, nil
}

func TestOnlyDynMetaChangeIterationSize(metadata types.Metadata, fill_size int32) func() {
  impl,ok := metadata.(*dynamoAdminMetadata)
  if !ok { util.Fatalf("called with the wrong impl") }
  old_val := impl.iter_buf_len
  impl.iter_buf_len = fill_size
  return func() { impl.iter_buf_len = old_val }
}

func (self *dynamoMetadata) describeTable(ctx context.Context) (*dyn_types.TableDescription, error) {
  params := &dynamodb.DescribeTableInput{
    TableName: &self.tab_name,
  }
  result, err := self.client.DescribeTable(ctx, params)
  if err != nil {
    apiErr := new(dyn_types.ResourceNotFoundException)
    if errors.As(err, &apiErr) { util.Debugf("'%s' does not exist", self.tab_name) }
    return nil, err
  }
  return result.Table, nil
}

func (self *dynamoMetadata) waitForTableCreation(ctx context.Context) error {
  ticker := time.NewTicker(self.describe_retry)
  defer ticker.Stop()

  for {
    select {
      case <-ticker.C:
        result, err := self.describeTable(ctx)
        if err != nil { return err }
        if result.TableStatus == dyn_types.TableStatusActive { return nil }
        if result.TableStatus != dyn_types.TableStatusCreating {
          return fmt.Errorf("Unexpected status while waiting for table creation: %v", result.TableStatus)
        }
      case <-ctx.Done():
        return fmt.Errorf("Timedout while waiting for table creation")
    }
  }
  return fmt.Errorf("WTF why am I out of the loop ?!")
}

func (self *dynamoMetadata) SetupMetadata(ctx context.Context) error {
  attrs := []dyn_types.AttributeDefinition{
    dyn_types.AttributeDefinition{
      AttributeName: &self.uuid_col,
      AttributeType: dyn_types.ScalarAttributeTypeS,
    },
    dyn_types.AttributeDefinition{
      AttributeName: &self.type_col,
      AttributeType: dyn_types.ScalarAttributeTypeS,
    },
  }
  schema := []dyn_types.KeySchemaElement{
    dyn_types.KeySchemaElement{
      AttributeName: &self.uuid_col,
      KeyType: dyn_types.KeyTypeHash,
    },
    dyn_types.KeySchemaElement{
      AttributeName: &self.type_col,
      KeyType: dyn_types.KeyTypeRange,
    },
  }
  params := &dynamodb.CreateTableInput{
    TableName: &self.tab_name,
    AttributeDefinitions: attrs,
    KeySchema: schema,
    BillingMode: dyn_types.BillingModePayPerRequest,
  }

  result, err := self.client.CreateTable(ctx, params)
  if err != nil {
    apiErr := new(dyn_types.ResourceInUseException)
    if errors.As(err, &apiErr) {
      util.Infof("Table '%s' already exists", self.tab_name)
      return nil
    }
    return err
  }
  if result.TableDescription.TableStatus == dyn_types.TableStatusActive {
    return nil
  }
  return self.waitForTableCreation(ctx)
}

func (self *dynamoMetadata) TearDownMetadata(ctx context.Context) error {
  return nil //noop
}

func (self *dynamoAdminMetadata) buildDeleteRequest(uuid string, typename string) dyn_types.WriteRequest {
  return dyn_types.WriteRequest{
    DeleteRequest: &dyn_types.DeleteRequest{ Key:self.uuidTypeToKey(uuid, typename), },
  }
}

func (self *dynamoAdminMetadata) flushDeletes(ctx context.Context, keys []dyn_types.WriteRequest) error {
  remaining_keys := map[string][]dyn_types.WriteRequest {
    self.tab_name: keys,
  }
  for len(remaining_keys[self.tab_name]) > 0 {
    del_in := &dynamodb.BatchWriteItemInput{
      RequestItems: remaining_keys,
      ReturnConsumedCapacity: dyn_types.ReturnConsumedCapacityNone,
    }
    del_out, err := self.client.BatchWriteItem(ctx, del_in)
    if err != nil { return err }
    remaining_keys = del_out.UnprocessedItems
  }
  return nil
}

func (self *dynamoAdminMetadata) DeleteMetadataUuids(
    ctx context.Context, seq_uuids []string, snap_uuids []string) error {
  uuid_map := map[string][]string {
    typeColValue(&pb.SnapshotSequence{}): seq_uuids,
    typeColValue(&pb.SubVolume{}): snap_uuids,
  }
  keys := make([]dyn_types.WriteRequest, 0, self.delete_batch)

  for typename,uuids := range uuid_map {
    for _,uuid := range uuids {
      keys = append(keys, self.buildDeleteRequest(uuid, typename))
      if len(keys) >= self.delete_batch {
        err := self.flushDeletes(ctx, keys)
        if err != nil { return err }
        keys = keys[:0]
      }
    }
  }
  err := self.flushDeletes(ctx, keys)
  if err != nil { return err }
  util.Infof("Deleted seq=%v, snap=%v", seq_uuids, snap_uuids)
  return nil
}

func (self *dynamoAdminMetadata) ReplaceSnapshotSeqHead(
    ctx context.Context, head *pb.SnapshotSeqHead) (*pb.SnapshotSeqHead, error) {
  var err error
  var put_out *dynamodb.PutItemOutput
  old_head := &pb.SnapshotSeqHead{}
  err = store.ValidateSnapshotSeqHead(head)
  if err != nil { return nil, err }

  item := self.getItemKey(head.Uuid, head)
  blob := new(bytes.Buffer)
  err = util.MarshalCompressedPb(blob, head)
  if err != nil { return nil, err }
  item[self.blob_col] = &dyn_types.AttributeValueMemberB{Value: blob.Bytes(),}

  // We use a condition expression to trigger an error in case the key does not exist.
  // Otherwise we cannot distinguish between the item not existing and a successful delete.
  put_in := &dynamodb.PutItemInput{
    TableName: &self.tab_name,
    Item: item,
    ConditionExpression: aws.String(fmt.Sprintf("attribute_exists(%s)", self.blob_col)),
    ReturnValues: dyn_types.ReturnValueAllOld,
  }
  put_out, err = self.client.PutItem(ctx, put_in)
  if err != nil {
    apiErr := new(dyn_types.ConditionalCheckFailedException)
    if errors.As(err, &apiErr) { return nil, fmt.Errorf("%w uuid=%v", types.ErrNotFound, head.Uuid) }
  }
  if err != nil { return nil, err }

  util.PbInfof("Wrote head: %v", head)
  buf, err := self.getBlobFromItem(put_out.Attributes)
  if err != nil { return nil, err }
  err = util.UnmarshalCompressedPb(bytes.NewReader(buf), old_head)
  return old_head, err
}

