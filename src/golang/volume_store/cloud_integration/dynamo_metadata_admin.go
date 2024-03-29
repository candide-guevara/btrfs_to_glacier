package main

import (
  "context"
  "errors"
  "time"

  pb "btrfs_to_glacier/messages"
  "btrfs_to_glacier/types"
  "btrfs_to_glacier/util"

  "github.com/aws/aws-sdk-go-v2/service/dynamodb"
  dyn_types "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"

  "github.com/google/uuid"
)

type dynAdminTester struct { *dynReadWriteTester }

func TestDynamoDbMetadataSetup(
    ctx context.Context, conf *pb.Config, client *dynamodb.Client, metadata types.AdminMetadata) {
  tab_name := DynTableName(conf)
  _, err := client.DeleteTable(ctx, &dynamodb.DeleteTableInput{
    TableName: &tab_name,
  })

  if err != nil {
    apiErr := new(dyn_types.ResourceNotFoundException)
    if !errors.As(err, &apiErr) { util.Fatalf("%v", err) }
    util.Infof("TestDynamoDbMetadataSetup '%s' not exist", tab_name)
  } else {
    waiter := dynamodb.NewTableNotExistsWaiter(client)
    wait_rq := &dynamodb.DescribeTableInput{ TableName: &tab_name, }
    err = waiter.Wait(ctx, wait_rq, 30 * time.Second)
    if err != nil { util.Fatalf("%v", err) }
    util.Infof("TestDynamoDbMetadataSetup '%s' deleted", tab_name)
  }

  done := make(chan bool)
  go func() {
    defer close(done)
    err := metadata.SetupMetadata(ctx)
    if err != nil { util.Fatalf("%v", err) }
    err = metadata.SetupMetadata(ctx)
    if err != nil { util.Fatalf("Idempotent err: %v", err) }
  }()
  select {
    case <-done:
    case <-ctx.Done(): util.Fatalf("Timeout: %v", ctx.Err())
  }
}

func (self *dynAdminTester) testDeleteMetadataUuids_Helper(
    ctx context.Context, seq_cnt int, snap_cnt int, missing_cnt int) {
  seq_uuids := make([]string, 0, seq_cnt)
  snap_uuids := make([]string, 0, snap_cnt)
  for len(seq_uuids) < seq_cnt || len(snap_uuids) < snap_cnt {
    if len(seq_uuids) < seq_cnt {
      seq := util.DummySnapshotSequence(uuid.NewString(), uuid.NewString())
      seq_uuids = append(seq_uuids, seq.Uuid)
      self.putItemOrDie(ctx, seq.Uuid, seq)
    }
    if len(snap_uuids) < snap_cnt {
      snap := util.DummySnapshot(uuid.NewString(), uuid.NewString())
      snap_uuids = append(snap_uuids, snap.Uuid)
      self.putItemOrDie(ctx, snap.Uuid, snap)
    }
  }
  for i:=0; i<missing_cnt; i+=1 {
    snap_uuids = append(snap_uuids, uuid.NewString())
    seq_uuids = append(seq_uuids, uuid.NewString())
  }

  done := make(chan bool)
  go func() {
    defer close(done)
    err := self.Metadata.DeleteMetadataUuids(ctx, seq_uuids, snap_uuids)
    if err != nil { util.Fatalf("Metadata.DeleteMetadataUuids error: %v", err) }

    for _,uuid := range seq_uuids {
      err := self.getItem(ctx, uuid, &pb.SnapshotSequence{})
      if !errors.Is(err, types.ErrNotFound) { util.Fatalf("failed to delete %s: %v", uuid, err) }
    }
    for _,uuid := range snap_uuids {
      err := self.getItem(ctx, uuid, &pb.SubVolume{})
      if !errors.Is(err, types.ErrNotFound) { util.Fatalf("failed to delete %s: %v", uuid, err) }
    }
  }()
  select {
    case <-done:
    case <-ctx.Done(): util.Fatalf("Timeout: %v", ctx.Err())
  }
}

func (self *dynAdminTester) TestDeleteMetadataUuids_Simple(ctx context.Context) {
  const seq_cnt = 3
  const snap_cnt = 5
  const missing_cnt = 0
  self.testDeleteMetadataUuids_Helper(ctx, seq_cnt, snap_cnt, missing_cnt)
}

func (self *dynAdminTester) TestDeleteMetadataUuids_MissingKeys(ctx context.Context) {
  const seq_cnt = 3
  const snap_cnt = 0
  const missing_cnt = 5
  self.testDeleteMetadataUuids_Helper(ctx, seq_cnt, snap_cnt, missing_cnt)
}

func (self *dynAdminTester) TestReplaceSnapshotSeqHead_Simple(ctx context.Context) {
  head_uuid := uuid.NewString()
  old_head := util.DummySnapshotSeqHead(util.DummySnapshotSequence(head_uuid, uuid.NewString()))
  new_head := util.DummySnapshotSeqHead(util.DummySnapshotSequence(head_uuid, uuid.NewString()))
  self.putItemOrDie(ctx, old_head.Uuid, old_head)
  got_old_head, err := self.Metadata.ReplaceSnapshotSeqHead(ctx, new_head)
  if err != nil { util.Fatalf("Returned error: %v", err) }

  got_new_head := &pb.SnapshotSeqHead{}
  self.getItemOrDie(ctx, new_head.Uuid, got_new_head)
  util.EqualsOrDie("OldSnapshotSeqHead", got_old_head, old_head)
  util.EqualsOrDie("NewSnapshotSeqHead", got_new_head, new_head)
}

func (self *dynAdminTester) TestReplaceSnapshotSeqHead_NoHead(ctx context.Context) {
  head_uuid := uuid.NewString()
  new_head := util.DummySnapshotSeqHead(util.DummySnapshotSequence(head_uuid, uuid.NewString()))
  _, err := self.Metadata.ReplaceSnapshotSeqHead(ctx, new_head)
  if !errors.Is(err, types.ErrNotFound) { util.Fatalf("Should have failed to replace %s: %v", head_uuid, err) }
}

func TestAllDynamoDbDelete(
    ctx context.Context, conf *pb.Config, client *dynamodb.Client, metadata types.AdminMetadata) {
  suite := &dynAdminTester{
    &dynReadWriteTester{ Conf:conf, Client:client, Metadata:metadata, },
  }
  suite.TestDeleteMetadataUuids_Simple(ctx)
  suite.TestDeleteMetadataUuids_MissingKeys(ctx)
  suite.TestReplaceSnapshotSeqHead_Simple(ctx)
  suite.TestReplaceSnapshotSeqHead_NoHead(ctx)
}

